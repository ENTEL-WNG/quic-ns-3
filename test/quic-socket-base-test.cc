/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * QUIC Socket State (TCB) Tests - RFC 9002 Compliance
 *
 * Tests the QUIC Transmission Control Block (QuicSocketState) as specified
 * in RFC 9002 Appendix B. QuicSocketBase requires a full L4 protocol stack
 * for safe construction, so these tests target QuicSocketState directly. The
 * ACK piggyback test drives a socket through an unbound QuicL4Protocol instead.
 *
 * RFC 9002 §7.2: Initial Congestion Window
 * RFC 9002 §7.3: Congestion Control States
 * RFC 9002 §7.2: Minimum Congestion Window
 */

#include "ns3/test.h"
#include "ns3/log.h"
#include "ns3/quic-socket-base.h"
#include "ns3/quic-l4-protocol.h"
#include "ns3/quic-subheader.h"
#include "ns3/quic-socket-tx-scheduler.h"
#include "ns3/quic-header.h"
#include "ns3/quic-received-packet-ranges.h"
#include "ns3/simulator.h"
#include "ns3/data-rate.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicSocketBaseTest");

/**
 * Test Case: TCB Initial State
 *
 * RFC 9002 §7.2: "Endpoints SHOULD use an initial congestion window of
 * 10 times the maximum datagram size (max_datagram_size), limited to the
 * larger of 14720 bytes or twice the maximum datagram size."
 *
 * RFC 9002 §7.3.1: "A sender is in slow start whenever the congestion
 * window is below the slow start threshold."
 */
class QuicTcbInitialStateTestCase : public TestCase
{
public:
  QuicTcbInitialStateTestCase ();

private:
  virtual void DoRun (void);
  virtual void DoTeardown (void);

  Ptr<QuicSocketState> m_tcb;
};

QuicTcbInitialStateTestCase::QuicTcbInitialStateTestCase ()
  : TestCase ("TCB Initial State - Congestion Window and Slow Start (RFC 9002 §7.2, §7.3.1)")
{
}

void
QuicTcbInitialStateTestCase::DoRun (void)
{
  m_tcb = CreateObject<QuicSocketState> ();
  NS_TEST_ASSERT_MSG_NE (m_tcb, nullptr, "QuicSocketState must be creatable");

  // Replicate what QuicSocketBase does during connection setup (RFC 9002 §B.2)
  m_tcb->m_segmentSize = 1200;
  m_tcb->m_initialSsThresh = UINT32_MAX; // RFC 9002: start in slow start
  m_tcb->m_cWnd = m_tcb->GetInitialWindow ();
  m_tcb->m_ssThresh = m_tcb->m_initialSsThresh;

  // Test 1: Segment size is set correctly
  NS_TEST_ASSERT_MSG_EQ (m_tcb->m_segmentSize, 1200,
                         "Segment size must be 1200 after initialization");

  // Test 2: Initial cwnd meets RFC 9002 §7.2 minimum (>= 2*MSS)
  uint32_t cWnd = m_tcb->m_cWnd.Get ();
  uint32_t minRequired = 2 * m_tcb->m_segmentSize;
  NS_TEST_ASSERT_MSG_GT_OR_EQ (cWnd, minRequired,
                               "Initial cwnd must be >= 2*MSS per RFC 9002 §7.2");

  // Test 3: ssThresh starts at UINT32_MAX (slow start until first loss, RFC 9002 §7.3.1)
  NS_TEST_ASSERT_MSG_EQ (m_tcb->m_ssThresh.Get (), UINT32_MAX,
                         "ssThresh must start at UINT32_MAX to begin in slow start");

  // Test 4: Initially in slow start (cwnd < ssThresh is always true when ssThresh=UINT32_MAX)
  NS_TEST_ASSERT_MSG_LT (cWnd, m_tcb->m_ssThresh.Get (),
                         "Must begin in slow start (cwnd < ssThresh)");
}

void
QuicTcbInitialStateTestCase::DoTeardown (void)
{
  m_tcb = nullptr;
}

/**
 * Test Case: Minimum Congestion Window
 *
 * RFC 9002 §7.2: "The RECOMMENDED value is 2 * max_datagram_size."
 * The congestion window must never drop below this floor.
 */
class QuicMinimumWindowTestCase : public TestCase
{
public:
  QuicMinimumWindowTestCase ();

private:
  virtual void DoRun (void);
  virtual void DoTeardown (void);

  Ptr<QuicSocketState> m_tcb;
};

QuicMinimumWindowTestCase::QuicMinimumWindowTestCase ()
  : TestCase ("Minimum Congestion Window Floor (RFC 9002 §7.2)")
{
}

void
QuicMinimumWindowTestCase::DoRun (void)
{
  m_tcb = CreateObject<QuicSocketState> ();

  // Test 1: GetMinimumWindow() returns 2*MSS
  uint32_t minWindow = m_tcb->GetMinimumWindow ();
  NS_TEST_ASSERT_MSG_EQ (minWindow, m_tcb->m_kMinimumWindowMultiplier * m_tcb->m_segmentSize,
                         "Minimum window must be kMinimumWindowMultiplier * MSS");

  // Test 2: Default multiplier is 2 (RFC 9002 §7.2)
  NS_TEST_ASSERT_MSG_EQ (m_tcb->m_kMinimumWindowMultiplier, 2,
                         "Default minimum window multiplier must be 2 per RFC 9002 §7.2");

  // Test 3: Minimum window is segment-size dependent
  uint32_t origSegSize = m_tcb->m_segmentSize;
  m_tcb->m_segmentSize = 1500;
  NS_TEST_ASSERT_MSG_EQ (m_tcb->GetMinimumWindow (), 2 * 1500,
                         "Minimum window scales with MSS");
  m_tcb->m_segmentSize = origSegSize;
}

void
QuicMinimumWindowTestCase::DoTeardown (void)
{
  m_tcb = nullptr;
}

/**
 * Test Case: RTT State Initialization
 *
 * RFC 9002 §5: "An endpoint uses the RTT samples it collects to generate
 * a smoothed RTT estimate."
 *
 * RFC 9002 §5.3: Initial smoothed RTT before any measurement should
 * reflect a reasonable initial estimate.
 */
class QuicRttInitializationTestCase : public TestCase
{
public:
  QuicRttInitializationTestCase ();

private:
  virtual void DoRun (void);
  virtual void DoTeardown (void);

  Ptr<QuicSocketState> m_tcb;
};

QuicRttInitializationTestCase::QuicRttInitializationTestCase ()
  : TestCase ("RTT State Initialization (RFC 9002 §5)")
{
}

void
QuicRttInitializationTestCase::DoRun (void)
{
  m_tcb = CreateObject<QuicSocketState> ();

  // Test 1: Initial smoothed RTT is set (RFC 9002 §5.3 suggests 333ms initial)
  NS_TEST_ASSERT_MSG_GT (m_tcb->m_smoothedRtt.GetMilliSeconds (), (int64_t)0,
                         "Initial smoothed RTT must be positive");

  // Test 2: Initial RTT variance is set
  NS_TEST_ASSERT_MSG_GT (m_tcb->m_rttVar.GetMilliSeconds (), (int64_t)0,
                         "Initial RTT variance must be positive");

  // Test 3: RTT variance >= 0 always (it's a variance, always non-negative)
  NS_TEST_ASSERT_MSG_GT_OR_EQ (m_tcb->m_rttVar.GetMilliSeconds (), (int64_t)0,
                               "RTT variance must be non-negative");

  // Test 4: Loss reduction factor is in valid range (RFC 9002 §7.3.2: 0.5)
  NS_TEST_ASSERT_MSG_GT (m_tcb->m_kLossReductionFactor, 0.0,
                         "Loss reduction factor must be positive");
  NS_TEST_ASSERT_MSG_LT (m_tcb->m_kLossReductionFactor, 1.0,
                         "Loss reduction factor must be < 1.0");
}

void
QuicRttInitializationTestCase::DoTeardown (void)
{
  m_tcb = nullptr;
}

/**
 * Test Case: Persistent Congestion Threshold
 *
 * RFC 9002 §7.6: "kPersistentCongestionThreshold: The RECOMMENDED value
 * is 3, which is approximately two RTTs according to historical TCP loss
 * detection algorithms."
 */
class QuicPersistentCongestionThresholdTestCase : public TestCase
{
public:
  QuicPersistentCongestionThresholdTestCase ();

private:
  virtual void DoRun (void);
  virtual void DoTeardown (void);

  Ptr<QuicSocketState> m_tcb;
};

QuicPersistentCongestionThresholdTestCase::QuicPersistentCongestionThresholdTestCase ()
  : TestCase ("Persistent Congestion Threshold (RFC 9002 §7.6)")
{
}

void
QuicPersistentCongestionThresholdTestCase::DoRun (void)
{
  m_tcb = CreateObject<QuicSocketState> ();

  // RFC 9002 §7.6: recommended value is 3
  NS_TEST_ASSERT_MSG_EQ (m_tcb->m_kPersistentCongestionThreshold, 3,
                         "kPersistentCongestionThreshold must be 3 per RFC 9002 §7.6");

  // Packet threshold for loss detection (RFC 9002 §6.1: recommended is 3)
  NS_TEST_ASSERT_MSG_EQ (m_tcb->m_kPacketThreshold, 3,
                         "kPacketThreshold must be 3 per RFC 9002 §6.1");
}

void
QuicPersistentCongestionThresholdTestCase::DoTeardown (void)
{
  m_tcb = nullptr;
}

/**
 * Test Case: ACK frames are piggybacked only when an ACK is owed
 *
 * RFC 9000 §13.2.1 lets any packet carry an ACK frame, but one is only owed
 * after an ack-eliciting reception, which MaybeQueueAck() marks by leaving an
 * ACK event running. A data packet that carries the ACK satisfies it, so the
 * event must be cancelled, while a send that aborts must leave it pending.
 *
 * The L4 protocol has no UDP binding, so SendPacket() delivers nothing and the
 * "Tx" trace is the observation point. The simulator never runs: the timers
 * are only inspected.
 */
class QuicAckPiggybackTestCase : public TestCase
{
public:
  QuicAckPiggybackTestCase ();

private:
  virtual void DoRun (void);

  /// Queue one STREAM frame for transmission
  void QueueStreamFrame (void);
  /// Record the frames of a transmitted packet
  void OnTx (Ptr<const Packet> p, const QuicHeader &q, Ptr<const QuicSocketBase> socket);

  Ptr<QuicSocketBase> m_socket;
  uint32_t m_txPackets;    //!< packets seen on the Tx trace
  bool m_lastHasStream;    //!< last packet carried a STREAM frame
  bool m_lastHasAck;       //!< last packet carried an ACK frame
  bool m_lastHasMaxData;   //!< last packet carried a MAX_DATA frame
};

QuicAckPiggybackTestCase::QuicAckPiggybackTestCase ()
  : TestCase ("ACK frames are piggybacked only when an ACK is owed (RFC 9000 §13.2.1)"),
    m_txPackets (0),
    m_lastHasStream (false),
    m_lastHasAck (false),
    m_lastHasMaxData (false)
{
}

void
QuicAckPiggybackTestCase::QueueStreamFrame (void)
{
  const uint32_t length = 100;
  Ptr<Packet> frame = Create<Packet> (length);
  frame->AddHeader (QuicSubheader::CreateStreamSubHeader (1, 0, length, true, true, false));
  m_socket->m_txBuffer->Add (frame, APPLICATION_DATA);
}

void
QuicAckPiggybackTestCase::OnTx (Ptr<const Packet> p, const QuicHeader &q, Ptr<const QuicSocketBase> socket)
{
  ++m_txPackets;
  m_lastHasStream = m_lastHasAck = m_lastHasMaxData = false;

  // SendPacket() has prepended the QUIC header by the time the trace fires
  Ptr<Packet> copy = p->Copy ();
  QuicHeader header;
  copy->RemoveHeader (header);
  while (copy->GetSize () > 0)
    {
      QuicSubheader sub;
      copy->RemoveHeader (sub);
      m_lastHasStream |= sub.IsStream ();
      m_lastHasAck |= sub.IsAck ();
      m_lastHasMaxData |= (sub.GetFrameType () == QuicSubheader::MAX_DATA);
      copy->RemoveAtStart (sub.GetLength ());
    }
}

void
QuicAckPiggybackTestCase::DoRun (void)
{
  m_socket = CreateObject<QuicSocketBase> ();
  m_socket->SetQuicL4 (CreateObject<QuicL4Protocol> ());
  m_socket->m_txBuffer->SetScheduler (CreateObject<QuicSocketTxScheduler> ());
  m_socket->TraceConnectWithoutContext ("Tx", MakeCallback (&QuicAckPiggybackTestCase::OnTx, this));
  m_socket->m_socketState = QuicSocket::OPEN;
  m_socket->m_connected = true;

  QuicPacketNumberSpace &pnSpace = m_socket->m_pnSpaces[APPLICATION_DATA];
  const uint32_t segSize = m_socket->GetSegSize ();

  // A peer packet was received but was not ack-eliciting: nothing is owed
  pnSpace.m_receivedRanges.Add (1, 21);
  pnSpace.m_largestReceived = SequenceNumber32 (1);
  pnSpace.m_lastReceived = Simulator::Now ();

  QueueStreamFrame ();
  m_socket->SendDataPacket (APPLICATION_DATA, segSize, true);
  NS_TEST_ASSERT_MSG_EQ (m_txPackets, 1, "The data packet should have been sent");
  NS_TEST_ASSERT_MSG_EQ (m_lastHasStream, true, "The packet should carry the STREAM frame");
  NS_TEST_ASSERT_MSG_EQ (m_lastHasAck, false, "No ACK is owed after an ACK-only reception");

  // A delayed ACK is owed: the next data packet carries it and satisfies it
  m_socket->MaybeQueueAck (APPLICATION_DATA, false);
  NS_TEST_ASSERT_MSG_EQ (pnSpace.m_delAckEvent.IsRunning (), true, "A delayed ACK should be pending");
  NS_TEST_ASSERT_MSG_EQ (m_socket->IsAckPending (APPLICATION_DATA), true, "A delayed ACK is owed");

  QueueStreamFrame ();
  m_socket->SendDataPacket (APPLICATION_DATA, segSize, true);
  NS_TEST_ASSERT_MSG_EQ (m_lastHasStream, true, "The packet should carry the STREAM frame");
  NS_TEST_ASSERT_MSG_EQ (m_lastHasAck, true, "The owed ACK should be piggybacked");
  NS_TEST_ASSERT_MSG_EQ (pnSpace.m_delAckEvent.IsRunning (), false, "The piggyback should cancel the delayed ACK");
  NS_TEST_ASSERT_MSG_EQ (pnSpace.m_numPacketsReceivedSinceLastAckSent, 0, "The piggyback should reset the counter");

  // The ACK was sent, so the following packet does not repeat it
  QueueStreamFrame ();
  m_socket->SendDataPacket (APPLICATION_DATA, segSize, true);
  NS_TEST_ASSERT_MSG_EQ (m_lastHasAck, false, "An ACK that was already sent should not be repeated");

  // withAck == false must keep an owed ACK pending, not lose it
  m_socket->MaybeQueueAck (APPLICATION_DATA, true);
  NS_TEST_ASSERT_MSG_EQ (pnSpace.m_sendAckEvent.IsRunning (), true, "An immediate ACK should be pending");
  QueueStreamFrame ();
  m_socket->SendDataPacket (APPLICATION_DATA, segSize, false);
  NS_TEST_ASSERT_MSG_EQ (m_lastHasAck, false, "withAck == false should not attach an ACK");
  NS_TEST_ASSERT_MSG_EQ (pnSpace.m_sendAckEvent.IsRunning (), true, "The ACK should stay pending");

  // Immediate ACKs are satisfied the same way
  QueueStreamFrame ();
  m_socket->SendDataPacket (APPLICATION_DATA, segSize, true);
  NS_TEST_ASSERT_MSG_EQ (m_lastHasAck, true, "The owed ACK should be piggybacked");
  NS_TEST_ASSERT_MSG_EQ (pnSpace.m_sendAckEvent.IsRunning (), false, "The piggyback should cancel the immediate ACK");

  // Neither payload nor an owed ACK: nothing goes out, and no pacing timer is
  // armed (a zero-byte packet would give a zero delay and a same-time loop)
  m_socket->m_tcb->m_pacing = true;
  m_socket->m_tcb->m_pacingRate = DataRate ("1Mbps");
  uint32_t txBefore = m_txPackets;
  SequenceNumber32 pnBefore = pnSpace.m_nextTxSequence;
  uint32_t sent = m_socket->SendDataPacket (APPLICATION_DATA, segSize, true);
  NS_TEST_ASSERT_MSG_EQ (sent, 0, "Nothing should have been sent");
  NS_TEST_ASSERT_MSG_EQ (m_txPackets, txBefore, "An empty packet should not be emitted");
  NS_TEST_ASSERT_MSG_EQ (pnSpace.m_nextTxSequence, pnBefore, "The packet number should not be consumed");
  NS_TEST_ASSERT_MSG_EQ (m_socket->m_pacingTimer.IsRunning (), false, "No pacing timer should be armed");
  m_socket->m_tcb->m_pacing = false;

  // No payload but an owed ACK: an ACK-only packet, outside bytes in flight
  m_socket->MaybeQueueAck (APPLICATION_DATA, false);
  uint32_t inFlightBefore = m_socket->m_txBuffer->BytesInFlight ();
  m_socket->SendDataPacket (APPLICATION_DATA, segSize, true);
  NS_TEST_ASSERT_MSG_EQ (m_txPackets, txBefore + 1, "An ACK-only packet should be sent");
  NS_TEST_ASSERT_MSG_EQ (m_lastHasAck, true, "The packet should carry the ACK");
  NS_TEST_ASSERT_MSG_EQ (m_lastHasStream, false, "The packet should carry no STREAM frame");
  NS_TEST_ASSERT_MSG_EQ (m_socket->IsAckPending (APPLICATION_DATA), false, "The ACK-only packet satisfies the ACK");
  NS_TEST_ASSERT_MSG_EQ (m_socket->m_txBuffer->BytesInFlight (), inFlightBefore,
                         "An ACK-only packet does not count towards bytes in flight");

  // A due MAX_DATA update is not consumed by a packet that carries no ACK...
  m_socket->m_handshakeConfirmed = true;
  m_socket->m_bytesRead = m_socket->GetSocketRcvBufSize ();
  m_socket->m_localMaxData = m_socket->GetSocketRcvBufSize ();
  uint32_t localMaxData = m_socket->m_localMaxData;
  uint64_t newMaxData;
  NS_TEST_ASSERT_MSG_EQ (m_socket->MaxDataUpdateDue (newMaxData, false), true, "An update should be due");
  QueueStreamFrame ();
  m_socket->SendDataPacket (APPLICATION_DATA, segSize, true);
  NS_TEST_ASSERT_MSG_EQ (m_lastHasMaxData, false, "No ACK frame means no MAX_DATA piggyback");
  NS_TEST_ASSERT_MSG_EQ (m_socket->m_localMaxData, localMaxData, "The update should remain due");

  // ...and rides on the ACK once one is owed
  m_socket->MaybeQueueAck (APPLICATION_DATA, false);
  QueueStreamFrame ();
  m_socket->SendDataPacket (APPLICATION_DATA, segSize, true);
  NS_TEST_ASSERT_MSG_EQ (m_lastHasMaxData, true, "The due update should ride on the ACK");
  NS_TEST_ASSERT_MSG_GT (m_socket->m_localMaxData, localMaxData, "The local limit should advance");

  // An aborted send leaves the owed ACK pending: a CRYPTO frame that the
  // congestion window blocks
  m_socket->MaybeQueueAck (APPLICATION_DATA, false);
  const uint32_t cryptoLength = 100;
  Ptr<Packet> crypto = Create<Packet> (cryptoLength);
  crypto->AddHeader (QuicSubheader::CreateCrypto (0, cryptoLength));
  m_socket->m_txBuffer->Add (crypto, APPLICATION_DATA);
  m_socket->m_tcb->m_cWnd = 0;
  txBefore = m_txPackets;
  pnBefore = pnSpace.m_nextTxSequence;
  sent = m_socket->SendDataPacket (APPLICATION_DATA, segSize, true);
  NS_TEST_ASSERT_MSG_EQ (sent, 0, "The congestion window should block the CRYPTO frame");
  NS_TEST_ASSERT_MSG_EQ (m_txPackets, txBefore, "An aborted send emits nothing");
  NS_TEST_ASSERT_MSG_EQ (pnSpace.m_nextTxSequence, pnBefore, "An aborted send consumes no packet number");
  NS_TEST_ASSERT_MSG_EQ (m_socket->IsAckPending (APPLICATION_DATA), true, "An aborted send should leave the ACK pending");

  // The pending events hold a raw pointer to the socket, so destroy them first
  Simulator::Destroy ();
  m_socket = nullptr;
}

/**
 * Test Case: the received packet number ranges
 *
 * RFC 9000 Sec. 13.2.3 and 13.2.4
 */
class QuicReceivedPacketRangesTestCase : public TestCase
{
public:
  QuicReceivedPacketRangesTestCase ()
    : TestCase ("Received packet number ranges (RFC 9000 Sec. 13.2.3, 13.2.4)")
  {
  }

private:
  virtual void DoRun (void);
};

void
QuicReceivedPacketRangesTestCase::DoRun (void)
{
  QuicReceivedPacketRanges ranges;
  NS_TEST_ASSERT_MSG_EQ (ranges.IsEmpty (), true, "Nothing was received yet");

  // In order, with gaps, and filling a gap
  for (uint32_t pn : {1, 2, 3, 7, 9, 5, 8})
    {
      NS_TEST_ASSERT_MSG_EQ (ranges.Add (pn, 10), true, "A new packet number");
    }
  NS_TEST_ASSERT_MSG_EQ (ranges.Add (3, 10), false, "A duplicate");
  NS_TEST_ASSERT_MSG_EQ (ranges.GetRanges ().size (), 3, "1-3, 5, 7-9");
  NS_TEST_ASSERT_MSG_EQ (ranges.GetRanges ()[0].low, 1, "1-3");
  NS_TEST_ASSERT_MSG_EQ (ranges.GetRanges ()[0].high, 3, "1-3");
  NS_TEST_ASSERT_MSG_EQ (ranges.GetRanges ()[1].low, 5, "5");
  NS_TEST_ASSERT_MSG_EQ (ranges.GetRanges ()[1].high, 5, "5");
  NS_TEST_ASSERT_MSG_EQ (ranges.GetRanges ()[2].low, 7, "7-9");
  NS_TEST_ASSERT_MSG_EQ (ranges.GetRanges ()[2].high, 9, "7-9");

  // Joining two ranges
  ranges.Add (4, 10);
  NS_TEST_ASSERT_MSG_EQ (ranges.GetRanges ().size (), 2, "1-5, 7-9");
  NS_TEST_ASSERT_MSG_EQ (ranges.GetRanges ()[0].high, 5, "1-5");

  // Everything is unreported at first, newest first
  auto report = ranges.GetRangesToReport (10);
  NS_TEST_ASSERT_MSG_EQ (report.size (), 2, "7-9, 1-5");
  NS_TEST_ASSERT_MSG_EQ (report[0].low, 7, "7-9 first");
  NS_TEST_ASSERT_MSG_EQ (report[1].high, 5, "then 1-5");
  NS_TEST_ASSERT_MSG_EQ (ranges.GetRangesToReport (1).size (), 1, "Limited to the largest");

  // Once reported, only the range holding the largest is repeated, and nothing is forgotten
  ranges.MarkReported (report);
  NS_TEST_ASSERT_MSG_EQ (ranges.GetUnreportedRanges ().empty (), true, "Everything was reported");
  NS_TEST_ASSERT_MSG_EQ (ranges.GetRangesToReport (10).size (), 1, "Only the largest");
  NS_TEST_ASSERT_MSG_EQ (ranges.GetRanges ().size (), 2, "Reporting forgets nothing");

  // A late packet is accepted, merges the ranges around it, and is reported
  NS_TEST_ASSERT_MSG_EQ (ranges.IsBelowFloor (6), false, "Reporting raises no floor");
  NS_TEST_ASSERT_MSG_EQ (ranges.Add (6, 10), true, "The late packet is new");
  NS_TEST_ASSERT_MSG_EQ (ranges.GetRanges ().size (), 1, "1-9");
  ranges.Add (12, 10);
  report = ranges.GetRangesToReport (10);
  NS_TEST_ASSERT_MSG_EQ (report.size (), 2, "12, then the late 6");
  NS_TEST_ASSERT_MSG_EQ (report[0].low, 12, "12");
  NS_TEST_ASSERT_MSG_EQ (report[1].low, 6, "6");
  NS_TEST_ASSERT_MSG_EQ (report[1].high, 6, "6");

  // Inside the range holding the largest, reporting stops at the lowest unreported
  // packet, and does not repeat what the peer has seen below it
  ranges.Add (11, 10);
  ranges.Add (10, 10);
  report = ranges.GetRangesToReport (10);
  NS_TEST_ASSERT_MSG_EQ (report.size (), 1, "6-12 holds everything unreported");
  NS_TEST_ASSERT_MSG_EQ (report[0].low, 6, "6-12, not 1-12");
  NS_TEST_ASSERT_MSG_EQ (report[0].high, 12, "6-12");

  // The memory limit forgets the oldest range, and refuses packets in or below it
  QuicReceivedPacketRanges limited;
  for (uint32_t pn : {1, 2, 4, 6, 8})
    {
      limited.Add (pn, 3);
    }
  NS_TEST_ASSERT_MSG_EQ (limited.GetRanges ().size (), 3, "Limited to 3 ranges");
  NS_TEST_ASSERT_MSG_EQ (limited.GetRanges ()[0].low, 4, "The oldest ranges went first");
  NS_TEST_ASSERT_MSG_EQ (limited.GetUnreportedRanges ()[0].low, 4, "Forgotten ranges are not reported either");
  NS_TEST_ASSERT_MSG_EQ (limited.Add (2, 3), false, "A forgotten packet number is refused");
  NS_TEST_ASSERT_MSG_EQ (limited.IsBelowFloor (2), true, "Nothing in a dropped range is accepted");
  NS_TEST_ASSERT_MSG_EQ (limited.IsBelowFloor (3), false, "The gap above a dropped range is still accepted");
  NS_TEST_ASSERT_MSG_EQ (limited.IsBelowFloor (5), false, "Gaps between kept ranges are still accepted");
}

/**
 * Test Case: building, decoding and pruning ACK ranges in the socket
 *
 * RFC 9000 Sec. 13.2.1, 13.2.4 and 19.3.1
 */
class QuicAckRangesTestCase : public TestCase
{
public:
  QuicAckRangesTestCase ()
    : TestCase ("ACK ranges: encoding, decoding and pruning (RFC 9000 Sec. 13.2.4, 19.3.1)")
  {
  }

private:
  virtual void DoRun (void);
  void OnTx (const Ptr<const Packet> p, const QuicHeader &h, Ptr<const QuicSocketBase> s);
  void Receive (std::initializer_list<uint32_t> packetNumbers);
  void ReceiveAck (uint32_t packetNumber);

  Ptr<QuicSocketBase> m_socket;
  uint32_t m_lastPacketNumber {0};
  bool m_lastHasPing {false};
  QuicSubheader m_lastAck;
};

void
QuicAckRangesTestCase::OnTx (const Ptr<const Packet> p, const QuicHeader &h, Ptr<const QuicSocketBase> s)
{
  m_lastPacketNumber = h.GetPacketNumber ().GetValue ();
  m_lastHasPing = false;

  Ptr<Packet> copy = p->Copy ();
  QuicHeader header;
  copy->RemoveHeader (header);
  while (copy->GetSize () > 0)
    {
      QuicSubheader sub;
      copy->RemoveHeader (sub);
      if (sub.IsAck ())
        {
          m_lastAck = sub;
        }
      m_lastHasPing |= sub.IsPing ();
      copy->RemoveAtStart (sub.GetLength ());
    }
}

void
QuicAckRangesTestCase::Receive (std::initializer_list<uint32_t> packetNumbers)
{
  for (uint32_t pn : packetNumbers)
    {
      m_socket->TrackReceivedPacket (APPLICATION_DATA, SequenceNumber32 (pn));
    }
}

void
QuicAckRangesTestCase::ReceiveAck (uint32_t packetNumber)
{
  std::vector<uint32_t> none;
  QuicSubheader ack = QuicSubheader::CreateAck (packetNumber, 0, 0, none, none);
  m_socket->OnReceivedAckFrame (ack, APPLICATION_DATA);
}

void
QuicAckRangesTestCase::DoRun (void)
{
  m_socket = CreateObject<QuicSocketBase> ();
  m_socket->SetQuicL4 (CreateObject<QuicL4Protocol> ());
  m_socket->m_txBuffer->SetScheduler (CreateObject<QuicSocketTxScheduler> ());
  m_socket->TraceConnectWithoutContext ("Tx", MakeCallback (&QuicAckRangesTestCase::OnTx, this));
  m_socket->m_socketState = QuicSocket::OPEN;
  m_socket->m_connected = true;

  UintegerValue defaultInterval;
  m_socket->GetAttribute ("AckElicitingInterval", defaultInterval);
  NS_TEST_ASSERT_MSG_EQ (defaultInterval.Get (), 20, "A PING every 20 ACK-only packets by default");

  m_socket->SetAckElicitingInterval (3);

  // Move the clock away from zero, which is not a time anything is sent at
  Simulator::Stop (Seconds (1));
  Simulator::Run ();

  QuicPacketNumberSpace &pnSpace = m_socket->m_pnSpaces[APPLICATION_DATA];

  // A contiguous range is all one number, and never needs a PING to clear it
  Receive ({0, 1, 2});
  for (int i = 0; i < 5; i++)
    {
      m_socket->SendAck (APPLICATION_DATA);
      NS_TEST_ASSERT_MSG_EQ (m_lastHasPing, false, "No PING without gaps to clear");
    }
  NS_TEST_ASSERT_MSG_EQ (m_lastAck.GetLargestAcknowledged (), 2, "Largest Acknowledged");
  NS_TEST_ASSERT_MSG_EQ (m_lastAck.GetFirstAckBlock (), 2, "First ACK Range is the count below Largest");
  NS_TEST_ASSERT_MSG_EQ (m_lastAck.GetAckBlockCount (), 0, "No gaps yet");

  // RFC 9000 Sec. 19.3.1 encoding of 0-4, 6 and 8-10
  Receive ({3, 4, 6, 8, 9, 10});
  pnSpace.m_ackOnlyPacketsSinceAckEliciting = 0;
  m_socket->SendAck (APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ (m_lastAck.GetLargestAcknowledged (), 10, "Largest Acknowledged");
  NS_TEST_ASSERT_MSG_EQ (m_lastAck.GetFirstAckBlock (), 2, "8-10");
  NS_TEST_ASSERT_MSG_EQ (m_lastAck.GetAckBlockCount (), 2, "Two more ranges");
  NS_TEST_ASSERT_MSG_EQ (m_lastAck.GetGaps ()[0], 0, "One packet missing: 7");
  NS_TEST_ASSERT_MSG_EQ (m_lastAck.GetAdditionalAckBlocks ()[0], 0, "6");
  NS_TEST_ASSERT_MSG_EQ (m_lastAck.GetGaps ()[1], 0, "One packet missing: 5");
  NS_TEST_ASSERT_MSG_EQ (m_lastAck.GetAdditionalAckBlocks ()[1], 4, "0-4");

  // Only the configured number of gaps is reported
  m_socket->m_maxTrackedGaps = 1;
  m_socket->SendAck (APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ (m_lastAck.GetAckBlockCount (), 1, "Limited to one gap");
  m_socket->m_maxTrackedGaps = 20;
  NS_TEST_ASSERT_MSG_EQ (m_lastHasPing, false, "This is only the second ACK-only packet");

  // The interval has passed and there are gaps to clear: this one elicits an ACK
  m_socket->SendAck (APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ (m_lastHasPing, true, "The third ACK-only packet should carry a PING");
  uint32_t pingPacket = m_lastPacketNumber;
  NS_TEST_ASSERT_MSG_EQ (m_socket->m_txBuffer->BytesInFlight (), 0, "The PING is outside of loss detection");

  // Not more than once per RTT, whatever the interval
  for (int i = 0; i < 5; i++)
    {
      m_socket->SendAck (APPLICATION_DATA);
      NS_TEST_ASSERT_MSG_EQ (m_lastHasPing, false, "At most one PING per RTT");
    }

  // An acknowledgement of something that carried no ACK frame prunes nothing
  ReceiveAck (pingPacket - 1);
  NS_TEST_ASSERT_MSG_EQ (pnSpace.m_receivedRanges.GetUnreportedRanges ().size (), 3, "Nothing to prune yet");

  // Once the PING's packet is acknowledged, its ACK frame is known to have arrived
  Receive ({12});
  ReceiveAck (pingPacket);
  NS_TEST_ASSERT_MSG_EQ (pnSpace.m_receivedRanges.GetUnreportedRanges ().size (), 1, "Ranges up to 10 are pruned");
  NS_TEST_ASSERT_MSG_EQ (pnSpace.m_receivedRanges.GetUnreportedRanges ()[0].low, 12, "Only 12 is left to report");
  NS_TEST_ASSERT_MSG_EQ (pnSpace.m_receivedRanges.GetRanges ().size (), 4, "Pruning forgets nothing");
  NS_TEST_ASSERT_MSG_EQ (pnSpace.m_sentAckFrames.empty (), true, "The record was consumed");
  NS_TEST_ASSERT_MSG_EQ (m_socket->TrackReceivedPacket (APPLICATION_DATA, SequenceNumber32 (11)), true,
                         "11 was never received, so it is accepted");

  // The ACK no longer repeats the pruned gaps, and stays valid
  m_socket->SendAck (APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ (m_lastAck.GetLargestAcknowledged (), 12, "Largest Acknowledged");
  NS_TEST_ASSERT_MSG_EQ (m_lastAck.GetFirstAckBlock (), 1, "11-12, not the reported 8-10 below");
  NS_TEST_ASSERT_MSG_EQ (m_lastAck.GetAckBlockCount (), 0, "The pruned gaps are gone");

  // Decoding: an ACK of the newest packet says nothing about the older ones
  const uint32_t segSize = m_socket->GetSegSize ();
  for (int i = 0; i < 3; i++)
    {
      Ptr<Packet> frame = Create<Packet> (100);
      frame->AddHeader (QuicSubheader::CreateStreamSubHeader (0, i * 100, 100, i > 0, true, false));
      m_socket->m_txBuffer->Add (frame);
      m_socket->SendDataPacket (APPLICATION_DATA, segSize, false);
    }
  NS_TEST_ASSERT_MSG_EQ (m_socket->m_txBuffer->GetPayloadBytesInFlight (), 300, "Three packets in flight");
  ReceiveAck (m_lastPacketNumber);
  NS_TEST_ASSERT_MSG_EQ (m_socket->m_txBuffer->GetPayloadBytesInFlight (), 200,
                         "Packets below the last block must not count as acknowledged");

  // With the PING disabled, ACKs never carry one however long the gaps stay
  m_socket->SetAckElicitingInterval (0);
  pnSpace.m_sentAckFrames.clear ();
  pnSpace.m_lastAckElicitingAck = Seconds (0);
  Receive ({20, 22, 24});
  for (int i = 0; i < 50; i++)
    {
      m_socket->SendAck (APPLICATION_DATA);
      NS_TEST_ASSERT_MSG_EQ (m_lastHasPing, false, "No PING when it is disabled");
    }
  NS_TEST_ASSERT_MSG_EQ (pnSpace.m_sentAckFrames.empty (), true, "ACK-only packets are not recorded");
  NS_TEST_ASSERT_MSG_GT (m_lastAck.GetAckBlockCount (), 0, "The gaps are still reported");

  // Never on all ACK-only packets, even at the smallest interval and with no RTT
  // limit (RFC 9000 Sec. 13.2.1)
  m_socket->SetAckElicitingInterval (2);
  pnSpace.m_ackOnlyPacketsSinceAckEliciting = 0;
  for (int i = 0; i < 6; i++)
    {
      pnSpace.m_lastAckElicitingAck = Seconds (0);
      m_socket->SendAck (APPLICATION_DATA);
      NS_TEST_ASSERT_MSG_EQ (m_lastHasPing, (i % 2 == 1), "A PING on every other ACK-only packet at most");
    }

  // The pending events hold a raw pointer to the socket, so destroy them first
  Simulator::Destroy ();
  m_socket = nullptr;
}

/**
 * Test Case: packets that arrive late, after the ranges around them are gone
 *
 * Pruning (RFC 9000 Sec. 13.2.4) only stops ACKs from repeating what the peer
 * has seen, and the limit on ACK ranges only bounds the ACK frame: neither may
 * make the receiver refuse a packet it has never received. A packet that arrives
 * late is accepted, and reported in a later ACK.
 */
class QuicLatePacketTestCase : public TestCase
{
public:
  QuicLatePacketTestCase ()
    : TestCase ("Late packets are accepted and reported after pruning and the range limit")
  {
  }

private:
  virtual void DoRun (void);
  void OnTx (const Ptr<const Packet> p, const QuicHeader &h, Ptr<const QuicSocketBase> s);
  /// Send an ACK made ack-eliciting, and have the peer acknowledge that packet
  void AckRoundTrip ();
  bool LastAckReports (uint32_t packetNumber) const;

  Ptr<QuicSocketBase> m_socket;
  uint32_t m_lastPacketNumber {0};
  bool m_lastHasPing {false};
  QuicSubheader m_lastAck;
};

void
QuicLatePacketTestCase::OnTx (const Ptr<const Packet> p, const QuicHeader &h, Ptr<const QuicSocketBase> s)
{
  m_lastPacketNumber = h.GetPacketNumber ().GetValue ();
  m_lastHasPing = false;
  Ptr<Packet> copy = p->Copy ();
  QuicHeader header;
  copy->RemoveHeader (header);
  while (copy->GetSize () > 0)
    {
      QuicSubheader sub;
      copy->RemoveHeader (sub);
      if (sub.IsAck ())
        {
          m_lastAck = sub;
        }
      m_lastHasPing |= sub.IsPing ();
      copy->RemoveAtStart (sub.GetLength ());
    }
}

void
QuicLatePacketTestCase::AckRoundTrip ()
{
  // At most one PING per RTT and interval: pretend both have passed
  m_socket->m_pnSpaces[APPLICATION_DATA].m_lastAckElicitingAck = Seconds (0);
  m_socket->m_pnSpaces[APPLICATION_DATA].m_ackOnlyPacketsSinceAckEliciting = 1;
  m_socket->SendAck (APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ (m_lastHasPing, true, "The ACK should have been made ack-eliciting");

  std::vector<uint32_t> none;
  QuicSubheader ack = QuicSubheader::CreateAck (m_lastPacketNumber, 0, 0, none, none);
  m_socket->OnReceivedAckFrame (ack, APPLICATION_DATA);
}

bool
QuicLatePacketTestCase::LastAckReports (uint32_t packetNumber) const
{
  // RFC 9000 Sec. 19.3.1 decoding
  uint64_t high = m_lastAck.GetLargestAcknowledged ();
  uint64_t low = high - m_lastAck.GetFirstAckBlock ();
  if (low <= packetNumber && packetNumber <= high)
    {
      return true;
    }
  for (uint32_t i = 0; i < m_lastAck.GetAckBlockCount (); ++i)
    {
      high = low - m_lastAck.GetGaps ()[i] - 2;
      low = high - m_lastAck.GetAdditionalAckBlocks ()[i];
      if (low <= packetNumber && packetNumber <= high)
        {
          return true;
        }
    }
  return false;
}

void
QuicLatePacketTestCase::DoRun (void)
{
  m_socket = CreateObject<QuicSocketBase> ();
  m_socket->SetQuicL4 (CreateObject<QuicL4Protocol> ());
  m_socket->m_txBuffer->SetScheduler (CreateObject<QuicSocketTxScheduler> ());
  m_socket->TraceConnectWithoutContext ("Tx", MakeCallback (&QuicLatePacketTestCase::OnTx, this));
  m_socket->m_socketState = QuicSocket::OPEN;
  m_socket->m_connected = true;
  m_socket->SetAckElicitingInterval (2);

  Simulator::Stop (Seconds (1));
  Simulator::Run ();

  // 1. Pruning. 5 and 7 are delayed on another path; the rest is acknowledged,
  // and the peer is known to have seen that ACK
  for (uint32_t pn : {0, 1, 2, 3, 4, 6, 8, 9, 10})
    {
      m_socket->TrackReceivedPacket (APPLICATION_DATA, SequenceNumber32 (pn));
    }
  AckRoundTrip ();
  for (uint32_t pn : {11, 12})
    {
      m_socket->TrackReceivedPacket (APPLICATION_DATA, SequenceNumber32 (pn));
    }

  NS_TEST_ASSERT_MSG_EQ (m_socket->TrackReceivedPacket (APPLICATION_DATA, SequenceNumber32 (5)), true,
                         "A late packet in a pruned gap was never received, so it must be accepted");
  m_socket->SendAck (APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ (LastAckReports (5), true, "The late packet should be reported");
  NS_TEST_ASSERT_MSG_EQ (LastAckReports (12), true, "The largest should still be reported");
  NS_TEST_ASSERT_MSG_EQ (LastAckReports (3), false, "What the peer has seen should not be repeated");

  // 2. The range limit. More gaps than an ACK can report, then a packet late
  // into the oldest of them
  m_socket->m_maxTrackedGaps = 3;
  for (uint32_t pn = 100; pn <= 140; pn += 2)
    {
      m_socket->TrackReceivedPacket (APPLICATION_DATA, SequenceNumber32 (pn));
    }
  NS_TEST_ASSERT_MSG_EQ (m_socket->TrackReceivedPacket (APPLICATION_DATA, SequenceNumber32 (101)), true,
                         "A late packet beyond the ACK range limit must be accepted");

  // Each round trip clears the newest unreported ranges, so the old one comes up
  bool reported = false;
  for (int round = 0; round < 15 && !reported; ++round)
    {
      AckRoundTrip ();
      reported = LastAckReports (101);
    }
  NS_TEST_ASSERT_MSG_EQ (reported, true, "The late packet should be reported eventually");

  Simulator::Destroy ();
  m_socket = nullptr;
}

class QuicSocketBaseTestSuite : public TestSuite
{
public:
  QuicSocketBaseTestSuite ();
};

QuicSocketBaseTestSuite::QuicSocketBaseTestSuite ()
  : TestSuite ("quic-socket-base", UNIT)
{
  AddTestCase (new QuicTcbInitialStateTestCase, TestCase::QUICK);
  AddTestCase (new QuicMinimumWindowTestCase, TestCase::QUICK);
  AddTestCase (new QuicRttInitializationTestCase, TestCase::QUICK);
  AddTestCase (new QuicPersistentCongestionThresholdTestCase, TestCase::QUICK);
  AddTestCase (new QuicAckPiggybackTestCase, TestCase::QUICK);
  AddTestCase (new QuicReceivedPacketRangesTestCase, TestCase::QUICK);
  AddTestCase (new QuicAckRangesTestCase, TestCase::QUICK);
  AddTestCase (new QuicLatePacketTestCase, TestCase::QUICK);
}

static QuicSocketBaseTestSuite quicSocketTestSuite;

} // namespace ns3
