/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "ns3/test.h"
#include "ns3/log.h"
#include "ns3/quic-congestion-ops.h"
#include "ns3/quic-socket-base.h"
#include "ns3/quic-socket-tx-buffer.h"
#include "ns3/simulator.h"

using namespace ns3;

/**
 * \ingroup internet-tests
 * \ingroup tests
 *
 * \brief The QuicCongestionOps Test
 */
class QuicCongestionOpsTestCase : public TestCase
{
public:
  QuicCongestionOpsTestCase ();

private:
  virtual void DoRun (void);
};

QuicCongestionOpsTestCase::QuicCongestionOpsTestCase ()
  : TestCase ("Check QUIC Congestion Control logic")
{}

class TestQuicCongestionOps : public QuicCongestionOps
{
public:
  void PublicOnPacketAcked (Ptr<TcpSocketState> tcb, Ptr<QuicSocketTxItem> ackedPacket)
  {
    OnPacketAcked (tcb, ackedPacket);
  }
};

void
QuicCongestionOpsTestCase::DoRun (void)
{
  Ptr<QuicSocketState> tcb = CreateObject<QuicSocketState> ();
  Ptr<TestQuicCongestionOps> cc = CreateObject<TestQuicCongestionOps> ();

  // Initialize TCB parameters
  tcb->m_segmentSize = 1200;
  tcb->m_cWnd = 12000; // Initial window
  tcb->m_ssThresh = UINT32_MAX; 
  tcb->m_kMinimumWindowMultiplier = 2;
  tcb->m_kLossReductionFactor = 0.5;

  // 1. Test Slow Start
  // Ack a packet of size 1200
  Ptr<Packet> p = Create<Packet> (1200);
  Ptr<QuicSocketTxItem> item = Create<QuicSocketTxItem> ();
  item->m_packet = p;
  item->m_packetNumber = SequenceNumber32 (1);
  item->m_lastSent = Now ();
  item->m_acked = true;

  tcb->m_bytesInFlight = tcb->m_cWnd;
  cc->PublicOnPacketAcked (tcb, item);
  tcb->m_bytesInFlight -= 1200;

  // In Slow Start, cwnd increases by bytes acked.
  // 12000 + 1200 = 13200
  NS_TEST_ASSERT_MSG_EQ (tcb->m_cWnd, 13200U, "Slow start did not increase cwnd correctly");

  // 2. Test Loss / Recovery
  std::vector<Ptr<QuicSocketTxItem>> lostPackets;
  Ptr<QuicSocketTxItem> lostItem = Create<QuicSocketTxItem> ();
  lostItem->m_packet = Create<Packet> (1200);
  lostItem->m_packetNumber = SequenceNumber32 (2); // New packet lost
  lostPackets.push_back (lostItem);
  
  // Set highTxMark to define recovery epoch
  tcb->m_highTxMark = SequenceNumber32 (10);

  cc->OnPacketsLost (tcb, lostPackets);
  tcb->m_bytesInFlight -= 1200;

  // Expect:
  // endOfRecovery = highTxMark (10)
  // cWnd = cWnd * reductionFactor (0.5) = 13200 * 0.5 = 6600
  // ssThresh = cWnd (6600)
  
  NS_TEST_ASSERT_MSG_EQ (tcb->m_endOfRecovery, SequenceNumber32 (10), "End of recovery not set");
  NS_TEST_ASSERT_MSG_EQ (tcb->m_cWnd, 6600U, "Window not reduced on loss");
  NS_TEST_ASSERT_MSG_EQ (tcb->m_ssThresh, 6600U, "ssthresh not updated on loss");

  // 3. Test Congestion Avoidance
  // We need to be out of recovery (packet > endOfRecovery)
  // And cwnd >= ssThresh.
  
  Ptr<QuicSocketTxItem> caItem = Create<QuicSocketTxItem> ();
  caItem->m_packet = Create<Packet> (1200);
  caItem->m_packetNumber = SequenceNumber32 (11); // After recovery
  caItem->m_lastSent = Now ();
  caItem->m_acked = true;
  
  tcb->m_bytesInFlight = tcb->m_cWnd;
  // Current cwnd 6600. ssThresh 6600.
  // Acking 1200 bytes.
  // Increase = segmentSize * bytesAcked / cwnd
  // Increase = 1200 * 1200 / 6600 = 1440000 / 6600 = 218.
  // New cwnd = 6600 + 218 = 6818.
  
  cc->PublicOnPacketAcked (tcb, caItem);
  tcb->m_bytesInFlight -= 1200;
  
  NS_TEST_ASSERT_MSG_EQ (tcb->m_cWnd, 6818U, "Congestion avoidance calculation incorrect");

  // 4. Test Persistent Congestion
  // Create a condition where the congestion period exceeds the threshold
  // RTT = 100ms, RTTVar = 0, MaxAckDelay = 25ms
  // Threshold = 3 * (100 + 0 + 25) = 375ms
  
  tcb->m_smoothedRtt = MilliSeconds (100);
  tcb->m_rttVar = MilliSeconds (0);
  tcb->m_peerMaxAckDelay = MilliSeconds (25);
  tcb->m_kPersistentCongestionThreshold = 3;
  
  std::vector<Ptr<QuicSocketTxItem>> pcPackets;
  
  // First lost packet at T0
  Ptr<QuicSocketTxItem> firstLost = Create<QuicSocketTxItem> ();
  firstLost->m_packet = Create<Packet> (1200);
  firstLost->m_packetNumber = SequenceNumber32 (20);
  firstLost->m_lastSent = Seconds (1.0);
  pcPackets.push_back (firstLost);
  
  // Last lost packet at T0 + 400ms (exceeds 375ms threshold)
  Ptr<QuicSocketTxItem> lastLost = Create<QuicSocketTxItem> ();
  lastLost->m_packet = Create<Packet> (1200);
  lastLost->m_packetNumber = SequenceNumber32 (30);
  lastLost->m_lastSent = Seconds (1.4);
  pcPackets.push_back (lastLost);
  
  // Ensure we are not in recovery from previous tests
  tcb->m_endOfRecovery = SequenceNumber32 (19);
  tcb->m_cWnd = 100000; // Large window
  tcb->m_ssThresh = 100000;
  
  cc->OnPacketsLost (tcb, pcPackets);
  
  // Expect window reset to minimum
  NS_TEST_ASSERT_MSG_EQ (tcb->m_cWnd, tcb->GetMinimumWindow (), "Persistent congestion did not reset cwnd");
  NS_TEST_ASSERT_MSG_EQ (tcb->m_ssThresh, tcb->GetMinimumWindow (), "Persistent congestion did not reset ssthresh");

}

/**
 * Test Case 2: No cwnd reduction twice in one RTT (RFC 9002 §7.3.2)
 *
 * "The sender MUST NOT reduce cwnd more than once per RTT."
 * This is enforced by the recovery epoch: a second loss within the same
 * recovery epoch (packetNumber <= endOfRecovery) must NOT trigger another
 * cwnd reduction.
 */
class QuicNoDuplicateReductionTestCase : public TestCase
{
public:
  QuicNoDuplicateReductionTestCase ();

private:
  virtual void DoRun (void);
};

QuicNoDuplicateReductionTestCase::QuicNoDuplicateReductionTestCase ()
  : TestCase ("No cwnd reduction twice per RTT - recovery epoch guard (RFC 9002 §7.3.2)")
{}

class TestQuicCongestionOps2 : public QuicCongestionOps
{
public:
  void PublicOnPacketAcked (Ptr<TcpSocketState> tcb, Ptr<QuicSocketTxItem> ackedPacket)
  {
    OnPacketAcked (tcb, ackedPacket);
  }
};

void
QuicNoDuplicateReductionTestCase::DoRun (void)
{
  Ptr<QuicSocketState> tcb = CreateObject<QuicSocketState> ();
  Ptr<TestQuicCongestionOps2> cc = CreateObject<TestQuicCongestionOps2> ();

  tcb->m_segmentSize = 1200;
  tcb->m_cWnd = 12000;
  tcb->m_ssThresh = UINT32_MAX;
  tcb->m_kLossReductionFactor = 0.5;
  tcb->m_highTxMark = SequenceNumber32 (10);

  // First loss: triggers recovery, cwnd halved
  std::vector<Ptr<QuicSocketTxItem>> firstLoss;
  Ptr<QuicSocketTxItem> lost1 = Create<QuicSocketTxItem> ();
  lost1->m_packet = Create<Packet> (1200);
  lost1->m_packetNumber = SequenceNumber32 (3);
  lost1->m_lastSent = Seconds (1.0);
  firstLoss.push_back (lost1);

  cc->OnPacketsLost (tcb, firstLoss);
  uint32_t cwndAfterFirstLoss = tcb->m_cWnd.Get ();
  // 12000 * 0.5 = 6000, but floor is GetMinimumWindow()
  NS_TEST_ASSERT_MSG_EQ (cwndAfterFirstLoss, 6000U,
                         "First loss should halve cwnd");
  NS_TEST_ASSERT_MSG_EQ (tcb->m_endOfRecovery, SequenceNumber32 (10),
                         "endOfRecovery set to highTxMark after first loss");

  // Second loss within same recovery epoch (packetNumber <= endOfRecovery=10)
  // RFC 9002 §7.3.2: cwnd MUST NOT be reduced again
  std::vector<Ptr<QuicSocketTxItem>> secondLoss;
  Ptr<QuicSocketTxItem> lost2 = Create<QuicSocketTxItem> ();
  lost2->m_packet = Create<Packet> (1200);
  lost2->m_packetNumber = SequenceNumber32 (5); // Still within recovery epoch
  lost2->m_lastSent = Seconds (1.1);
  secondLoss.push_back (lost2);

  cc->OnPacketsLost (tcb, secondLoss);
  uint32_t cwndAfterSecondLoss = tcb->m_cWnd.Get ();
  NS_TEST_ASSERT_MSG_EQ (cwndAfterSecondLoss, cwndAfterFirstLoss,
                         "Second loss in same recovery epoch must NOT reduce cwnd again (RFC 9002 §7.3.2)");
}

/**
 * Test Case 3: Minimum window floor enforcement (RFC 9002 §7.2)
 *
 * "The RECOMMENDED minimum congestion window is 2 * max_datagram_size."
 * After any reduction, cwnd must not drop below 2*MSS.
 */
class QuicMinWindowFloorTestCase : public TestCase
{
public:
  QuicMinWindowFloorTestCase ();

private:
  virtual void DoRun (void);
};

QuicMinWindowFloorTestCase::QuicMinWindowFloorTestCase ()
  : TestCase ("Minimum window floor after loss (RFC 9002 §7.2)")
{}

void
QuicMinWindowFloorTestCase::DoRun (void)
{
  Ptr<QuicSocketState> tcb = CreateObject<QuicSocketState> ();
  Ptr<TestQuicCongestionOps2> cc = CreateObject<TestQuicCongestionOps2> ();

  tcb->m_segmentSize = 1200;
  tcb->m_kLossReductionFactor = 0.5;
  tcb->m_kMinimumWindowMultiplier = 2;
  tcb->m_highTxMark = SequenceNumber32 (5);

  // Start with a very small cwnd just above minimum
  tcb->m_cWnd = 3 * tcb->m_segmentSize; // 3600 bytes
  tcb->m_ssThresh = 3600;
  tcb->m_endOfRecovery = SequenceNumber32 (0); // Not in recovery

  std::vector<Ptr<QuicSocketTxItem>> lostPackets;
  Ptr<QuicSocketTxItem> lost = Create<QuicSocketTxItem> ();
  lost->m_packet = Create<Packet> (1200);
  lost->m_packetNumber = SequenceNumber32 (3);
  lost->m_lastSent = Seconds (1.0);
  lostPackets.push_back (lost);

  cc->OnPacketsLost (tcb, lostPackets);

  uint32_t minWindow = tcb->GetMinimumWindow ();
  NS_TEST_ASSERT_MSG_GT_OR_EQ (tcb->m_cWnd.Get (), minWindow,
                               "cwnd must not drop below 2*MSS minimum after loss (RFC 9002 §7.2)");
  // 3600 * 0.5 = 1800 = 1.5*MSS, which is less than 2*MSS=2400
  // So the floor should kick in and cwnd = 2*MSS = 2400
  NS_TEST_ASSERT_MSG_EQ (tcb->m_cWnd.Get (), minWindow,
                         "cwnd floored at 2*MSS when reduction would go below minimum");
}

class QuicCongestionOpsTestSuite : public TestSuite
{
public:
  QuicCongestionOpsTestSuite ()
    : TestSuite ("quic-congestion-ops", UNIT)
  {
    AddTestCase (new QuicCongestionOpsTestCase, TestCase::QUICK);
    AddTestCase (new QuicNoDuplicateReductionTestCase, TestCase::QUICK);
    AddTestCase (new QuicMinWindowFloorTestCase, TestCase::QUICK);
  }
};

static QuicCongestionOpsTestSuite g_quicCongestionOpsTestSuite;
