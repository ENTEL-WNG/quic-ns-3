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
  tcb->m_kMinimumWindow = 2 * tcb->m_segmentSize;
  tcb->m_kLossReductionFactor = 0.5;

  // 1. Test Slow Start
  // Ack a packet of size 1200
  Ptr<Packet> p = Create<Packet> (1200);
  Ptr<QuicSocketTxItem> item = Create<QuicSocketTxItem> ();
  item->m_packet = p;
  item->m_packetNumber = SequenceNumber32 (1);
  item->m_lastSent = Now ();
  item->m_acked = true;

  cc->PublicOnPacketAcked (tcb, item);

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
  
  // Current cwnd 6600. ssThresh 6600.
  // Acking 1200 bytes.
  // Increase = segmentSize * bytesAcked / cwnd
  // Increase = 1200 * 1200 / 6600 = 1440000 / 6600 = 218.
  // New cwnd = 6600 + 218 = 6818.
  
  cc->PublicOnPacketAcked (tcb, caItem);
  
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
  NS_TEST_ASSERT_MSG_EQ (tcb->m_cWnd, tcb->m_kMinimumWindow, "Persistent congestion did not reset cwnd");
  NS_TEST_ASSERT_MSG_EQ (tcb->m_ssThresh, tcb->m_kMinimumWindow, "Persistent congestion did not reset ssthresh");

}

class QuicCongestionOpsTestSuite : public TestSuite
{
public:
  QuicCongestionOpsTestSuite ()
    : TestSuite ("quic-congestion-ops", UNIT)
  {
    AddTestCase (new QuicCongestionOpsTestCase, TestCase::QUICK);
  }
};

static QuicCongestionOpsTestSuite g_quicCongestionOpsTestSuite;
