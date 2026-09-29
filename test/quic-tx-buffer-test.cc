/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2019 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Alvise De Biasio <alvise.debiasio@gmail.com>
 *          Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 *
 */

#include "ns3/test.h"
#include "ns3/quic-socket-tx-buffer.h"
#include "ns3/quic-stream-tx-buffer.h"
#include "ns3/quic-socket-tx-scheduler.h"
#include "ns3/quic-socket-base.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/log.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("QuicTxBufferTestSuite");

/**
 * \ingroup internet-tests
 * \ingroup tests
 *
 * \brief Scheduled QUIC TX Buffer Tests (require Simulator)
 */
class QuicTxBufferScheduledTestCase : public TestCase
{
public:
  QuicTxBufferScheduledTestCase ();
  virtual ~QuicTxBufferScheduledTestCase ();

private:
  virtual void DoRun (void);

  void TestNewBlock ();
  void TestPartialAck ();
  void TestAckLoss ();
  void TestSetLoss ();
  void TestAddBlocks ();
  void TestStream0 ();
};

QuicTxBufferScheduledTestCase::QuicTxBufferScheduledTestCase () :
    TestCase ("QuicTxBuffer Scheduled Tests")
{
}

QuicTxBufferScheduledTestCase::~QuicTxBufferScheduledTestCase ()
{
}

void
QuicTxBufferScheduledTestCase::DoRun ()
{
  Simulator::Schedule (Seconds (0.0), &QuicTxBufferScheduledTestCase::TestNewBlock, this);
  Simulator::Schedule (Seconds (0.0), &QuicTxBufferScheduledTestCase::TestPartialAck, this);
  Simulator::Schedule (Seconds (0.0), &QuicTxBufferScheduledTestCase::TestAckLoss, this);
  Simulator::Schedule (Seconds (0.0), &QuicTxBufferScheduledTestCase::TestSetLoss, this);
  Simulator::Schedule (Seconds (0.0), &QuicTxBufferScheduledTestCase::TestAddBlocks, this);
  Simulator::Schedule (Seconds (0.0), &QuicTxBufferScheduledTestCase::TestStream0, this);
  Simulator::Run ();
  Simulator::Destroy ();
}

void
QuicTxBufferScheduledTestCase::TestNewBlock ()
{
  QuicSocketTxBuffer txBuf;
  Ptr<QuicSocketTxScheduler> sched = CreateObject<QuicSocketTxScheduler>();
  txBuf.SetScheduler(sched);
  Ptr<QuicSocketBase> socket = CreateObject<QuicSocketBase> ();
  txBuf.SetSocket(socket);
  Ptr<QuicSocketState> tcbd;

  tcbd = CreateObject<QuicSocketState> ();
  txBuf.SetQuicSocketState(tcbd);

  NS_TEST_ASSERT_MSG_EQ(
      txBuf.BytesInFlight (), 0,
      "TxBuf miscalculates initial size of in flight segments");

  Ptr<Packet> p1 = Create<Packet> (1196);
  QuicSubheader sub = QuicSubheader::CreateStreamSubHeader (1, 0, p1->GetSize (), false,
                                                   true, false);
  p1->AddHeader (sub);
  txBuf.Add (p1);
  NS_TEST_ASSERT_MSG_EQ(p1->GetSize (), 1200, "Wrong header size");

  Ptr<Packet> ptx = txBuf.NextSequence (1200, SequenceNumber32 (1), APPLICATION_DATA);

  NS_TEST_ASSERT_MSG_EQ(ptx->GetSize (), 1200, "TxBuf miscalculates size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 1200,
                        "TxBuf miscalculates size of in flight segments");

  std::vector<uint32_t> additionalAckBlocks;
  std::vector<uint32_t> gaps;
  uint32_t largestAcknowledged = 1;
  additionalAckBlocks.push_back (1);

  std::vector<Ptr<QuicSocketTxItem>> acked = txBuf.OnAckUpdate (tcbd,
                                                                largestAcknowledged,
                                                                additionalAckBlocks,
                                                                gaps, APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(acked.size (), 1, "Wrong acked packet vector size");
  NS_TEST_ASSERT_MSG_EQ(acked.at (0)->m_packet->GetSize (), 1200,
                        "TxBuf miscalculates size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 0,
                        "TxBuf miscalculates size of in flight segments");

  Ptr<Packet> p2 = Create<Packet> (2996);
  sub = QuicSubheader::CreateStreamSubHeader (1, 0, p2->GetSize (), false,
                                              true, false);
  p2->AddHeader (sub);
  txBuf.Add (p2);

  ptx = txBuf.NextSequence (1200, SequenceNumber32 (2), APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(ptx->GetSize (), 1200,
                        "Returned packet has different size than requested");
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 1200,
                        "TxBuf miscalculates size of in flight segments");

  ptx = txBuf.NextSequence (3000, SequenceNumber32 (3), APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(ptx->GetSize (), 1806,
                        "Returned packet has different size than requested");
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 3006,
                        "TxBuf miscalculates size of in flight segments");

  Ptr<Packet> p3 = Create<Packet> (1196);
  sub = QuicSubheader::CreateStreamSubHeader (1, 0, p3->GetSize (), false,
                                              true, false);
  p3->AddHeader (sub);
  txBuf.Add (p3);
  Ptr<Packet> p4 = Create<Packet> (1196);
  sub = QuicSubheader::CreateStreamSubHeader (1, 0, p4->GetSize (), false,
                                              true, false);
  p4->AddHeader (sub);
  txBuf.Add (p4);
  ptx = txBuf.NextSequence (2400, SequenceNumber32 (4), APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(ptx->GetSize (), 2400,
                        "Returned packet has different size than requested");
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 5406,
                        "TxBuf miscalculates size of in flight segments");

  additionalAckBlocks.pop_back ();
  largestAcknowledged = 4;
  acked = txBuf.OnAckUpdate (tcbd, largestAcknowledged, additionalAckBlocks,
                             gaps, APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 0,
                        "TxBuf miscalculates size of in flight segments");
}

void
QuicTxBufferScheduledTestCase::TestPartialAck ()
{
  QuicSocketTxBuffer txBuf;
  Ptr<QuicSocketTxScheduler> sched = CreateObject<QuicSocketTxScheduler>();
  txBuf.SetScheduler(sched);
  Ptr<QuicSocketBase> socket = CreateObject<QuicSocketBase> ();
  txBuf.SetSocket(socket);
  Ptr<QuicSocketState> tcbd;

  tcbd = CreateObject<QuicSocketState> ();
  txBuf.SetQuicSocketState(tcbd);

  Ptr<Packet> p1 = Create<Packet> (1196);
  QuicSubheader sub = QuicSubheader::CreateStreamSubHeader (1, 0, p1->GetSize (), false,
                                                   true, false);
  p1->AddHeader (sub);

  Ptr<Packet> p2 = Copy (p1);
  Ptr<Packet> p3 = Copy (p1);
  Ptr<Packet> p4 = Copy (p1);
  Ptr<Packet> p5 = Copy (p1);
  Ptr<Packet> p6 = Copy (p1);

  txBuf.Add (p1);
  txBuf.Add (p2);
  txBuf.Add (p3);
  txBuf.Add (p4);
  txBuf.Add (p5);
  txBuf.Add (p6);

  Ptr<Packet> ptx1 = txBuf.NextSequence (1200, SequenceNumber32 (1), APPLICATION_DATA);
  Ptr<Packet> ptx2 = txBuf.NextSequence (1200, SequenceNumber32 (2), APPLICATION_DATA);
  Ptr<Packet> ptx3 = txBuf.NextSequence (1200, SequenceNumber32 (3), APPLICATION_DATA);
  Ptr<Packet> ptx4 = txBuf.NextSequence (1200, SequenceNumber32 (4), APPLICATION_DATA);
  Ptr<Packet> ptx5 = txBuf.NextSequence (1200, SequenceNumber32 (5), APPLICATION_DATA);
  Ptr<Packet> ptx6 = txBuf.NextSequence (1200, SequenceNumber32 (6), APPLICATION_DATA);

  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 7200,
                        "TxBuf miscalculates size of in flight segments");

  std::vector<uint32_t> additionalAckBlocks;
  std::vector<uint32_t> gaps;
  uint32_t largestAcknowledged = 6;
  additionalAckBlocks.push_back (4);
  gaps.push_back (5);

  std::vector<Ptr<QuicSocketTxItem>> acked = txBuf.OnAckUpdate (tcbd,
                                                            largestAcknowledged,
                                                            additionalAckBlocks,
                                                            gaps, APPLICATION_DATA);

  std::vector<Ptr<QuicSocketTxItem>> lost = txBuf.DetectLostPackets (tcbd, APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(lost.empty (), true,
                        "TxBuf detects a non-existent loss");

  std::vector<uint32_t> pkts;
  pkts.push_back (6);
  pkts.push_back (4);
  pkts.push_back (3);
  pkts.push_back (2);
  pkts.push_back (1);
  uint32_t i = 0;
  for (auto acked_it = acked.begin (); acked_it != acked.end ();
      ++acked_it, i++)
    {
      NS_LOG_LOGIC("Hello");
      NS_TEST_ASSERT_MSG_EQ(
          (*acked_it)->m_packetNumber.GetValue (), pkts.at (i),
          "TxBuf does not correctly detect the IDs of ACKed packets");
    }

  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 1200,
                        "TxBuf miscalculates size of in flight segments");
}

void
QuicTxBufferScheduledTestCase::TestAckLoss ()
{
  QuicSocketTxBuffer txBuf;
  Ptr<QuicSocketTxScheduler> sched = CreateObject<QuicSocketTxScheduler>();
  txBuf.SetScheduler(sched);
  Ptr<QuicSocketBase> socket = CreateObject<QuicSocketBase> ();
  txBuf.SetSocket(socket);
  Ptr<QuicSocketState> tcbd;

  tcbd = CreateObject<QuicSocketState> ();
  txBuf.SetQuicSocketState(tcbd);

  Ptr<Packet> p1 = Create<Packet> (1196);
  QuicSubheader sub = QuicSubheader::CreateStreamSubHeader (1, 0, p1->GetSize (), false,
                                                   true, false);
  p1->AddHeader (sub);

  Ptr<Packet> p2 = Copy (p1);
  Ptr<Packet> p3 = Copy (p1);
  Ptr<Packet> p4 = Copy (p1);
  Ptr<Packet> p5 = Copy (p1);
  Ptr<Packet> p6 = Copy (p1);

  txBuf.Add (p1);
  txBuf.Add (p2);
  txBuf.Add (p3);
  txBuf.Add (p4);
  txBuf.Add (p5);
  txBuf.Add (p6);

  Ptr<Packet> ptx1 = txBuf.NextSequence (1200, SequenceNumber32 (1), APPLICATION_DATA);
  Ptr<Packet> ptx2 = txBuf.NextSequence (1200, SequenceNumber32 (2), APPLICATION_DATA);
  Ptr<Packet> ptx3 = txBuf.NextSequence (1200, SequenceNumber32 (3), APPLICATION_DATA);
  Ptr<Packet> ptx4 = txBuf.NextSequence (1200, SequenceNumber32 (4), APPLICATION_DATA);
  Ptr<Packet> ptx5 = txBuf.NextSequence (1200, SequenceNumber32 (5), APPLICATION_DATA);
  Ptr<Packet> ptx6 = txBuf.NextSequence (1200, SequenceNumber32 (6), APPLICATION_DATA);

  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 7200,
                        "TxBuf miscalculates size of in flight segments");

  std::vector<uint32_t> additionalAckBlocks;
  std::vector<uint32_t> gaps;
  uint32_t largestAcknowledged = 6;
  gaps.push_back (2);
  additionalAckBlocks.push_back (1);

  std::vector<Ptr<QuicSocketTxItem>> acked = txBuf.OnAckUpdate (tcbd,
                                                            largestAcknowledged,
                                                            additionalAckBlocks,
                                                            gaps, APPLICATION_DATA);

  std::vector<Ptr<QuicSocketTxItem>> lost = txBuf.DetectLostPackets (tcbd, APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(
      acked.size(), 5,
      "TxBuf does not correctly detect the number of ACKed packets");

  std::vector<uint32_t> pkts;
  pkts.push_back (6);
  pkts.push_back (5);
  pkts.push_back (4);
  pkts.push_back (3);
  pkts.push_back (1);
  uint32_t i = 0;
  for (auto acked_it = acked.begin (); acked_it != acked.end ();
      ++acked_it, i++)
    {

      NS_TEST_ASSERT_MSG_EQ(
          (*acked_it)->m_packetNumber.GetValue (), pkts.at (i),
          "TxBuf does not correctly detect the IDs of ACKed packets");
    }

  NS_TEST_ASSERT_MSG_EQ(lost.size (), 1, "TxBuf misses a loss");

  NS_TEST_ASSERT_MSG_EQ(
      lost.at (0)->m_packetNumber.GetValue (), 2,
      "TxBuf does not correctly detect the IDs of lost packets");

  NS_TEST_ASSERT_MSG_EQ (txBuf.BytesInFlight (), 0,
                         "TxBuf miscalculates size of in flight segments");
}

void
QuicTxBufferScheduledTestCase::TestSetLoss ()
{
  QuicSocketTxBuffer txBuf;
  Ptr<QuicSocketTxScheduler> sched = CreateObject<QuicSocketTxScheduler>();
  txBuf.SetScheduler(sched);
  Ptr<QuicSocketBase> socket = CreateObject<QuicSocketBase> ();
  txBuf.SetSocket(socket);
  Ptr<QuicSocketState> tcbd;

  tcbd = CreateObject<QuicSocketState> ();
  txBuf.SetQuicSocketState(tcbd);

  Ptr<Packet> p1 = Create<Packet> (1196);
  QuicSubheader sub = QuicSubheader::CreateStreamSubHeader (1, 0, p1->GetSize (), false,
                                                   true, false);
  p1->AddHeader (sub);

  Ptr<Packet> p2 = Copy (p1);
  Ptr<Packet> p3 = Copy (p1);
  Ptr<Packet> p4 = Copy (p1);
  Ptr<Packet> p5 = Copy (p1);
  Ptr<Packet> p6 = Copy (p1);

  txBuf.Add (p1);
  txBuf.Add (p2);
  txBuf.Add (p3);
  txBuf.Add (p4);
  txBuf.Add (p5);
  txBuf.Add (p6);

  Ptr<Packet> ptx1 = txBuf.NextSequence (1200, SequenceNumber32 (1), APPLICATION_DATA);
  Ptr<Packet> ptx2 = txBuf.NextSequence (1200, SequenceNumber32 (2), APPLICATION_DATA);
  Ptr<Packet> ptx3 = txBuf.NextSequence (1200, SequenceNumber32 (3), APPLICATION_DATA);
  Ptr<Packet> ptx4 = txBuf.NextSequence (1200, SequenceNumber32 (4), APPLICATION_DATA);
  Ptr<Packet> ptx5 = txBuf.NextSequence (1200, SequenceNumber32 (5), APPLICATION_DATA);
  Ptr<Packet> ptx6 = txBuf.NextSequence (1200, SequenceNumber32 (6), APPLICATION_DATA);

  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 7200,
                        "TxBuf miscalculates size of in flight segments");
  bool found = txBuf.MarkAsLost (SequenceNumber32 (4), APPLICATION_DATA);

  NS_TEST_ASSERT_MSG_EQ(found, true, "TxBuf misses lost packet");

  std::vector<Ptr<QuicSocketTxItem>> lost = txBuf.DetectLostPackets (tcbd, APPLICATION_DATA);

  NS_TEST_ASSERT_MSG_EQ(lost.size (), 1,
                        "TxBuf cannot set the correct number of lost packets");
  NS_TEST_ASSERT_MSG_EQ(lost.at (0)->m_packetNumber, SequenceNumber32 (4),
                        "TxBuf gets the wrong lost packet ID");

  txBuf.ResetSentList (4);

  lost = txBuf.DetectLostPackets (tcbd, APPLICATION_DATA);

  NS_TEST_ASSERT_MSG_EQ(lost.size (), 3,
                        "TxBuf cannot set the correct number of lost packets");
  NS_TEST_ASSERT_MSG_EQ(lost.at (0)->m_packetNumber, SequenceNumber32 (1),
                        "TxBuf gets the wrong lost packet ID");
  NS_TEST_ASSERT_MSG_EQ(lost.at (1)->m_packetNumber, SequenceNumber32 (2),
                        "TxBuf gets the wrong lost packet ID");
  NS_TEST_ASSERT_MSG_EQ(lost.at (2)->m_packetNumber, SequenceNumber32 (4),
                        "TxBuf gets the wrong lost packet ID");

  NS_TEST_ASSERT_MSG_EQ (txBuf.BytesInFlight (), 3600,
                         "TxBuf miscalculates size of in flight segments");
}

void
QuicTxBufferScheduledTestCase::TestAddBlocks ()
{
  QuicSocketTxBuffer txBuf;
  Ptr<QuicSocketTxScheduler> sched = CreateObject<QuicSocketTxScheduler>();
  txBuf.SetScheduler(sched);
  Ptr<QuicSocketBase> socket = CreateObject<QuicSocketBase> ();
  txBuf.SetSocket(socket);
  Ptr<QuicSocketState> tcbd;

  txBuf.SetMaxBufferSize (6000);

  tcbd = CreateObject<QuicSocketState> ();
  txBuf.SetQuicSocketState(tcbd);

  Ptr<Packet> p1 = Create<Packet> (1196);
  QuicSubheader sub = QuicSubheader::CreateStreamSubHeader (1, 0, p1->GetSize (), false,
                                                   true, false);
  p1->AddHeader (sub);

  Ptr<Packet> p2 = Copy (p1);
  Ptr<Packet> p3 = Copy (p1);
  Ptr<Packet> p4 = Copy (p1);
  Ptr<Packet> p5 = Copy (p1);
  Ptr<Packet> p6 = Copy (p1);

  txBuf.Add (p1);
  txBuf.Add (p2);
  txBuf.Add (p3);
  txBuf.Add (p4);
  bool full = txBuf.Add (p5);
  bool extra = txBuf.Add (p6);

  NS_TEST_ASSERT_MSG_EQ(full, true, "TxBuf does not add a correct packet");
  NS_TEST_ASSERT_MSG_EQ(extra, false, "TxBuf adds a packet in overflow");

  Ptr<Packet> ptx1 = txBuf.NextSequence (1200, SequenceNumber32 (1), APPLICATION_DATA);
  Ptr<Packet> ptx2 = txBuf.NextSequence (1200, SequenceNumber32 (2), APPLICATION_DATA);
  Ptr<Packet> ptx3 = txBuf.NextSequence (1200, SequenceNumber32 (3), APPLICATION_DATA);
  Ptr<Packet> ptx4 = txBuf.NextSequence (1200, SequenceNumber32 (4), APPLICATION_DATA);
  Ptr<Packet> ptx5 = txBuf.NextSequence (1200, SequenceNumber32 (5), APPLICATION_DATA);
  Ptr<Packet> ptx6 = txBuf.NextSequence (1200, SequenceNumber32 (6), APPLICATION_DATA);

  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 6000,
                        "TxBuf miscalculates size of in flight segments");
}

void
QuicTxBufferScheduledTestCase::TestStream0 ()
{
  QuicSocketTxBuffer txBuf;
  Ptr<QuicSocketTxScheduler> sched = CreateObject<QuicSocketTxScheduler>();
  txBuf.SetScheduler(sched);
  Ptr<QuicSocketBase> socket = CreateObject<QuicSocketBase> ();
  txBuf.SetSocket(socket);
  Ptr<QuicSocketState> tcbd;

  tcbd = CreateObject<QuicSocketState> ();
  txBuf.SetQuicSocketState(tcbd);

  Ptr<Packet> p1 = Create<Packet> (1196);
  Ptr<Packet> p2 = Copy (p1);
  QuicSubheader sub = QuicSubheader::CreateStreamSubHeader (1, 0, p1->GetSize (), false,
                                                   true, false);
  QuicSubheader sub0 = QuicSubheader::CreateCrypto (0, p1->GetSize ());
  p1->AddHeader (sub);
  p2->AddHeader (sub0);

  Ptr<Packet> p3 = Copy (p1);

  txBuf.Add (p1);
  txBuf.Add (p2);
  txBuf.Add (p3);

  Ptr<Packet> ptx1 = txBuf.NextSequence (1200, SequenceNumber32 (1), APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 1200,
                        "TxBuf miscalculates size of in flight segments");

  // Peeking reports the whole CRYPTO frame without dequeuing it
  NS_TEST_ASSERT_MSG_EQ (txBuf.PeekCryptoFrameSize (APPLICATION_DATA), 1200,
                         "Peek reports the wrong CRYPTO frame size");
  NS_TEST_ASSERT_MSG_EQ (txBuf.GetNumCryptoFramesInBuffer (APPLICATION_DATA), 1,
                         "Peek dequeued the CRYPTO frame");

  Ptr<Packet> ptx2 = txBuf.NextCryptoSequence (SequenceNumber32 (2), APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 2400,
                        "TxBuf miscalculates size of in flight segments");
  NS_TEST_ASSERT_MSG_EQ (txBuf.PeekCryptoFrameSize (APPLICATION_DATA), 0,
                         "Peek reports a CRYPTO frame in an empty queue");

  Ptr<Packet> ptx3 = txBuf.NextSequence (1200, SequenceNumber32 (3), APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 3600,
                        "TxBuf miscalculates size of in flight segments");

  std::vector<uint32_t> additionalAckBlocks;
  std::vector<uint32_t> gaps;
  uint32_t largestAcknowledged = 1;
  additionalAckBlocks.push_back (1);

  std::vector<Ptr<QuicSocketTxItem>> acked = txBuf.OnAckUpdate (tcbd,
                                                            largestAcknowledged,
                                                            additionalAckBlocks,
                                                            gaps, APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ (txBuf.BytesInFlight (), 2400,
                        "TxBuf miscalculates size of in flight segments");

  largestAcknowledged = 2;
  additionalAckBlocks.push_back (2);

  acked = txBuf.OnAckUpdate (tcbd,
                                                            largestAcknowledged,
                                                            additionalAckBlocks,
                                                            gaps, APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 1200,
                        "TxBuf miscalculates size of in flight segments");
}

/**
 * \ingroup internet-tests
 * \ingroup tests
 *
 * \brief Pure Logic QUIC TX Buffer Tests (no Simulator)
 */
class QuicTxBufferPureLogicTestCase : public TestCase
{
public:
  QuicTxBufferPureLogicTestCase ();
  virtual ~QuicTxBufferPureLogicTestCase ();

private:
  virtual void DoRun (void);

  void TestStreamAdd ();
  void TestStreamExtract ();
  void TestRejection ();
  void TestRetransmission ();
};

QuicTxBufferPureLogicTestCase::QuicTxBufferPureLogicTestCase () :
    TestCase ("QuicTxBuffer Pure Logic Tests")
{
}

QuicTxBufferPureLogicTestCase::~QuicTxBufferPureLogicTestCase ()
{
}

void
QuicTxBufferPureLogicTestCase::DoRun ()
{
  TestStreamAdd ();
  TestStreamExtract ();
  TestRejection ();
  TestRetransmission ();
}

void
QuicTxBufferPureLogicTestCase::TestRetransmission ()
{
  QuicSocketTxBuffer txBuf;

  Ptr<QuicSocketTxScheduler> sched = CreateObject<QuicSocketTxScheduler>();
  txBuf.SetScheduler(sched);
  Ptr<QuicSocketBase> socket = CreateObject<QuicSocketBase> ();
  txBuf.SetSocket(socket);
  Ptr<QuicSocketState> tcbd;

  tcbd = CreateObject<QuicSocketState> ();
  txBuf.SetQuicSocketState(tcbd);

  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 0, "TxBuf miscalculates initial size of in flight segments");

  Ptr<Packet> p1 = Create<Packet> (1196);
  QuicSubheader sub = QuicSubheader::CreateStreamSubHeader (1, 0, p1->GetSize (),
                                          false, true, false);
  p1->AddHeader (sub);
  txBuf.Add (p1);

  Ptr<Packet> ptx = txBuf.NextSequence (1200, SequenceNumber32 (1), APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(ptx->GetSize (), 1200, "TxBuf miscalculates size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 1200, "TxBuf miscalculates size of in flight segments");

  std::vector<uint32_t> additionalAckBlocks;
  std::vector<uint32_t> gaps;
  uint32_t largestAcknowledged = 1;
  additionalAckBlocks.push_back (0);
  gaps.push_back (0);

  std::vector<Ptr<QuicSocketTxItem>> acked = txBuf.OnAckUpdate (tcbd,
                                                            largestAcknowledged,
                                                            additionalAckBlocks,
                                                            gaps, APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(acked.size (), 1, "Wrong acked packet vector size");
  NS_TEST_ASSERT_MSG_EQ(acked.at (0)->m_packet->GetSize (), 1200, "TxBuf miscalculates size");
  NS_TEST_ASSERT_MSG_EQ(acked.at (0)->m_packetNumber, SequenceNumber32 (1),
                        "TxBuf gets the wrong lost packet ID");
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 0, "TxBuf miscalculates size of in flight segments");

  Ptr<Packet> p2 = Create<Packet> (1196);
  sub = QuicSubheader::CreateStreamSubHeader (1, 1200, p2->GetSize (),
                                          false, true, false);
  p2->AddHeader (sub);
  txBuf.Add (p2);

  ptx = txBuf.NextSequence (1200, SequenceNumber32 (2), APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(ptx->GetSize (), 1200, "TxBuf miscalculates size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 1200, "TxBuf miscalculates size of in flight segments");

  Ptr<Packet> p3 = Create<Packet> (1196);
  sub = QuicSubheader::CreateStreamSubHeader (1, 2400, p3->GetSize (),
                                          false, true, false);
  p3->AddHeader (sub);
  txBuf.Add (p3);

  ptx = txBuf.NextSequence (1200, SequenceNumber32 (3), APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(ptx->GetSize (), 1200, "TxBuf miscalculates size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 2400, "TxBuf miscalculates size of in flight segments");

  acked = txBuf.OnAckUpdate (tcbd,
                             largestAcknowledged,
                             additionalAckBlocks,
                             gaps, APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(acked.size (), 0, "Wrong acked packet vector size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 2400, "TxBuf miscalculates size of in flight segments");

  uint32_t newPackets = 1;
  txBuf.ResetSentList (newPackets);
  std::vector<Ptr<QuicSocketTxItem>> lostPackets = txBuf.DetectLostPackets (tcbd, APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(lostPackets.size (), 1, "Wrong lost packet vector size");
  NS_TEST_ASSERT_MSG_EQ(lostPackets.at (0)->m_packet->GetSize (), 1200, "TxBuf miscalculates size");
  NS_TEST_ASSERT_MSG_EQ(lostPackets.at (0)->m_packetNumber, SequenceNumber32 (2),
                        "TxBuf gets the wrong lost packet ID");
  NS_TEST_ASSERT_MSG_EQ (txBuf.BytesInFlight (), 1200, "TxBuf miscalculates size of in flight segments");

  uint32_t toRetx = txBuf.Retransmission (SequenceNumber32(2), APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(toRetx, 1200, "wrong number of lost bytes");
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 1200, "TxBuf miscalculates size of in flight segments");

  ptx = txBuf.NextSequence (toRetx, SequenceNumber32 (4), APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(ptx->GetSize (), 1200, "TxBuf miscalculates size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 2400, "TxBuf miscalculates size of in flight segments");

  largestAcknowledged = 3;
  acked = txBuf.OnAckUpdate (tcbd,
                             largestAcknowledged,
                             additionalAckBlocks,
                             gaps, APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(acked.size (), 1, "Wrong acked packet vector size");
  NS_TEST_ASSERT_MSG_EQ(acked.at (0)->m_packet->GetSize (), 1200, "TxBuf miscalculates size");
  NS_TEST_ASSERT_MSG_EQ(acked.at (0)->m_packetNumber, SequenceNumber32 (3),
                        "TxBuf gets the wrong lost packet ID");
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 1200, "TxBuf miscalculates size of in flight segments");

  largestAcknowledged = 4;
  acked = txBuf.OnAckUpdate (tcbd,
                             largestAcknowledged,
                             additionalAckBlocks,
                             gaps, APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ(acked.size (), 1, "Wrong acked packet vector size");
  NS_TEST_ASSERT_MSG_EQ(acked.at (0)->m_packet->GetSize (), 1200, "TxBuf miscalculates size");
  NS_TEST_ASSERT_MSG_EQ(acked.at (0)->m_packetNumber, SequenceNumber32 (4),
                        "TxBuf gets the wrong lost packet ID");
  NS_TEST_ASSERT_MSG_EQ(txBuf.BytesInFlight (), 0, "TxBuf miscalculates size of in flight segments");
}

void
QuicTxBufferPureLogicTestCase::TestRejection ()
{
  QuicStreamTxBuffer streamTxBuf;
  streamTxBuf.SetMaxBufferSize (18000);

  QuicSocketTxBuffer socketTxBuf;
  Ptr<QuicSocketTxScheduler> sched = CreateObject<QuicSocketTxScheduler>();
  socketTxBuf.SetScheduler(sched);
  socketTxBuf.SetMaxBufferSize (4800);

  Ptr<Packet> p = Create<Packet> (1200);

  bool pos = streamTxBuf.Add(p);
  pos = streamTxBuf.Add(p);
  pos = streamTxBuf.Add(p);
  pos = streamTxBuf.Add(p);
  pos = streamTxBuf.Add(p);

  NS_TEST_ASSERT_MSG_EQ(pos, true, "Failed to add packet");
  NS_TEST_ASSERT_MSG_EQ(streamTxBuf.Available (), 12000, "Wrong available data size");
  NS_TEST_ASSERT_MSG_EQ(streamTxBuf.AppSize (), 6000, "Wrong buffer size");

  Ptr<Packet> outPkt = streamTxBuf.NextSequence(2400, SequenceNumber32(0));

  NS_TEST_ASSERT_MSG_NE(!outPkt, true, "Failed to extract packets");
  NS_TEST_ASSERT_MSG_EQ(outPkt->GetSize(), 2400,  "Wrong packet size");
  NS_TEST_ASSERT_MSG_EQ(streamTxBuf.Available (), 14400, "Wrong available data size");
  NS_TEST_ASSERT_MSG_EQ(streamTxBuf.AppSize (), 3600, "Wrong buffer size");

  QuicSubheader sub = QuicSubheader::CreateStreamSubHeader (1, 0, outPkt->GetSize (),
                         false, true, false);
  outPkt->AddHeader (sub);
  NS_TEST_ASSERT_MSG_EQ(outPkt->GetSize(), 2400 + sub.GetSerializedSize (),  "Wrong packet size");

  pos = socketTxBuf.Add (outPkt);
  NS_TEST_ASSERT_MSG_EQ(pos, true, "Failed to add packet");
  NS_TEST_ASSERT_MSG_EQ(socketTxBuf.Available (), 4800 - outPkt->GetSize (), "Wrong available data size");
  NS_TEST_ASSERT_MSG_EQ(socketTxBuf.AppSize (), outPkt->GetSize (), "Wrong buffer size");

  Ptr<Packet> outPktMore = streamTxBuf.NextSequence(2400, SequenceNumber32(0));

  NS_TEST_ASSERT_MSG_NE(!outPktMore, true, "Failed to extract packets");
  NS_TEST_ASSERT_MSG_EQ(outPktMore->GetSize(), 2400,  "Wrong packet size");
  NS_TEST_ASSERT_MSG_EQ(streamTxBuf.Available (), 16800, "Wrong available data size");
  NS_TEST_ASSERT_MSG_EQ(streamTxBuf.AppSize (), 1200, "Wrong buffer size");

  sub = QuicSubheader::CreateStreamSubHeader (1, 2400, outPktMore->GetSize (),
                         true, true, false);
  outPktMore->AddHeader (sub);
  NS_TEST_ASSERT_MSG_EQ(outPktMore->GetSize(), 2400 + sub.GetSerializedSize (),  "Wrong packet size");

  pos = socketTxBuf.Add (outPktMore);
  NS_TEST_ASSERT_MSG_EQ(pos, false, "Buffer overflow");
  NS_TEST_ASSERT_MSG_EQ(socketTxBuf.Available (), 4800 - outPkt->GetSize (), "Wrong available data size");
  NS_TEST_ASSERT_MSG_EQ(socketTxBuf.AppSize (), outPkt->GetSize (), "Wrong buffer size");

  pos = streamTxBuf.Rejected(outPktMore);

  NS_TEST_ASSERT_MSG_EQ(pos, true, "Failed to add packet");
  NS_TEST_ASSERT_MSG_EQ(streamTxBuf.Available (), 14400 - sub.GetSerializedSize (), "Wrong available data size");
  NS_TEST_ASSERT_MSG_EQ(streamTxBuf.AppSize (), 3600 + sub.GetSerializedSize (), "Wrong buffer size");
}

void
QuicTxBufferPureLogicTestCase::TestStreamExtract ()
{
  QuicStreamTxBuffer txBuf;
  txBuf.SetMaxBufferSize (18000);

  Ptr<Packet> p = Create<Packet> (1200);

  bool pos = txBuf.Add(p);
  pos = txBuf.Add(p);
  pos = txBuf.Add(p);

  NS_TEST_ASSERT_MSG_EQ(pos, true, "Failed to add packet");
  NS_TEST_ASSERT_MSG_EQ(txBuf.Available (), 14400, "Wrong available data size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.AppSize (), 3600, "Wrong buffer size");

  Ptr<Packet> outPkt = txBuf.NextSequence(2400, SequenceNumber32(0));

  NS_TEST_ASSERT_MSG_EQ(pos, true, "Failed to add packet");
  NS_TEST_ASSERT_MSG_EQ(outPkt->GetSize(), 2400,  "Wrong packet size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.Available (), 16800, "Wrong available data size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.AppSize (), 1200, "Wrong buffer size");

  pos = txBuf.Add(outPkt);

  NS_TEST_ASSERT_MSG_EQ(pos, true, "Failed to add packet");
  NS_TEST_ASSERT_MSG_EQ(txBuf.Available (), 14400, "Wrong available data size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.AppSize (), 3600, "Wrong buffer size");

  outPkt = txBuf.NextSequence(3600, SequenceNumber32(1));

  NS_TEST_ASSERT_MSG_NE(!outPkt, true, "Failed to extract packets");
  NS_TEST_ASSERT_MSG_EQ(outPkt->GetSize(), 3600,  "Wrong packet size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.Available (), 18000, "Wrong available data size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.AppSize (), 0, "Wrong buffer size");

  outPkt = txBuf.NextSequence(1200, SequenceNumber32(2));
  NS_TEST_ASSERT_MSG_EQ(outPkt->GetSize(), 0,  "Wrong packet size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.Available (), 18000, "Wrong available data size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.AppSize (), 0, "Wrong buffer size");
}

void
QuicTxBufferPureLogicTestCase::TestStreamAdd ()
{
  QuicStreamTxBuffer txBuf;
  txBuf.SetMaxBufferSize (18000);

  Ptr<Packet> p = Create<Packet> (1200);

  bool pos = txBuf.Add(p);

  NS_TEST_ASSERT_MSG_EQ(pos, true, "Failed to add packet");
  NS_TEST_ASSERT_MSG_EQ(txBuf.Available (), 16800, "Wrong available data size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.AppSize (), 1200, "Wrong buffer size");

  pos = txBuf.Add(p);

  NS_TEST_ASSERT_MSG_EQ(pos, true, "Failed to add packet");
  NS_TEST_ASSERT_MSG_EQ(txBuf.Available (), 15600, "Wrong available data size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.AppSize (), 2400, "Wrong buffer size");

  pos = txBuf.Add(p);

  NS_TEST_ASSERT_MSG_EQ(pos, true, "Failed to add packet");
  NS_TEST_ASSERT_MSG_EQ(txBuf.Available (), 14400, "Wrong available data size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.AppSize (), 3600, "Wrong buffer size");

  p = Create<Packet> (14400);
  pos = txBuf.Add(p);

  NS_TEST_ASSERT_MSG_EQ(pos, true, "Failed to add packet");
  NS_TEST_ASSERT_MSG_EQ(txBuf.Available (), 0, "Wrong available data size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.AppSize (), 18000, "Wrong buffer size");

  pos = txBuf.Add(p);

  NS_TEST_ASSERT_MSG_EQ(pos, false, "Buffer overflow");
  NS_TEST_ASSERT_MSG_EQ(txBuf.Available (), 0, "Wrong available data size");
  NS_TEST_ASSERT_MSG_EQ(txBuf.AppSize (), 18000, "Wrong buffer size");
}

/**
 * \ingroup internet-test
 * \ingroup tests
 *
 * \brief Check that the memoized in-flight totals survive every kind of sent-list mutation
 *
 * BytesInFlight(), GetCongestionControlledBytesInFlight() and GetPayloadBytesInFlight() are
 * served from per-space totals that the send path maintains incrementally, so a mutation that
 * neither updates nor invalidates them would silently return a stale window. This walks a
 * buffer through send, wire-size revision, loss marking, acknowledgement, reset and discard,
 * checking the reported totals against independently computed values at each step.
 */
class QuicTxBufferInFlightCacheTestCase : public TestCase
{
public:
  QuicTxBufferInFlightCacheTestCase ();
  virtual ~QuicTxBufferInFlightCacheTestCase ();

private:
  virtual void DoRun (void);

  /**
   * \brief Buffer a STREAM frame and hand it to the sent list
   *
   * \param txBuf the buffer under test
   * \param packetNumber the packet number to assign
   * \param offset the stream offset of the frame
   */
  void SendOne (QuicSocketTxBuffer &txBuf, uint32_t packetNumber, uint32_t offset);
};

QuicTxBufferInFlightCacheTestCase::QuicTxBufferInFlightCacheTestCase () :
    TestCase ("QuicTxBuffer In-Flight Cache Consistency")
{
}

QuicTxBufferInFlightCacheTestCase::~QuicTxBufferInFlightCacheTestCase ()
{
}

void
QuicTxBufferInFlightCacheTestCase::SendOne (QuicSocketTxBuffer &txBuf, uint32_t packetNumber,
                                            uint32_t offset)
{
  Ptr<Packet> p = Create<Packet> (1196);
  QuicSubheader sub = QuicSubheader::CreateStreamSubHeader (1, offset, p->GetSize (),
                                                            false, true, false);
  p->AddHeader (sub);
  txBuf.Add (p);
  txBuf.NextSequence (1200, SequenceNumber32 (packetNumber), APPLICATION_DATA);
}

void
QuicTxBufferInFlightCacheTestCase::DoRun ()
{
  QuicSocketTxBuffer txBuf;

  Ptr<QuicSocketTxScheduler> sched = CreateObject<QuicSocketTxScheduler> ();
  txBuf.SetScheduler (sched);
  Ptr<QuicSocketBase> socket = CreateObject<QuicSocketBase> ();
  txBuf.SetSocket (socket);
  Ptr<QuicSocketState> tcbd = CreateObject<QuicSocketState> ();
  txBuf.SetQuicSocketState (tcbd);

  NS_TEST_ASSERT_MSG_EQ (txBuf.BytesInFlight (), 0, "Fresh buffer reports bytes in flight");
  NS_TEST_ASSERT_MSG_EQ (txBuf.GetPayloadBytesInFlight (), 0,
                         "Fresh buffer reports payload in flight");

  // Sending grows the totals incrementally: 1200 wire bytes carrying 1196 payload bytes each.
  for (uint32_t i = 1; i <= 3; ++i)
    {
      SendOne (txBuf, i, (i - 1) * 1200);
      NS_TEST_ASSERT_MSG_EQ (txBuf.BytesInFlight (), i * 1200,
                             "Wrong wire bytes in flight after sending packet " << i);
      NS_TEST_ASSERT_MSG_EQ (txBuf.GetPayloadBytesInFlight (), i * 1196,
                             "Wrong payload bytes in flight after sending packet " << i);
    }

  // Congestion control only accounts for APPLICATION_DATA, which is all we have sent.
  NS_TEST_ASSERT_MSG_EQ (txBuf.GetCongestionControlledBytesInFlight (), 3600,
                         "Congestion controlled bytes disagree with total wire bytes");

  // Revising a packet's wire size (the header overhead is known only once it is serialised)
  // must resize the total in place rather than leave the old contribution behind.
  txBuf.UpdatePacketSent (SequenceNumber32 (3), 1250, APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ (txBuf.BytesInFlight (), 3650,
                         "Wire bytes not adjusted after a packet was resized");
  NS_TEST_ASSERT_MSG_EQ (txBuf.GetPayloadBytesInFlight (), 3588,
                         "Payload bytes changed by a wire-size revision");

  // A packet declared lost stops counting against the window.
  txBuf.MarkAsLost (SequenceNumber32 (2), APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ (txBuf.BytesInFlight (), 2450,
                         "Lost packet still counted in wire bytes in flight");
  NS_TEST_ASSERT_MSG_EQ (txBuf.GetPayloadBytesInFlight (), 2392,
                         "Lost packet still counted in payload bytes in flight");

  // Acknowledging packet 1 both clears its in-flight contribution and erases it from the list.
  std::vector<uint32_t> additionalAckBlocks;
  std::vector<uint32_t> gaps;
  additionalAckBlocks.push_back (0);
  gaps.push_back (0);
  std::vector<Ptr<QuicSocketTxItem>> acked = txBuf.OnAckUpdate (tcbd, 1, additionalAckBlocks,
                                                                gaps, APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ (acked.size (), 1, "Wrong number of newly acknowledged packets");
  NS_TEST_ASSERT_MSG_EQ (txBuf.BytesInFlight (), 1250,
                         "Acknowledged packet still counted in wire bytes in flight");
  NS_TEST_ASSERT_MSG_EQ (txBuf.GetPayloadBytesInFlight (), 1196,
                         "Acknowledged packet still counted in payload bytes in flight");

  // ResetSentList marks every unacknowledged packet lost, emptying the window.
  txBuf.ResetSentList (0);
  NS_TEST_ASSERT_MSG_EQ (txBuf.BytesInFlight (), 0,
                         "Wire bytes still in flight after the sent list was reset");
  NS_TEST_ASSERT_MSG_EQ (txBuf.GetPayloadBytesInFlight (), 0,
                         "Payload bytes still in flight after the sent list was reset");

  // Discarding a packet number space drops whatever is left in it.
  txBuf.DiscardSpace (APPLICATION_DATA);
  NS_TEST_ASSERT_MSG_EQ (txBuf.BytesInFlight (), 0,
                         "Wire bytes still in flight after the space was discarded");
  NS_TEST_ASSERT_MSG_EQ (txBuf.GetPayloadBytesInFlight (), 0,
                         "Payload bytes still in flight after the space was discarded");
}

/**
 * \ingroup internet-test
 * \ingroup tests
 *
 * \brief TestSuite for QuicTxBuffer
 */
class QuicTxBufferTestSuite : public TestSuite
{
public:
  QuicTxBufferTestSuite () :
      TestSuite ("quic-tx-buffer", UNIT)
  {
    LogComponentEnable ("QuicTxBufferTestSuite", LOG_LEVEL_ALL);
    LogComponentEnable ("QuicSocketTxBuffer", LOG_LEVEL_LOGIC);

    AddTestCase (new QuicTxBufferScheduledTestCase, TestCase::QUICK);
    AddTestCase (new QuicTxBufferPureLogicTestCase, TestCase::QUICK);
    AddTestCase (new QuicTxBufferInFlightCacheTestCase, TestCase::QUICK);
  }
};

static QuicTxBufferTestSuite g_quicTxBufferTestSuite;
