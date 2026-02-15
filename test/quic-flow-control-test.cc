/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "ns3/test.h"
#include "ns3/log.h"
#include "ns3/quic-socket-base.h"
#include "ns3/quic-stream-base.h"
#include "ns3/quic-l5-protocol.h"
#include "ns3/quic-socket-tx-scheduler.h"
#include "ns3/simulator.h"
#include "ns3/quic-header.h"
#include "ns3/quic-subheader.h"

using namespace ns3;

/**
 * \ingroup internet-tests
 * \ingroup tests
 *
 * \brief The QuicFlowControl Test
 */
class QuicFlowControlTestCase : public TestCase
{
public:
  QuicFlowControlTestCase ();
  virtual ~QuicFlowControlTestCase ();

private:
  virtual void DoRun (void);
  
  // Helpers
  void Setup ();
  void TestStreamFlowControl ();
  void TestConnectionFlowControl ();
  void TestCongestionWindow ();
  
  Ptr<QuicSocketBase> m_socket;
  Ptr<QuicL5Protocol> m_l5;
  Ptr<QuicStreamBase> m_stream;
};

QuicFlowControlTestCase::QuicFlowControlTestCase ()
  : TestCase ("Check QUIC Flow Control and Congestion Window logic")
{}

QuicFlowControlTestCase::~QuicFlowControlTestCase ()
{}

void
QuicFlowControlTestCase::Setup ()
{
  m_socket = CreateObject<QuicSocketBase> ();
  
  // Initialize scheduler (required for TX buffer)
  m_socket->InitializeScheduling();
  
  m_l5 = CreateObject<QuicL5Protocol> ();
  m_l5->SetSocket (m_socket);
  
  // Create stream
  m_stream = CreateObject<QuicStreamBase> ();
  m_stream->SetQuicL5 (m_l5);
  m_stream->SetStreamId (0);
  m_stream->SetStreamDirectionType (QuicStream::BIDIRECTIONAL);
  m_stream->SetStreamType (QuicStream::CLIENT_INITIATED_BIDIRECTIONAL);
  // Set buffer size
  m_stream->SetStreamSndBufSize (100000);
}

void
QuicFlowControlTestCase::TestStreamFlowControl ()
{
  Setup ();
  // Set Stream Max Data
  uint32_t maxStreamData = 1000;
  m_stream->SetMaxStreamData (maxStreamData);
  
  // Verify initial window
  NS_TEST_ASSERT_MSG_EQ (m_stream->StreamWindow (), 1000, "Initial Stream Window incorrect");
  
  // Create a packet of 600 bytes
  Ptr<Packet> p1 = Create<Packet> (600);
  m_stream->Send (p1);
  
  Simulator::Stop (Seconds (0.1));
  Simulator::Run ();
  
  NS_TEST_ASSERT_MSG_EQ (m_stream->StreamWindow (), 400, "Stream Window not reduced after send");
  
  Ptr<Packet> p2 = Create<Packet> (500);
  m_stream->Send (p2);
  
  Simulator::Stop (Seconds (0.2));
  Simulator::Run ();
  
  NS_TEST_ASSERT_MSG_EQ (m_stream->StreamWindow (), 0, "Stream Window should be 0");
  
  uint32_t bufSize = m_stream->GetStreamSndBufSize ();
  uint32_t available = m_stream->GetStreamTxAvailable ();
  uint32_t buffered = bufSize - available;
  NS_TEST_ASSERT_MSG_EQ (buffered, 100, "Buffer should contain remaining 100 bytes");
  
  m_stream->SetMaxStreamData (1500);
  NS_TEST_ASSERT_MSG_EQ (m_stream->StreamWindow (), 500, "Stream Window not updated");
  
  Simulator::Schedule (TimeStep (1), &QuicStreamBase::SendPendingData, m_stream);
  Simulator::Stop (Seconds (0.3));
  Simulator::Run ();
  
  available = m_stream->GetStreamTxAvailable ();
  buffered = bufSize - available;
  NS_TEST_ASSERT_MSG_EQ (buffered, 0, "Buffer should be empty after window update");
  NS_TEST_ASSERT_MSG_EQ (m_stream->StreamWindow (), 400, "Window should be 400");
  Simulator::Destroy ();
}

void
QuicFlowControlTestCase::TestConnectionFlowControl ()
{
  Setup ();
  // Set Connection Max Data
  m_socket->SetConnectionMaxData (2000);
  m_socket->SetState (QuicSocket::OPEN); // Required for AppendingTx

  // Stream data also counts towards connection flow control
  Ptr<Packet> p1 = Create<Packet> (1200);
  m_socket->AppendingTx (p1);
  
  Simulator::Stop (Seconds (0.1));
  Simulator::Run ();
  
  // Connection window should be 2000 - 1200 = 800
  // Note: AppendingTx calls SendPendingData, which calls SendDataPacket.
  // SendDataPacket adds headers (short header is 1 + 8 + 4 = 13 bytes by default if CID omitted is false)
  // AvailableWindow uses PayloadBytesInFlight for Flow Control part.
  
  NS_TEST_ASSERT_MSG_EQ (m_socket->GetConnectionMaxData (), 2000, "Max data not set correctly");
  
  // AvailableWindow() returns min(CongestionAvail, FlowControlAvail)
  // Default CWND is 10 * 1200 = 12000 or similar.
  // FlowControlAvail = 2000 - 1200 = 800.
  NS_TEST_ASSERT_MSG_EQ (m_socket->AvailableWindow (), 800, "Connection Flow Control Window incorrect");
  
  Simulator::Destroy ();
}

void
QuicFlowControlTestCase::TestCongestionWindow ()
{
  Setup ();
  Ptr<QuicSocketState> tcb = m_socket->GetTcb ();
  tcb->m_cWnd = 5000;
  m_socket->SetConnectionMaxData (10000); // Large flow control
  m_socket->SetState (QuicSocket::OPEN);

  Ptr<Packet> p1 = Create<Packet> (1000);
  m_socket->AppendingTx (p1);
  
  Simulator::Stop (Seconds (0.1));
  Simulator::Run ();
  
  // CWND was 5000. Sent 1000 bytes payload. 
  // With header (13 bytes), wire size is 1013.
  // CongestionAvail = 5000 - 1013 = 3987.
  // FlowControlAvail = 10000 - 1000 = 9000.
  // min(3987, 9000) = 3987.
  
  NS_TEST_ASSERT_MSG_EQ (m_socket->AvailableWindow (), 3987, "Congestion Window not correctly reflected in AvailableWindow");
  
  Simulator::Destroy ();
}

void
QuicFlowControlTestCase::DoRun (void)
{
  TestStreamFlowControl ();
  TestConnectionFlowControl ();
  TestCongestionWindow ();
}

class QuicFlowControlTestSuite : public TestSuite
{
public:
  QuicFlowControlTestSuite ()
    : TestSuite ("quic-flow-control", UNIT)
  {
    AddTestCase (new QuicFlowControlTestCase, TestCase::QUICK);
  }
};

static QuicFlowControlTestSuite g_quicFlowControlTestSuite;
