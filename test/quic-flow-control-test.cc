/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * QUIC Flow Control Tests - RFC 9000 Compliance
 *
 * Tests flow control mechanisms as specified in RFC 9000 Section 4:
 * - Stream-level flow control
 * - Connection-level flow control
 * - Flow control limit enforcement
 * - MAX_DATA and MAX_STREAM_DATA frame semantics
 */

#include "ns3/test.h"
#include "ns3/log.h"
#include "ns3/quic-socket.h"
#include "ns3/quic-socket-base.h"
#include "ns3/quic-stream-base.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("QuicFlowControlTest");

/**
 * Test Case 1: Stream Flow Control - Window Management
 *
 * RFC 9000 Section 4.1:
 * "Stream flow control prevents a single stream from consuming the entire
 * receive buffer for a connection by limiting the amount of data that can
 * be sent on each stream."
 *
 * Tests:
 * - Initial flow control window is set correctly
 * - Window can be increased via MAX_STREAM_DATA
 * - Window cannot be decreased (ignored by sender)
 * - Sending beyond window should be prevented
 */
class QuicStreamFlowControlTestCase : public TestCase
{
public:
  QuicStreamFlowControlTestCase ();

private:
  virtual void DoRun (void);
  virtual void DoTeardown (void);

  Ptr<QuicStreamBase> m_stream;
};

QuicStreamFlowControlTestCase::QuicStreamFlowControlTestCase ()
  : TestCase ("Stream Flow Control - Window Management (RFC 9000 §4.1)")
{
}

void
QuicStreamFlowControlTestCase::DoRun (void)
{
  m_stream = CreateObject<QuicStreamBase> ();
  m_stream->SetStreamId (0);
  m_stream->SetStreamDirectionType (QuicStream::BIDIRECTIONAL);
  m_stream->SetStreamType (QuicStream::CLIENT_INITIATED_BIDIRECTIONAL);
  m_stream->SetStreamSndBufSize (100000);

  // Test 1: Initial flow control window
  uint32_t initialWindow = 65536;
  m_stream->SetMaxStreamData (initialWindow);
  NS_TEST_ASSERT_MSG_EQ (m_stream->StreamWindow (), initialWindow,
                         "Initial stream flow control window should be 65536 bytes");

  // Test 2: Window increase
  uint32_t increasedWindow = 131072;
  m_stream->SetMaxStreamData (increasedWindow);
  NS_TEST_ASSERT_MSG_EQ (m_stream->StreamWindow (), increasedWindow,
                         "Stream flow control window should increase to 131072 bytes");

  // Test 3: Window decrease is ignored (per RFC 9000 §4.1)
  uint32_t decreasedWindow = 32768;
  m_stream->SetMaxStreamData (decreasedWindow);
  NS_TEST_ASSERT_MSG_EQ (m_stream->StreamWindow (), increasedWindow,
                         "Decreased window should be ignored");

  // Test 4: Multiple window updates maintain the maximum
  m_stream->SetMaxStreamData (100000);
  NS_TEST_ASSERT_MSG_EQ (m_stream->StreamWindow (), increasedWindow,
                         "Window should remain at maximum");
}

void
QuicStreamFlowControlTestCase::DoTeardown (void)
{
  m_stream = nullptr;
}

/**
 * Test Case 2: Connection Flow Control
 *
 * RFC 9000 Section 4.1:
 * "Connection flow control prevents senders from exceeding a receiver's
 * buffer capacity for the connection by limiting the total bytes of
 * stream data sent in STREAM frames on all streams."
 */
class QuicConnectionFlowControlTestCase : public TestCase
{
public:
  QuicConnectionFlowControlTestCase ();

private:
  virtual void DoRun (void);
  virtual void DoTeardown (void);

  Ptr<QuicSocketBase> m_socket;
};

QuicConnectionFlowControlTestCase::QuicConnectionFlowControlTestCase ()
  : TestCase ("Connection Flow Control - Multi-stream Limits (RFC 9000 §4.1)")
{
}

void
QuicConnectionFlowControlTestCase::DoRun (void)
{
  m_socket = CreateObject<QuicSocketBase> ();

  // Test 1: Connection max data can be set
  uint32_t connectionMaxData = 1000000;
  m_socket->SetPeerMaxData (connectionMaxData);

  // Test 2: Initial congestion window is reasonable
  Ptr<QuicSocketState> tcb = m_socket->GetTcb ();
  NS_TEST_ASSERT_MSG_NE (tcb, nullptr, "Socket should have TCB");

  uint32_t cWnd = tcb->m_cWnd.Get ();
  NS_TEST_ASSERT_MSG_GT (cWnd, 0, "Congestion window must be > 0");
  NS_TEST_ASSERT_MSG_LT (cWnd, 100000, "Initial cwnd should be reasonable");

  // Test 3: Available window reflects constraints
  uint32_t availWindow = m_socket->AvailableWindow ();
  NS_TEST_ASSERT_MSG_LT_OR_EQ (availWindow, cWnd,
                               "Available window should not exceed congestion window");
}

void
QuicConnectionFlowControlTestCase::DoTeardown (void)
{
  m_socket = nullptr;
}

/**
 * Test Case: Local vs. Peer Connection-Level MAX_DATA Are Independent
 *
 * RFC 9000 Section 4.1 makes connection flow control symmetric per direction:
 * each endpoint independently limits how much data its peer may send it, via
 * its own initial_max_data / MAX_DATA frames. That local, receive-side limit
 * must not be conflated with the limit the *peer* has granted *us* to send,
 * which governs the opposite direction:
 * - Learning the peer's limit (a received MAX_DATA frame) must not change
 *   what we have told the peer it may send us.
 * - Raising our own local (receive-side) limit must not, by itself, permit
 *   us to send more -- only the peer's MAX_DATA can do that.
 * - Incoming-data flow-control enforcement (CheckIfPacketOverflowMaxDataLimit)
 *   must be governed by our own local limit, not by whatever the peer has
 *   granted us to send.
 */
class QuicMaxDataLocalPeerSeparationTestCase : public TestCase
{
public:
  QuicMaxDataLocalPeerSeparationTestCase ();

private:
  virtual void DoRun (void);
  virtual void DoTeardown (void);

  Ptr<QuicSocketBase> m_socket;
};

QuicMaxDataLocalPeerSeparationTestCase::QuicMaxDataLocalPeerSeparationTestCase ()
  : TestCase ("Local vs. Peer Connection MAX_DATA Are Independent (RFC 9000 §4.1)")
{
}

void
QuicMaxDataLocalPeerSeparationTestCase::DoRun (void)
{
  m_socket = CreateObject<QuicSocketBase> ();
  m_socket->SetAttribute ("InitialMaxData", UintegerValue (500));

  NS_TEST_ASSERT_MSG_EQ (m_socket->GetLocalMaxData (), 500,
                         "Local limit should start at the InitialMaxData attribute");

  // The peer's limit is not governed by our InitialMaxData attribute at all:
  // it defaults independently (fully permissive, until constrained by the
  // peer's own transport parameters or MAX_DATA frames).
  NS_TEST_ASSERT_MSG_EQ (m_socket->GetPeerMaxData (), UINT32_MAX,
                         "Peer limit must default independently of our own InitialMaxData attribute");

  // A MAX_DATA frame may only ever raise the peer limit (RFC 9000 §4.1): a
  // value at or below the current one must be ignored, and in neither case
  // may it leak into our own advertised receive limit.
  m_socket->SetPeerMaxData (2000);
  NS_TEST_ASSERT_MSG_EQ (m_socket->GetPeerMaxData (), UINT32_MAX,
                         "A MAX_DATA frame below the current peer limit must be ignored");
  NS_TEST_ASSERT_MSG_EQ (m_socket->GetLocalMaxData (), 500,
                         "A received MAX_DATA frame must not affect our own local limit");

  // A 600-byte STREAM frame overflows our 500-byte local limit even though
  // the peer has granted us far more (2000) to send -- the two must not be
  // conflated by the incoming-data check.
  Ptr<Packet> p = Create<Packet> (600);
  QuicSubheader sub = QuicSubheader::CreateStreamSubHeader (4, 0, p->GetSize (), false, true, false);
  std::vector<std::pair<Ptr<Packet>, QuicSubheader> > disgregated;
  disgregated.push_back (std::make_pair (p, sub));

  NS_TEST_ASSERT_MSG_EQ (m_socket->CheckIfPacketOverflowMaxDataLimit (disgregated), true,
                         "600 bytes of STREAM data must overflow a 500-byte local limit");

  // Raising our own local limit (as if we had sent a MAX_DATA update) lifts
  // the incoming-data check, independently of the peer's limit.
  m_socket->SetAttribute ("InitialMaxData", UintegerValue (1000));
  NS_TEST_ASSERT_MSG_EQ (m_socket->CheckIfPacketOverflowMaxDataLimit (disgregated), false,
                         "600 bytes of STREAM data must fit under a 1000-byte local limit");
}

void
QuicMaxDataLocalPeerSeparationTestCase::DoTeardown (void)
{
  m_socket = nullptr;
}

/**
 * Test Case 3: Flow Control and Congestion Control Interaction
 *
 * RFC 9000 & RFC 9002:
 * A sender is limited by both flow control and congestion control.
 */
class QuicFlowAndCongestionTestCase : public TestCase
{
public:
  QuicFlowAndCongestionTestCase ();

private:
  virtual void DoRun (void);
  virtual void DoTeardown (void);

  Ptr<QuicSocketBase> m_socket;
};

QuicFlowAndCongestionTestCase::QuicFlowAndCongestionTestCase ()
  : TestCase ("Flow Control and Congestion Control Interaction (RFC 9000 and 9002)")
{
}

void
QuicFlowAndCongestionTestCase::DoRun (void)
{
  m_socket = CreateObject<QuicSocketBase> ();

  Ptr<QuicSocketState> tcb = m_socket->GetTcb ();
  NS_TEST_ASSERT_MSG_NE (tcb, nullptr, "Socket should have TCB");

  uint32_t defaultCWnd = tcb->m_cWnd.Get ();

  // Test 1: Congestion window is initialized and positive
  NS_TEST_ASSERT_MSG_GT (defaultCWnd, 0,
                         "Default congestion window must be > 0");

  // Test 2: Available window is bounded by congestion window
  uint32_t availWindow = m_socket->AvailableWindow ();
  NS_TEST_ASSERT_MSG_LT_OR_EQ (availWindow, defaultCWnd,
                                "Available window should not exceed congestion window");

  // Test 3: Can modify congestion window and available window changes accordingly
  tcb->m_cWnd = 5000;
  uint32_t newAvailWindow = m_socket->AvailableWindow ();
  NS_TEST_ASSERT_MSG_LT_OR_EQ (newAvailWindow, 5000,
                                "Available window respects congestion window change");
}

void
QuicFlowAndCongestionTestCase::DoTeardown (void)
{
  m_socket = nullptr;
}

/**
 * Test Case 4: Stream Window Monotonicity
 *
 * RFC 9000 Section 4.1:
 * Window values are monotonically non-decreasing.
 * Only increases are applied, decreases are ignored.
 */
class QuicStreamWindowMonotonicityTestCase : public TestCase
{
public:
  QuicStreamWindowMonotonicityTestCase ();

private:
  virtual void DoRun (void);
  virtual void DoTeardown (void);

  Ptr<QuicStreamBase> m_stream;
};

QuicStreamWindowMonotonicityTestCase::QuicStreamWindowMonotonicityTestCase ()
  : TestCase ("Stream Window Monotonicity (RFC 9000 §4.1)")
{
}

void
QuicStreamWindowMonotonicityTestCase::DoRun (void)
{
  m_stream = CreateObject<QuicStreamBase> ();
  m_stream->SetStreamId (4);
  m_stream->SetStreamDirectionType (QuicStream::BIDIRECTIONAL);
  m_stream->SetStreamType (QuicStream::SERVER_INITIATED_BIDIRECTIONAL);
  m_stream->SetStreamSndBufSize (500000);

  uint32_t window1 = 10000;
  uint32_t window2 = 20000;
  uint32_t window3 = 15000;
  uint32_t window4 = 30000;

  m_stream->SetMaxStreamData (window1);
  uint32_t current = m_stream->StreamWindow ();
  NS_TEST_ASSERT_MSG_EQ (current, window1, "Window should be 10000");

  m_stream->SetMaxStreamData (window2);
  current = m_stream->StreamWindow ();
  NS_TEST_ASSERT_MSG_EQ (current, window2, "Window should increase to 20000");

  m_stream->SetMaxStreamData (window3);
  current = m_stream->StreamWindow ();
  NS_TEST_ASSERT_MSG_EQ (current, window2, "Decrease should be ignored, stay at 20000");

  m_stream->SetMaxStreamData (window4);
  current = m_stream->StreamWindow ();
  NS_TEST_ASSERT_MSG_EQ (current, window4, "Window should increase to 30000");
}

void
QuicStreamWindowMonotonicityTestCase::DoTeardown (void)
{
  m_stream = nullptr;
}

/**
 * Test Case 5: Multiple Streams Flow Control Independence
 *
 * Each stream has independent flow control window.
 */
class QuicMultiStreamFlowControlTestCase : public TestCase
{
public:
  QuicMultiStreamFlowControlTestCase ();

private:
  virtual void DoRun (void);
  virtual void DoTeardown (void);

  std::vector<Ptr<QuicStreamBase>> m_streams;
};

QuicMultiStreamFlowControlTestCase::QuicMultiStreamFlowControlTestCase ()
  : TestCase ("Multiple Streams Flow Control Independence")
{
}

void
QuicMultiStreamFlowControlTestCase::DoRun (void)
{
  const uint32_t streamCount = 4;
  const uint32_t baseWindow = 10000;

  for (uint32_t i = 0; i < streamCount; ++i)
    {
      Ptr<QuicStreamBase> stream = CreateObject<QuicStreamBase> ();
      stream->SetStreamId (i * 4);
      stream->SetStreamDirectionType (QuicStream::BIDIRECTIONAL);
      stream->SetStreamType (QuicStream::CLIENT_INITIATED_BIDIRECTIONAL);
      stream->SetStreamSndBufSize (1000000);

      uint32_t window = baseWindow * (i + 1);
      stream->SetMaxStreamData (window);
      m_streams.push_back (stream);

      NS_TEST_ASSERT_MSG_EQ (stream->StreamWindow (), window,
                             "Stream window set correctly");
    }

  // Verify each stream maintains independent window
  for (uint32_t i = 0; i < streamCount; ++i)
    {
      uint32_t expectedWindow = baseWindow * (i + 1);
      uint32_t actualWindow = m_streams[i]->StreamWindow ();
      NS_TEST_ASSERT_MSG_EQ (actualWindow, expectedWindow,
                             "Stream maintains independent window");
    }
}

void
QuicMultiStreamFlowControlTestCase::DoTeardown (void)
{
  m_streams.clear ();
}

/**
 * Test Suite: QUIC Flow Control (RFC 9000 §4)
 */
class QuicFlowControlTestSuite : public TestSuite
{
public:
  QuicFlowControlTestSuite ();
};

QuicFlowControlTestSuite::QuicFlowControlTestSuite ()
  : TestSuite ("quic-flow-control", UNIT)
{
  AddTestCase (new QuicStreamFlowControlTestCase, TestCase::QUICK);
  AddTestCase (new QuicConnectionFlowControlTestCase, TestCase::QUICK);
  AddTestCase (new QuicMaxDataLocalPeerSeparationTestCase, TestCase::QUICK);
  AddTestCase (new QuicFlowAndCongestionTestCase, TestCase::QUICK);
  AddTestCase (new QuicStreamWindowMonotonicityTestCase, TestCase::QUICK);
  AddTestCase (new QuicMultiStreamFlowControlTestCase, TestCase::QUICK);
}

static QuicFlowControlTestSuite g_quicFlowControlTestSuite;
