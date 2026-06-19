/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * QUIC Socket State (TCB) Tests - RFC 9002 Compliance
 *
 * Tests the QUIC Transmission Control Block (QuicSocketState) as specified
 * in RFC 9002 Appendix B. QuicSocketBase requires a full L4 protocol stack
 * for safe construction, so these tests target QuicSocketState directly.
 *
 * RFC 9002 §7.2: Initial Congestion Window
 * RFC 9002 §7.3: Congestion Control States
 * RFC 9002 §7.2: Minimum Congestion Window
 */

#include "ns3/test.h"
#include "ns3/log.h"
#include "ns3/quic-socket-base.h"

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
}

static QuicSocketBaseTestSuite quicSocketTestSuite;

} // namespace ns3
