/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2020 SIGNET Lab, Department of Information Engineering, University of Padova
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
 *          Umberto Paro <umberto.paro@me.com>
 *
 */
/*
 #define NS_LOG_APPEND_CONTEXT \
  if (m_node and m_connectionId) { std::clog << " [node " << m_node->GetId () << " socket " << m_connectionId << "] "; }
*/

#include "ns3/abort.h"
#include "ns3/node.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/log.h"
#include "ns3/ipv4.h"
#include "ns3/ipv6.h"
#include "ns3/ipv4-interface-address.h"
#include "ns3/ipv4-route.h"
#include "ns3/ipv6-route.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv6-routing-protocol.h"
#include "ns3/simulation-singleton.h"
#include "ns3/simulator.h"
#include "ns3/packet.h"
#include "ns3/random-variable-stream.h"
#include "ns3/nstime.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/pointer.h"
#include "ns3/trace-source-accessor.h"
#include "quic-socket-base.h"
#include "quic-congestion-ops.h"
#include "ns3/tcp-congestion-ops.h"
#include "quic-header.h"
#include "quic-l4-protocol.h"
#include "ns3/ipv4-end-point.h"
#include "ns3/ipv6-end-point.h"
#include "ns3/ipv6-l3-protocol.h"
#include "ns3/tcp-header.h"
#include "ns3/tcp-option-winscale.h"
#include "ns3/tcp-option-ts.h"
#include "ns3/tcp-option-sack-permitted.h"
#include "ns3/tcp-option-sack.h"
#include "ns3/rtt-estimator.h"
#include "quic-socket-tx-edf-scheduler.h"
#include "quic-stream-base.h"
#include <math.h>
#include <algorithm>
#include <vector>
#include <sstream>
#include <ns3/core-module.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicSocketBase");

NS_OBJECT_ENSURE_REGISTERED (QuicSocketBase);
NS_OBJECT_ENSURE_REGISTERED (QuicSocketState);

const uint16_t QuicSocketBase::MIN_INITIAL_PACKET_SIZE = 1200;

TypeId
QuicSocketBase::GetInstanceTypeId () const
{
  return QuicSocketBase::GetTypeId ();
}

TypeId
QuicSocketBase::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicSocketBase")
    .SetParent<QuicSocket> ()
    .SetGroupName ("Internet")
    .AddConstructor<QuicSocketBase> ()
    .AddAttribute ("InitialVersion",
                   "The version used by the socket.",
                   UintegerValue (QUIC_VERSION_NS3_IMPL),
                   MakeUintegerAccessor (&QuicSocketBase::m_vers),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("IdleTimeout",
                   "Idle timeout value after which the socket is closed",
                   TimeValue (Seconds (300)),
                   MakeTimeAccessor (&QuicSocketBase::m_idleTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("MaxStreamData",
                   "Stream Maximum Data",
                   UintegerValue (4294967295),
                   MakeUintegerAccessor (&QuicSocketBase::m_initial_max_stream_data),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxData",
                   "Connection Maximum Data",
                   UintegerValue (4294967295),
                   MakeUintegerAccessor (&QuicSocketBase::m_max_data),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxStreamIdBidi",
                   "Maximum StreamId for Bidirectional Streams",
                   UintegerValue (5),
                   MakeUintegerAccessor (&QuicSocketBase::m_initial_max_stream_id_bidi),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxStreamIdUni", "Maximum StreamId for Unidirectional Streams",
                   UintegerValue (5),
                   MakeUintegerAccessor (&QuicSocketBase::m_initial_max_stream_id_uni),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxTrackedGaps", "Maximum number of gaps in an ACK",
                   UintegerValue (20),
                   MakeUintegerAccessor (&QuicSocketBase::m_maxTrackedGaps),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxPacketSize", "Maximum Packet Size",
                   UintegerValue (1460),
                   MakeUintegerAccessor (&QuicSocketBase::GetSegSize,
                                         &QuicSocketBase::SetSegSize),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("SocketSndBufSize", "QuicSocketBase maximum transmit buffer size (bytes)",
                   UintegerValue (131072),                                  // 128k
                   MakeUintegerAccessor (&QuicSocketBase::GetSocketSndBufSize,
                                         &QuicSocketBase::SetSocketSndBufSize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("SocketRcvBufSize", "QuicSocketBase maximum receive buffer size (bytes)",
                   UintegerValue (131072),                                  // 128k
                   MakeUintegerAccessor (&QuicSocketBase::GetSocketRcvBufSize,
                                         &QuicSocketBase::SetSocketRcvBufSize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("AckDelayExponent", "Ack Delay Exponent",
                   UintegerValue (3),
                   MakeUintegerAccessor (&QuicSocketBase::m_ack_delay_exponent),
                   MakeUintegerChecker<uint8_t> ())
    .AddAttribute ("MaxAckDelay", "The maximum amount of time by which the endpoint will delay sending acknowledgments",
                   TimeValue (MilliSeconds (25)),
                   MakeTimeAccessor (&QuicSocketBase::GetMaxAckDelay,
                                     &QuicSocketBase::SetMaxAckDelay),
                   MakeTimeChecker ())
    .AddAttribute ("FlushOnClose", "Determines the connection close behavior",
                   BooleanValue (true),
                   MakeBooleanAccessor (&QuicSocketBase::m_flushOnClose),
                   MakeBooleanChecker ())
    .AddAttribute ("InitialSlowStartThreshold",
                   "QUIC initial slow start threshold (bytes)",
                   UintegerValue (INT32_MAX),
                   MakeUintegerAccessor (&QuicSocketBase::GetInitialSSThresh,
                                         &QuicSocketBase::SetInitialSSThresh),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("InitialPacketSize",
                   "QUIC initial slow start threshold (bytes)",
                   UintegerValue (1200),
                   MakeUintegerAccessor (&QuicSocketBase::GetInitialPacketSize,
                                         &QuicSocketBase::SetInitialPacketSize),
                   MakeUintegerChecker<uint32_t> (
                     QuicSocketBase::MIN_INITIAL_PACKET_SIZE, UINT32_MAX))
    .AddAttribute ("SchedulingPolicy",
                   "Scheduling policy among streams",
                   TypeIdValue (QuicSocketTxScheduler::GetTypeId ()),
                   MakeTypeIdAccessor (&QuicSocketBase::m_schedulingTypeId),
                   MakeTypeIdChecker ())
    .AddAttribute ("DefaultLatency",
                   "Default latency bound for the EDF scheduler",
                   TimeValue (MilliSeconds (100)),
                   MakeTimeAccessor (&QuicSocketBase::m_defaultLatency),
                   MakeTimeChecker ())
    .AddAttribute ("TCB",
                   "The connection's QuicSocketState",
                   PointerValue (),
                   MakePointerAccessor (&QuicSocketBase::m_tcb),
                   MakePointerChecker<QuicSocketState> ())
    .AddTraceSource ("PTO",
                     "Probe timeout",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_pto),
                     "ns3::Time::TracedValueCallback")
    .AddTraceSource ("RTT",
                     "Last RTT sample",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_lastRtt),
                     "ns3::Time::TracedValueCallback")
    .AddTraceSource ("NextTxSequence",
                     "Next sequence number to send (SND.NXT)",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_nextTxSequenceTrace),
                     "ns3::TracedValueCallback::Uint32")
    .AddTraceSource ("HighestSequence",
                     "Highest sequence number ever sent in socket's life time",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_highTxMarkTrace),
                     "ns3::TracedValueCallback::Uint32")
    .AddTraceSource ("CongState",
                     "TCP Congestion machine state",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_congStateTrace),
                     "ns3::TcpSocketState::TcpCongStatesTracedValueCallback")
    .AddTraceSource ("CongestionWindow",
                     "The QUIC connection's congestion window",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_cWndTrace),
                     "ns3::TracedValueCallback::Uint32")
    .AddTraceSource ("SlowStartThreshold",
                     "TCP slow start threshold (bytes)",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_ssThTrace),
                     "ns3::TracedValueCallback::Uint32")
    .AddTraceSource ("BytesInFlight",
                     "The QUIC connection's bytes in flight",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_bytesInFlightTrace),
                     "ns3::TracedValueCallback::Uint32")
    .AddTraceSource ("Tx",
                     "Send QUIC packet to UDP protocol",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_txTrace),
                     "ns3::QuicSocketBase::QuicTxRxTracedCallback")
    .AddTraceSource ("Rx",
                     "Receive QUIC packet from UDP protocol",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_rxTrace),
                     "ns3::QuicSocketBase::QuicTxRxTracedCallback")
    .AddTraceSource ("HandshakeConfirmed",
                     "For clients, true when the server confirmed the handshake",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_handshakeConfirmed),
                     "ns3::TracedValueCallback::Bool")
  ;
  return tid;
}

TypeId
QuicSocketState::GetTypeId (void)
{
  static TypeId tid =
    TypeId ("ns3::QuicSocketState")
    .SetParent<TcpSocketState> ()
    .SetGroupName ("Internet")
    .AddConstructor<QuicSocketState> ()
    .AddAttribute ("kInitialRtt",
                   "The default RTT used before an RTT sample is taken",
                   TimeValue (MilliSeconds (333)),
                   MakeTimeAccessor (&QuicSocketState::SetInitialRtt,
                                     &QuicSocketState::GetInitialRtt),
                   MakeTimeChecker ())
    .AddAttribute ("kPacketThreshold",
                   "Maximum reordering in packet number space before loss detection considers a packet lost",
                   UintegerValue (3),
                   MakeUintegerAccessor (&QuicSocketState::m_kPacketThreshold),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("kTimeThreshold",
                   "Maximum reordering in time space before time based loss detection considers a packet lost",
                   DoubleValue (9.0 / 8),
                   MakeDoubleAccessor (&QuicSocketState::m_kTimeThreshold),
                   MakeDoubleChecker<double> (0))
    .AddAttribute ("max_ack_delay", "The maximum ack delay promised to the peer",
                   TimeValue (MilliSeconds (25)),
                   MakeTimeAccessor (&QuicSocketState::m_max_ack_delay),
                   MakeTimeChecker ())
    .AddAttribute ("kMaxPacketsReceivedBeforeAckSend",
                   "The maximum number of packets without sending an ACK",
                   UintegerValue (2),
                   MakeUintegerAccessor (&QuicSocketState::m_kMaxPacketsReceivedBeforeAckSend),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("kGranularity",
                   "The clock granularity (default 1 time step)",
                   TimeValue (TimeStep (1)),
                   MakeTimeAccessor (&QuicSocketState::m_kGranularity),
                   MakeTimeChecker ())
    .AddAttribute ("kPersistentCongestionThreshold",
                   "Threshold for persistent congestion (default 3)",
                   UintegerValue (3),
                   MakeUintegerAccessor (&QuicSocketState::m_kPersistentCongestionThreshold),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("kLossReductionFactor",
                   "Reduction in congestion window when a new loss event is detected",
                   DoubleValue (0.5),
                   MakeDoubleAccessor (&QuicSocketState::m_kLossReductionFactor),
                   MakeDoubleChecker<double> ())
    .AddAttribute ("kInitialWindowMultiplier",
                   "Multiplier for initial window calculation",
                   UintegerValue (10),
                   MakeUintegerAccessor (&QuicSocketState::SetInitialWindowMultiplier,
                                         &QuicSocketState::GetInitialWindowMultiplier),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("kMinimumWindowMultiplier",
                   "Multiplier for minimum window calculation",
                   UintegerValue (2),
                   MakeUintegerAccessor (&QuicSocketState::SetMinimumWindowMultiplier,
                                         &QuicSocketState::GetMinimumWindowMultiplier),
                   MakeUintegerChecker<uint32_t> ())
  ;
  return tid;
}

QuicSocketState::QuicSocketState ()
  : TcpSocketState (),
    m_kPacketThreshold (3),
    m_kTimeThreshold (9.0 / 8),
    m_max_ack_delay (MilliSeconds (25)),
    m_kInitialRtt (MilliSeconds (333)),
    m_kGranularity (MilliSeconds (1)),
    m_kMaxPacketsReceivedBeforeAckSend (20),
    m_latestRtt (Seconds (0)),
    m_smoothedRtt (MilliSeconds (333)),
    m_rttVar (MilliSeconds (333 / 2)),
    m_firstRttSample (Time::Max ()),
    m_lossDetectionAlarm (),
    m_handshakeCount (0),
    m_timeOfLastSentAckElicitingPacket (Seconds (0)),
    m_largestAckedPacket (0),
    m_peerMaxAckDelay (Seconds (0)),
    m_lossTime (Seconds (0)),
    m_alarmType (0),
    m_nextAlarmTrigger (Seconds (100)),
    m_kInitialWindow (0),
    m_kMinimumWindow (0),
    m_kInitialWindowMultiplier (10),
    m_kMinimumWindowMultiplier (2),
    m_kLossReductionFactor (0.5),
    m_kPersistentCongestionThreshold (3),
    m_endOfRecovery (0),
    m_congestionRecoveryStartTime (Seconds (0)),
    m_firstLostTime (Seconds (0)),
    m_ptoCount (0),
    m_priorInFlight (0)
{
  m_lossDetectionAlarm.Cancel ();

  // m_minRtt is inherited from TcpSocketState
  m_minRtt = Time::Max ();

  // Initialize window based on segment size (inherited from TcpSocketState)
  m_kMinimumWindow = m_kMinimumWindowMultiplier * m_segmentSize;
  m_initialCWnd = std::min (m_kInitialWindowMultiplier * m_segmentSize, std::max (2 * m_segmentSize, 14720U));
}

QuicSocketState::QuicSocketState (const QuicSocketState &other)
  : TcpSocketState (other),
    m_kPacketThreshold (other.m_kPacketThreshold),
    m_kTimeThreshold (other.m_kTimeThreshold),
    m_max_ack_delay (other.m_max_ack_delay),
    m_kInitialRtt (other.m_kInitialRtt),
    m_kGranularity (other.m_kGranularity),
    m_kMaxPacketsReceivedBeforeAckSend (other.m_kMaxPacketsReceivedBeforeAckSend),
    m_latestRtt (other.m_latestRtt),
    m_smoothedRtt (other.m_smoothedRtt),
    m_rttVar (other.m_rttVar),
    m_firstRttSample (other.m_firstRttSample),
    m_lossDetectionAlarm (),
    m_handshakeCount (other.m_handshakeCount),
    m_timeOfLastSentAckElicitingPacket (other.m_timeOfLastSentAckElicitingPacket),
    m_largestAckedPacket (other.m_largestAckedPacket),
    m_peerMaxAckDelay (other.m_peerMaxAckDelay),
    m_lossTime (other.m_lossTime),
    m_alarmType (other.m_alarmType),
    m_nextAlarmTrigger (other.m_nextAlarmTrigger),
    m_kInitialWindow (other.m_kInitialWindow),
    m_kMinimumWindow (other.m_kMinimumWindow),
    m_kInitialWindowMultiplier (other.m_kInitialWindowMultiplier),
    m_kMinimumWindowMultiplier (other.m_kMinimumWindowMultiplier),
    m_kLossReductionFactor (other.m_kLossReductionFactor),
    m_kPersistentCongestionThreshold (other.m_kPersistentCongestionThreshold),
    m_endOfRecovery (other.m_endOfRecovery),
    m_congestionRecoveryStartTime (other.m_congestionRecoveryStartTime),
    m_firstLostTime (other.m_firstLostTime),
    m_ptoCount (other.m_ptoCount),
    m_priorInFlight (other.m_priorInFlight)
{
  m_lossDetectionAlarm.Cancel ();
}

void
QuicSocketState::SetInitialWindowMultiplier (uint32_t multiplier)
{
  m_kInitialWindowMultiplier = multiplier;
  m_initialCWnd = std::min (m_kInitialWindowMultiplier * m_segmentSize, std::max (m_kMinimumWindowMultiplier * m_segmentSize, 14720U));
  if (m_delivered == 0)
    {
      m_cWnd = m_initialCWnd;
    }
}

void
QuicSocketState::SetMinimumWindowMultiplier (uint32_t multiplier)
{
  m_kMinimumWindowMultiplier = multiplier;
  m_kMinimumWindow = m_kMinimumWindowMultiplier * m_segmentSize;
}

uint32_t
QuicSocketState::GetInitialWindowMultiplier (void) const
{
  return m_kInitialWindowMultiplier;
}

uint32_t
QuicSocketState::GetMinimumWindowMultiplier (void) const
{
  return m_kMinimumWindowMultiplier;
}

void
QuicSocketState::SetInitialRtt (Time initialRtt)
{
  m_kInitialRtt = initialRtt;
  m_smoothedRtt = initialRtt;
  m_rttVar = initialRtt / 2;
}

Time
QuicSocketState::GetInitialRtt (void) const
{
  return m_kInitialRtt;
}

QuicSocketBase::QuicSocketBase (void)
  : QuicSocket (),
    m_endPoint (nullptr),
    m_endPoint6 (nullptr),
    m_node (nullptr),
    m_quicl4 (nullptr),
    m_quicl5 (nullptr),
    // Rx and Tx buffer management
    m_rxBuffer (CreateObject<QuicSocketRxBuffer> ()),
    m_txBuffer (CreateObject<QuicSocketTxBuffer> ()),
    m_socketTxBufferSize (131072), // Default 128KB
    m_socketRxBufferSize (131072), // Default 128KB
    m_schedulingTypeId (QuicSocketTxScheduler::GetTypeId ()),
    m_defaultLatency (MilliSeconds (100)),
    m_bytesRead (0),
    // State-related attributes
    m_handshakeDoneSent (false),
    m_handshakeConfirmed (false),
    m_socketState (IDLE),
    m_transportErrorCode (QuicSubheader::TransportErrorCodes_t::NO_ERROR),
    m_serverBusy (false),
    m_errno (ERROR_NOTERROR),
    m_connected (false),
    m_connectionId (0),
    m_vers (QUIC_VERSION),
    m_keyPhase (QuicHeader::PHASE_ZERO),
    m_isServer (false),
    m_lastReceived (Seconds (0)),
    // Transport Parameters values
    m_initial_max_stream_data (0),
    m_max_data (0),
    m_initial_max_stream_id_bidi (0),
    m_idleTimeout (Seconds (300.0)),
    m_ack_delay_exponent (3),
    m_max_ack_delay (MilliSeconds (25)),
    m_initial_max_stream_id_uni (0),
    m_maxTrackedGaps (20),
    // Transport Parameters management
    m_receivedTransportParameters (false),
    m_couldContainTransportParameters (true),
    // Timers and Events
    m_idleTimeoutEvent (),
    m_drainingPeriodEvent (),
    m_pto (Seconds (30.0)),
    m_drainingPeriodTimeout (Seconds (90.0)),
    m_flushOnClose (false),
    m_closeOnEmpty (false),
    // Congestion Control
    m_tcb (CreateObject<QuicSocketState> ()),
    m_congestionControl (CreateObject<QuicCongestionOps> ()),
    m_lastRtt (Seconds (0.0)),
    m_quicCongestionControlLegacy (false),
    m_lastMaxData (0),
    m_maxDataInterval (10),
    m_initialPacketSize (1200),
    m_pacingTimer (Timer::REMOVE_ON_DESTROY)
{
  NS_LOG_FUNCTION (this);

  m_txBuffer->SetSocket (this);
  m_txBuffer->SetMaxBufferSize (m_socketTxBufferSize);
  m_rxBuffer->SetMaxBufferSize (m_socketRxBufferSize);

  for (int i = 0; i < 3; i++)
    {
      m_pnSpaces[i] = QuicPacketNumberSpace ();
    }

  m_tcb->m_max_ack_delay = m_max_ack_delay;
  m_tcb->m_cWnd = m_tcb->m_initialCWnd;
  m_tcb->m_ssThresh = m_tcb->m_initialSsThresh;
  m_txBuffer->SetQuicSocketState (m_tcb);

  m_tcb->m_pacingRate = m_tcb->m_maxPacingRate;
  m_pacingTimer.SetFunction (&QuicSocketBase::NotifyPacingPerformed, this);

  if (!m_quicCongestionControlLegacy)
    {
      for (int i = 0; i < 3; i++)
        {
          m_pnSpaces[i].m_nextTxSequence = SequenceNumber32 (0);
        }
      m_tcb->m_nextTxSequence = SequenceNumber32 (0);
    }

  ConnectTcbTraces ();
}

QuicSocketBase::QuicSocketBase (const QuicSocketBase& sock)   // Copy constructor
  : QuicSocket (sock),
    m_endPoint (nullptr),
    m_endPoint6 (nullptr),
    m_node (sock.m_node),
    m_quicl4 (sock.m_quicl4),
    m_quicl5 (nullptr),
    // Buffers copied later
    m_socketTxBufferSize (sock.m_socketTxBufferSize),
    m_socketRxBufferSize (sock.m_socketRxBufferSize),
    m_schedulingTypeId (sock.m_schedulingTypeId),
    m_defaultLatency (sock.m_defaultLatency),
    m_bytesRead (0), // New socket starts fresh
    // State
    m_handshakeDoneSent (sock.m_handshakeDoneSent),
    m_handshakeConfirmed (sock.m_handshakeConfirmed),
    m_socketState (LISTENING),
    m_transportErrorCode (sock.m_transportErrorCode),
    m_serverBusy (sock.m_serverBusy),
    m_errno (sock.m_errno),
    m_connected (sock.m_connected),
    m_connectionId (0),
    m_vers (sock.m_vers),
    m_keyPhase (QuicHeader::PHASE_ZERO),
    m_isServer (false),
    m_lastReceived (sock.m_lastReceived),
    // Transport Params
    m_initial_max_stream_data (sock.m_initial_max_stream_data),
    m_max_data (sock.m_max_data),
    m_initial_max_stream_id_bidi (sock.m_initial_max_stream_id_bidi),
    m_idleTimeout (sock.m_idleTimeout),
    m_ack_delay_exponent (sock.m_ack_delay_exponent),
    m_max_ack_delay (sock.m_max_ack_delay),
    m_initial_max_stream_id_uni (sock.m_initial_max_stream_id_uni),
    m_maxTrackedGaps (sock.m_maxTrackedGaps),
    // Transport Params Management
    m_receivedTransportParameters (sock.m_receivedTransportParameters),
    m_couldContainTransportParameters (sock.m_couldContainTransportParameters),
    // Timers
    m_idleTimeoutEvent (),
    m_drainingPeriodEvent (),
    m_pto (sock.m_pto),
    m_drainingPeriodTimeout (sock.m_drainingPeriodTimeout),
    m_flushOnClose (sock.m_flushOnClose),
    m_closeOnEmpty (sock.m_closeOnEmpty),
    // Congestion Control
    m_tcb (CopyObject (sock.m_tcb)),
    m_congestionControl (nullptr),
    m_lastRtt (sock.m_lastRtt),
    m_quicCongestionControlLegacy (sock.m_quicCongestionControlLegacy),
    m_lastMaxData (0),
    m_maxDataInterval (10),
    m_initialPacketSize (sock.m_initialPacketSize),
    m_pacingTimer (Timer::REMOVE_ON_DESTROY)
{
  NS_LOG_FUNCTION (this);

  m_txBuffer = CopyObject (sock.m_txBuffer);
  m_rxBuffer = CopyObject (sock.m_rxBuffer);
  m_tcb->m_cWnd = m_tcb->m_initialCWnd;
  m_tcb->m_ssThresh = m_tcb->m_initialSsThresh;
  
  if (sock.m_congestionControl)
    {
      m_congestionControl = sock.m_congestionControl->Fork ();
    }
  else
    {
      m_congestionControl = CreateObject<QuicCongestionOps> ();
    }
  
  m_txBuffer->SetQuicSocketState (m_tcb);
  m_tcb->m_pacingRate = m_tcb->m_maxPacingRate;
  m_pacingTimer.SetFunction (&QuicSocketBase::NotifyPacingPerformed, this);

  if (!m_quicCongestionControlLegacy)
    {
      for (int i = 0; i < 3; i++)
        {
          m_pnSpaces[i].m_nextTxSequence = SequenceNumber32 (0);
        }
      m_tcb->m_nextTxSequence = SequenceNumber32 (0);
    }

  ConnectTcbTraces ();
  
  m_txTrace = sock.m_txTrace;
  m_rxTrace = sock.m_rxTrace;
}

void
QuicSocketBase::ConnectTcbTraces ()
{
  NS_LOG_FUNCTION (this);
  // connect callbacks
  bool ok;
  ok = m_tcb->TraceConnectWithoutContext ("CongestionWindow",
                                          MakeCallback (&QuicSocketBase::UpdateCwnd, this));
  NS_ASSERT_MSG (ok == true, "Failed connection to CWND trace");

  ok = m_tcb->TraceConnectWithoutContext ("SlowStartThreshold",
                                          MakeCallback (&QuicSocketBase::UpdateSsThresh, this));
  NS_ASSERT_MSG (ok == true, "Failed connection to SSTHR trace");

  ok = m_tcb->TraceConnectWithoutContext ("CongState",
                                          MakeCallback (&QuicSocketBase::UpdateCongState, this));
  NS_ASSERT_MSG (ok == true, "Failed connection to CongState trace");

  ok = m_tcb->TraceConnectWithoutContext ("NextTxSequence",
                                          MakeCallback (&QuicSocketBase::UpdateNextTxSequence, this));
  NS_ASSERT_MSG (ok == true, "Failed connection to TxSequence trace");

  ok = m_tcb->TraceConnectWithoutContext ("HighestSequence",
                                          MakeCallback (&QuicSocketBase::UpdateHighTxMark, this));
  NS_ASSERT_MSG (ok == true, "Failed connection to highest sequence trace");

  ok = m_tcb->TraceConnectWithoutContext ("BytesInFlight",
                                          MakeCallback (&QuicSocketBase::UpdateBytesInFlight, this));
  NS_ASSERT_MSG (ok == true, "Failed connection to bytes in flight trace");
}

QuicSocketBase::~QuicSocketBase (void)
{
  NS_LOG_FUNCTION (this);
  m_node = 0;
  if (m_endPoint)
    {
      NS_ASSERT (m_quicl4);
      m_quicl4->DeAllocate (m_endPoint);
      m_endPoint = 0;
    }
  if (m_endPoint6)
    {
      NS_ASSERT (m_quicl4);
      m_quicl4->DeAllocate (m_endPoint6);
      m_endPoint6 = 0;
    }
  m_quicl4 = 0;
  m_pacingTimer.Cancel ();
}

/* Inherit from Socket class: Bind socket to an end-point in QuicL4Protocol */
int
QuicSocketBase::Bind (void)
{
  //NS_LOG_FUNCTION (this);
  m_endPoint = m_quicl4->Allocate ();
  if (0 == m_endPoint)
    {
      m_errno = ERROR_ADDRNOTAVAIL;
      return -1;
    }
  // Bind ussing allocated address and port
  InetSocketAddress allocatedAddr (m_endPoint->GetLocalAddress (), m_endPoint->GetLocalPort ());
  m_quicl4->UdpBind (allocatedAddr, this);
  return SetupCallback ();
}

int
QuicSocketBase::Bind (const Address &address)
{
  NS_LOG_FUNCTION (this);
  if (InetSocketAddress::IsMatchingType (address))
    {
      InetSocketAddress transport = InetSocketAddress::ConvertFrom (address);
      Ipv4Address ipv4 = transport.GetIpv4 ();
      uint16_t port = transport.GetPort ();
      //SetIpTos (transport.GetTos ());
      if (ipv4 == Ipv4Address::GetAny () && port == 0)
        {
          m_endPoint = m_quicl4->Allocate ();
        }
      else if (ipv4 == Ipv4Address::GetAny () && port != 0)
        {
          m_endPoint = m_quicl4->Allocate (GetBoundNetDevice (), port);
        }
      else if (ipv4 != Ipv4Address::GetAny () && port == 0)
        {
          m_endPoint = m_quicl4->Allocate (ipv4);
        }
      else if (ipv4 != Ipv4Address::GetAny () && port != 0)
        {
          m_endPoint = m_quicl4->Allocate (GetBoundNetDevice (), ipv4, port);
        }
      if (0 == m_endPoint)
        {
          m_errno = port ? ERROR_ADDRINUSE : ERROR_ADDRNOTAVAIL;
          return -1;
        }
    }
  else if (Inet6SocketAddress::IsMatchingType (address))
    {
      Inet6SocketAddress transport = Inet6SocketAddress::ConvertFrom (address);
      Ipv6Address ipv6 = transport.GetIpv6 ();
      uint16_t port = transport.GetPort ();
      if (ipv6 == Ipv6Address::GetAny () && port == 0)
        {
          m_endPoint6 = m_quicl4->Allocate6 ();
        }
      else if (ipv6 == Ipv6Address::GetAny () && port != 0)
        {
          m_endPoint6 = m_quicl4->Allocate6 (GetBoundNetDevice (), port);
        }
      else if (ipv6 != Ipv6Address::GetAny () && port == 0)
        {
          m_endPoint6 = m_quicl4->Allocate6 (ipv6);
        }
      else if (ipv6 != Ipv6Address::GetAny () && port != 0)
        {
          m_endPoint6 = m_quicl4->Allocate6 (GetBoundNetDevice (), ipv6, port);
        }
      if (0 == m_endPoint6)
        {
          m_errno = port ? ERROR_ADDRINUSE : ERROR_ADDRNOTAVAIL;
          return -1;
        }
    }
  else
    {
      m_errno = ERROR_INVAL;
      return -1;
    }
  // Bind ussing allocated address and port
  if (m_endPoint6)
    {
      Inet6SocketAddress allocatedAddr (m_endPoint6->GetLocalAddress (), m_endPoint6->GetLocalPort ());
      m_quicl4->UdpBind (allocatedAddr, this);
    }
  else if (m_endPoint)
    {
      InetSocketAddress allocatedAddr (m_endPoint->GetLocalAddress (), m_endPoint->GetLocalPort ());
      m_quicl4->UdpBind (allocatedAddr, this);
    }
  else
    {
      // Fallback
      m_quicl4->UdpBind (address, this);
    }
  return SetupCallback ();
}

int
QuicSocketBase::Bind6 (void)
{
  NS_LOG_FUNCTION (this);
  m_endPoint6 = m_quicl4->Allocate6 ();
  if (0 == m_endPoint6)
    {
      m_errno = ERROR_ADDRNOTAVAIL;
      return -1;
    }
  // Bind ussing allocated address and port
  Inet6SocketAddress allocatedAddr (m_endPoint6->GetLocalAddress (), m_endPoint6->GetLocalPort ());
  m_quicl4->UdpBind (allocatedAddr, this);
  return SetupCallback ();
}

/* Inherit from Socket class: Bind this socket to the specified NetDevice */
void
QuicSocketBase::BindToNetDevice (Ptr<NetDevice> netdevice)
{
  NS_LOG_FUNCTION (this);

  m_quicl4->BindToNetDevice (this, netdevice);
}

int
QuicSocketBase::Listen (void)
{
  NS_LOG_FUNCTION (this);
  if (m_socketType == NONE)
    {
      m_socketType = SERVER;
    }

  if (m_socketState != IDLE and m_socketState != QuicSocket::CONNECTING_SVR)
    {
      //m_errno = ERROR_INVAL;
      return -1;
    }

  bool res = m_quicl4->SetListener (this);
  NS_ASSERT (res);

  SetState (LISTENING);

  return 0;
}

int
QuicSocketBase::Connect (const Address & address)
{
  NS_LOG_FUNCTION (this);

  if (InetSocketAddress::IsMatchingType (address))
    {
      if (!m_endPoint)
        {
          if (Bind () == -1)
            {
              NS_ASSERT (!m_endPoint);
              return -1; // Bind() failed
            }
          NS_ASSERT (m_endPoint);
        }
      InetSocketAddress transport = InetSocketAddress::ConvertFrom (address);
      m_endPoint->SetPeer (transport.GetIpv4 (), transport.GetPort ());
    }
  else if (Inet6SocketAddress::IsMatchingType (address))
    {
      // If we are operating on a v4-mapped address, translate the address to
      // a v4 address and re-call this function
      Inet6SocketAddress transport = Inet6SocketAddress::ConvertFrom (address);
      Ipv6Address v6Addr = transport.GetIpv6 ();
      if (v6Addr.IsIpv4MappedAddress () == true)
        {
          Ipv4Address v4Addr = v6Addr.GetIpv4MappedAddress ();
          return Connect (InetSocketAddress (v4Addr, transport.GetPort ()));
        }

      if (!m_endPoint6)
        {
          if (Bind6 () == -1)
            {
              NS_ASSERT (!m_endPoint6);
              return -1; // Bind() failed
            }
          NS_ASSERT (m_endPoint6);
        }
      m_endPoint6->SetPeer (v6Addr, transport.GetPort ());
    }
  else
    {
      m_errno = ERROR_INVAL;
      return -1;
    }


  if (m_socketType == NONE)
    {
      m_socketType = CLIENT;
    }

  if (!m_quicl5)
    {
      m_quicl5 = CreateStreamController ();
    }

  if (InetSocketAddress::IsMatchingType (address))
    {
      // check if the address is in a list of known and authenticated addresses
      auto result = std::find (
        m_quicl4->GetAuthAddresses ().begin (), m_quicl4->GetAuthAddresses ().end (),
        InetSocketAddress::ConvertFrom (address).GetIpv4 ());

      if (result != m_quicl4->GetAuthAddresses ().end ()
          || m_quicl4->Is0RTTHandshakeAllowed ())
        {
          NS_LOG_INFO (
            "CONNECTION AUTHENTICATED Client found the Server " << InetSocketAddress::ConvertFrom (address).GetIpv4 () << " port " << InetSocketAddress::ConvertFrom (address).GetPort () << " in authenticated list");
          // connect the underlying UDP socket
          m_quicl4->UdpConnect (address, this);
          return DoFastConnect ();
        }
    }
  
  // For IPv6 or unauthenticated IPv4, proceed with normal handshake
  NS_LOG_INFO (
    "CONNECTION not authenticated: cannot perform 0-RTT Handshake");
  // connect the underlying UDP socket
  m_quicl4->UdpConnect (address, this);
  return DoConnect ();


}

/* Inherit from Socket class: Invoked by upper-layer application */
int
QuicSocketBase::Send (Ptr<Packet> p, uint32_t flags)
{
  NS_LOG_FUNCTION (this << flags);
  int data = 0;

  if (m_drainingPeriodEvent.IsRunning ())
    {
      NS_LOG_INFO ("Socket in draining state, cannot send packets");
      return 0;
    }

  if (flags == 0)
    {
      data = Send (p);
    }
  else
    {
      data = m_quicl5->DispatchSend (p, flags);
    }
  return data;
}

int
QuicSocketBase::Send (Ptr<Packet> p)
{
  NS_LOG_FUNCTION (this);

  if (m_drainingPeriodEvent.IsRunning ())
    {
      NS_LOG_INFO ("Socket in draining state, cannot send packets");
      return 0;
    }

  int data = m_quicl5->DispatchSend (p);

  return data;
}

int
QuicSocketBase::AppendingTx (Ptr<Packet> frame, PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << space);

  if (m_socketState != IDLE)
    {
      bool done = m_txBuffer->Add (frame, space);
      if (!done)
        {
          NS_LOG_INFO ("Exceeding Socket Tx Buffer Size");
          m_errno = ERROR_MSGSIZE;
          return -1;
        }
      else
        {
          uint32_t win = AvailableWindow ();
          NS_LOG_DEBUG (
            "Added packet to the buffer - txBufSize = " << m_txBuffer->AppSize ()
                                                        << " Window = " << win);

          // Artificially delay the "flush" so that L5 has finished putting app bytes in to the buffer
          Simulator::Schedule (MicroSeconds (1), &QuicSocketBase::SendPendingData, this, m_connected);
          return frame->GetSize ();
        }
    }
  else
    {
      NS_ABORT_MSG ("Sending in state" << QuicStateName[m_socketState]);
      return -1;
    }
}

uint32_t
QuicSocketBase::SendPendingData (bool withAck)
{
  NS_LOG_FUNCTION (this << withAck);

  if (m_txBuffer->AppSize () == 0)
    {
      if (m_closeOnEmpty)
        {
          m_drainingPeriodEvent.Cancel ();
          SendConnectionClosePacket (0, "Scheduled connection close - no error");
        }
      NS_LOG_INFO ("Nothing to send");
      return 0;
    }

  uint32_t nPacketsSent = 0;

  // 1. prioritize INITIAL_DATA (handshake data)
  while (m_txBuffer->GetNumCryptoFramesInBuffer (INITIAL_DATA) > 0)
    {
      if (m_drainingPeriodEvent.IsRunning ()) return 0;
      if (m_tcb->m_pacing && m_pacingTimer.IsRunning ()) break;

      uint32_t sent = SendDataPacket (INITIAL_DATA, GetSegSize (), withAck);
      if (sent > 0) nPacketsSent++;
      else break;
    }

  // 2. prioritize HANDSHAKE_DATA (handshake data)
  while (m_txBuffer->GetNumCryptoFramesInBuffer (HANDSHAKE_DATA) > 0)
    {
      if (m_drainingPeriodEvent.IsRunning ()) return 0;
      if (m_tcb->m_pacing && m_pacingTimer.IsRunning ()) break;

      uint32_t sent = SendDataPacket (HANDSHAKE_DATA, GetSegSize (), withAck);
      if (sent > 0) nPacketsSent++;
      else break;
    }

  // 3. finally APPLICATION_DATA
  while (m_txBuffer->AppSize () > 0)
    {
      // check draining period
      if (m_drainingPeriodEvent.IsRunning ())
        {
          NS_LOG_INFO ("Draining period: no packets can be sent");
          return nPacketsSent;
        }

      // check pacing timer
      if (m_tcb->m_pacing)
        {
          if (m_pacingTimer.IsRunning ())
            {
              NS_LOG_INFO ("Skipping Packet due to pacing - for " << m_pacingTimer.GetDelayLeft ());
              break;
            }
        }

      // check congestion window
      uint32_t win = AvailableWindow ();
      if (win == 0) 
        {
          NS_LOG_INFO ("Skipping Packet due to zero window");
          break;
        }

      // Cap the packet size at the window OR the segment size
      uint32_t sendSize = std::min (win, GetSegSize ());
      // Pass sendSize to SendDataPacket instead of GetSegSize()
      uint32_t sent = SendDataPacket (APPLICATION_DATA, sendSize, withAck);
      if (sent > 0)
        {
          nPacketsSent++;
        }
      else
        {
          break;
        }
    }

  return nPacketsSent;
}

void
QuicSocketBase::SetSegSize (uint32_t size)
{
  NS_LOG_FUNCTION (this << size);
  NS_ABORT_MSG_UNLESS (m_socketState == IDLE || m_tcb->m_segmentSize == size,
                       "Cannot change segment size dynamically.");

  m_tcb->m_segmentSize = size;
  // Update minimum congestion window
  m_tcb->m_initialCWnd = std::min (m_tcb->m_kInitialWindowMultiplier * size, std::max (m_tcb->m_kMinimumWindowMultiplier * size, 14720U));
  m_tcb->m_kMinimumWindow = m_tcb->m_kMinimumWindowMultiplier * size;
  if (m_socketState == IDLE)
    {
      m_tcb->m_cWnd = m_tcb->m_initialCWnd;
    }
}

uint32_t
QuicSocketBase::GetSegSize (void) const
{
  return m_tcb->m_segmentSize;
}

void
QuicSocketBase::MaybeQueueAck (PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << space);
  QuicPacketNumberSpace &pnSpace = m_pnSpaces[space];
  
  ++pnSpace.m_numPacketsReceivedSinceLastAckSent;
  NS_LOG_INFO ("space " << space << " numPacketsReceived " << pnSpace.m_numPacketsReceivedSinceLastAckSent << " queueAck " << pnSpace.m_queue_ack);

  if (pnSpace.m_receivedPacketNumbers.empty ())
    {
      NS_LOG_INFO ("Nothing to ACK in space " << space);
      pnSpace.m_queue_ack = false;
      return;
    }

  if (pnSpace.m_numPacketsReceivedSinceLastAckSent > m_tcb->m_kMaxPacketsReceivedBeforeAckSend)
    {
    NS_LOG_INFO ("immediately schedule ACK - threshold reached");
    pnSpace.m_queue_ack = true;
    if (!pnSpace.m_sendAckEvent.IsRunning ())
    {
        // Use ScheduleNow to break the function call stack
        pnSpace.m_sendAckEvent = Simulator::ScheduleNow(static_cast<void (QuicSocketBase::*)(PacketNumberSpace)>(&QuicSocketBase::SendAck), this, space);
    }
}

  if (HasReceivedMissing ())  // immediately queue the ACK
    {
      NS_LOG_INFO ("immediately send ACK - some packets have been received out of order");
      pnSpace.m_queue_ack = true;
      if (!pnSpace.m_sendAckEvent.IsRunning ())
        {
          pnSpace.m_sendAckEvent = Simulator::Schedule (TimeStep (1), static_cast<void (QuicSocketBase::*)(PacketNumberSpace)>(&QuicSocketBase::SendAck), this, space);
        }
    }

  if (!pnSpace.m_queue_ack)
    {
      if (pnSpace.m_numPacketsReceivedSinceLastAckSent >= m_tcb->m_kMaxPacketsReceivedBeforeAckSend)
        {
          NS_LOG_INFO ("immediately send ACK - more than 2 packets received");
          pnSpace.m_queue_ack = true;
          if (!pnSpace.m_sendAckEvent.IsRunning ())
            {
              pnSpace.m_sendAckEvent = Simulator::Schedule (TimeStep (1), static_cast<void (QuicSocketBase::*)(PacketNumberSpace)>(&QuicSocketBase::SendAck), this, space);
            }
        }
      else
        {
          if (!pnSpace.m_delAckEvent.IsRunning ())
            {
              NS_LOG_INFO ("Schedule a delayed ACK for space " << space);
              pnSpace.m_delAckEvent = Simulator::Schedule (
                m_tcb->m_max_ack_delay, static_cast<void (QuicSocketBase::*)(PacketNumberSpace)>(&QuicSocketBase::SendAck), this, space);
            }
        }
    }
}

bool
QuicSocketBase::HasReceivedMissing ()
{
  if (!m_quicl5)
    {
      return false;
    }

  for (auto const& stream : m_quicl5->GetStreams ())
    {
      if (stream->GetRxBuffer()->Size () > 0 &&
          stream->GetRxBuffer()->GetDeliverable (stream->GetRecvSize()).second == 0)
        {
          // There is data in the buffer, but none of it is contiguous with the
          // currently expected receive offset (m_recvSize) for this stream.
          // This indicates a missing segment in the stream.
          NS_LOG_DEBUG ("Found missing data in stream " << stream->GetStreamId()
                                     << ": expected offset " << stream->GetRecvSize()
                                     << ", but next deliverable is 0, with "
                                     << stream->GetRxBuffer()->Size() << " bytes buffered.");
          return true;
        }
    }
  return false;
}

void
QuicSocketBase::SendAck (PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << space);
  QuicPacketNumberSpace &pnSpace = m_pnSpaces[space];
  
  pnSpace.m_delAckEvent.Cancel ();
  pnSpace.m_sendAckEvent.Cancel ();
  pnSpace.m_queue_ack = false;
  pnSpace.m_numPacketsReceivedSinceLastAckSent = 0;

  if (pnSpace.m_receivedPacketNumbers.empty ())
    {
      return;
    }

  Ptr<Packet> p = Create<Packet> ();
  p->AddAtEnd (OnSendingAckFrame (space));
  
  SequenceNumber32 packetNumber = pnSpace.m_nextTxSequence++;

  QuicHeader head;
  if (space == INITIAL_DATA)
    {
      head = QuicHeader::CreateInitial (m_connectionId, m_vers, packetNumber);
      // Pad Initial ACKs? Usually not required unless it's the very first packet, 
      // but let's be safe if it's Client speaking.
      if (m_socketState == CONNECTING_CLT && p->GetSize () + head.GetSerializedSize () < MIN_INITIAL_PACKET_SIZE)
        {
          uint32_t padding = MIN_INITIAL_PACKET_SIZE - (p->GetSize () + head.GetSerializedSize ());
          p->AddAtEnd (Create<Packet> (padding));
        }
    }
  else if (space == HANDSHAKE_DATA)
    {
      head = QuicHeader::CreateHandshake (m_connectionId, m_vers, packetNumber);
    }
  else
    {
      head = QuicHeader::CreateShort (m_connectionId, packetNumber,
                                      true, m_keyPhase);
    }

  uint32_t finalSize = p->GetSize () + head.GetSerializedSize ();
  m_txBuffer->UpdateAckSent (packetNumber, finalSize, space);

  NS_LOG_INFO ("Send ACK packet in space " << space << " with header " << head);
  m_quicl4->SendPacket (this, p, head);
  m_txTrace (p, head, this);
}

uint32_t
QuicSocketBase::SendDataPacket (PacketNumberSpace space, uint32_t maxSize, bool withAck)
{
  SequenceNumber32 packetNumber = m_pnSpaces[space].m_nextTxSequence++;
  NS_LOG_FUNCTION (this << space << packetNumber << maxSize << withAck);

  if (!m_drainingPeriodEvent.IsRunning ())
    {
      m_idleTimeoutEvent.Cancel ();
      NS_LOG_LOGIC (
        this << " IdleTimeout canceled at " << Simulator::Now ().GetSeconds () << " New Close event to expire at time " << (Simulator::Now () + m_idleTimeout.Get ()).GetSeconds ());
      m_idleTimeoutEvent = Simulator::Schedule (m_idleTimeout,
                                                &QuicSocketBase::Close, this);
    }
  else
    {
      NS_LOG_INFO ("Draining period event running");
      return -1;
    }

  Ptr<Packet> p;

  if (m_txBuffer->GetNumCryptoFramesInBuffer (space) > 0)
    {
      // Try to get crypto for this space first
      p = m_txBuffer->NextCryptoSequence (packetNumber, space);
      if (!p && space == APPLICATION_DATA) 
        {
          // If app data space requested but more crypto is available (probably in handshake),
          // we should probably not reach here if SendPendingData is correct, 
          // but let's be safe.
          p = m_txBuffer->NextSequence (maxSize, packetNumber, space);
        }
      else if (!p)
        {
          // No crypto for this specific space?
          return 0; 
        }
    }
  else
    {
      NS_LOG_LOGIC (
        this << " SendDataPacket - sending packet " << packetNumber.GetValue () << " of size " << maxSize << " at time " << Simulator::Now ().GetSeconds ());
      m_idleTimeoutEvent = Simulator::Schedule (m_idleTimeout,
                                                &QuicSocketBase::Close, this);
      p = m_txBuffer->NextSequence (maxSize, packetNumber, space);
    }

  uint32_t sz = p->GetSize ();
  // If payload is 0 and it's not an ACK-only packet, DO NOT SEND.
  // This prevents the "size 0" deadlock.
  if (sz == 0 && !withAck && space == APPLICATION_DATA)
    {
      NS_LOG_INFO ("Skipping empty packet (payload 0, no ACK)");
      return 0;
    }

  // check whether the connection is appLimited, i.e. not enough data to fill a packet
  if (sz < maxSize and m_txBuffer->AppSize () == 0 and m_tcb->m_bytesInFlight.Get () < m_tcb->m_cWnd)
    {
      NS_LOG_LOGIC ("Connection is Application-Limited. sz = " << sz << " < maxSize = " << maxSize);
      m_tcb->m_appLimitedUntil = m_tcb->m_delivered + m_tcb->m_bytesInFlight.Get () ? : 1U;
    }

  // perform pacing
  if (m_tcb->m_pacing)
    {
      NS_LOG_DEBUG ("Pacing is enabled");
      if (m_pacingTimer.IsExpired ())
        {
          NS_LOG_DEBUG ("Current Pacing Rate " << m_tcb->m_pacingRate);
          Time pacingDelay = Seconds (0);
          if (m_tcb->m_pacingRate.Get ().GetBitRate () > 0)
            {
              pacingDelay = m_tcb->m_pacingRate.Get ().CalculateBytesTxTime (sz);
              NS_LOG_DEBUG ("Pacing Timer is in expired state, activate it. Expires in " << pacingDelay);
              m_pacingTimer.Schedule (pacingDelay);
            }
          else
            {
               NS_LOG_WARN ("Pacing rate is 0, skipping timer schedule");
            }
        }
      else
        {
          NS_LOG_INFO ("Pacing Timer is already in running state");
        }
    }

  bool isAckOnly = ((sz == 0) && (withAck));

  if (withAck && !m_pnSpaces[space].m_receivedPacketNumbers.empty ())
    {
      p = p->Copy ();
      p->AddAtEnd (OnSendingAckFrame (space));
    }


  QuicHeader head;
  if (space == INITIAL_DATA)
    {
      head = QuicHeader::CreateInitial (m_connectionId, m_vers, packetNumber);
      // RFC 9000: Initial packets MUST be padded to 1200 bytes if they are the first ones
      // Simplification: always pad initial packets if they are small
      if (p->GetSize () + head.GetSerializedSize () < MIN_INITIAL_PACKET_SIZE)
        {
          uint32_t padding = MIN_INITIAL_PACKET_SIZE - (p->GetSize () + head.GetSerializedSize ());
          p->AddAtEnd (Create<Packet> (padding));
        }
    }
  else if (space == HANDSHAKE_DATA)
    {
      head = QuicHeader::CreateHandshake (m_connectionId, m_vers, packetNumber);
    }
  else // APPLICATION_DATA
    {
      if (m_socketState == OPEN && !m_connected && m_quicl4->Is0RTTHandshakeAllowed ())
        {
          head = QuicHeader::Create0RTT (m_connectionId, m_vers, packetNumber);
          // 0-RTT usually switches key phase? No, but let's keep old logic if valid
        }
      else
        {
          head = QuicHeader::CreateShort (m_connectionId, packetNumber,
                                          true, m_keyPhase);
        }
    }

  // Add padding to the packet to match segment size if app-limited
  uint32_t finalSize = p->GetSize () + head.GetSerializedSize ();
  // if (!isAckOnly && finalSize < GetSegSize () && m_txBuffer->AppSize () == 0)
  //   {
  //     uint32_t paddingSize = GetSegSize () - finalSize;
  //     p->AddAtEnd (Create<Packet> (paddingSize));
  //     finalSize += paddingSize;
  //     NS_LOG_DEBUG ("Padded packet " << packetNumber << " by " << paddingSize << " bytes. Final size: " << finalSize);
  //   }

  NS_LOG_INFO ("SendDataPacket of space " << space << " and size " << p->GetSize ());
  m_quicl4->SendPacket (this, p, head);
  m_txTrace (p, head, this);
  NotifyDataSent (sz);

  if (isAckOnly)
    {
      m_txBuffer->UpdateAckSent (packetNumber, finalSize, space);
    }
  else
    {
      m_txBuffer->UpdatePacketSent (packetNumber, finalSize, space);
    }

  BytesInFlight ();
  // Update TCB trace for compatibility (though it might be confusing with 3 spaces)
  m_nextTxSequenceTrace (0, packetNumber.GetValue ());

  if (!m_quicCongestionControlLegacy)
    {
      Ptr<QuicCongestionOps> qcc = DynamicCast<QuicCongestionOps> (m_congestionControl);
      if (qcc)
        {
          qcc->OnPacketSent (m_tcb, packetNumber, isAckOnly);
        }
    }
  if (!isAckOnly)
    {
      m_pnSpaces[space].m_ackElicitingOutstanding = true;
      // Update the time of last sent packet.
      m_pnSpaces[space].m_timeOfLastSentAckElicitingPacket = Simulator::Now ();
      SetReTxTimeout ();
    }

  return sz;
}

void
QuicSocketBase::SetReTxTimeout ()
{
  NS_LOG_FUNCTION (this);

  Ptr<QuicSocketState> tcbd = m_tcb;
  Time now = Simulator::Now ();

  // 1. Loss Timer: Check for packets that have exceeded the reordering window
  Time lossTime = Time::Max ();
  bool anyLossTimerActive = false;

  for (int i = 0; i < 3; i++)
    {
      if (m_pnSpaces[i].m_lossTime != Seconds (0))
        {
          lossTime = std::min (lossTime, m_pnSpaces[i].m_lossTime);
          anyLossTimerActive = true;
        }
    }

  if (anyLossTimerActive)
    {
      m_tcb->m_lossDetectionAlarm.Cancel ();
      m_tcb->m_nextAlarmTrigger = lossTime;
      m_tcb->m_alarmType = 0; // LOSS_TIMER

      // Ensure we don't schedule in the past; if lossTime <= now, trigger in next timestep
      Time delay = (lossTime > now) ? (lossTime - now) : TimeStep (1);
      m_tcb->m_lossDetectionAlarm = Simulator::Schedule (delay, &QuicSocketBase::ReTxTimeout, this);
      return;
    }

  // 2. PTO Timer: Calculate based on Smoothed RTT and RTT Variance
  Time earliestPTO = Time::Max ();
  bool anyOutstanding = false;

  for (int i = 0; i < 3; i++)
    {
      // Only schedule PTO if there is data that can be lost in this space
      if (!m_pnSpaces[i].m_ackElicitingOutstanding) continue;

      // RFC 9002: PTO = SRTT + max(4*RTTVAR, Granularity) + MaxAckDelay
      Time timeout = tcbd->m_smoothedRtt + std::max (4 * tcbd->m_rttVar, tcbd->m_kGranularity);
      
      // Handshake spaces do not include peer's max_ack_delay
      if (i == APPLICATION_DATA)
        {
          timeout += tcbd->m_peerMaxAckDelay;
        }
      
      // Exponential backoff for repeated timeouts
      timeout = timeout * (1 << tcbd->m_ptoCount);
      
      Time ptoTime = m_pnSpaces[i].m_timeOfLastSentAckElicitingPacket + timeout;
      if (ptoTime < earliestPTO)
        {
          earliestPTO = ptoTime;
          anyOutstanding = true;
        }
    }

  if (!anyOutstanding)
    {
      m_tcb->m_lossDetectionAlarm.Cancel ();
      return;
    }

  m_tcb->m_lossDetectionAlarm.Cancel ();
  m_tcb->m_nextAlarmTrigger = earliestPTO;
  m_tcb->m_alarmType = 1; // PTO_TIMER

  // If the calculated ptoTime is already behind us, we trigger it nearly immediately 
  // but let ReTxTimeout handle the state advancement.
  Time ptoDelay = (earliestPTO > now) ? (earliestPTO - now) : TimeStep (1);

  m_tcb->m_lossDetectionAlarm = Simulator::Schedule (ptoDelay, &QuicSocketBase::ReTxTimeout, this);
}

void
QuicSocketBase::DoRetransmit (std::vector<Ptr<QuicSocketTxItem> > lostPackets)
{
  NS_LOG_FUNCTION (this);
  
  if (lostPackets.empty()) { return; }
  
  // Group lost packets by space
  std::map<PacketNumberSpace, bool> spacesWithLoss;
  for (auto &item : lostPackets)
    {
      spacesWithLoss[item->m_space] = true;
    }
  
  // Retransmit once per space
  // The packet numbers will be assigned inside Retransmission()
  for (auto &pair : spacesWithLoss)
    {
      PacketNumberSpace space = pair.first;
      m_txBuffer->Retransmission (SequenceNumber32(0), space);
    }
  SendPendingData (m_connected);
}

void
QuicSocketBase::ReTxTimeout ()
{
  if (Simulator::Now () < m_tcb->m_nextAlarmTrigger)
    {
      NS_LOG_INFO ("Canceled alarm");
      return;
    }
  NS_LOG_FUNCTION (this);
  NS_LOG_INFO ("ReTxTimeout Expired at time " << Simulator::Now ().GetSeconds () << " alarm type " << (int)m_tcb->m_alarmType);

  if (m_tcb->m_alarmType == 0) // LOSS_TIMER
    {
      std::vector<Ptr<QuicSocketTxItem> > allLost;
      for (int i = 0; i < 3; i++)
        {
          std::vector<Ptr<QuicSocketTxItem> > lost = m_txBuffer->DetectLostPackets (m_tcb, static_cast<PacketNumberSpace>(i));
          allLost.insert (allLost.end (), lost.begin (), lost.end ());
          m_pnSpaces[i].m_lossTime = Seconds (0);
        }
      NS_LOG_INFO ("Loss detection triggered. Newly lost packets: " << allLost.size ());
      if (!allLost.empty ())
        {
          DoRetransmit (allLost);
        }
    }
  else // PTO_TIMER
    {
      NS_LOG_INFO ("PTO triggered");
      m_tcb->m_ptoCount++;
      
      // Determine which space to send in. 
      PacketNumberSpace ptoSpace = APPLICATION_DATA;
      if (m_txBuffer->GetHandshakeInFlight () > 0)
        {
           if (m_txBuffer->BytesInFlight (INITIAL_DATA) > 0) ptoSpace = INITIAL_DATA;
           else ptoSpace = HANDSHAKE_DATA;
        }

      // Send a PING frame to ensure ack-eliciting
      Ptr<Packet> ping = Create<Packet> ();
      QuicSubheader sub;
      sub.SetPing ();
      ping->AddHeader (sub);
      m_txBuffer->Add (ping, ptoSpace);
      
      // Force transmission of at least one packet bypassing window checks in SendPendingData
      SendDataPacket (ptoSpace, GetSegSize (), m_connected);
      
      // Also try to send one more if possible (up to 2 packets)
      SendPendingData (m_connected);
    }
  SetReTxTimeout ();
}

uint32_t
QuicSocketBase::AvailableWindow () const
{
  // 1. Congestion Window (Wire Bytes)
  uint32_t cwnd = m_tcb->m_cWnd.Get ();
  uint32_t wireBytesInFlight = m_txBuffer->GetCongestionControlledBytesInFlight ();
  uint32_t congestionAvail = (wireBytesInFlight >= cwnd) ? 0 : cwnd - wireBytesInFlight;

  // 2. Flow Control Window (Payload Bytes Only)
  // m_delivered now tracks only STREAM payload bytes (after UpdateRateSample fix)
  uint32_t unackedPayload = m_txBuffer->GetPayloadBytesInFlight ();
  uint64_t totalPayloadSent = m_tcb->m_delivered + unackedPayload;
  
  uint32_t flowControlAvail = 0;
  if (m_max_data > totalPayloadSent)
    {
      flowControlAvail = m_max_data - totalPayloadSent;
    }

  NS_LOG_DEBUG ("Congestion avail: " << congestionAvail 
               << " bytes, Flow control avail: " << flowControlAvail << " bytes"
               << " (delivered: " << m_tcb->m_delivered 
               << ", unacked payload: " << unackedPayload << ")");

  // 3. Return the more restrictive limit
  return std::min (congestionAvail, flowControlAvail);
}

uint32_t
QuicSocketBase::BytesInFlight () const
{
  NS_LOG_FUNCTION (this);

  uint32_t bytesInFlight = m_txBuffer->BytesInFlight ();

  NS_LOG_INFO ("Returning calculated bytesInFlight: " << bytesInFlight);
  m_tcb->m_bytesInFlight = bytesInFlight;
  return bytesInFlight;
}

/* Inherit from Socket class: In QuicSocketBase, it is same as Send() call */
int
QuicSocketBase::SendTo (Ptr<Packet> p, uint32_t flags, const Address &address)
{
  NS_LOG_FUNCTION (this);

  return Send (p, flags);
}

/* Inherit from Socket class: Return data to upper-layer application. Parameter flags
 is not used. Data is returned as a packet of size no larger than maxSize */
Ptr<Packet>
QuicSocketBase::Recv (uint32_t maxSize, uint32_t flags)
{
  NS_LOG_FUNCTION (this);
  NS_ABORT_MSG_IF (flags,
                   "use of flags is not supported in QuicSocketBase::Recv()");

  if (m_rxBuffer->Size () == 0 && m_socketState == CLOSING)
    {
      return Create<Packet> ();
    }
  Ptr<Packet> outPacket = m_rxBuffer->Extract (maxSize);
  if (outPacket)
    {
      m_bytesRead += outPacket->GetSize ();
    }
  return outPacket;
}

/* Inherit from Socket class: Recv and return the remote's address */
Ptr<Packet>
QuicSocketBase::RecvFrom (uint32_t maxSize, uint32_t flags,
                          Address &fromAddress)
{
  NS_LOG_FUNCTION (this);

  Ptr<Packet> packet = m_rxBuffer->Extract (maxSize);

  if (packet && packet->GetSize () != 0)
    {
      m_bytesRead += packet->GetSize ();
      if (m_endPoint)
        {
          fromAddress = InetSocketAddress (m_endPoint->GetPeerAddress (), m_endPoint->GetPeerPort ());
        }
      else if (m_endPoint6)
        {
          fromAddress = Inet6SocketAddress (m_endPoint6->GetPeerAddress (), m_endPoint6->GetPeerPort ());
        }
      else
        {
          fromAddress = InetSocketAddress (Ipv4Address::GetZero (), 0);
        }
    }

  return packet;
}

void
QuicSocketBase::ScheduleCloseAndSendConnectionClosePacket ()
{
  m_drainingPeriodEvent.Cancel ();
  NS_LOG_LOGIC (this << " Close Schedule DoClose at time " << Simulator::Now ().GetSeconds () << " to expire at time " << (Simulator::Now () + m_drainingPeriodTimeout.Get ()).GetSeconds ());
  m_drainingPeriodEvent = Simulator::Schedule (m_drainingPeriodTimeout, &QuicSocketBase::DoClose, this);
  SendConnectionClosePacket (0, "Scheduled connection close - no error");
}


int
QuicSocketBase::Close (void)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_INFO (this << " Close at time " << Simulator::Now ().GetSeconds ());

  m_receivedTransportParameters = false;

  if (m_idleTimeoutEvent.IsRunning () and m_socketState != IDLE
      and m_socketState != CLOSING)   //Connection Close from application signal
    {
      SetState (CLOSING);
      if (m_flushOnClose)
        {
          m_closeOnEmpty = true;
        }
      else
        {
          ScheduleCloseAndSendConnectionClosePacket ();
        }
    }
  else if (m_idleTimeoutEvent.IsExpired () and m_socketState != CLOSING
           and m_socketState != IDLE and m_socketState != LISTENING) //Connection Close due to Idle Period termination
    {
      SetState (CLOSING);
      m_drainingPeriodEvent.Cancel ();
      NS_LOG_LOGIC (
        this << " Close Schedule DoClose at time " << Simulator::Now ().GetSeconds () << " to expire at time " << (Simulator::Now () + m_drainingPeriodTimeout.Get ()).GetSeconds ());
      m_drainingPeriodEvent = Simulator::Schedule (m_drainingPeriodTimeout,
                                                   &QuicSocketBase::DoClose,
                                                   this);
    }
  else if (m_idleTimeoutEvent.IsExpired ()
           and m_drainingPeriodEvent.IsExpired () and m_socketState != CLOSING
           and m_socketState != IDLE) //close last listening sockets
    {
      NS_LOG_LOGIC (this << " Closing listening socket");
      DoClose ();
    }
  else if (m_idleTimeoutEvent.IsExpired ()
           and m_drainingPeriodEvent.IsExpired () and m_socketState == IDLE)
    {
      NS_LOG_LOGIC (this << " Has already been closed");
    }

  return 0;
}

/* Send a CONNECTION_CLOSE frame */
uint32_t
QuicSocketBase::SendConnectionClosePacket (uint16_t errorCode, std::string phrase)
{
  NS_LOG_FUNCTION (this);

  Ptr<Packet> p = Create<Packet> ();

  QuicSubheader qsb = QuicSubheader::CreateConnectionClose (errorCode, phrase.c_str ());
  p->AddHeader (qsb);

  PacketNumberSpace space = APPLICATION_DATA;
  if (!m_handshakeConfirmed && m_txBuffer->GetHandshakeInFlight () > 0) space = HANDSHAKE_DATA;
  else if (!m_connected) space = INITIAL_DATA; 

  SequenceNumber32 packetNumber = m_pnSpaces[space].m_nextTxSequence++;

  QuicHeader head;
  if (space == INITIAL_DATA) head = QuicHeader::CreateInitial (m_connectionId, m_vers, packetNumber);
  else if (space == HANDSHAKE_DATA) head = QuicHeader::CreateHandshake (m_connectionId, m_vers, packetNumber);
  else head = QuicHeader::CreateShort (m_connectionId, packetNumber,
                                  true, m_keyPhase);


  NS_LOG_DEBUG ("Send Connection Close packet with header " << head);
  m_quicl4->SendPacket (this, p, head);
  m_txTrace (p, head, this);

  return 0;
}

/* Inherit from Socket class: Signal a termination of send */
int
QuicSocketBase::ShutdownSend (void)
{
  NS_LOG_FUNCTION (this);



  return 0;
}

/* Inherit from Socket class: Signal a termination of receive */
int
QuicSocketBase::ShutdownRecv (void)
{
  NS_LOG_FUNCTION (this);

  return 0;
}

void
QuicSocketBase::SetNode (Ptr<Node> node)
{
//NS_LOG_FUNCTION (this);

  m_node = node;
}

Ptr<Node>
QuicSocketBase::GetNode (void) const
{
//NS_LOG_FUNCTION_NOARGS ();

  return m_node;
}

/* Inherit from Socket class: Return local address:port */
int
QuicSocketBase::GetSockName (Address &address) const
{
  NS_LOG_FUNCTION (this);

  return m_quicl4->GetSockName (this, address);
}

int
QuicSocketBase::GetPeerName (Address &address) const
{
  NS_LOG_FUNCTION (this);

  return m_quicl4->GetPeerName (this, address);
}

/* Inherit from Socket class: Get the max number of bytes an app can send */
uint32_t
QuicSocketBase::GetTxAvailable (void) const
{
  NS_LOG_FUNCTION (this);

  return m_txBuffer->Available ();
}

/* Inherit from Socket class: Get the max number of bytes an app can read */
uint32_t
QuicSocketBase::GetRxAvailable (void) const
{
  NS_LOG_FUNCTION (this);

  return m_rxBuffer->Available ();
}

/* Inherit from Socket class: Returns error code */
enum Socket::SocketErrno
QuicSocketBase::GetErrno (void) const
{
  return m_errno;
}

/* Inherit from Socket class: Returns socket type, NS3_SOCK_STREAM */
enum Socket::SocketType
QuicSocketBase::GetSocketType (void) const
{
  return NS3_SOCK_STREAM;
}

//////////////////////////////////////////////////////////////////////////////////////

/* Clean up after Bind. Set up callback functions in the end-point. */
int
QuicSocketBase::SetupCallback (void)
{
  NS_LOG_FUNCTION (this);

  if (!m_quicl4)
    {
      return -1;
    }
  else
    {
      m_quicl4->SetRecvCallback (
        MakeCallback (&QuicSocketBase::ReceivedData, this), this);
    }

  return 0;
}

int
QuicSocketBase::AppendingRx (Ptr<Packet> frame, Address &address)
{

  NS_LOG_FUNCTION (this);

  if (!m_rxBuffer->Add (frame))
    {
      // Insert failed: No data or RX buffer full
      NS_LOG_INFO ("Dropping packet due to full RX buffer");
      return 0;
    }
  else
    {
      NS_LOG_INFO ("Notify Data Recv");
      NotifyDataRecv ();
    }

  return frame->GetSize ();
}

void
QuicSocketBase::SetQuicL4 (Ptr<QuicL4Protocol> quic)
{
  NS_LOG_FUNCTION (this);

  m_quicl4 = quic;
}

void
QuicSocketBase::SetConnectionId (uint64_t connectionId)
{
  NS_LOG_FUNCTION_NOARGS ();

  m_connectionId = connectionId;
}

void
QuicSocketBase::InitializeScheduling ()
{
  ObjectFactory schedulerFactory;
  schedulerFactory.SetTypeId (m_schedulingTypeId);
  Ptr<QuicSocketTxScheduler> sched = schedulerFactory.Create<QuicSocketTxScheduler> ();
  m_txBuffer->SetScheduler (sched);
  SetDefaultLatency (m_defaultLatency);
}

uint64_t
QuicSocketBase::GetConnectionId (void) const
{
  NS_LOG_FUNCTION_NOARGS ();

  return m_connectionId;
}

void
QuicSocketBase::SetVersion (uint32_t version)
{
  NS_LOG_FUNCTION (this);

  m_vers = version;
  return;
}

//////////////////////////////////////////////////////////////////////////////////////

bool
QuicSocketBase::SetAllowBroadcast (bool allowBroadcast)
{
  NS_LOG_FUNCTION (this);

  return (!allowBroadcast);
}

bool
QuicSocketBase::GetAllowBroadcast (void) const
{
  return false;
}

Ptr<QuicL5Protocol>
QuicSocketBase::CreateStreamController ()
{
  NS_LOG_FUNCTION (this);

  Ptr<QuicL5Protocol> quicl5 = CreateObject<QuicL5Protocol> ();

  quicl5->SetSocket (this);
  quicl5->SetNode (m_node);
  quicl5->SetConnectionId (m_connectionId);

  return quicl5;
}

void
QuicSocketBase::SendInitialHandshake (uint8_t type,
                                      const QuicHeader &quicHeader,
                                      Ptr<Packet> packet)
 {
  NS_LOG_FUNCTION (this << m_vers);

  if (type == QuicHeader::VERSION_NEGOTIATION)
    {
      NS_LOG_INFO ("Create VERSION_NEGOTIATION");
      m_receivedTransportParameters = false;
      m_couldContainTransportParameters = true;

      std::vector<uint32_t> supportedVersions;
      supportedVersions.push_back (QUIC_VERSION);
      supportedVersions.push_back (QUIC_VERSION_NS3_IMPL);

      uint8_t *buffer = new uint8_t[4 * supportedVersions.size ()];

      Ptr<Packet> payload = Create<Packet> (buffer,
                                            4 * supportedVersions.size ());

      for (uint8_t i = 0; i < (uint8_t) supportedVersions.size (); i++)
        {

          buffer[4 * i] = (supportedVersions[i]);
          buffer[4 * i + 1] = (supportedVersions[i] >> 8);
          buffer[4 * i + 2] = (supportedVersions[i] >> 16);
          buffer[4 * i + 3] = (supportedVersions[i] >> 24);
          //NS_LOG_INFO(" " << (uint64_t) buffer[4*i] << " " << (uint64_t)buffer[4*i+1] << " " << (uint64_t)buffer[4*i+2] << " " << (uint64_t)buffer[4*i+3] );

        }

      Ptr<Packet> p = Create<Packet> (buffer, 4 * supportedVersions.size ());
      QuicHeader head = QuicHeader::CreateVersionNegotiation (
        quicHeader.GetConnectionId (),
        QUIC_VERSION_NEGOTIATION,
        supportedVersions);

      // Set initial congestion window and Ssthresh
      m_tcb->m_cWnd = m_tcb->m_initialCWnd;
      m_tcb->m_ssThresh = m_tcb->m_initialSsThresh;

      m_quicl4->SendPacket (this, p, head);
      m_txTrace (p, head, this);
      NotifyDataSent (p->GetSize ());

    }
  else if (type == QuicHeader::INITIAL)
    {
      // Set initial congestion window and Ssthresh
      m_tcb->m_cWnd = m_tcb->m_initialCWnd;
      m_tcb->m_ssThresh = m_tcb->m_initialSsThresh;

      NS_LOG_INFO ("Create INITIAL");
      Ptr<Packet> p = Create<Packet> ();
      
      QuicTransportParameters tp = OnSendingTransportParameters ();
      Ptr<Packet> tpPkt = Create<Packet> ();
      tpPkt->AddHeader (tp);
      
      QuicSubheader crypto = QuicSubheader::CreateCrypto (0, tpPkt->GetSize ());
      p->AddHeader (crypto);
      p->AddAtEnd (tpPkt);

      // RFC 9000 Section 14.1: Initial packets must be padded to at least 1200 bytes.
      // We assume 0 header size to be safe and ensure the total packet size is always >= 1200.
      uint32_t currentSize = p->GetSize ();
      if (currentSize < GetInitialPacketSize ())
        {
          Ptr<Packet> padding = Create<Packet> (GetInitialPacketSize () - currentSize);
          p->AddAtEnd (padding);
        }

      // RFC 9000: CRYPTO frames go directly to socket TX buffer, not through a stream
      AppendingTx (p, INITIAL_DATA);
 
    }
  else if (type == QuicHeader::RETRY)
    {
      NS_LOG_INFO ("Create RETRY");
      Ptr<Packet> p = Create<Packet> ();
      QuicTransportParameters tp = OnSendingTransportParameters ();
      Ptr<Packet> tpPkt = Create<Packet> ();
      tpPkt->AddHeader (tp);
      
      QuicSubheader crypto = QuicSubheader::CreateCrypto (0, tpPkt->GetSize ());
      p->AddHeader (crypto);
      p->AddAtEnd (tpPkt);

      // RFC 9000: CRYPTO frames go directly to socket TX buffer, not through a stream
      AppendingTx (p, INITIAL_DATA);
    }
  else if (type == QuicHeader::HANDSHAKE)
    {
      NS_LOG_INFO ("Create HANDSHAKE");
      Ptr<Packet> p = Create<Packet> ();
      if (m_socketState == CONNECTING_SVR)
        {
          QuicTransportParameters tp = OnSendingTransportParameters ();
          Ptr<Packet> tpPkt = Create<Packet> ();
          tpPkt->AddHeader (tp);
          
          QuicSubheader crypto = QuicSubheader::CreateCrypto (0, tpPkt->GetSize ());
          p->AddHeader (crypto);
          p->AddAtEnd (tpPkt);
        }

      // RFC 9000: CRYPTO frames go directly to socket TX buffer, not through a stream
      if (p->GetSize () > 0)
        {
          AppendingTx (p, HANDSHAKE_DATA);
        }
      m_congestionControl->CongestionStateSet (m_tcb,
                                              TcpSocketState::CA_OPEN);
    }
  else if (type == QuicHeader::ZERO_RTT)
    {
    NS_LOG_INFO ("Create ZERO_RTT");
    Ptr<Packet> p = Create<Packet> ();
    QuicTransportParameters tp = OnSendingTransportParameters ();
    Ptr<Packet> tpPkt = Create<Packet> ();
    tpPkt->AddHeader (tp);
    
    QuicSubheader crypto = QuicSubheader::CreateCrypto (0, tpPkt->GetSize ());
    p->AddHeader (crypto);
    p->AddAtEnd (tpPkt);

    // Set initial congestion window and Ssthresh
    m_tcb->m_cWnd = m_tcb->m_initialCWnd;
    m_tcb->m_ssThresh = m_tcb->m_initialSsThresh;

    // RFC 9000: CRYPTO frames go directly to socket TX buffer, not through a stream
    AppendingTx (p);
 
    }
  else
    {
      NS_LOG_INFO ("Wrong Handshake Type");
      return;
    }
}

void
QuicSocketBase::OnReceivedFrame (Ptr<Packet> p, QuicSubheader &sub, PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << space);

  if (sub.IsStream ())
    {
      NS_ABORT_MSG ("Stream frame should be handled by QuicStream");
    }
  else if (sub.IsAck ())
    {
      OnReceivedAckFrame (sub, space);
    }
  else if (sub.GetFrameType () == QuicSubheader::CRYPTO)
    {
      NS_LOG_INFO ("Received CRYPTO frame");
      // RFC 9000: Implement a buffer limit for CRYPTO frames (minimum 4096 bytes)
      if (p->GetSize () > 4096)
        {
          AbortConnection (
            QuicSubheader::TransportErrorCodes_t::CRYPTO_BUFFER_EXCEEDED,
            "Crypto buffer limit exceeded");
          return;
        }

      if (CouldContainTransportParameters ())
        {
          QuicTransportParameters transport;
          if (p->GetSize () > 0 && p->RemoveHeader (transport) > 0)
            {
              OnReceivedTransportParameters (transport);
            }
        }
    }
  else if (sub.GetFrameType () == QuicSubheader::CONNECTION_CLOSE)
    {
      NS_LOG_INFO ("Received CONNECTION_CLOSE frame");
      Close ();
    }
  else if (sub.GetFrameType () == QuicSubheader::APPLICATION_CLOSE)
    {
      NS_LOG_INFO ("Received APPLICATION_CLOSE frame");
      DoClose ();
    }
  else if (sub.GetFrameType () == QuicSubheader::PADDING)
    {
      NS_LOG_INFO ("Received PADDING frame");
      // no need to do anything
    }
  else if (sub.GetFrameType () == QuicSubheader::MAX_DATA)
    {
      // set the maximum amount of data that can be sent
      // on this connection
      NS_LOG_INFO ("Received MAX_DATA frame");
      SetConnectionMaxData (sub.GetMaxData ());
    }
  else if (sub.GetFrameType () == QuicSubheader::MAX_STREAMS_BIDI)
    {
      NS_LOG_INFO ("Received MAX_STREAMS_BIDI frame");
      SetMaxStreamIdBidirectional (sub.GetMaxStreamId ());
    }
  else if (sub.GetFrameType () == QuicSubheader::MAX_STREAMS_UNI)
    {
      NS_LOG_INFO ("Received MAX_STREAMS_UNI frame");
      SetMaxStreamIdUnidirectional (sub.GetMaxStreamId ());
    }
  else if (sub.GetFrameType () == QuicSubheader::PING)
    {
      NS_LOG_INFO ("Received PING frame");
      // PING triggers an ACK, which is already handled by MaybeQueueAck called after processing frames
    }
  else if (sub.GetFrameType () == QuicSubheader::DATA_BLOCKED)
    {
      NS_LOG_INFO ("Received DATA_BLOCKED frame at offset " << sub.GetOffset ());
      // RFC 9000 Section 19.12: Informational only, could trigger an increase in MAX_DATA
    }
  else if (sub.GetFrameType () == QuicSubheader::STREAMS_BLOCKED_BIDI || sub.GetFrameType () == QuicSubheader::STREAMS_BLOCKED_UNI)
    {
      NS_LOG_INFO ("Received STREAMS_BLOCKED frame for limit " << sub.GetMaxStreamId ());
      // RFC 9000 Section 19.14: Informational only
    }
  else if (sub.GetFrameType () == QuicSubheader::NEW_CONNECTION_ID)
    {
      NS_LOG_INFO ("Received NEW_CONNECTION_ID frame: Seq " << sub.GetSequence () << " CID " << sub.GetConnectionId ());
      // TODO: Store alternative connection IDs for path migration
    }
  else if (sub.GetFrameType () == QuicSubheader::PATH_CHALLENGE)
    {
      NS_LOG_INFO ("Received PATH_CHALLENGE frame with data " << sub.GetData ());
      SendPathResponse (sub.GetData ());
    }
  else if (sub.GetFrameType () == QuicSubheader::PATH_RESPONSE)
    {
      NS_LOG_INFO ("Received PATH_RESPONSE frame with data " << sub.GetData ());
      // TODO: Validate against pending PATH_CHALLENGE
    }
  else
    {
      switch (sub.GetFrameType ())
        {
        case QuicSubheader::HANDSHAKE_DONE:
          NS_LOG_INFO ("Received HANDSHAKE_DONE frame");
          if (m_quicl4->IsServer () or space != APPLICATION_DATA)
            {
              AbortConnection (
                QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                "HANDSHAKE_DONE received by server or in non-App space");
              return;
            }
          m_handshakeConfirmed = true;
          m_txBuffer->DiscardSpace (HANDSHAKE_DATA);
          m_pnSpaces[HANDSHAKE_DATA].m_ackElicitingOutstanding = false;
          break;
        default:
          AbortConnection (
            QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
            "Received Corrupted Frame");
          return;
        }
    }

}

Ptr<Packet>
QuicSocketBase::OnSendingAckFrame (PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << space);

  std::vector<SequenceNumber32> &receivedPn = m_pnSpaces[space].m_receivedPacketNumbers;
  NS_ABORT_MSG_IF (receivedPn.empty (), "No packet numbers received - cannot build ACK");

  std::sort(receivedPn.begin(), receivedPn.end(), std::greater<SequenceNumber32>());

  SequenceNumber32 largestReceived = m_pnSpaces[space].m_largestReceived;

  uint32_t ackBlockCount = 0;
  std::vector<uint32_t> additionalAckBlocks;
  std::vector<uint32_t> gaps;

  std::vector<SequenceNumber32>::const_iterator curr_rec_it =
    receivedPn.begin ();
  std::vector<SequenceNumber32>::const_iterator next_rec_it =
    receivedPn.begin () + 1;

  for (; next_rec_it != receivedPn.end ();
       ++curr_rec_it, ++next_rec_it)
    {

      if (((*curr_rec_it) - (*next_rec_it) - 1 > 0)
          and ((*curr_rec_it) != (*next_rec_it)))
        {
          //std::clog << "curr " << (*curr_rec_it) << " next " << (*next_rec_it) << " ";
          additionalAckBlocks.push_back ((*next_rec_it).GetValue ());
          gaps.push_back ((*curr_rec_it).GetValue () - 1);
          ackBlockCount++;
        }
      // Limit the number of gaps that are sent in an ACK (older packets have already been retransmitted)
      if (ackBlockCount >= m_maxTrackedGaps)
        {
          break;
        }
    }


  Time delay = Simulator::Now () - m_pnSpaces[space].m_lastReceived;
  uint64_t ack_delay = delay.GetMicroSeconds ();
  QuicSubheader sub = QuicSubheader::CreateAck (
    largestReceived.GetValue (), ack_delay, largestReceived.GetValue (),
    gaps, additionalAckBlocks);

  Ptr<Packet> ackFrame = Create<Packet> ();
  ackFrame->AddHeader (sub);

  if (space == APPLICATION_DATA && m_handshakeConfirmed)
    {
      if (m_lastMaxData < m_maxDataInterval)
        {
          m_lastMaxData++;
        }
      else
        {
          // New Max Data = Total Bytes Read by App + RX Buffer Capacity
          uint64_t newMaxData = m_bytesRead + GetSocketRcvBufSize ();

          QuicSubheader maxData = QuicSubheader::CreateMaxData (newMaxData);
          ackFrame->AddHeader (maxData);
          m_lastMaxData = 0;
          
          NS_LOG_INFO ("Sending MAX_DATA update: " << newMaxData);
        }
    }

  return ackFrame;
}

void
QuicSocketBase::OnReceivedAckFrame (QuicSubheader &sub, PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << space);
  NS_LOG_INFO ("Process ACK");

  // Generate RateSample
  struct RateSample * rs = m_txBuffer->GetRateSample ();
  uint32_t previousWindow = BytesInFlight ();
  rs->m_priorInFlight = m_tcb->m_bytesInFlight.Get ();
  m_tcb->m_priorInFlight = rs->m_priorInFlight;

  uint32_t lostOut = m_txBuffer->GetLost ();
  uint32_t delivered = m_tcb->m_delivered;

  std::vector<uint32_t> additionalAckBlocks = sub.GetAdditionalAckBlocks ();
  std::vector<uint32_t> gaps = sub.GetGaps ();
  uint32_t largestAcknowledged = sub.GetLargestAcknowledged ();
  m_tcb->m_lastAckedSeq = largestAcknowledged;
  uint32_t ackBlockCount = sub.GetAckBlockCount ();

  NS_ABORT_MSG_IF (
    ackBlockCount != additionalAckBlocks.size ()
    and ackBlockCount != gaps.size (),
    "Received Corrupted Ack Frame.");

  std::vector<Ptr<QuicSocketTxItem> > ackedPackets = m_txBuffer->OnAckUpdate (
    m_tcb, largestAcknowledged, additionalAckBlocks, gaps, space);

  if (space == HANDSHAKE_DATA && m_quicl4->IsServer () && !m_handshakeDoneSent)
    {
      if (!ackedPackets.empty ())
        {
          NS_LOG_INFO ("Handshake confirmed, sending HANDSHAKE_DONE");
          m_handshakeDoneSent = true;
          m_handshakeConfirmed = true;
          m_txBuffer->DiscardSpace (HANDSHAKE_DATA);
          m_pnSpaces[HANDSHAKE_DATA].m_ackElicitingOutstanding = false;

          Ptr<Packet> hsd = Create<Packet> ();
          QuicSubheader sub;
          sub.SetHandshakeDone ();
          hsd->AddHeader (sub);
          AppendingTx (hsd, APPLICATION_DATA);
        }
    }

  // Count newly acked bytes
  uint32_t ackedBytes = previousWindow - m_txBuffer->BytesInFlight ();

  // Reset PTO count on successful ACK (RFC 9002 Section 6.2.1)
  if (!ackedPackets.empty ())
    {
      m_tcb->m_ptoCount = 0;
    }

  m_txBuffer->GenerateRateSample ();
  rs->m_packetLoss = std::abs ((int) lostOut - (int) m_txBuffer->GetLost ());
  m_tcb->m_lastAckedSackedBytes = m_tcb->m_delivered - delivered;

  // PTO reset already handled above

  // Find lost packets
  std::vector<Ptr<QuicSocketTxItem> > lostPackets =
    m_txBuffer->DetectLostPackets (m_tcb, space);
  // Recover from losses
  if (!lostPackets.empty ())
    {
      if (m_quicCongestionControlLegacy)
        {
          //Enter recovery (RFC 6675, Sec. 5)
          if (m_tcb->m_congState != TcpSocketState::CA_RECOVERY)
            {
              m_tcb->m_congState = TcpSocketState::CA_RECOVERY;
              m_tcb->m_endOfRecovery = m_tcb->m_highTxMark;
              m_congestionControl->CongestionStateSet (
                m_tcb, TcpSocketState::CA_RECOVERY);
              m_tcb->m_ssThresh = m_congestionControl->GetSsThresh (
                m_tcb, BytesInFlight ());
              m_tcb->m_cWnd = m_tcb->m_ssThresh;
            }
          NS_ASSERT (m_tcb->m_congState == TcpSocketState::CA_RECOVERY);
        }
      else
        {
          Ptr<QuicCongestionOps> qcc = DynamicCast<QuicCongestionOps> (m_congestionControl);
          if (qcc)
            {
              qcc->OnPacketsLost (m_tcb, lostPackets);
            }
        }
      DoRetransmit (lostPackets);
    }
  /* else */ if (ackedBytes > 0)
    {
      if (!m_quicCongestionControlLegacy)
        {
          NS_LOG_INFO ("Update the variables in the congestion control (QUIC)");
          // Process the ACK
          Ptr<QuicCongestionOps> qcc = DynamicCast<QuicCongestionOps> (m_congestionControl);
          if (qcc)
            {
              qcc->OnAckReceived (m_tcb, sub, ackedPackets, rs);
              m_lastRtt = m_tcb->m_lastRtt;
              NS_LOG_DEBUG ("Updated m_lastRtt to " << m_lastRtt.Get().GetSeconds());
            }
        }
      else
        {
          uint32_t ackedSegments = ackedBytes / GetSegSize ();

          NS_LOG_INFO ("Update the variables in the congestion control (legacy), ackedBytes "
                       << ackedBytes << " ackedSegments " << ackedSegments);
          if (ackedPackets.empty ())
            {
              return;
            }
          // new acks are ordered from the highest packet number to the smalles
          Ptr<QuicSocketTxItem> lastAcked = ackedPackets.at (0);

          NS_LOG_LOGIC ("Updating RTT estimate");
          // If the largest acked is newly acked, update the RTT.
          if (lastAcked->m_packetNumber >= m_tcb->m_largestAckedPacket)
            {
              Time ackDelay = MicroSeconds (sub.GetAckDelay ());
              m_tcb->m_lastRtt = Now () - lastAcked->m_lastSent - ackDelay;
              m_lastRtt = m_tcb->m_lastRtt;
              NS_LOG_DEBUG ("Updated m_lastRtt (legacy) to " << m_lastRtt.Get().GetSeconds());
            }
          if (m_tcb->m_congState != TcpSocketState::CA_RECOVERY
              && m_tcb->m_congState != TcpSocketState::CA_LOSS)
            {
              // Increase the congestion window
              m_congestionControl->PktsAcked (m_tcb, ackedSegments,
                                              m_tcb->m_lastRtt);
              m_congestionControl->IncreaseWindow (m_tcb, ackedSegments);
            }
          else
            {
              if (m_tcb->m_endOfRecovery.GetValue () > largestAcknowledged)
                {
                  m_congestionControl->PktsAcked (m_tcb, ackedSegments,
                                                  m_tcb->m_lastRtt);
                  m_congestionControl->IncreaseWindow (m_tcb, ackedSegments);
                }
              else
                {
                  m_tcb->m_congState = TcpSocketState::CA_OPEN;
                  m_congestionControl->PktsAcked (m_tcb, ackedSegments, m_tcb->m_lastRtt);
                  m_congestionControl->CongestionStateSet (m_tcb, TcpSocketState::CA_OPEN);
                }
            }
        }
    }
  else
    {
      NS_LOG_DEBUG ("Duplicate or old ACK received");
    }

  // notify the application that more data can be sent
  if (GetTxAvailable () > 0)
    {
  NotifySend (GetTxAvailable ());
    }

  // try to send more data
  SendPendingData (m_connected);
  // FIX: If we have no bytes in flight for this space, turn off the PTO flag
  if (m_txBuffer->BytesInFlight (space) == 0)
    {
      m_pnSpaces[space].m_ackElicitingOutstanding = false;
      // Cancel existing alarm to prevent unnecessary callbacks
      m_tcb->m_lossDetectionAlarm.Cancel ();
    }
}

QuicTransportParameters
QuicSocketBase::OnSendingTransportParameters ()
{
  NS_LOG_FUNCTION (this);

  QuicTransportParameters transportParameters;
  transportParameters = transportParameters.CreateTransportParameters (
    m_initial_max_stream_data, m_max_data, m_initial_max_stream_id_bidi,
    (uint16_t) m_idleTimeout.Get ().GetSeconds (),
    m_tcb->m_segmentSize,
    m_ack_delay_exponent, (uint16_t) m_max_ack_delay.GetMilliSeconds (), 
    m_initial_max_stream_id_uni);

  return transportParameters;
}

void
QuicSocketBase::OnReceivedTransportParameters (
  QuicTransportParameters transportParameters)
{
  NS_LOG_FUNCTION (this);

  if (m_receivedTransportParameters)
    {
      AbortConnection (
        QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR,
        "Duplicate transport parameters reception");
      return;
    }
  m_receivedTransportParameters = true;

  if (transportParameters.HasStatelessResetToken () && m_socketState == CONNECTING_CLT)
    {
      AbortConnection (
        QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR,
        "Client MUST NOT include a stateless reset token");
      return;
    }

  // RFC 9000: initial_max_streams_bidi and initial_max_streams_uni are counts,
  // not Stream IDs. Therefore, we do not check for Stream ID alignment (0x03 mask).

  if (transportParameters.GetMaxPacketSize ()
      < QuicSocketBase::MIN_INITIAL_PACKET_SIZE
      or transportParameters.GetMaxPacketSize () > 65527)
    {
      AbortConnection (
        QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR,
        "Invalid Max Packet Size value provided");
      return;
    }

  NS_LOG_DEBUG (
    "Before applying received transport parameters " << " m_initial_max_stream_data " << m_initial_max_stream_data << " m_max_data " << m_max_data << " m_initial_max_stream_id_bidi " << m_initial_max_stream_id_bidi << " m_idleTimeout " << m_idleTimeout << " m_tcb->m_segmentSize " << m_tcb->m_segmentSize << " m_ack_delay_exponent " << m_ack_delay_exponent << " m_initial_max_stream_id_uni " << m_initial_max_stream_id_uni);

  m_initial_max_stream_data = std::min (
    transportParameters.GetInitialMaxStreamData (),
    m_initial_max_stream_data);
  m_quicl5->UpdateInitialMaxStreamData (m_initial_max_stream_data);

  m_max_data = std::min (transportParameters.GetInitialMaxData (),
                         m_max_data);

  m_initial_max_stream_id_bidi = std::min (
    transportParameters.GetInitialMaxStreamIdBidi (),
    m_initial_max_stream_id_bidi);

  m_idleTimeout = Time (
    std::min (transportParameters.GetIdleTimeout (),
              (uint16_t) m_idleTimeout.Get ().GetSeconds ()) * 1e9);

  m_tcb->m_peerMaxAckDelay = MilliSeconds (transportParameters.GetMaxAckDelay ());

  SetSegSize (
    std::min ((uint32_t) transportParameters.GetMaxPacketSize (),
              m_tcb->m_segmentSize));

//m_stateless_reset_token = std::min(transportParameters.getStatelessResetToken(), m_stateless_reset_token);
  m_ack_delay_exponent = std::min (transportParameters.GetAckDelayExponent (),
                                   m_ack_delay_exponent);

  m_initial_max_stream_id_uni = std::min (
    transportParameters.GetInitialMaxStreamIdUni (),
    m_initial_max_stream_id_uni);

  NS_LOG_DEBUG (
    "After applying received transport parameters " << " m_initial_max_stream_data " << m_initial_max_stream_data << " m_max_data " << m_max_data << " m_initial_max_stream_id_bidi " << m_initial_max_stream_id_bidi << " m_idleTimeout " << m_idleTimeout << " m_tcb->m_segmentSize " << m_tcb->m_segmentSize << " m_ack_delay_exponent " << m_ack_delay_exponent << " m_initial_max_stream_id_uni " << m_initial_max_stream_id_uni);
}

int
QuicSocketBase::DoConnect (void)
{
  NS_LOG_FUNCTION (this);

  if (m_socketState != IDLE and m_socketState != QuicSocket::LISTENING)
    {
      //m_errno = ERROR_INVAL;
      return -1;
    }

  if (m_socketState == LISTENING)
    {
      SetState (CONNECTING_SVR);
    }
  else if (m_socketState == IDLE)
    {
      SetState (CONNECTING_CLT);
      QuicHeader q;
      SendInitialHandshake (QuicHeader::INITIAL, q, 0);
    }
  return 0;
}

int
QuicSocketBase::DoFastConnect (void)
{
  NS_LOG_FUNCTION (this);
  NS_ABORT_MSG_IF (!IsVersionSupported (m_vers),
                   "0RTT Handshake requested with wrong Initial Version");

  if (m_socketState != IDLE)
    {
      //m_errno = ERROR_INVAL;
      return -1;
    }

  else if (m_socketState == IDLE)
    {
      SetState (OPEN);
      Simulator::ScheduleNow (&QuicSocketBase::ConnectionSucceeded, this);
      m_congestionControl->CongestionStateSet (m_tcb,
                                               TcpSocketState::CA_OPEN);
      QuicHeader q;
      SendInitialHandshake (QuicHeader::ZERO_RTT, q, 0);
    }
  return 0;
}

void
QuicSocketBase::ConnectionSucceeded ()
{ // Wrapper to protected function NotifyConnectionSucceeded() so that it can
  // be called as a scheduled event
  NotifyConnectionSucceeded ();
  // The if-block below was moved from ProcessSynSent() to here because we need
  // to invoke the NotifySend() only after NotifyConnectionSucceeded() to
  // reflect the behaviour in the real world.
  if (GetTxAvailable () > 0)
    {
      NotifySend (GetTxAvailable ());
    }
}

int
QuicSocketBase::DoClose (void)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_INFO (this << " DoClose at time " << Simulator::Now ().GetSeconds ());

  if (m_socketState != IDLE)
    {
      SetState (IDLE);
    }

  SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
  return m_quicl4->RemoveSocket (this);
}

void
QuicSocketBase::ReceivedData (Ptr<Packet> p, const QuicHeader& quicHeader,
                              Address &address)
{
  NS_LOG_FUNCTION (this);

  m_rxTrace (p, quicHeader, this);

  NS_LOG_INFO ("Received packet of size " << p->GetSize ());

  // check if this packet is not received during the draining period
  if (!m_drainingPeriodEvent.IsRunning ())
    {
      m_idleTimeoutEvent.Cancel ();   // reset the IDLE timeout
      NS_LOG_LOGIC (
        this << " IdleTimeout canceled at " << Simulator::Now ().GetSeconds () << " New Close event to expire at time " << (Simulator::Now () + m_idleTimeout.Get ()).GetSeconds ());
      m_idleTimeoutEvent = Simulator::Schedule (m_idleTimeout,
                                                &QuicSocketBase::Close, this);
    }
  else   // If the socket is in Draining Period, discard the packets
    {
      return;
    }

  int isAckEliciting = 0;
  bool unsupportedVersion = false;
  PacketNumberSpace space = APPLICATION_DATA;

  if (quicHeader.IsORTT () and m_socketState == LISTENING)
    {
      NS_LOG_INFO ("Server receives 0-RTT while in LISTENING state");
      if (m_serverBusy)
        {
          AbortConnection (QuicSubheader::TransportErrorCodes_t::SERVER_BUSY,
                           "Server too busy to accept new connections");
          return;
        }

      m_couldContainTransportParameters = true;

      PacketNumberSpace space = APPLICATION_DATA;
      isAckEliciting = m_quicl5->DispatchRecv (p, address, space);
      if (m_socketState == IDLE || m_socketState == CLOSING)
        {
          return;
        }
      m_pnSpaces[space].m_receivedPacketNumbers.push_back (quicHeader.GetPacketNumber ());
      m_pnSpaces[space].m_largestReceived = std::max (m_pnSpaces[space].m_largestReceived.GetValue (), quicHeader.GetPacketNumber ().GetValue ());
      m_pnSpaces[space].m_lastReceived = Simulator::Now ();

      m_connected = true;
      m_keyPhase == QuicHeader::PHASE_ONE ? m_keyPhase =
        QuicHeader::PHASE_ZERO :
        m_keyPhase =
          QuicHeader::PHASE_ONE;
      SetState (OPEN);
      Simulator::ScheduleNow (&QuicSocketBase::ConnectionSucceeded, this);
      m_congestionControl->CongestionStateSet (m_tcb,
                                               TcpSocketState::CA_OPEN);
      m_couldContainTransportParameters = false;

    }
  else if (quicHeader.IsInitial () and m_socketState == CONNECTING_SVR)
    {
      NS_LOG_INFO ("Server receives INITIAL");
      if (m_serverBusy)
        {
          AbortConnection (QuicSubheader::TransportErrorCodes_t::SERVER_BUSY,
                           "Server too busy to accept new connections");
          return;
        }

      if (p->GetSize () < QuicSocketBase::MIN_INITIAL_PACKET_SIZE)
        {
          std::stringstream error;
          error << "Initial Packet smaller than "
                << QuicSocketBase::MIN_INITIAL_PACKET_SIZE << " octects";
          AbortConnection (
            QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
            error.str ().c_str ());
          return;
        }

      space = INITIAL_DATA;
      m_pnSpaces[space].m_receivedPacketNumbers.push_back (quicHeader.GetPacketNumber ());
      m_pnSpaces[space].m_largestReceived = std::max (m_pnSpaces[space].m_largestReceived.GetValue (), quicHeader.GetPacketNumber ().GetValue ());
      m_pnSpaces[space].m_lastReceived = Simulator::Now ();
      isAckEliciting = m_quicl5->DispatchRecv (p, address, space);
      if (isAckEliciting == 1) MaybeQueueAck (space);

      if (m_socketState == IDLE || m_socketState == CLOSING)
        {
          return;
        }

      if (m_quicl4->IsServer ())
        {
          m_couldContainTransportParameters = false;
          SendInitialHandshake (QuicHeader::HANDSHAKE, quicHeader, p);
        }
      else
        {
          NS_LOG_INFO (this << " WRONG VERSION " << quicHeader.GetVersion ());
          unsupportedVersion = true;
          SendInitialHandshake (QuicHeader::VERSION_NEGOTIATION, quicHeader,
                                 p);
        }
      return;
    }
  else if (quicHeader.IsHandshake () and m_socketState == CONNECTING_CLT)   // Undefined compiler behaviour if i try to receive transport parameters
    {
      NS_LOG_INFO ("Client receives HANDSHAKE");

      space = HANDSHAKE_DATA;
      m_pnSpaces[space].m_receivedPacketNumbers.push_back (quicHeader.GetPacketNumber ());
      m_pnSpaces[space].m_largestReceived = std::max (m_pnSpaces[space].m_largestReceived.GetValue (), quicHeader.GetPacketNumber ().GetValue ());
      m_pnSpaces[space].m_lastReceived = Simulator::Now ();
      isAckEliciting = m_quicl5->DispatchRecv (p, address, space);
      if (isAckEliciting == 1) MaybeQueueAck (space);
      if (m_socketState == IDLE || m_socketState == CLOSING)
        {
          return;
        }

      SetState (OPEN);
      Simulator::ScheduleNow (&QuicSocketBase::ConnectionSucceeded, this);
      m_congestionControl->CongestionStateSet (m_tcb,
                                               TcpSocketState::CA_OPEN);
      m_couldContainTransportParameters = false;
      m_txBuffer->DiscardSpace (INITIAL_DATA);
      m_pnSpaces[INITIAL_DATA].m_ackElicitingOutstanding = false;

      SendInitialHandshake (QuicHeader::HANDSHAKE, quicHeader, p);
      return;
    }
  else if (quicHeader.IsHandshake () and m_socketState == CONNECTING_SVR)
    {
      NS_LOG_INFO ("Server receives HANDSHAKE");

      space = HANDSHAKE_DATA;
      m_pnSpaces[space].m_receivedPacketNumbers.push_back (quicHeader.GetPacketNumber ());
      m_pnSpaces[space].m_largestReceived = std::max (m_pnSpaces[space].m_largestReceived.GetValue (), quicHeader.GetPacketNumber ().GetValue ());
      m_pnSpaces[space].m_lastReceived = Simulator::Now ();
      isAckEliciting = m_quicl5->DispatchRecv (p, address, space);
      if (isAckEliciting == 1) MaybeQueueAck (space);
      if (m_socketState == IDLE || m_socketState == CLOSING)
        {
          return;
        }

      SetState (OPEN);
      Simulator::ScheduleNow (&QuicSocketBase::ConnectionSucceeded, this);
      m_congestionControl->CongestionStateSet (m_tcb,
                                               TcpSocketState::CA_OPEN);
      m_txBuffer->DiscardSpace (INITIAL_DATA);
      m_pnSpaces[INITIAL_DATA].m_ackElicitingOutstanding = false;
      SendPendingData (true);
      return;
    }
  else if (quicHeader.IsVersionNegotiation ()
           and m_socketState == CONNECTING_CLT)
    {
      NS_LOG_INFO ("Client receives VERSION_NEGOTIATION");

      uint8_t *buffer = new uint8_t[p->GetSize ()];
      p->CopyData (buffer, p->GetSize ());

      std::vector<uint32_t> receivedVersions;
      for (uint8_t i = 0; i < p->GetSize (); i = i + 4)
        {
          receivedVersions.push_back (
            buffer[i] + (buffer[i + 1] << 8) + (buffer[i + 2] << 16)
            + (buffer[i + 3] << 24));
          //NS_LOG_INFO(" " << (uint64_t) buffer[i] << " " << (uint64_t)buffer[i+1] << " " << (uint64_t)buffer[i+2] << " " << (uint64_t)buffer[i+3] );
        }

      std::vector<uint32_t> supportedVersions;
      supportedVersions.push_back (QUIC_VERSION);
      supportedVersions.push_back (QUIC_VERSION_NS3_IMPL);

      uint32_t foundVersion = 0;
      for (uint8_t i = 0; i < receivedVersions.size (); i++)
        {
          for (uint8_t j = 0; j < supportedVersions.size (); j++)
            {
//			NS_LOG_INFO("rec " << receivedVersions[i] << " myvers " << m_supportedVersions[j] );
              if (receivedVersions[i] == supportedVersions[j])
                {
                  foundVersion = receivedVersions[i];
                }
            }
        }

      if (foundVersion != 0)
        {
          NS_LOG_INFO ("A matching supported version is found " << foundVersion << " re-send initial");
          m_vers = foundVersion;
          SendInitialHandshake (QuicHeader::INITIAL, quicHeader, p);
        }
      else
        {
          AbortConnection (
            QuicSubheader::TransportErrorCodes_t::VERSION_NEGOTIATION_ERROR,
            "No supported Version found by the Client");
          return;
        }
      return;
    }
  else if (quicHeader.IsShort () and m_socketState == OPEN)
    {
      NS_LOG_INFO ("Received 0-RTT while in OPEN state");
      space = APPLICATION_DATA;
      m_pnSpaces[space].m_receivedPacketNumbers.push_back (quicHeader.GetPacketNumber ());
      m_pnSpaces[space].m_largestReceived = std::max (m_pnSpaces[space].m_largestReceived.GetValue (), quicHeader.GetPacketNumber ().GetValue ());
      m_pnSpaces[space].m_lastReceived = Simulator::Now ();
      isAckEliciting = m_quicl5->DispatchRecv (p, address, space);
    }
  else if (m_socketState == CLOSING)
    {
      AbortConnection (m_transportErrorCode,
                       "Received packet in Closing state");
    }
  else
    {
      return;
    }

  // Trigger ACK handling only for ack-eliciting packets
  // isAckEliciting: true (1) means packet IS ack-eliciting, false (0) means NOT ack-eliciting
  NS_LOG_DEBUG ("isAckEliciting " << isAckEliciting << " unsupportedVersion " << unsupportedVersion);
  if (isAckEliciting == 1 && !unsupportedVersion)
    {
      NS_LOG_DEBUG ("Received ack-eliciting packet, call MaybeQueueAck");
      MaybeQueueAck (space);
    }
  else if (isAckEliciting == 0)
    {
      NS_LOG_INFO ("Received non-ack-eliciting packet (ACK-only), no ACK needed");
    }

}

uint32_t
QuicSocketBase::GetInitialMaxStreamData () const
{
  return m_initial_max_stream_data;
}

uint32_t
QuicSocketBase::GetConnectionMaxData () const
{
  return m_max_data;
}

void
QuicSocketBase::SetConnectionMaxData (uint32_t maxData)
{
  // Only allow increases, never decreases (RFC 9000 compliance)
  if (maxData > m_max_data)
    {
      m_max_data = maxData;
      // Flush buffered data now that the window has opened.
      SendPendingData (m_connected);

      if (GetTxAvailable () > 0)
        {
          NotifySend (GetTxAvailable ());
        }
    }
  else
    {
      NS_LOG_INFO ("Ignoring MAX_DATA " << maxData << " (not greater than current " << m_max_data << ")");
    }
}

QuicSocket::QuicStates_t
QuicSocketBase::GetSocketState () const
{
  return m_socketState;
}

void
QuicSocketBase::SetState (TracedValue<QuicStates_t> newstate)
{
  NS_LOG_FUNCTION (this);

  if (m_quicl4->IsServer ())
    {
      NS_LOG_INFO (
        "Server " << QuicStateName[m_socketState] << " -> " << QuicStateName[newstate] << "");
    }
  else
    {
      NS_LOG_INFO (
        "Client " << QuicStateName[m_socketState] << " -> " << QuicStateName[newstate] << "");
    }

  m_socketState = newstate;
}

bool
QuicSocketBase::IsVersionSupported (uint32_t version)
{
  if (version == QUIC_VERSION || version == QUIC_VERSION_NS3_IMPL)
    {
      return true;
    }
  else
    {
      return false;
    }
}

void
QuicSocketBase::AbortConnection (uint16_t transportErrorCode,
                                 const char* reasonPhrase,
                                 bool applicationClose)
{
  NS_LOG_FUNCTION (this);

  NS_LOG_INFO (
    "Abort connection " << transportErrorCode << " because " << reasonPhrase);

  m_transportErrorCode = transportErrorCode;

  QuicSubheader quicSubheader;
  Ptr<Packet> frame = Create<Packet> ();
  if (!applicationClose)
    {
      quicSubheader = QuicSubheader::CreateConnectionClose (
        m_transportErrorCode, reasonPhrase);
    }
  else
    {
      quicSubheader = QuicSubheader::CreateApplicationClose (
        m_transportErrorCode, reasonPhrase);
    }
  frame->AddHeader (quicSubheader);

  QuicHeader quicHeader;
  PacketNumberSpace space = APPLICATION_DATA;
  switch (m_socketState)
    {
      case CONNECTING_CLT:
        space = INITIAL_DATA;
        quicHeader = QuicHeader::CreateInitial (m_connectionId, m_vers,
                                                m_pnSpaces[space].m_nextTxSequence++);
        break;
      case CONNECTING_SVR:
        space = HANDSHAKE_DATA;
        quicHeader = QuicHeader::CreateHandshake (m_connectionId, m_vers,
                                                  m_pnSpaces[space].m_nextTxSequence++);
        break;
      case OPEN:
        if (!m_connected) space = HANDSHAKE_DATA;
        else space = APPLICATION_DATA;
        
        quicHeader =
          !m_connected ?
          QuicHeader::CreateHandshake (m_connectionId, m_vers,
                                       m_pnSpaces[space].m_nextTxSequence++) :
          QuicHeader::CreateShort (m_connectionId,
                                   m_pnSpaces[space].m_nextTxSequence++,
                                   true, m_keyPhase);
        break;
      case CLOSING:
        space = APPLICATION_DATA;
        quicHeader = QuicHeader::CreateShort (m_connectionId,
                                               m_pnSpaces[space].m_nextTxSequence++,
                                               true,
                                               m_keyPhase);
        break;
      default:
        NS_ABORT_MSG (
          "AbortConnection in unfeasible Socket State for the request");
        return;
    }
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddAtEnd (frame);
  uint32_t sz = packet->GetSize ();

  m_quicl4->SendPacket (this, packet, quicHeader);
  m_txTrace (packet, quicHeader, this);
  NotifyDataSent (sz);

  Close ();
}

bool
QuicSocketBase::GetReceivedTransportParametersFlag () const
{
  return m_receivedTransportParameters;
}

bool
QuicSocketBase::CheckIfPacketOverflowMaxDataLimit (
  std::vector<std::pair<Ptr<Packet>, QuicSubheader> > disgregated)
{
  NS_LOG_FUNCTION (this);
  uint32_t validPacketSize = 0;

  for (auto frame_recv_it = disgregated.begin ();
       frame_recv_it != disgregated.end () and !disgregated.empty ();
       ++frame_recv_it)
    {
      QuicSubheader sub = (*frame_recv_it).second;
      // (*frame_recv_it)->PeekHeader (sub);

      if (sub.IsStream () and sub.GetStreamId () != 0)
        {
          validPacketSize += (*frame_recv_it).first->GetSize ();
        }
    }

  if ((m_max_data < m_rxBuffer->Size () + validPacketSize))
    {
      return true;
    }
  return false;
}

void
QuicSocketBase::SetMaxStreamIdBidirectional (uint32_t maxStreamId)
{
  NS_LOG_FUNCTION (this << maxStreamId);
  m_initial_max_stream_id_bidi = maxStreamId;
}

void
QuicSocketBase::SetMaxStreamIdUnidirectional (uint32_t maxStreamId)
{
  NS_LOG_FUNCTION (this << maxStreamId);
  m_initial_max_stream_id_uni = maxStreamId;
}

void
QuicSocketBase::SendPathResponse (uint64_t data)
{
  NS_LOG_FUNCTION (this << data);

  QuicSubheader sub = QuicSubheader::CreatePathResponse (data);
  Ptr<Packet> p = Create<Packet> ();
  p->AddHeader (sub);

  PacketNumberSpace space = APPLICATION_DATA;
  if (m_socketState == CONNECTING_SVR) space = HANDSHAKE_DATA;
  else if (m_socketState == CONNECTING_CLT) space = INITIAL_DATA;
  
  SequenceNumber32 next = m_pnSpaces[space].m_nextTxSequence++;
  QuicHeader head;
  if (space == HANDSHAKE_DATA)
    {
      head = QuicHeader::CreateHandshake (m_connectionId, m_vers, next);
    }
  else if (space == INITIAL_DATA)
    {
      head = QuicHeader::CreateInitial (m_connectionId, m_vers, next);
    }
  else if (m_socketState == OPEN)
    {
      head = QuicHeader::CreateShort (m_connectionId, next, true, m_keyPhase);
    }

  m_quicl4->SendPacket (this, p, head);
  m_txTrace (p, head, this);
  NotifyDataSent (p->GetSize ());
}

uint32_t
QuicSocketBase::GetMaxStreamId () const
{
  return std::max (m_initial_max_stream_id_bidi, m_initial_max_stream_id_uni);
}

uint32_t
QuicSocketBase::GetMaxStreamIdBidirectional () const
{
  return m_initial_max_stream_id_bidi;
}

uint32_t
QuicSocketBase::GetMaxStreamIdUnidirectional () const
{
  return m_initial_max_stream_id_uni;
}

bool
QuicSocketBase::CouldContainTransportParameters () const
{
  return m_couldContainTransportParameters;
}

void
QuicSocketBase::SetCongestionControlAlgorithm (Ptr<TcpCongestionOps> algo)
{
  NS_LOG_FUNCTION (this << algo);
  m_congestionControl = algo;
  if (!m_congestionControl)
    {
      m_congestionControl = CreateObject<QuicCongestionOps> ();
    }

  if (DynamicCast<QuicCongestionOps> (m_congestionControl))
    {
      NS_LOG_INFO ("Non-legacy congestion control algorithm installed. Forcing LegacyCongestionControl to false.");
      m_quicCongestionControlLegacy = false;
    }
  else
    {
      NS_LOG_INFO (
        "Legacy congestion control, using only TCP standard functions. Forcing LegacyCongestionControl to true.");
      m_quicCongestionControlLegacy = true;
    }
}

void
QuicSocketBase::SetSocketSndBufSize (uint32_t size)
{
  NS_LOG_FUNCTION (this << size);
  m_socketTxBufferSize = size;
  m_txBuffer->SetMaxBufferSize (size);
}

uint32_t
QuicSocketBase::GetSocketSndBufSize (void) const
{
  return m_txBuffer->GetMaxBufferSize ();
}

void
QuicSocketBase::SetSocketRcvBufSize (uint32_t size)
{
  NS_LOG_FUNCTION (this << size);
  m_socketRxBufferSize = size;
  m_rxBuffer->SetMaxBufferSize (size);
}

uint32_t
QuicSocketBase::GetSocketRcvBufSize (void) const
{
  return m_rxBuffer->GetMaxBufferSize ();
}

void
QuicSocketBase::UpdateCwnd (uint32_t oldValue, uint32_t newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);
  m_cWndTrace (oldValue, newValue);
}

void
QuicSocketBase::UpdateSsThresh (uint32_t oldValue, uint32_t newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);
  m_ssThTrace (oldValue, newValue);
}

void
QuicSocketBase::UpdateCongState (TcpSocketState::TcpCongState_t oldValue,
                                 TcpSocketState::TcpCongState_t newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);
  m_congStateTrace (oldValue, newValue);
}

void
QuicSocketBase::UpdateNextTxSequence (SequenceNumber32 oldValue,
                                      SequenceNumber32 newValue)

{
  NS_LOG_FUNCTION (this << oldValue << newValue);
  m_nextTxSequenceTrace (oldValue.GetValue (), newValue.GetValue ());
}

void
QuicSocketBase::UpdateHighTxMark (SequenceNumber32 oldValue, SequenceNumber32 newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);
  m_highTxMarkTrace (oldValue.GetValue (), newValue.GetValue ());
}

void
QuicSocketBase::UpdateBytesInFlight (uint32_t oldValue, uint32_t newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);
  m_bytesInFlightTrace (oldValue, newValue);
}

void
QuicSocketBase::SetInitialSSThresh (uint32_t threshold)
{
  NS_ABORT_MSG_UNLESS ( (m_socketState == IDLE) || threshold == m_tcb->m_initialSsThresh,
                        "QuicSocketBase::SetSSThresh() cannot change initial ssThresh after connection started.");

  m_tcb->m_initialSsThresh = threshold;
  if (m_socketState == IDLE)
    {
      m_tcb->m_ssThresh = threshold;
    }
}

uint32_t
QuicSocketBase::GetInitialSSThresh (void) const
{
  return m_tcb->m_initialSsThresh;
}

void
QuicSocketBase::SetInitialPacketSize (uint32_t size)
{
  NS_ABORT_MSG_IF (size < 1200, "The size of the initial packet should be at least 1200 bytes");
  m_initialPacketSize = size;
}

uint32_t
QuicSocketBase::GetInitialPacketSize () const
{
  return m_initialPacketSize;
}

void
QuicSocketBase::SetMaxAckDelay (Time maxAckDelay)
{
  m_max_ack_delay = maxAckDelay;
  if (m_tcb)
    {
      m_tcb->m_max_ack_delay = maxAckDelay;
    }
}

Time
QuicSocketBase::GetMaxAckDelay (void) const
{
  return m_max_ack_delay;
}

void QuicSocketBase::SetLatency (uint32_t streamId, Time latency)
{
  m_txBuffer->SetLatency (streamId, latency);
}

Time QuicSocketBase::GetLatency (uint32_t streamId)
{
  return m_txBuffer->GetLatency (streamId);
}

void QuicSocketBase::SetDefaultLatency (Time latency)
{
  m_txBuffer->SetDefaultLatency (latency);
}

Time QuicSocketBase::GetDefaultLatency ()
{
  return m_txBuffer->GetDefaultLatency ();
}

void
QuicSocketBase::NotifyPacingPerformed (void)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_INFO ("Pacing timer expired, try sending a packet");
  SendPendingData (m_connected);
  if (GetTxAvailable () > 0)
    {
      NotifySend (GetTxAvailable ());
    }
}

} // namespace ns3
