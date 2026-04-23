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

#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/nstime.h"
#include "ns3/boolean.h"
#include "ns3/object-vector.h"

#include "ns3/packet.h"
#include "ns3/node.h"
#include "ns3/simulator.h"
// #include "ns3/ipv4-route.h"
// #include "ns3/ipv6-route.h"

#include "quic-l5-protocol.h"
// #include "ns3/ipv4-end-point-demux.h"
// #include "ns3/ipv6-end-point-demux.h"
// #include "ns3/ipv4-end-point.h"
// #include "ns3/ipv6-end-point.h"
// #include "ns3/ipv4-l3-protocol.h"
// #include "ns3/ipv6-l3-protocol.h"
// #include "ns3/ipv6-routing-protocol.h"
#include "quic-socket-factory.h"
#include "quic-socket-base.h"
#include "quic-stream-base.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicL5Protocol");

NS_OBJECT_ENSURE_REGISTERED (QuicL5Protocol);

// #undef NS_LOG_APPEND_CONTEXT
// #define NS_LOG_APPEND_CONTEXT
// if (m_node and m_connectionId) { std::clog << " [node " << m_node->GetId () << " socket " << m_connectionId << "] "; }

TypeId
QuicL5Protocol::GetTypeId (void)
{
  static TypeId tid =
    TypeId ("ns3::QuicL5Protocol")
      .SetParent<QuicSocketBase> ()
      .SetGroupName ("Internet")
      .AddConstructor<QuicL5Protocol> ()
      .AddAttribute ("StreamList", "The list of streams associated to this protocol.",
                     ObjectVectorValue (),
                     MakeObjectVectorAccessor (&QuicL5Protocol::m_streams),
                     MakeObjectVectorChecker<QuicStreamBase> ())
  ;
  return tid;
}

QuicL5Protocol::QuicL5Protocol ()
  : m_socket (0),
  m_node (0),
  m_connectionId (),
  m_nextBidiStreamId (0),
  m_nextUniStreamId (0),
  m_streamCountersInitialized (false)
{
  NS_LOG_FUNCTION_NOARGS ();
  NS_LOG_LOGIC ("Made a QuicL5Protocol " << this);
  m_socket = 0;
  m_node = 0;
  m_connectionId = 0;
}

QuicL5Protocol::~QuicL5Protocol ()
{
  NS_LOG_FUNCTION (this);
}

void
QuicL5Protocol::CreateStream (
  const QuicStream::QuicStreamDirectionTypes_t streamDirectionType,
  uint64_t streamId)
{
  NS_LOG_FUNCTION (this << m_streams.size () << streamId);

  // RFC 9000: Last 2 bits indicate Stream Type
  uint64_t typeMask = 0x00000003;
  uint8_t type = streamId & typeMask;
  bool isBidi = (type == QuicStream::CLIENT_INITIATED_BIDIRECTIONAL || type == QuicStream::SERVER_INITIATED_BIDIRECTIONAL);

  uint32_t limit = isBidi ? m_socket->GetMaxStreamIdBidirectional () : m_socket->GetMaxStreamIdUnidirectional ();

  // Check limits as per RFC 9000
  if (streamId / 4 >= limit)
    {
      NS_LOG_INFO ("Stream ID " << streamId << " exceeds limit (count limit: " << limit << ")");
      SignalAbortConnection (
        QuicSubheader::TransportErrorCodes_t::STREAM_ID_ERROR, 
        "Initiating Stream beyond negotiated limit (STREAM_LIMIT_ERROR)");
      return;
    }

  // If exists, do nothing (lazy creation)
  if (SearchStream(streamId))
    {
      return;
    }

  NS_LOG_DEBUG ("Create stream with exact ID " << streamId);
  Ptr<QuicStreamBase> stream = CreateObject<QuicStreamBase> ();
  stream->SetQuicL5 (this);
  stream->SetNode (m_node);
  stream->SetConnectionId (m_connectionId);
  
  // Assign requested ID
  stream->SetStreamId (streamId);

  if (isBidi)
    {
      stream->SetStreamDirectionType (QuicStream::BIDIRECTIONAL);
    }
  else
    {
      stream->SetStreamDirectionType (streamDirectionType);
    }

  stream->SetMaxStreamData (m_socket->GetInitialMaxStreamData ());
  m_streams.push_back (stream);
}

void
QuicL5Protocol::SetSocket (Ptr<QuicSocketBase> sock)
{
  NS_LOG_FUNCTION (this);
  m_socket = sock;
}

int
QuicL5Protocol::DispatchSend (Ptr<Packet> data)
{
  NS_LOG_FUNCTION (this);

  int sentData = 0;

  if (m_streams.empty ())
    {
      uint64_t newStreamId = GetNextStreamId (true); 
      NS_LOG_INFO ("No streams available, creating a new bidirectional App Stream with ID " << newStreamId);
      CreateStream (QuicStream::BIDIRECTIONAL, newStreamId);
    }

  std::vector<Ptr<Packet> > disgregated = DisgregateSend (data);

  std::vector<Ptr<QuicStreamBase> >::iterator jt = m_streams.begin ();   // Include stream 0 - all streams are application streams per RFC 9000

  for (std::vector<Ptr<Packet> >::iterator it = disgregated.begin ();
       it != disgregated.end (); ++jt)
    {
      if (jt == m_streams.end ())             // Sending Remaining Load
        {
          jt = m_streams.begin ();
        }
      NS_LOG_LOGIC (
        this << " " << (uint64_t)(*jt)->GetStreamDirectionType () << (uint64_t) QuicStream::SENDER << (uint64_t) QuicStream::BIDIRECTIONAL);

      if ((*jt)->GetStreamDirectionType () == QuicStream::SENDER
          or (*jt)->GetStreamDirectionType () == QuicStream::BIDIRECTIONAL)
        {
          NS_LOG_INFO (
            "Sending data on stream " << (*jt)->GetStreamId ());
          int streamSentData = (*jt)->Send ((*it));
          if (streamSentData > 0)
            {
              sentData += streamSentData;
            }
          ++it;
        }
    }

  return (sentData > 0) ? sentData : -1;
}

int
QuicL5Protocol::DispatchSend (Ptr<Packet> data, uint64_t streamId)
{
  NS_LOG_FUNCTION (this);

  NS_LOG_INFO ("Send packet on (specified) stream " << streamId);

  Ptr<QuicStreamBase> stream = SearchStream (streamId);

  if (!stream)
    {
      CreateStream (QuicStream::SENDER, streamId);
    }

  stream = SearchStream (streamId);
  if (!stream)
    {
      NS_LOG_INFO ("Stream creation failed (likely due to connection abort), dropping packet");
      return -1;
    }
  int sentData = 0;

  if (stream->GetStreamDirectionType () == QuicStream::SENDER
      or stream->GetStreamDirectionType () == QuicStream::BIDIRECTIONAL)
    {
      sentData = stream->Send (data);
    }

  return sentData;
}

int
QuicL5Protocol::DispatchRecv (Ptr<Packet> data, Address &address, PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << space);
  auto disgregated = DisgregateRecv (data);

  if (m_socket->CheckIfPacketOverflowMaxDataLimit (disgregated))
    {
      NS_LOG_WARN ("Maximum data limit overflow");
      // put here this check instead of in QuicSocketBase due to framework mismatch in packet->Copy()
      SignalAbortConnection (
        QuicSubheader::TransportErrorCodes_t::FLOW_CONTROL_ERROR,
        "Received more data w.r.t. Max Data limit");
      return -1;
    }

  // RFC 9000 Section 13.2: Determine if packet is ack-eliciting
  // A packet is ack-eliciting if it contains ANY frame other than ACK, PADDING, or CONNECTION_CLOSE
  bool isAckEliciting = false;
  uint64_t currStreamNum = m_streams.size () - 1;
  for (auto &elem : disgregated)
    {
      QuicSubheader sub = elem.second;
      // RFC 9000 Section 13.2.1: Frames that are NOT ack-eliciting:
      // - ACK
      // - PADDING  
      // - CONNECTION_CLOSE
      // - APPLICATION_CLOSE
      // All other frames ARE ack-eliciting (including STREAM, PING, CRYPTO, etc.)
      if (!sub.IsAck () && !sub.IsPadding () && !sub.IsConnectionClose () && !sub.IsApplicationClose ())
        {
          isAckEliciting = true;
        }

      if (sub.IsStream () || sub.IsRstStream () || sub.IsMaxStreamData () 
          || sub.IsStreamBlocked () || sub.IsStopSending ())
        {
          if (m_streams.empty () || sub.GetStreamId () > currStreamNum)
            {
              currStreamNum = sub.GetStreamId ();
            }
        }
    }

  if (!m_streams.empty () || currStreamNum != (uint64_t)-1)
    {
      CreateStream (QuicStream::RECEIVER, currStreamNum);
    }

  for (auto it = disgregated.begin (); it != disgregated.end (); ++it)
    {
      QuicSubheader sub = (*it).second;

      if (sub.IsRstStream () or sub.IsMaxStreamData ()
          or sub.IsStreamBlocked () or sub.IsStopSending ()
          or sub.IsStream ())
        {
          Ptr<QuicStreamBase> stream = SearchStream (sub.GetStreamId ());

          if (stream
              and (stream->GetStreamDirectionType () == QuicStream::RECEIVER
                   or stream->GetStreamDirectionType () == QuicStream::BIDIRECTIONAL))
            {
              NS_LOG_INFO (
                "Receiving frame on stream " << stream->GetStreamId () <<
                  " trigger stream");
              stream->Recv ((*it).first, sub, address);
            }
        }
      else
        {
          NS_LOG_INFO (
            "Receiving frame on stream " << sub.GetStreamId () <<
              " trigger socket in space " << space);
          m_socket->OnReceivedFrame ((*it).first, sub, space);
        }
    }

  // Return 1 if packet IS ack-eliciting, 0 if NOT ack-eliciting
  // This tells QuicSocketBase whether to call MaybeQueueAck()
  return isAckEliciting ? 1 : 0;
}

int
QuicL5Protocol::Send (Ptr<Packet> frame)
{
  NS_LOG_FUNCTION (this);

  return m_socket->AppendingTx (frame);
}

int
QuicL5Protocol::Recv (Ptr<Packet> frame, Address &address)
{
  NS_LOG_FUNCTION (this);

  m_socket->AppendingRx (frame, address);

  return frame->GetSize ();
}

std::vector<Ptr<Packet> >
QuicL5Protocol::DisgregateSend (Ptr<Packet> data)
{
  NS_LOG_FUNCTION (this);

  uint32_t dataSizeByte = data->GetSize ();
  std::vector< Ptr<Packet> > disgregated;
  //data->Print(std::cout);

  if (m_streams.size () < 1)
    {
      NS_LOG_WARN ("No application streams available to send data");
      return disgregated;
    }

  // Equally distribute load on all streams (stream 0 is a normal application stream per RFC 9000)
  uint32_t loadPerStream = dataSizeByte / m_streams.size ();
  uint32_t remainingLoad = dataSizeByte - loadPerStream * m_streams.size ();
  if (loadPerStream < 1)
    {
      loadPerStream = 1;
    }

  for (uint32_t start = 0; start < dataSizeByte; start += loadPerStream)
    {
      if (remainingLoad > 0 && start + remainingLoad == dataSizeByte)
        {
          Ptr<Packet> remainingfragment = data->CreateFragment (
            start, remainingLoad);
          disgregated.push_back (remainingfragment);
        }
      else
        {
          Ptr<Packet> fragment = data->CreateFragment (start, loadPerStream);
          disgregated.push_back (fragment);
        }

    }

  return disgregated;
}

std::vector< std::pair<Ptr<Packet>, QuicSubheader> >
QuicL5Protocol::DisgregateRecv (Ptr<Packet> data)
{
  NS_LOG_FUNCTION (this);

  std::vector< std::pair<Ptr<Packet>, QuicSubheader> > disgregated;
  NS_LOG_INFO ("DisgregateRecv for a packet with size " << data->GetSize ());
  //data->Print(std::cout);

  // the packet could contain multiple frames
  // each of them starts with a subheader
  // cycle through the data packet and extract the frames
  while (data->GetSize () > 0)
    {
      QuicSubheader sub;
      data->RemoveHeader (sub);
      NS_LOG_INFO ("subheader " << sub << " remaining " << data->GetSize () << " frame size " << sub.GetLength ());

      if (sub.IsPadding ())
        {
          // Padding MUST be the last frame/s in the packet
          // We can stop parsing.
          disgregated.push_back (std::make_pair (Create<Packet> (), sub));
          break;
        }
      else
        {
          Ptr<Packet> remainingfragment = data->CreateFragment (0, sub.GetLength ());
          NS_LOG_INFO ("fragment size " << remainingfragment->GetSize ());

          // remove the first portion of the packet
          data->RemoveAtStart (sub.GetLength ());
          disgregated.push_back (std::make_pair (remainingfragment, sub));
        }
    }
  return disgregated;
}

Ptr<QuicStreamBase>
QuicL5Protocol::SearchStream (uint64_t streamId)
{
  NS_LOG_FUNCTION (this);
  std::vector<Ptr<QuicStreamBase> >::iterator it = m_streams.begin ();
  Ptr<QuicStreamBase> stream;
  while (it != m_streams.end ())
    {
      if ((*it)->GetStreamId () == streamId)
        {
          stream = *it;
          break;
        }
      ++it;
    }
  return stream;
}

void
QuicL5Protocol::SetNode (Ptr<Node> node)
{
  NS_LOG_FUNCTION (this << node);
  m_node = node;
}

void
QuicL5Protocol::SetConnectionId (uint64_t connId)
{
  NS_LOG_FUNCTION (this << connId);
  m_connectionId = connId;
}

uint16_t
QuicL5Protocol::GetMaxPacketSize () const
{
  return m_socket->GetSegSize ();
}

bool
QuicL5Protocol::ContainsTransportParameters ()
{
  return m_socket->CouldContainTransportParameters ();
}

void
QuicL5Protocol::OnReceivedTransportParameters (
  QuicTransportParameters transportParameters)
{
  m_socket->OnReceivedTransportParameters (transportParameters);
}

void
QuicL5Protocol::SignalAbortConnection (uint16_t transportErrorCode,
                                       const char* reasonPhrase)
{
  NS_LOG_FUNCTION (this);
  m_socket->AbortConnection (transportErrorCode, reasonPhrase);
}

void
QuicL5Protocol::UpdateInitialMaxStreamData (uint32_t newMaxStreamData)
{
  NS_LOG_FUNCTION (this << newMaxStreamData);

  // TODO handle in a different way bidirectional and unidirectional streams
  for (auto stream : m_streams)
    {
      stream->SetMaxStreamData (newMaxStreamData);
    }
}

uint64_t
QuicL5Protocol::GetMaxData ()
{
  NS_LOG_FUNCTION (this);
  return m_socket->GetConnectionMaxData ();
}

const std::vector<Ptr<QuicStreamBase> >&
QuicL5Protocol::GetStreams() const
{
  return m_streams;
}

uint64_t
QuicL5Protocol::GetNextStreamId (bool isBidi)
{
  NS_LOG_FUNCTION (this << isBidi);

  // Initialize counters first time we need an ID
  if (!m_streamCountersInitialized)
    {
      bool isServer = m_socket->IsServer ();
      // RFC 9000: Bidi Client=0, Bidi Server=1 | Uni Client=2, Uni Server=3
      m_nextBidiStreamId = isServer ? 1 : 0;
      m_nextUniStreamId  = isServer ? 3 : 2;
      m_streamCountersInitialized = true;
    }

  uint64_t nextId = 0;
  // adding +4 gives us the next valid ID for each type
  if (isBidi)
    {
      nextId = m_nextBidiStreamId;
      m_nextBidiStreamId += 4;
    }
  else
    {
      nextId = m_nextUniStreamId;
      m_nextUniStreamId += 4;
    }
  
  return nextId;
}

} // namespace ns3

