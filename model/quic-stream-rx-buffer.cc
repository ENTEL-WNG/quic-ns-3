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

#include "ns3/packet.h"
#include "ns3/fatal-error.h"
#include "ns3/log.h"
// #include "ns3/ipv4-end-point-demux.h"
// #include "ns3/ipv6-end-point-demux.h"
// #include "ns3/ipv4-end-point.h"
// #include "ns3/ipv6-end-point.h"
// #include "ns3/ipv4-l3-protocol.h"
// #include "ns3/ipv6-l3-protocol.h"
// #include "ns3/ipv6-routing-protocol.h"
#include <algorithm>
#include <vector>
#include "quic-stream-rx-buffer.h"
#include "quic-subheader.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicStreamRxBuffer");

QuicStreamRxItem::QuicStreamRxItem ()
  : m_packet (0),
  m_offset (0),
  m_fin (false)
{
}

QuicStreamRxItem::QuicStreamRxItem (const QuicStreamRxItem &other)
  : m_packet (other.m_packet),
  m_offset (other.m_offset),
  m_fin (other.m_fin)
{
}

void
QuicStreamRxItem::Print (std::ostream &os) const
{
  os << "[OFF " << m_offset << "]";

  if (m_fin)
    {
      os << "|fin|";
    }

}

NS_OBJECT_ENSURE_REGISTERED (QuicStreamRxBuffer);

TypeId
QuicStreamRxBuffer::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicStreamRxBuffer")
    .SetParent<Object> ()
    .SetGroupName ("Internet")
    .AddConstructor<QuicStreamRxBuffer> ()
  ;
  return tid;
}

QuicStreamRxBuffer::QuicStreamRxBuffer ()
  : m_numBytesInBuffer (0),
  m_finalSize (0),
  m_maxBuffer (131072),
  m_recvFin (
    false)
{
  m_streamRecvList = QuicStreamRxPacketList ();
}

QuicStreamRxBuffer::~QuicStreamRxBuffer ()
{
}

bool
QuicStreamRxBuffer::Add (Ptr<Packet> p, const QuicSubheader& sub)
{
  NS_LOG_FUNCTION (this << p << sub);

  NS_LOG_INFO (
    "Try to append " << p->GetSize () << " bytes " << ", availSize=" << Available ());

  if (p->GetSize () <= Available ())
    {
      if (p->GetSize () > 0)
        {

          // FIN packet for the stream
          if (sub.IsStreamFin ())
            {
              NS_LOG_LOGIC ("FIN packet for the stream");
              m_finalSize = sub.GetOffset () + p->GetSize ();
              m_recvFin = true;
            }
          else if (m_streamRecvList.find (sub.GetOffset ()) != m_streamRecvList.end ())
            {
              // Duplicate packet
              NS_LOG_WARN ("Discarded duplicate packet.");
              return false;
            }

          QuicStreamRxItem item;
          item.m_packet = p->Copy ();
          item.m_offset = sub.GetOffset ();
          item.m_fin = sub.IsStreamFin ();
          m_streamRecvList.emplace (item.m_offset, item);
          NS_LOG_LOGIC ("Inserted packet");
          m_numBytesInBuffer += p->GetSize ();
          NS_LOG_INFO ("Update: Received Size = " << m_numBytesInBuffer);
          return true;

        }
      else
        {
          NS_LOG_WARN ("Discarded. Trying to insert empty packet.");
          return false;
        }
    }
  NS_LOG_WARN ("Rejected. Not enough room to buffer packet.");
  return false;
}

Ptr<Packet>
QuicStreamRxBuffer::Extract (uint32_t maxSize)
{
  NS_LOG_FUNCTION (this << maxSize);

  uint32_t extractSize = std::min (maxSize, m_numBytesInBuffer);
  NS_LOG_INFO (
    "Requested to extract " << extractSize << " bytes from QuicStreamRxBuffer of size = " << m_numBytesInBuffer);

  Ptr<Packet> outPkt = Create<Packet> ();

  if (extractSize == 0)
    {
      return outPkt;
    }

  std::vector<Ptr<Packet> > parts;
  QuicStreamRxPacketList::iterator it = m_streamRecvList.begin ();

  while (extractSize > 0 && it != m_streamRecvList.end ()
         && it->second.m_packet->GetSize () <= extractSize)
    {
      parts.push_back (it->second.m_packet);
      NS_LOG_LOGIC ("Extracted and removed packet " << it->first << " from RxBuffer, bytes to extract: " << extractSize);

      m_numBytesInBuffer -= parts.back ()->GetSize ();
      extractSize -= parts.back ()->GetSize ();
      it = m_streamRecvList.erase (it);
    }

  // Packet::AddAtEnd reallocates and copies the whole packet whenever it runs
  // out of room, so appending the parts one by one onto a growing packet copies
  // O(N^2) bytes. Merging adjacent pairs in rounds copies O(N log N) bytes and
  // yields the same packet. The parts are owned here, so changing them is safe.
  for (size_t count = parts.size (); count > 1; count = (count + 1) / 2)
    {
      for (size_t i = 0; i < count; i += 2)
        {
          Ptr<Packet> merged = parts[i];
          if (i + 1 < count)
            {
              merged->AddAtEnd (parts[i + 1]);
              parts[i + 1] = nullptr;
            }
          parts[i / 2] = merged;
        }
    }

  if (!parts.empty ())
    {
      outPkt->AddAtEnd (parts.front ());
    }

  if (outPkt->GetSize () == 0)
    {
      NS_LOG_INFO ("Nothing extracted.");
    }

  return outPkt;
}

std::pair<uint64_t, uint64_t>
QuicStreamRxBuffer::GetDeliverable (uint64_t currRecvOffset)
{
  NS_LOG_FUNCTION (this);
  uint64_t offsetToExtract = currRecvOffset;
  uint64_t lengthToExtract = 0;
  NS_LOG_LOGIC ("Calculating deliverable size");

  // First, purge any stale items that are entirely below currRecvOffset
  // (already-delivered retransmissions that were buffered out-of-order).
  // Stored packets are never empty, so an item at or above currRecvOffset cannot
  // be stale, and the list is ordered by offset: the walk can stop at the first one.
  QuicStreamRxPacketList::iterator i = m_streamRecvList.begin ();
  while (i != m_streamRecvList.end () && i->first < currRecvOffset)
    {
      uint64_t itemEnd = i->first + i->second.m_packet->GetSize ();
      if (itemEnd <= currRecvOffset)
        {
          // Entirely stale - remove it
          NS_LOG_LOGIC ("Purging stale buffered packet at offset " << i->first
                        << " (already consumed up to " << currRecvOffset << ")");
          m_numBytesInBuffer -= i->second.m_packet->GetSize ();
          i = m_streamRecvList.erase (i);
        }
      else
        {
          ++i;
        }
    }

  // Stop only past the expected offset, not at the first mismatch: an item below
  // it (a duplicate FIN, or a frame overlapping the run) must not end the run.
  for (; i != m_streamRecvList.end () && i->first <= currRecvOffset + lengthToExtract; ++i)
    {
      if (i->first == currRecvOffset + lengthToExtract)
        {
          offsetToExtract = i->first;
          lengthToExtract += i->second.m_packet->GetSize ();
        }
      NS_LOG_LOGIC ("Inspected packet with offset " << i->first);
    }

  return std::make_pair (offsetToExtract, lengthToExtract);
}

uint32_t
QuicStreamRxBuffer::Size (void) const
{
  NS_LOG_FUNCTION (this);

  // uint32_t inFlight = 0;
  // for (auto recv_it = m_streamRecvList.begin (); recv_it != m_streamRecvList.end () and !m_streamRecvList.empty (); ++recv_it)
  //   {
  //     inFlight += (*recv_it)->m_packet->GetSize ();
  //   }

  return m_numBytesInBuffer;
}

uint32_t
QuicStreamRxBuffer::Available (void) const
{
  return m_maxBuffer - m_numBytesInBuffer;
}

uint32_t
QuicStreamRxBuffer::GetMaxBufferSize (void) const
{
  return m_maxBuffer;
}

void
QuicStreamRxBuffer::SetMaxBufferSize (uint32_t s)
{
  m_maxBuffer = s;
}

uint32_t
QuicStreamRxBuffer::GetFinalSize () const
{
  return m_finalSize;
}

void
QuicStreamRxBuffer::Print (std::ostream & os) const
{
  NS_LOG_FUNCTION (this);
  QuicStreamRxBuffer::QuicStreamRxPacketList::const_iterator it;
  std::stringstream ss;
  std::stringstream as;

  for (it = m_streamRecvList.begin (); it != m_streamRecvList.end (); ++it)
    {
      it->second.Print (ss);
    }

  os << "Stream Recv list: \n" << ss.str () << "\n\nCurrent Status: "
     << "\nNumber of receptions = " << m_streamRecvList.size ()
     << "\nReceived Size = " << m_numBytesInBuffer;
  if (m_recvFin)
    {
      os << "\nFinal Size = " << m_finalSize;

    }

}

} //namepsace ns3
