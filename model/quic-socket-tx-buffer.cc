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
 *
 */

#include "quic-socket-tx-buffer.h"

#include <algorithm>
#include <iostream>
#include <sstream>
#include "ns3/simulator.h"

#include "ns3/packet.h"
#include "ns3/log.h"
#include "ns3/abort.h"
#include "quic-subheader.h"
#include "quic-socket-base.h"
#include "quic-socket-tx-scheduler.h"
#include "quic-socket-tx-edf-scheduler.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicSocketTxBuffer");

TypeId QuicSocketTxItem::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicSocketTxItem")
    .SetParent<Object>()
    .SetGroupName ("Internet")
    .AddConstructor<QuicSocketTxItem>()
//    .AddTraceSource ("UnackSequence",
//                     "First unacknowledged sequence number (SND.UNA)",
//                     MakeTraceSourceAccessor (&QuicSocketTxBuffer::m_sentSize),
//                     "ns3::SequenceNumber32TracedValueCallback")
  ;
  return tid;
}

QuicSocketTxItem::QuicSocketTxItem ()
  : m_packet (0),
    m_packetNumber (0),
    m_lost (false),
    m_retrans (false),
    m_sacked (false),
    m_acked (false),
    m_isStream (false),
    m_isCrypto (false),
    m_lastSent (Time::Min ()),
    m_delivered (0),
    m_deliveredTime (Time::Max ()),
    m_firstSentTime (Seconds (0)),
    m_isAppLimited (false),
    m_ackBytesSent (0),
    m_wireBytes (0),
    m_payloadBytes (0)
{
  m_generated = Simulator::Now ();
}

QuicSocketTxItem::QuicSocketTxItem (const QuicSocketTxItem &other)
  : m_packet (other.m_packet),
    m_packetNumber (other.m_packetNumber),
    m_lost (other.m_lost),
    m_retrans (other.m_retrans),
    m_sacked (other.m_sacked),
    m_acked (other.m_acked),
    m_isStream (other.m_isStream),
    m_isCrypto (other.m_isCrypto),
    m_lastSent (other.m_lastSent),
    m_generated (other.m_generated),
    m_wireBytes (other.m_wireBytes),
    m_payloadBytes(other.m_payloadBytes)
{
  m_packet = other.m_packet->Copy ();
}

void QuicSocketTxItem::Print (std::ostream &os) const
{
  NS_LOG_FUNCTION (this);
  os << "[SN " << m_packetNumber.GetValue () << " - Last Sent: " << m_lastSent
     << " size " << m_packet->GetSize () << "]";

  if (m_lost)
    {
      os << "|lost|";
    }
  if (m_retrans)
    {
      os << "|retr|";
    }
  if (m_sacked)
    {
      os << "|ackd|";
    }
}

uint32_t 
QuicSocketTxItem::GetStreamPayloadSize () const
{
  NS_LOG_FUNCTION (this);
  
  if (!m_isStream)
    {
      return 0; // Non-STREAM frames don't count toward flow control
    }
  
  // For STREAM frames, the payload is stored in m_payloadBytes
  return m_payloadBytes;
}

void QuicSocketTxItem::MergeItems (QuicSocketTxItem &t1, QuicSocketTxItem &t2)
{

  if (t1.m_sacked == true && t2.m_sacked == true)
    {
      t1.m_sacked = true;
    }
  else
    {
      t1.m_sacked = false;
    }
  if (t1.m_acked == true && t2.m_acked == true)
    {
      t1.m_acked = true;
    }
  else
    {
      t1.m_acked = false;
    }

  if (t2.m_retrans == true && t1.m_retrans == false)
    {
      t1.m_retrans = true;
    }
  if (t1.m_lastSent < t2.m_lastSent)
    {
      t1.m_lastSent = t2.m_lastSent;
    }
  if (t2.m_lost)
    {
      t1.m_lost = true;
    }
  if (t1.m_ackTime > t2.m_ackTime)
    {
      t1.m_ackTime = t2.m_ackTime;
    }
  if (t1.m_generated > t2.m_generated)
    {
      t1.m_generated = t2.m_generated;
    }

  t1.m_packet->AddAtEnd (t2.m_packet);
}

void QuicSocketTxItem::SplitItems (QuicSocketTxItem &t1, QuicSocketTxItem &t2,
                                   uint32_t size)
{
  uint32_t initialSize = t1.m_packet->GetSize ();

  t2.m_sacked = t1.m_sacked;
  t2.m_retrans = t1.m_retrans;
  t2.m_lastSent = t1.m_lastSent;
  t2.m_lost = t1.m_lost;
  if (t1.m_lastSent < t2.m_lastSent)
    {
      t1.m_lastSent = t2.m_lastSent;
    }
  if (t2.m_lost)
    {
      t1.m_lost = true;
    }
  t2.m_generated = t1.m_generated;
  // Copy the packet into t2
  t2.m_packet = t1.m_packet->Copy ();
  // Remove the first size bytes from t2
  t2.m_packet->RemoveAtStart (size);

  // Change subheader
  QuicSubheader qsb;
  t1.m_packet->RemoveHeader (qsb);
  qsb.SetLength (t1.m_packet->GetSize () - size);
  t1.m_packet->AddHeader (qsb);

  NS_ASSERT_MSG (t2.m_packet->GetSize () == initialSize - size,
                 "Wrong size " << t2.m_packet->GetSize ());
  qsb.SetLength (t2.m_packet->GetSize ());
  t2.m_packet->AddHeader (qsb);
  // Remove the bytes from size to end from t1
  t1.m_packet->RemoveAtEnd (t1.m_packet->GetSize () - size);
  NS_ASSERT_MSG (t1.m_packet->GetSize () == size,
                 "Wrong size " << t1.m_packet->GetSize ());
}

NS_OBJECT_ENSURE_REGISTERED (QuicSocketTxBuffer);

TypeId QuicSocketTxBuffer::GetTypeId (void)
{
  static TypeId tid =
    TypeId ("ns3::QuicSocketTxBuffer").SetParent<Object>().SetGroupName (
      "Internet").AddConstructor<QuicSocketTxBuffer>()
//    .AddTraceSource ("UnackSequence",
//                     "First unacknowledged sequence number (SND.UNA)",
//                     MakeTraceSourceAccessor (&QuicSocketTxBuffer::m_sentSize),
//                     "ns3::SequenceNumber32TracedValueCallback")
  ;
  return tid;
}

QuicSocketTxBuffer::QuicSocketTxBuffer () :
  m_maxBuffer (32768), m_cryptoSize (0), m_sentSize (0), m_numCryptoFramesInBuffer (
    0)
{
  for (int i = 0; i < 3; i++)
    {
      m_cryptoList[i] = QuicTxPacketList ();
      m_sentList[i] = QuicTxPacketList ();
      m_inFlightWire[i] = 0;
      m_inFlightPayload[i] = 0;
      m_inFlightDirty[i] = false;
    }
}

QuicSocketTxBuffer::~QuicSocketTxBuffer (void)
{
  for (int i = 0; i < 3; i++)
    {
      m_sentList[i] = QuicTxPacketList ();
      m_cryptoList[i] = QuicTxPacketList ();
    }
  m_sentSize = 0;
  m_cryptoSize = 0;
}

void
QuicSocketTxBuffer::Print (std::ostream &os) const
{
  NS_LOG_FUNCTION (this);
  std::stringstream ss;
  std::stringstream as;

  for (int i = 0; i < 3; i++)
    {
      for (auto it = m_sentList[i].begin (); it != m_sentList[i].end (); ++it)
        {
          (*it)->Print (ss);
        }
      for (auto it = m_cryptoList[i].begin (); it != m_cryptoList[i].end (); ++it)
        {
          (*it)->Print (as);
        }
    }

  os << Simulator::Now ().GetSeconds () << "\nCRYPTO frame list: \n" << as.str ()
     << "\n\nSent list: \n" << ss.str () << "\n\nCurrent Status: "
     << "\nNumber of transmissions = " << m_sentList[0].size() + m_sentList[1].size() + m_sentList[2].size()
     << "\nSent Size = " << m_sentSize
     << "\nNumber of CRYPTO frames waiting = "
     << m_cryptoList[0].size() + m_cryptoList[1].size() + m_cryptoList[2].size() << "\nCRYPTO waiting packet size = "
     << m_cryptoSize;
}

bool QuicSocketTxBuffer::Add (Ptr<Packet> p, PacketNumberSpace space, bool urgent)
{
  NS_LOG_FUNCTION (this << p << space);

  if (p->GetSize () == 0)
    {
      NS_LOG_WARN ("Discarded. Try to insert empty packet.");
      return false;
    }

  QuicSubheader qsb;
  uint32_t headerSize = p->PeekHeader (qsb);
  NS_LOG_INFO (
    "Try to append " << p->GetSize () << " bytes " << ", availSize=" << Available () << " offset " << qsb.GetOffset () << " on stream " << qsb.GetStreamId () << " space " << space);

  if (p->GetSize () <= Available ())
    {
      Ptr<QuicSocketTxItem> item = CreateObject<QuicSocketTxItem> ();
      item->m_packet = p;
      item->m_space = space;
      // check to which stream this packet belongs to
      bool isStream = false;
      bool isCrypto = false;
      if (headerSize)
        {
          isStream = qsb.IsStream ();
          isCrypto = qsb.IsCrypto ();
        }
      else
        {
          NS_ABORT_MSG ("No QuicSubheader in this QUIC frame " << p);
        }
      item->m_isStream = isStream;
      item->m_isCrypto = isCrypto;
      m_numCryptoFramesInBuffer += isCrypto;
      if (isCrypto)
        {
          m_cryptoList[space].insert (m_cryptoList[space].end (), item);
          m_cryptoSize += item->m_packet->GetSize ();
        }
      else
        {
          // Reuse the scheduler's retx=true path to jump the queue: it is not
          // a real retransmission, but it gets the same "send first" priority.
          m_scheduler->Add (item, urgent);
        }

      NS_LOG_INFO (
        "Update: Application Size = " << m_scheduler->AppSize () << ", offset " << qsb.GetOffset ());
      return true;
    }
  NS_LOG_WARN ("Rejected. Not enough room to buffer packet.");
  return false;
}

Ptr<Packet> QuicSocketTxBuffer::NextCryptoSequence (
  const SequenceNumber32 seq, PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << seq << space);

  Ptr<QuicSocketTxItem> outItem = CreateObject<QuicSocketTxItem> ();

  QuicTxPacketList::iterator it = m_cryptoList[space].begin ();
  if (it != m_cryptoList[space].end ())
    {
      Ptr<Packet> currentPacket = (*it)->m_packet;
      outItem->m_packetNumber = seq;
      outItem->m_space = space;
      outItem->m_lastSent = Now ();
      outItem->m_packet = currentPacket;
      outItem->m_isCrypto = (*it)->m_isCrypto;
      
      // CRYPTO frames don't count toward flow control, only wire size matters
      outItem->m_wireBytes = currentPacket->GetSize ();
      outItem->m_payloadBytes = 0;
      
      m_cryptoList[space].erase (it);
      m_cryptoSize -= currentPacket->GetSize ();
      m_sentList[space].insert (m_sentList[space].end (), outItem);
      m_sentSize += outItem->m_wireBytes;
      NoteItemSent (space, outItem);
      --m_numCryptoFramesInBuffer;
      Ptr<Packet> toRet = outItem->m_packet;
      return toRet;
    }
  return 0;
}

Ptr<Packet> QuicSocketTxBuffer::NextSequence (uint32_t numBytes,
                                              const SequenceNumber32 seq,
                                              PacketNumberSpace space,
                                              bool singleItem)
{
  NS_LOG_FUNCTION (this << numBytes << seq << space << singleItem);

  Ptr<QuicSocketTxItem> outItem = GetNewSegment (numBytes, space, singleItem);

  if (outItem)
    {
      NS_LOG_INFO ("Extracting " << outItem->m_packet->GetSize () << " bytes");
      outItem->m_packetNumber = seq;
      outItem->m_lastSent = Now ();
      Ptr<Packet> toRet = outItem->m_packet->Copy();
      return toRet;
    }
  else
    {
      NS_LOG_INFO ("Empty packet");
      return Create<Packet>();
    }

}

Ptr<QuicSocketTxItem> QuicSocketTxBuffer::GetNewSegment (uint32_t numBytes, PacketNumberSpace space, bool singleItem)
{
  NS_LOG_FUNCTION (this << numBytes << space << singleItem);

  Ptr<QuicSocketTxItem> outItem = m_scheduler->GetNewSegment (numBytes, singleItem);

  if (outItem->m_packet->GetSize () > 0)
    {
      NS_LOG_LOGIC ("Adding packet to sent buffer");
      outItem->m_space = space;
      
      // Extract payload size from ALL STREAM frames in the packet
      outItem->m_wireBytes = outItem->m_packet->GetSize ();
      outItem->m_payloadBytes = 0;
      
      if (outItem->m_isStream)
        {
          // Parse ALL frames in the packet to sum STREAM payloads
          Ptr<Packet> tempPacket = outItem->m_packet->Copy ();
          
          while (tempPacket->GetSize () > 0)
            {
              QuicSubheader sub;
              tempPacket->RemoveHeader (sub);
              
              if (sub.IsStream ())
                {
                  // Add this STREAM frame's payload
                  outItem->m_payloadBytes += sub.GetLength ();
                }
              
              if (sub.IsPadding ())
                {
                  // Padding is always last
                  break;
                }
              else
                {
                  // Skip the frame data
                  uint32_t frameDataSize = sub.GetLength ();
                  if (frameDataSize > 0 && tempPacket->GetSize () >= frameDataSize)
                    {
                      tempPacket->RemoveAtStart (frameDataSize);
                    }
                  else if (frameDataSize > 0)
                    {
                      NS_LOG_WARN ("Frame data size " << frameDataSize 
                                   << " exceeds remaining packet size " 
                                   << tempPacket->GetSize ());
                      break;
                    }
                }
            }
          
          NS_LOG_INFO ("Packet has total STREAM payload: " << outItem->m_payloadBytes
                      << " bytes (wire size: " << outItem->m_wireBytes << ")");
        }
      
      m_sentList[space].insert (m_sentList[space].end (), outItem);
      m_sentSize += outItem->m_wireBytes;
      NoteItemSent (space, outItem);
    }

  NS_LOG_INFO (
    "Update: Sent Size = " << m_sentSize << " remaining App Size " << m_scheduler->AppSize ());

  return outItem;
}

std::vector<Ptr<QuicSocketTxItem> > QuicSocketTxBuffer::OnAckUpdate (
  Ptr<TcpSocketState> tcb, const uint32_t largestAcknowledged,
  const std::vector<uint32_t> &additionalAckBlocks,
  const std::vector<uint32_t> &gaps,
  PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << space);

  MarkInFlightDirty (space);

  std::vector<uint32_t> compAckBlocks = additionalAckBlocks;
  std::vector<uint32_t> compGaps = gaps;

  std::vector<Ptr<QuicSocketTxItem> > newlyAcked;
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));

  compAckBlocks.insert (compAckBlocks.begin (), largestAcknowledged);
  uint32_t ackBlockCount = compAckBlocks.size ();

  m_socket->m_pnSpaces[space].m_largestAcked = std::max (m_socket->m_pnSpaces[space].m_largestAcked.GetValue (), largestAcknowledged);

  std::vector<uint32_t>::const_iterator ack_it = compAckBlocks.begin ();
  std::vector<uint32_t>::const_iterator gap_it = compGaps.begin ();

  std::stringstream gap_print;
  for (auto i = gaps.begin (); i != gaps.end (); ++i)
    {
      gap_print << (*i) << " ";
    }

  std::stringstream block_print;
  for (auto i = compAckBlocks.begin (); i != compAckBlocks.end (); ++i)
    {
      block_print << (*i) << " ";
    }

  NS_LOG_INFO (
    "Space: " << space << " Largest ACK: " << largestAcknowledged << ", blocks: " << block_print.str () << ", gaps: " << gap_print.str ());

  // Iterate over the ACK blocks and gaps in a single reverse sweep of the
  // sent list, shared across all blocks: the list is ordered ascending by
  // packet number and the (block, gap) pairs are ordered descending, so
  // sent_it only ever needs to move forward-in-reverse. Previously this
  // restarted from rbegin() for every ACK block, rescanning (and
  // re-skipping, since already-sacked items are a no-op) the newest part
  // of the list once per block -- O(ackBlockCount * listSize) instead of
  // O(listSize). With a very large in-flight backlog (e.g. after a long
  // DTN outage) and multiple SACK blocks in one ACK, that difference is
  // the dominant cost of processing the ACK.
  auto sent_it = m_sentList[space].rbegin ();
  for (uint32_t numAckBlockAnalyzed = 0; numAckBlockAnalyzed < ackBlockCount;
       ++numAckBlockAnalyzed, ++ack_it, ++gap_it)
    {
      while (sent_it != m_sentList[space].rend ())
        {
          NS_LOG_LOGIC (
            "Consider packet " << (*sent_it)->m_packetNumber << " (ACK block " << SequenceNumber32 ((*ack_it)) << ")");
          // The packet is in the next gap
          bool inGap = (gap_it < compGaps.end ())
            && ((*sent_it)->m_packetNumber
                <= SequenceNumber32 ((*gap_it)));
          if (inGap)               // Just for optimization we suppose All is perfectly ordered
            {
              NS_LOG_LOGIC (
                "Packet " << (*sent_it)->m_packetNumber << " missing");
              break;
            }
          // The packet is in the current block: ACK it
          NS_LOG_LOGIC ("Packet " << (*sent_it)->m_packetNumber << " ACKed");
          bool notInGap =
            ((gap_it >= compGaps.end ())
             || ((*sent_it)->m_packetNumber
                 > SequenceNumber32 ((*gap_it))));

          if ((*sent_it)->m_packetNumber <= SequenceNumber32 ((*ack_it))
              and notInGap and (*sent_it)->m_sacked == false)
            {
              (*sent_it)->m_sacked = true;
              (*sent_it)->m_ackTime = Now ();
              newlyAcked.push_back ((*sent_it));
              UpdateRateSample ((*sent_it));
            }

          ++sent_it;
        }
    }
  NS_LOG_LOGIC ("Mark lost packets");
  // RFC 9002 Appendix A.10: DetectAndRemoveLostPackets
  m_socket->m_pnSpaces[space].m_lossTime = Seconds (0);
  Time loss_delay = std::max (tcbd->m_kTimeThreshold * std::max (tcbd->m_latestRtt, tcbd->m_smoothedRtt), MilliSeconds (1)); // kGranularity = 1ms
  Time lost_send_time = Now () - loss_delay;

  // Single forward pass folding loss detection together with
  // CleanSentList's sacked-packet cleanup (previously two full walks of
  // the same list back to back). Sacked and lost are mutually exclusive
  // here (loss detection never marks a sacked packet lost), so per item
  // this is either "clean it up" or "run loss detection" -- same net
  // effect as the two separate passes, one traversal instead of two.
  auto sweep_it = m_sentList[space].begin ();
  while (sweep_it != m_sentList[space].end ())
    {
      Ptr<QuicSocketTxItem> unacked = *sweep_it;

      if (unacked->m_sacked)
        {
          unacked->m_acked = true;
          // Subtract the tracked wire bytes
          // Use logic to prevent underflow if logic ever desyncs
          if (m_sentSize >= unacked->m_wireBytes)
            {
              m_sentSize -= unacked->m_wireBytes;
            }
          else
            {
              m_sentSize = 0;
              NS_LOG_WARN ("m_sentSize underflow detected in CleanSentList");
            }

          sweep_it = m_sentList[space].erase (sweep_it);
          NS_LOG_LOGIC ("Cleaning packet " << unacked->m_packetNumber << " from sent buffer");
          continue;
        }

      if (!unacked->m_lost && unacked->m_packetNumber <= m_socket->m_pnSpaces[space].m_largestAcked)
        {
          // Mark packet as lost, or set time when it should be marked.
          if (unacked->m_lastSent <= lost_send_time ||
              m_socket->m_pnSpaces[space].m_largestAcked.GetValue () >= unacked->m_packetNumber.GetValue () + tcbd->m_kPacketThreshold)
            {
              unacked->m_lost = true;
              NS_LOG_INFO ("Packet " << unacked->m_packetNumber << " in space " << space << " marked lost. PN distance "
                           << (m_socket->m_pnSpaces[space].m_largestAcked.GetValue () - unacked->m_packetNumber.GetValue ())
                           << " or time distance " << (Now () - unacked->m_lastSent).GetSeconds () << "s");
            }
          else
            {
              if (m_socket->m_pnSpaces[space].m_lossTime == Seconds (0))
                {
                  m_socket->m_pnSpaces[space].m_lossTime = unacked->m_lastSent + loss_delay;
                }
              else
                {
                  m_socket->m_pnSpaces[space].m_lossTime = std::min (m_socket->m_pnSpaces[space].m_lossTime, unacked->m_lastSent + loss_delay);
                }
            }
        }

      ++sweep_it;
    }

  // Clear loss detection variables if no data in flight
  if (BytesInFlight(space) == 0)
  {
      m_socket->m_pnSpaces[space].m_ackElicitingOutstanding = false;
      m_socket->m_pnSpaces[space].m_lossTime = Seconds(0);
  }
  return newlyAcked;
}

void QuicSocketTxBuffer::ResetSentList (uint32_t keepItems)
{
  NS_LOG_FUNCTION (this << keepItems);
  for (int i = 0; i < 3; i++)
    {
      MarkInFlightDirty (static_cast<PacketNumberSpace> (i));
      uint32_t kept = 0;
      for (auto sent_it = m_sentList[i].rbegin ();
           sent_it != m_sentList[i].rend () and !m_sentList[i].empty ();
           ++sent_it, kept++)
        {
          if (kept >= keepItems && !(*sent_it)->m_sacked)
            {
              (*sent_it)->m_lost = true;
            }
        }
    }
}

bool QuicSocketTxBuffer::MarkAsLost (const SequenceNumber32 seq, PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << seq << space);

  MarkInFlightDirty (space);
  bool found = false;
  for (auto sent_it = m_sentList[space].begin ();
       sent_it != m_sentList[space].end () and !m_sentList[space].empty (); ++sent_it)
    {
      if ((*sent_it)->m_packetNumber == seq)
        {
          found = true;
          (*sent_it)->m_lost = true;
        }
    }
  return found;
}

uint32_t QuicSocketTxBuffer::Retransmission (SequenceNumber32 packetNumber, PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << space);
  NS_ASSERT_MSG(m_socket, "m_socket must be set before calling Retransmission");

  MarkInFlightDirty (space);
  
  uint32_t toRetx = 0;

  auto sent_it = m_sentList[space].begin ();
  while (sent_it != m_sentList[space].end ())
    {
      Ptr<QuicSocketTxItem> item = *sent_it;
      if (item->m_lost)
        {
          NS_LOG_INFO ("Processing lost packet " << item->m_packetNumber 
                       << " isCrypto=" << item->m_isCrypto 
                       << " isStream=" << item->m_isStream
                       << " size=" << item->m_packet->GetSize());
          
          if (item->m_isCrypto)
            {
              // CRYPTO packets are retransmitted whole with new packet numbers
              Ptr<QuicSocketTxItem> retx = CreateObject<QuicSocketTxItem>();
              retx->m_packetNumber = m_socket->m_pnSpaces[space].m_nextTxSequence++;
              retx->m_space = space;
              retx->m_isStream = false;
              retx->m_isCrypto = true;
              retx->m_packet = item->m_packet->Copy();
              retx->m_lost = false;
              retx->m_retrans = true;
              
              NS_LOG_INFO("Retransmitting CRYPTO packet " << item->m_packetNumber 
                          << " as " << retx->m_packetNumber);
              
              // Add to CRYPTO list for immediate transmission
              m_cryptoList[space].insert(m_cryptoList[space].begin(), retx);
              m_cryptoSize += retx->m_packet->GetSize();
              m_numCryptoFramesInBuffer++;
              
              toRetx += retx->m_packet->GetSize();
            }
          else  // Data packet - extract STREAM frames and store in retx list
            {
              Ptr<Packet> lostPacket = item->m_packet->Copy();
              
              while (lostPacket->GetSize() > 0)
                {
                  QuicSubheader sub;
                  lostPacket->RemoveHeader(sub);
                  
                  if (sub.IsStream())
                    {
                      uint32_t dataLen = sub.GetLength();
                      if (dataLen > 0 && lostPacket->GetSize() >= dataLen)
                        {
                          // Extract raw payload data
                          Ptr<Packet> streamData = lostPacket->CreateFragment(0, dataLen);
                          lostPacket->RemoveAtStart(dataLen);
                          
                          // Create NEW STREAM frame header
                          QuicSubheader newSub = QuicSubheader::CreateStreamSubHeader(
                              sub.GetStreamId(),
                              sub.GetOffset(),
                              dataLen,
                              !(sub.GetOffset() == 0),
                              true,
                              sub.IsStreamFin()
                          );
                          
                          streamData->AddHeader(newSub);
                          
                          // Create new TxItem
                          Ptr<QuicSocketTxItem> retx = CreateObject<QuicSocketTxItem>();
                          retx->m_packet = streamData;
                          retx->m_isStream = true;
                          retx->m_isCrypto = false;
                          // Add it back to the scheduler
                          m_scheduler->Add(retx, true);
                          toRetx += streamData->GetSize();
                          
                          NS_LOG_INFO("Queuing STREAM retx: stream=" << sub.GetStreamId() 
                                     << " offset=" << sub.GetOffset() 
                                     << " len=" << dataLen 
                                     << " from lost packet " << item->m_packetNumber);
                        }
                      else if (dataLen > 0)
                        {
                          NS_LOG_WARN("STREAM frame data length " << dataLen 
                                      << " exceeds remaining packet size " 
                                      << lostPacket->GetSize());
                          break;
                        }
                      else
                        {
                          // Zero-length STREAM frame (possibly FIN-only)
                          Ptr<Packet> streamData = Create<Packet>();
                          
                          QuicSubheader newSub = QuicSubheader::CreateStreamSubHeader(
                              sub.GetStreamId(),
                              sub.GetOffset(),
                              0,
                              !(sub.GetOffset() == 0),
                              false,
                              sub.IsStreamFin()
                          );
                          
                          streamData->AddHeader(newSub);
                          
                          Ptr<QuicSocketTxItem> retx = CreateObject<QuicSocketTxItem>();
                          retx->m_packet = streamData;
                          retx->m_isStream = true;
                          retx->m_isCrypto = false;
                          
                          m_scheduler->Add(retx, true);
                          toRetx += streamData->GetSize();
                          
                          NS_LOG_INFO("Re-queuing zero-length STREAM frame " << sub.GetStreamId() 
                                     << " offset " << sub.GetOffset());
                        }
                    }
                  else if (sub.IsPadding())
                    {
                      break;
                    }
                  else
                    {
                      // Handle other frame types (MAX_DATA, MAX_STREAM_DATA, etc.)
                      // These control frames should be retransmitted as-is
                      uint32_t frameLen = sub.GetLength();
                      
                      Ptr<Packet> frameData = Create<Packet>();
                      
                      if (frameLen > 0 && lostPacket->GetSize() >= frameLen)
                        {
                          // Extract frame data using CreateFragment
                          frameData = lostPacket->CreateFragment(0, frameLen);
                          lostPacket->RemoveAtStart(frameLen);
                        }
                      
                      // Re-add the header
                      frameData->AddHeader(sub);
                      
                      Ptr<QuicSocketTxItem> retx = CreateObject<QuicSocketTxItem>();
                      retx->m_packet = frameData;
                      retx->m_isStream = false;
                      retx->m_isCrypto = false;
                      
                      m_scheduler->Add(retx, true);
                      toRetx += frameData->GetSize();
                      
                      NS_LOG_INFO("Re-queuing control frame type " << (int)sub.GetFrameType());
                    }
                }
              
              NS_LOG_INFO("Finished processing STREAM data from lost packet " << item->m_packetNumber);
            }
          
          // Update m_sentSize (guarded subtraction)
          uint32_t bytesToRemove = item->m_wireBytes > 0 ? item->m_wireBytes : item->m_packet->GetSize();
          if (m_sentSize >= bytesToRemove)
            {
              m_sentSize -= bytesToRemove;
            }
          else
            {
              NS_LOG_WARN ("m_sentSize underflow detected in Retransmission. Resetting to 0.");
              m_sentSize = 0;
            }
          
          // Remove lost item from sent list
          sent_it = m_sentList[space].erase (sent_it);
        }
      else
        {
          // Packet is not lost, just move to the next item
          sent_it++;
        }
    }
  NS_LOG_INFO ("Retransmission() complete. m_sentSize=" << m_sentSize
               << " AppSize=" << AppSize()
               << " m_cryptoSize=" << m_cryptoSize
               << " toRetx=" << toRetx);

  return toRetx;
}

uint32_t QuicSocketTxBuffer::RetransmitOldestOutstanding (PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << space);

  // m_sentList is ordered ascending by packet number, so the first
  // not-yet-lost, ack-eliciting entry is the oldest outstanding one.
  for (auto &item : m_sentList[space])
    {
      if (!item->m_lost && (item->m_isStream || item->m_isCrypto))
        {
          item->m_lost = true;
          break;
        }
    }

  return Retransmission (SequenceNumber32 (0), space);
}

std::vector<Ptr<QuicSocketTxItem> > QuicSocketTxBuffer::DetectLostPackets (Ptr<TcpSocketState> tcb, PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << space);

  MarkInFlightDirty (space);

  std::vector<Ptr<QuicSocketTxItem>> newly_lost;
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  NS_ASSERT_MSG (tcbd, "tcb is not a QuicSocketState");
  NS_ASSERT_MSG (m_socket, "m_socket is null in DetectLostPackets");

  m_socket->m_pnSpaces[space].m_lossTime = Seconds (0);
  Time loss_delay = std::max (tcbd->m_kTimeThreshold * std::max (tcbd->m_latestRtt, tcbd->m_smoothedRtt), tcbd->m_kGranularity);
  Time lost_send_time = Now () - loss_delay;

  NS_LOG_INFO ("Entering loss detection process with --> Time threshold: " << lost_send_time.GetSeconds()
              << "and LargestAcked: " << m_socket->m_pnSpaces[space].m_largestAcked);
  auto sent_it = m_sentList[space].begin ();
  while (sent_it != m_sentList[space].end ())
    {
      Ptr<QuicSocketTxItem> unacked = *sent_it;

      // Skip packets already handled (sacked)
      if (unacked->m_sacked) { 
          sent_it++; 
          continue; 
      }

      // Check if already marked as lost
      if (unacked->m_lost) {
        newly_lost.push_back (unacked);
        NS_LOG_INFO ("Packet " << unacked->m_packetNumber << " in space " << space << " already marked lost.");
        sent_it++;
        continue;
      }

      // RFC 9002: Loss detection should check only packets sent before the largestAcked
      if (unacked->m_packetNumber > m_socket->m_pnSpaces[space].m_largestAcked) {
          sent_it++;
          continue;
      }

      bool is_lost = false;

      // RFC 9002 Section 6.1.1: Time-based loss detection
      // A packet is declared lost if it was sent long enough ago
      if (unacked->m_lastSent <= lost_send_time) {
        is_lost = true;
        NS_LOG_INFO ("Packet " << unacked->m_packetNumber << " in space " << space << " detected lost (time-based). Sent at " << unacked->m_lastSent.GetSeconds());
      }

      // RFC 9002 Section 6.1.2: Packet-based loss detection
      // A packet is declared lost if a packet that was sent after it has been acknowledged
      // and the packet number gap is >= kPacketThreshold
      if (unacked->m_packetNumber < m_socket->m_pnSpaces[space].m_largestAcked &&
          m_socket->m_pnSpaces[space].m_largestAcked.GetValue () >= unacked->m_packetNumber.GetValue () + tcbd->m_kPacketThreshold) {
        is_lost = true;
        NS_LOG_INFO ("Packet " << unacked->m_packetNumber << " in space " << space << " detected lost (packet-based).");
      }

      if (is_lost) {
        unacked->m_lost = true;
        newly_lost.push_back (unacked);
        sent_it++;
        continue;
      }
      else
        {
          // Update the loss timer for future checks
          Time expected_loss_time = unacked->m_lastSent + loss_delay;
          if (expected_loss_time <= Now()) {
              expected_loss_time = Now() + tcbd->m_kGranularity;
          }
          if (m_socket->m_pnSpaces[space].m_lossTime == Seconds (0) || expected_loss_time < m_socket->m_pnSpaces[space].m_lossTime) {
              m_socket->m_pnSpaces[space].m_lossTime = expected_loss_time;
          }
          sent_it++;
        }
    }
  return newly_lost;
}

uint32_t QuicSocketTxBuffer::GetLost ()
{
  NS_LOG_FUNCTION (this);
  uint32_t lostCount = 0;
  for (int i = 0; i < 3; i++)
    {
      for (auto sent_it = m_sentList[i].begin ();
           sent_it != m_sentList[i].end () and !m_sentList[i].empty (); ++sent_it)
        {
          if ((*sent_it)->m_lost)
            {
              lostCount += (*sent_it)->m_packet->GetSize ();
            }
        }
    }
  return lostCount;
}

uint32_t QuicSocketTxBuffer::Available (void) const
{
  uint32_t appSize = m_scheduler->AppSize ();
  uint32_t totalUsed = m_cryptoSize + appSize + m_sentSize;
  
  if (totalUsed >= m_maxBuffer)
    {
      return 0;
    }
  
  return m_maxBuffer - totalUsed;
}

uint32_t QuicSocketTxBuffer::GetMaxBufferSize (void) const
{
  return m_maxBuffer;
}

void QuicSocketTxBuffer::SetMaxBufferSize (uint32_t n)
{
  m_maxBuffer = n;
}

uint32_t QuicSocketTxBuffer::AppSize (void) const
{
  return m_cryptoSize + m_scheduler->AppSize ();
}

uint32_t QuicSocketTxBuffer::GetNumCryptoFramesInBuffer (PacketNumberSpace space) const
{
  return m_cryptoList[space].size ();
}

uint32_t QuicSocketTxBuffer::PeekCryptoFrameSize (PacketNumberSpace space) const
{
  if (m_cryptoList[space].empty ())
    {
      return 0;
    }
  return m_cryptoList[space].front ()->m_packet->GetSize ();
}

void QuicSocketTxBuffer::MarkInFlightDirty (PacketNumberSpace space)
{
  m_inFlightDirty[space] = true;
}

void QuicSocketTxBuffer::NoteItemSent (PacketNumberSpace space, Ptr<QuicSocketTxItem> item)
{
  if (m_inFlightDirty[space])
    {
      // The next reader rebuilds the totals from scratch; nothing to keep up to date.
      return;
    }
  // A freshly sent item is neither sacked nor lost, so it always counts as in flight.
  m_inFlightWire[space] += item->m_wireBytes > 0 ? item->m_wireBytes : item->m_packet->GetSize ();
  m_inFlightPayload[space] += item->GetStreamPayloadSize ();
}

void QuicSocketTxBuffer::AssertInFlightConsistent (PacketNumberSpace space) const
{
#ifdef NS3_ASSERT_ENABLE
  if (m_inFlightDirty[space])
    {
      // Stale by design: the next reader rebuilds the totals, so there is nothing to check.
      return;
    }

  uint32_t wire = 0;
  uint32_t payload = 0;
  for (auto const& item : m_sentList[space])
    {
      if (!item->m_sacked && !item->m_lost)
        {
          wire += item->m_wireBytes > 0 ? item->m_wireBytes : item->m_packet->GetSize ();
          payload += item->GetStreamPayloadSize ();
        }
    }

  NS_ASSERT_MSG (wire == m_inFlightWire[space] && payload == m_inFlightPayload[space],
                 "In-flight cache out of sync in packet number space " << space
                 << ": cached wire=" << m_inFlightWire[space] << " actual=" << wire
                 << ", cached payload=" << m_inFlightPayload[space] << " actual=" << payload
                 << ". A sent list was mutated without updating the totals or marking the "
                 "space dirty -- see MarkInFlightDirty().");
#endif
}

void QuicSocketTxBuffer::RefreshInFlight (PacketNumberSpace space) const
{
  AssertInFlightConsistent (space);

  if (!m_inFlightDirty[space])
    {
      return;
    }
  uint32_t wire = 0;
  uint32_t payload = 0;
  for (auto const& item : m_sentList[space])
    {
      if (!item->m_sacked && !item->m_lost)
        {
          wire += item->m_wireBytes > 0 ? item->m_wireBytes : item->m_packet->GetSize ();
          payload += item->GetStreamPayloadSize ();
        }
    }
  m_inFlightWire[space] = wire;
  m_inFlightPayload[space] = payload;
  m_inFlightDirty[space] = false;
}

uint32_t QuicSocketTxBuffer::BytesInFlight () const
{
  NS_LOG_FUNCTION (this);
  uint32_t inFlight = 0;
  for (int i = 0; i < 3; i++)
    {
      inFlight += BytesInFlight (static_cast<PacketNumberSpace> (i));
    }
  NS_LOG_INFO (
    "Compute total bytes in flight " << inFlight << " m_sentSize " << m_sentSize << " m_appSize " << m_cryptoSize + (m_scheduler ? m_scheduler->AppSize () : 0));
  return inFlight;
}

uint32_t QuicSocketTxBuffer::BytesInFlight (PacketNumberSpace space) const
{
  RefreshInFlight (space);
  return m_inFlightWire[space];
}

uint32_t QuicSocketTxBuffer::GetHandshakeInFlight () const
{
  NS_LOG_FUNCTION (this);
  RefreshInFlight (INITIAL_DATA);
  RefreshInFlight (HANDSHAKE_DATA);
  return m_inFlightWire[INITIAL_DATA] + m_inFlightWire[HANDSHAKE_DATA];
}

void QuicSocketTxBuffer::SetQuicSocketState (Ptr<QuicSocketState> tcb)
{
  NS_LOG_FUNCTION (this);
  m_tcb = tcb;
}

void QuicSocketTxBuffer::SetScheduler (Ptr<QuicSocketTxScheduler> sched)
{
  NS_LOG_FUNCTION (this);
  m_scheduler = sched;
}

void QuicSocketTxBuffer::SetSocket (Ptr<QuicSocketBase> socket)
{
  NS_LOG_FUNCTION (this);
  m_socket = socket;
}

void QuicSocketTxBuffer::UpdatePacketSent (SequenceNumber32 seq, uint32_t sz, PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << seq << sz << space);

  if (!m_tcb or sz == 0)
    {
      return;
    }

  if (m_tcb->m_bytesInFlight.Get () == 0)
    {
      m_tcb->m_firstSentTime = Simulator::Now ();
      m_tcb->m_deliveredTime = Simulator::Now ();
    }

  Ptr<QuicSocketTxItem> item;
  for (auto it = m_sentList[space].rbegin (); it != m_sentList[space].rend (); ++it)
    {
      if ((*it)->m_packetNumber == seq)
        {
          item = *it;
          break;
        }
    }
  if (!item)
    {
      NS_LOG_WARN ("Packet " << seq << " in space " << space << " not found in sent list during UpdatePacketSent");
      return;
    }
  if (m_sentSize >= item->m_wireBytes)
    {
      m_sentSize -= item->m_wireBytes;
    } 
  else
    {
      m_sentSize = 0;
      NS_LOG_WARN("m_sentSize underflow detected in UpdatePacketSent");
    }

  m_sentSize += sz;

  // Runs once per sent packet, so resize the cached total in place rather than
  // dirtying the space (which would force a full rescan on the next send).
  if (!m_inFlightDirty[space] && !item->m_sacked && !item->m_lost)
    {
      uint32_t previous = item->m_wireBytes > 0 ? item->m_wireBytes : item->m_packet->GetSize ();
      m_inFlightWire[space] = m_inFlightWire[space] - previous + sz;
    }

  item->m_wireBytes = sz;
  item->m_firstSentTime = m_tcb->m_firstSentTime;
  item->m_deliveredTime = m_tcb->m_deliveredTime;
  item->m_isAppLimited = (m_tcb->m_appLimitedUntil > m_tcb->m_delivered);
  item->m_delivered = m_tcb->m_delivered;
  item->m_ackBytesSent = m_tcb->m_ackBytesSent;
}

void QuicSocketTxBuffer::DiscardSpace (PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << space);

  MarkInFlightDirty (space);

  // 1. Correctly update m_sentSize before clearing sent list
  for (auto const& item : m_sentList[space])
    {
      // Use wireBytes if available, otherwise packet size
      uint32_t size = item->m_wireBytes > 0 ? item->m_wireBytes : item->m_packet->GetSize();
      
      if (m_sentSize >= size)
        {
          m_sentSize -= size;
        }
      else
        {
          m_sentSize = 0;
          NS_LOG_WARN ("m_sentSize underflow detected in DiscardSpace");
        }
    }
  m_sentList[space].clear ();

  // 2. Correctly update m_cryptoSize before clearing crypto list
  for (auto const& item : m_cryptoList[space])
    {
      uint32_t size = item->m_packet->GetSize();
      
      if (m_cryptoSize >= size)
        {
          m_cryptoSize -= size;
        }
      else
        {
          m_cryptoSize = 0;
           NS_LOG_WARN ("m_cryptoSize underflow detected in DiscardSpace");
        }

      if (m_numCryptoFramesInBuffer > 0)
        {
          m_numCryptoFramesInBuffer--;
        }
    }
  m_cryptoList[space].clear ();
}

void
QuicSocketTxBuffer::UpdateAckSent (SequenceNumber32 seq, uint32_t sz, PacketNumberSpace space)
{
  if (!m_tcb or sz == 0)
    {
      return;
    }

  m_tcb->m_ackBytesSent += sz;
}

struct RateSample*
QuicSocketTxBuffer::GetRateSample ()
{
  NS_LOG_FUNCTION (this);
  return &m_rs;
}

void
QuicSocketTxBuffer::UpdateRateSample (Ptr<QuicSocketTxItem> item)
{
  NS_LOG_FUNCTION (this << item);

  if (!m_tcb or item->m_deliveredTime == Time::Max ())
    {
      // item already SACKed
      return;
    }

  // RFC 9000: m_delivered tracks STREAM payload bytes only for flow control
  // CRYPTO and other frames don't count (m_payloadBytes = 0 for those)
  m_tcb->m_delivered         += item->m_payloadBytes;
  m_tcb->m_deliveredTime      = Simulator::Now ();
  
  NS_LOG_INFO ("Delivered " << item->m_payloadBytes << " payload bytes (total delivered: " 
               << m_tcb->m_delivered << ")");

  if (item->m_delivered > m_rs.m_priorDelivered)
    {
      m_rs.m_priorDelivered   = item->m_delivered;
      m_rs.m_priorTime        = item->m_deliveredTime;
      m_rs.m_isAppLimited     = item->m_isAppLimited;
      m_rs.m_sendElapsed      = item->m_lastSent - item->m_firstSentTime;
      m_rs.m_ackElapsed       = m_tcb->m_deliveredTime - item->m_deliveredTime;
      m_tcb->m_firstSentTime  = item->m_lastSent;
      m_rs.m_priorAckBytesSent  = item->m_ackBytesSent;
    }

  /* Mark the packet as delivered once it is SACKed to avoid
   * being used again when it's cumulatively acked.
   */
  item->m_deliveredTime = Time::Max ();
  m_tcb->m_txItemDelivered = item->m_delivered;
}

bool
QuicSocketTxBuffer::GenerateRateSample ()
{
  NS_LOG_FUNCTION (this);

  if (!m_tcb)
    {
      return false;
    }

  if (m_rs.m_priorTime == Seconds (0))
    {
      return false;
    }

  m_rs.m_interval = std::max (m_rs.m_sendElapsed, m_rs.m_ackElapsed);

  m_rs.m_delivered = m_tcb->m_delivered - m_rs.m_priorDelivered;


  if (m_rs.m_ackBytesSent < m_tcb->m_ackBytesSent - m_rs.m_priorAckBytesSent or++ m_rs.m_ackBytesMaxWin > 5) //quick maxfilter implementation
    {
      m_rs.m_ackBytesSent = m_tcb->m_ackBytesSent - m_rs.m_priorAckBytesSent;
      m_rs.m_ackBytesMaxWin = 0;
    }

  uint32_t discountedDelivered = m_rs.m_delivered > m_rs.m_ackBytesSent ? m_rs.m_delivered - m_rs.m_ackBytesSent : 0U;

  if (m_rs.m_interval < m_tcb->m_minRtt)
    {
      m_rs.m_interval = Seconds (0);
      return false;
    }

  if (m_rs.m_interval != Seconds (0) && m_rs.m_interval.GetSeconds () > 0.0)
    {
      m_rs.m_deliveryRate = DataRate (discountedDelivered * 8.0 / m_rs.m_interval.GetSeconds ());
    }
  NS_LOG_DEBUG ("computed delivery rate: " << m_rs.m_deliveryRate);
  return true;
}


void QuicSocketTxBuffer::SetLatency (uint32_t streamId, Time latency)
{
  // Only relevant for the EDF scheduler
  if (m_scheduler->GetTypeId () == QuicSocketTxEdfScheduler::GetTypeId ())
    {
      (DynamicCast<QuicSocketTxEdfScheduler> (m_scheduler))->SetLatency (streamId, latency);
    }
}

Time QuicSocketTxBuffer::GetLatency (uint32_t streamId)
{
  // Only relevant for the EDF scheduler
  if (m_scheduler->GetTypeId () == QuicSocketTxEdfScheduler::GetTypeId ())
    {
      return (DynamicCast<QuicSocketTxEdfScheduler> (m_scheduler))->GetLatency (streamId);
    }
  else
    {
      return Seconds (0);
    }
}

void QuicSocketTxBuffer::SetDefaultLatency (Time latency)
{
  // Only relevant for the EDF scheduler
  if (m_scheduler->GetTypeId () == QuicSocketTxEdfScheduler::GetTypeId ())
    {
      (DynamicCast<QuicSocketTxEdfScheduler> (m_scheduler))->SetDefaultLatency (latency);
    }
}

Time QuicSocketTxBuffer::GetDefaultLatency ()
{
  return GetLatency (0);
}

uint32_t
QuicSocketTxBuffer::GetPayloadBytesInFlight () const
{
  NS_LOG_FUNCTION (this);
  
  uint32_t payloadBytesInFlight = 0;
  // Sum up payload bytes across all packet number spaces
  for (uint32_t space = 0; space < 3; ++space)
    {
      RefreshInFlight (static_cast<PacketNumberSpace> (space));
      payloadBytesInFlight += m_inFlightPayload[space];
    }

  NS_LOG_INFO ("Payload bytes in flight: " << payloadBytesInFlight);
  return payloadBytesInFlight;
}

}
