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

bool QuicSocketTxBuffer::Add (Ptr<Packet> p, PacketNumberSpace space)
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
          m_scheduler->Add (item, false);
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
      m_sentSize += outItem->m_packet->GetSize ();
      --m_numCryptoFramesInBuffer;
      Ptr<Packet> toRet = outItem->m_packet;
      return toRet;
    }
  return 0;
}

Ptr<Packet> QuicSocketTxBuffer::NextSequence (uint32_t numBytes,
                                              const SequenceNumber32 seq,
                                              PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << numBytes << seq << space);

  Ptr<QuicSocketTxItem> outItem = GetNewSegment (numBytes, space);

  if (outItem)
    {
      NS_LOG_INFO ("Extracting " << outItem->m_packet->GetSize () << " bytes");
      outItem->m_packetNumber = seq;
      outItem->m_lastSent = Now ();
      Ptr<Packet> toRet = outItem->m_packet;
      return toRet;
    }
  else
    {
      NS_LOG_INFO ("Empty packet");
      return Create<Packet>();
    }

}

Ptr<QuicSocketTxItem> QuicSocketTxBuffer::GetNewSegment (uint32_t numBytes, PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << numBytes << space);

  Ptr<QuicSocketTxItem> outItem = m_scheduler->GetNewSegment (numBytes);

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

  // Iterate over the ACK blocks and gaps
  for (uint32_t numAckBlockAnalyzed = 0; numAckBlockAnalyzed < ackBlockCount;
       ++numAckBlockAnalyzed, ++ack_it, ++gap_it)
    {
      for (auto sent_it = m_sentList[space].rbegin ();
           sent_it != m_sentList[space].rend () and !m_sentList[space].empty (); ++sent_it)                    // Visit sentList in reverse Order for optimization
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

        }
    }
  NS_LOG_LOGIC ("Mark lost packets");
  // RFC 9002 Appendix A.10: DetectAndRemoveLostPackets
  m_socket->m_pnSpaces[space].m_lossTime = Seconds (0);
  Time loss_delay = std::max (tcbd->m_kTimeThreshold * std::max (tcbd->m_latestRtt, tcbd->m_smoothedRtt), MilliSeconds (1)); // kGranularity = 1ms
  Time lost_send_time = Now () - loss_delay;

  for (auto sent_it = m_sentList[space].begin ();
       sent_it != m_sentList[space].end () and !m_sentList[space].empty ();
       ++sent_it)
    {
      Ptr<QuicSocketTxItem> unacked = *sent_it;
      if (unacked->m_sacked || unacked->m_lost)
        {
          continue;
        }

      if (unacked->m_packetNumber > m_socket->m_pnSpaces[space].m_largestAcked)
        {
          continue;
        }

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

  // Clean up acked packets and return new ACKed packet vector
  CleanSentList (space);
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
  uint32_t toRetx = 0;
  // First pass: add lost packets to the application buffer
  for (auto sent_it = m_sentList[space].rbegin (); sent_it != m_sentList[space].rend ();
       ++sent_it)
    {
      Ptr<QuicSocketTxItem> item = *sent_it;
      if (item->m_lost)
        {
          // Add lost packet contents to app buffer
          Ptr<QuicSocketTxItem> retx = CreateObject<QuicSocketTxItem> ();
          retx->m_packetNumber = packetNumber++;
          retx->m_space = space;
          retx->m_isStream = item->m_isStream;
          retx->m_isCrypto = item->m_isCrypto;
          retx->m_packet = Create<Packet>();
          NS_LOG_INFO (
            "Retx packet " << item->m_packetNumber << " as " << retx->m_packetNumber.GetValue () << " in space " << space);
          QuicSocketTxItem::MergeItems (*retx, *item);
          retx->m_lost = false;
          retx->m_retrans = true;
          toRetx += retx->m_packet->GetSize ();
          // Subtract the tracked wire bytes of the LOST item
          if (m_sentSize >= item->m_wireBytes)
            {
              m_sentSize -= item->m_wireBytes;
            }
          else
            {
              m_sentSize = 0;
              NS_LOG_WARN("m_sentSize underflow detected in Retransmission");
            }
            
          if (retx->m_isCrypto)
            {
              NS_LOG_INFO ("Lost CRYPTO frame packet, re-inserting in list");
              m_cryptoList[space].insert (m_cryptoList[space].begin (), retx);
              m_cryptoSize += retx->m_packet->GetSize ();
              m_numCryptoFramesInBuffer++;
            }
          else
            {
              m_scheduler->Add (retx, true);
            }
        }
    }

  NS_LOG_LOGIC ("Remove retransmitted packets from sent list in space " << space);
  auto sent_it = m_sentList[space].begin ();
  // Remove lost packets from the sent list
  while (!m_sentList[space].empty () && sent_it != m_sentList[space].end ())
    {
      Ptr<QuicSocketTxItem> item = *sent_it;
      if (item->m_lost)
        {
          uint32_t bytesToRemove = item->m_wireBytes > 0 ? item->m_wireBytes : item->m_packet->GetSize();
          
          if (m_sentSize >= bytesToRemove) {
              m_sentSize -= bytesToRemove;
          } else {
              m_sentSize = 0;
              NS_LOG_WARN("m_sentSize underflow detected in Retransmission");
          }
          // Remove lost packet from sent vector
          sent_it = m_sentList[space].erase (sent_it);
        }
      else
        {
          sent_it++;
        }
    }
  return toRetx;
}

std::vector<Ptr<QuicSocketTxItem> > QuicSocketTxBuffer::DetectLostPackets (Ptr<TcpSocketState> tcb, PacketNumberSpace space)
{
  NS_LOG_FUNCTION (this << space);
  std::vector<Ptr<QuicSocketTxItem>> newly_lost;
  Ptr<QuicSocketState> tcbd = dynamic_cast<QuicSocketState*> (&(*tcb));
  NS_ASSERT_MSG (tcbd, "tcb is not a QuicSocketState");
  NS_ASSERT_MSG (m_socket, "m_socket is null in DetectLostPackets");

  m_socket->m_pnSpaces[space].m_lossTime = Seconds (0);
  Time loss_delay = std::max (tcbd->m_kTimeThreshold * std::max (tcbd->m_latestRtt, tcbd->m_smoothedRtt), tcbd->m_kGranularity);
  Time lost_send_time = Now () - loss_delay;

  auto sent_it = m_sentList[space].begin ();
  while (sent_it != m_sentList[space].end ())
    {
      Ptr<QuicSocketTxItem> unacked = *sent_it;

      // Skip packets already handled (sacked)
      if (unacked->m_sacked) { 
          sent_it++; 
          continue; 
      }

      // Check RFC 9002 Loss Thresholds or manual loss
      if (unacked->m_lost || 
          (unacked->m_packetNumber <= m_socket->m_pnSpaces[space].m_largestAcked &&
           (unacked->m_lastSent <= lost_send_time ||
            m_socket->m_pnSpaces[space].m_largestAcked.GetValue () >= unacked->m_packetNumber.GetValue () + tcbd->m_kPacketThreshold)))
        {
          unacked->m_lost = true;
          newly_lost.push_back (unacked);
          // Do not remove from flight list (Retransmission needs them there).
          // BytesInFlight ignores lost packets automatically.
          
          NS_LOG_INFO ("Packet " << unacked->m_packetNumber << " in space " << space << " detected lost.");
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

void QuicSocketTxBuffer::CleanSentList (PacketNumberSpace space)
{
  auto sent_it = m_sentList[space].begin ();
  while (sent_it != m_sentList[space].end ())
    {
      Ptr<QuicSocketTxItem> item = *sent_it;
      // Only clean if Sacked (leave Lost for Retransmission)
      if (item->m_sacked) 
        {
          item->m_acked = true;
          // Subtract the tracked wire bytes
          // Use logic to prevent underflow if logic ever desyncs
          if (m_sentSize >= item->m_wireBytes)
            {
            m_sentSize -= item->m_wireBytes;
            }
          else
            {
            m_sentSize = 0;
            NS_LOG_WARN("m_sentSize underflow detected in CleanSentList");
            }
            
          sent_it = m_sentList[space].erase (sent_it);
          NS_LOG_LOGIC ("Cleaning packet " << item->m_packetNumber << " from sent buffer");
        }
      else
        {
          sent_it++;
        }
    }
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

uint32_t QuicSocketTxBuffer::BytesInFlight () const
{
  NS_LOG_FUNCTION (this);
  uint32_t inFlight = 0;
  for (int i = 0; i < 3; i++)
    {
      inFlight += BytesInFlight (static_cast<PacketNumberSpace> (i));
    }
  NS_LOG_INFO (
    "Compute total bytes in flight " << inFlight << " m_sentSize " << m_sentSize << " m_appSize " << m_cryptoSize + m_scheduler->AppSize ());
  return inFlight;
}

uint32_t QuicSocketTxBuffer::BytesInFlight (PacketNumberSpace space) const
{
  uint32_t inFlight = 0;
  for (auto sent_it = m_sentList[space].begin ();
       sent_it != m_sentList[space].end () and !m_sentList[space].empty (); ++sent_it)
    {
      if (!(*sent_it)->m_sacked && !(*sent_it)->m_lost)
        {
          inFlight += (*sent_it)->m_wireBytes > 0 ? (*sent_it)->m_wireBytes : (*sent_it)->m_packet->GetSize ();
        }
    }
  return inFlight;
}

uint32_t QuicSocketTxBuffer::GetCongestionControlledBytesInFlight () const
{
  NS_LOG_FUNCTION (this);
  uint32_t inFlight = 0;
  // RFC 9002: Congestion control applies to all packets, but often we only track ApplicationData
  // for standard congestion control logic in simple implementations.
  for (auto sent_it = m_sentList[APPLICATION_DATA].begin ();
       sent_it != m_sentList[APPLICATION_DATA].end () and !m_sentList[APPLICATION_DATA].empty (); ++sent_it)
    {
      if (!(*sent_it)->m_sacked && !(*sent_it)->m_lost)
        {
          inFlight += (*sent_it)->m_wireBytes > 0 ? (*sent_it)->m_wireBytes : (*sent_it)->m_packet->GetSize ();
        }
    }
  return inFlight;
}

uint32_t QuicSocketTxBuffer::GetHandshakeInFlight () const
{
  NS_LOG_FUNCTION (this);
  uint32_t inFlight = 0;
  for (int i = 0; i < 2; i++) // INITIAL_DATA and HANDSHAKE_DATA
    {
      for (auto sent_it = m_sentList[i].begin ();
           sent_it != m_sentList[i].end () and !m_sentList[i].empty (); ++sent_it)
        {
          if (!(*sent_it)->m_sacked && !(*sent_it)->m_lost)
            {
              inFlight += (*sent_it)->m_wireBytes > 0 ? (*sent_it)->m_wireBytes : (*sent_it)->m_packet->GetSize ();
            }
        }
    }
  return inFlight;
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
  m_sentList[space].clear ();
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
      for (auto it = m_sentList[space].begin (); it != m_sentList[space].end (); ++it)
        {
          Ptr<QuicSocketTxItem> item = *it;
          if (!item->m_sacked && !item->m_lost)
            {
              payloadBytesInFlight += item->GetStreamPayloadSize ();
            }
        }
    }
  
  NS_LOG_INFO ("Payload bytes in flight: " << payloadBytesInFlight);
  return payloadBytesInFlight;
}

}
