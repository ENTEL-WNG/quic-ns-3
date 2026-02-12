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

#include <stdint.h>
#include <iostream>
#include "quic-subheader.h"
#include "ns3/buffer.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicSubheader");

NS_OBJECT_ENSURE_REGISTERED (QuicSubheader);

QuicSubheader::QuicSubheader ()
  : m_frameType (PADDING),
    m_streamId (0),
    m_errorCode (0),
    m_offset (0),
    m_reasonPhraseLength (0),
    m_maxData (0),
    m_maxStreamData (0),
    m_maxStreamId (0),
    m_sequence (0),
    m_connectionId (0),
    //statelessResetToken(0),
    m_largestAcknowledged (0),
    m_ackDelay (0),
    m_ackBlockCount (0),
    m_firstAckBlock (0),
    m_data (0),
    m_length (0)
{
  m_reasonPhrase = std::vector<uint8_t> ();
  m_additionalAckBlocks = std::vector<uint32_t> ();
  m_gaps = std::vector<uint32_t> ();
  for (int i = 0; i < 16; i++) m_statelessResetToken[i] = 0;
}

QuicSubheader::~QuicSubheader ()
{}

TypeId
QuicSubheader::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicSubHeader")
    .SetParent<Header> ()
    .SetGroupName ("Internet")
    .AddConstructor<QuicSubheader> ()
  ;
  return tid;
}

TypeId
QuicSubheader::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

std::string
QuicSubheader::FrameTypeToString () const
{
  if (IsStream ())
    {
      return "STREAM";
    }

  static const char* frameTypeNames[32] = {
    "PADDING",
    "PING",
    "ACK",
    "ACK_ECN",
    "RESET_STREAM",
    "STOP_SENDING",
    "CRYPTO",
    "NEW_TOKEN",
    "STREAM_08", "STREAM_09", "STREAM_0a", "STREAM_0b", "STREAM_0c", "STREAM_0d", "STREAM_0e", "STREAM_0f",
    "MAX_DATA",
    "MAX_STREAM_DATA",
    "MAX_STREAMS_BIDI",
    "MAX_STREAMS_UNI",
    "DATA_BLOCKED",
    "STREAM_DATA_BLOCKED",
    "STREAMS_BLOCKED_BIDI",
    "STREAMS_BLOCKED_UNI",
    "NEW_CONNECTION_ID",
    "RETIRE_CONNECTION_ID",
    "PATH_CHALLENGE",
    "PATH_RESPONSE",
    "CONNECTION_CLOSE",
    "APPLICATION_CLOSE",
    "HANDSHAKE_DONE"
  };
  std::string typeDescription = "";

  if (m_frameType < 32)
    {
      typeDescription.append (frameTypeNames[m_frameType]);
    }
  else
    {
      typeDescription.append ("UNKNOWN");
    }

  return typeDescription;
}

std::string
QuicSubheader::TransportErrorCodeToString () const
{
  static const char* transportErrorCodeNames[13] = {
    "NO_ERROR",
    "INTERNAL_ERROR",
    "SERVER_BUSY",
    "FLOW_CONTROL_ERROR",
    "STREAM_ID_ERROR",
    "STREAM_STATE_ERROR",
    "FINAL_OFFSET_ERROR",
    "FRAME_FORMAT_ERROR",
    "TRANSPORT_PARAMETER_ERROR",
    "VERSION_NEGOTIATION_ERROR",
    "PROTOCOL_VIOLATION",
    "UNSOLICITED_PATH_ERROR",
    "FRAME_ERROR"
  };
  std::string typeDescription = "";

  typeDescription.append (transportErrorCodeNames[m_errorCode]);

  return typeDescription;
}


uint32_t
QuicSubheader::GetSerializedSize (void) const
{
  NS_LOG_FUNCTION (this << (uint64_t)m_frameType);

  return CalculateSubHeaderLength ();
}

uint32_t
QuicSubheader::CalculateSubHeaderLength () const
{
  NS_LOG_FUNCTION (this);
  uint32_t len = 8; // RFC 9000 Section 12.4: Frame Type (VarInt)

  if (IsStream ())
    {
      // RFC 9000 Section 19.8: STREAM Frame
      len += GetVarInt64Size (m_streamId);
      if (m_frameType & 0x04) // OFF bit
        {
          len += GetVarInt64Size (m_offset);
        }
      if (m_frameType & 0x02) // LEN bit
        {
          len += GetVarInt64Size (m_length);
        }
      return len / 8;
    }

  switch (m_frameType)
    {
      case PADDING: // RFC 9000 Section 19.1
      case PING:    // RFC 9000 Section 19.2
      case HANDSHAKE_DONE: // RFC 9000 Section 19.20
        break;

      case RESET_STREAM: // RFC 9000 Section 19.4
        len += GetVarInt64Size (m_streamId);
        len += GetVarInt64Size (m_errorCode);
        len += GetVarInt64Size (m_offset);
        break;

      case STOP_SENDING: // RFC 9000 Section 19.5
        len += GetVarInt64Size (m_streamId);
        len += GetVarInt64Size (m_errorCode);
        break;

      case CRYPTO: // RFC 9000 Section 19.6
        len += GetVarInt64Size (m_offset);
        len += GetVarInt64Size (m_length);
        break;

      case ACK:     // RFC 9000 Section 19.3
      case ACK_ECN: // RFC 9000 Section 19.3.2
        len += GetVarInt64Size (m_largestAcknowledged);
        len += GetVarInt64Size (m_ackDelay);
        len += GetVarInt64Size (m_ackBlockCount);
        len += GetVarInt64Size (m_firstAckBlock);
        for (uint64_t j = 0; j < m_ackBlockCount; j++)
          {
            len += GetVarInt64Size (m_gaps[j]);
            len += GetVarInt64Size (m_additionalAckBlocks[j]);
          }
        if (m_frameType == ACK_ECN)
          {
            len += GetVarInt64Size (0); // ECT(0) count
            len += GetVarInt64Size (0); // ECT(1) count
            len += GetVarInt64Size (0); // ECN-CE count
          }
        break;

      case MAX_DATA: // RFC 9000 Section 19.9
        len += GetVarInt64Size (m_maxData);
        break;

      case MAX_STREAM_DATA: // RFC 9000 Section 19.10
        len += GetVarInt64Size (m_streamId);
        len += GetVarInt64Size (m_maxStreamData);
        break;

      case MAX_STREAMS_BIDI: // RFC 9000 Section 19.11
      case MAX_STREAMS_UNI:
        len += GetVarInt64Size (m_maxStreamId);
        break;

      case DATA_BLOCKED: // RFC 9000 Section 19.12
        len += GetVarInt64Size (m_offset);
        break;

      case STREAM_DATA_BLOCKED: // RFC 9000 Section 19.13
        len += GetVarInt64Size (m_streamId);
        len += GetVarInt64Size (m_offset);
        break;

      case STREAMS_BLOCKED_BIDI: // RFC 9000 Section 19.14
      case STREAMS_BLOCKED_UNI:
        len += GetVarInt64Size (m_maxStreamId);
        break;

      case NEW_CONNECTION_ID: // RFC 9000 Section 19.15
        len += GetVarInt64Size (m_sequence);
        len += GetVarInt64Size (0); // Retire Prior To
        len += 8; // Length (1 octet)
        len += 64; // Connection ID
        len += 128; // Stateless Reset Token
        break;

      case RETIRE_CONNECTION_ID: // RFC 9000 Section 19.16
        len += GetVarInt64Size (m_sequence);
        break;

      case PATH_CHALLENGE: // RFC 9000 Section 19.17
      case PATH_RESPONSE:  // RFC 9000 Section 19.18
        len += 64;
        break;

      case CONNECTION_CLOSE: // RFC 9000 Section 19.19
      case APPLICATION_CLOSE:
        len += GetVarInt64Size (m_errorCode);
        if (m_frameType == CONNECTION_CLOSE)
          {
            len += GetVarInt64Size (0); // Frame Type
          }
        len += GetVarInt64Size (m_reasonPhraseLength);
        len += (m_reasonPhraseLength * 8);
        break;

      default:
        NS_LOG_WARN ("Unknown frame type " << (uint32_t)m_frameType);
        break;
    }

  NS_LOG_LOGIC ("CalculateSubHeaderLength - len " << len << " " << len / 8);
  NS_ABORT_MSG_IF (len % 8 != 0, "len not divisible by 8 " << len);

  return (len / 8);
}

void
QuicSubheader::Serialize (Buffer::Iterator start) const
{
  NS_LOG_FUNCTION (this << (uint32_t)m_frameType);

  Buffer::Iterator i = start;
  i.WriteU8 (m_frameType);

  if (IsStream ())
    {
      WriteVarInt64 (i, m_streamId);
      if (m_frameType & 0x04) // Offset bit
        {
          WriteVarInt64 (i, m_offset);
        }
      if (m_frameType & 0x02) // Length bit
        {
          WriteVarInt64 (i, m_length);
        }
      return;
    }

  switch (m_frameType)
    {
      case PADDING:
      case PING:
      case HANDSHAKE_DONE:
        break;

      case RESET_STREAM:
        WriteVarInt64 (i, m_streamId);
        WriteVarInt64 (i, m_errorCode);
        WriteVarInt64 (i, m_offset);
        break;

      case STOP_SENDING:
        WriteVarInt64 (i, m_streamId);
        WriteVarInt64 (i, m_errorCode);
        break;

      case CRYPTO:
        WriteVarInt64 (i, m_offset);
        WriteVarInt64 (i, m_length);
        break;

      case ACK:
      case ACK_ECN:
        WriteVarInt64 (i, m_largestAcknowledged);
        WriteVarInt64 (i, m_ackDelay);
        WriteVarInt64 (i, m_ackBlockCount);
        WriteVarInt64 (i, m_firstAckBlock);
        for (uint64_t j = 0; j < m_ackBlockCount; j++)
          {
            WriteVarInt64 (i, m_gaps[j]);
            WriteVarInt64 (i, m_additionalAckBlocks[j]);
          }
        if (m_frameType == ACK_ECN)
          {
            WriteVarInt64 (i, 0); // ECT(0) count
            WriteVarInt64 (i, 0); // ECT(1) count
            WriteVarInt64 (i, 0); // ECN-CE count
          }
        break;

      case MAX_DATA:
        WriteVarInt64 (i, m_maxData);
        break;

      case MAX_STREAM_DATA:
        WriteVarInt64 (i, m_streamId);
        WriteVarInt64 (i, m_maxStreamData);
        break;

      case MAX_STREAMS_BIDI:
      case MAX_STREAMS_UNI:
        WriteVarInt64 (i, m_maxStreamId);
        break;

      case DATA_BLOCKED:
        WriteVarInt64 (i, m_offset); // Data Limit
        break;

      case STREAM_DATA_BLOCKED:
        WriteVarInt64 (i, m_streamId);
        WriteVarInt64 (i, m_offset); // Stream Data Limit
        break;

      case STREAMS_BLOCKED_BIDI:
      case STREAMS_BLOCKED_UNI:
        WriteVarInt64 (i, m_maxStreamId);
        break;

      case NEW_CONNECTION_ID:
        WriteVarInt64 (i, m_sequence);
        WriteVarInt64 (i, 0); // Retire Prior To
        i.WriteU8 (8); // CID length
        i.WriteHtonU64 (m_connectionId);
        for (int j = 0; j < 16; j++) i.WriteU8 (m_statelessResetToken[j]); // Stateless Reset Token
        break;

      case RETIRE_CONNECTION_ID:
        WriteVarInt64 (i, m_sequence);
        break;

      case PATH_CHALLENGE:
      case PATH_RESPONSE:
        i.WriteHtonU64 (m_data);
        break;

      case CONNECTION_CLOSE:
      case APPLICATION_CLOSE:
        WriteVarInt64 (i, m_errorCode);
        if (m_frameType == CONNECTION_CLOSE)
          {
            WriteVarInt64 (i, 0); // Frame Type
          }
        WriteVarInt64 (i, m_reasonPhraseLength);
        for (auto& elem : m_reasonPhrase)
          {
            i.WriteU8 (elem);
          }
        break;
    }
}

uint32_t
QuicSubheader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  m_frameType = i.ReadU8 ();

  NS_LOG_FUNCTION (this << (uint32_t)m_frameType);

  if (IsStream ())
    {
      m_streamId = ReadVarInt64 (i);
      if (m_frameType & 0x04) // Offset bit
        {
          m_offset = ReadVarInt64 (i);
        }
      else
        {
          m_offset = 0;
        }
      if (m_frameType & 0x02) // Length bit
        {
          m_length = ReadVarInt64 (i);
        }
      else
        {
          m_length = 0;
        }
      return GetSerializedSize ();
    }

  switch (m_frameType)
    {
      case PADDING:
      case PING:
      case HANDSHAKE_DONE:
        break;

      case RESET_STREAM:
        m_streamId = ReadVarInt64 (i);
        m_errorCode = ReadVarInt64 (i);
        m_offset = ReadVarInt64 (i);
        break;

      case STOP_SENDING:
        m_streamId = ReadVarInt64 (i);
        m_errorCode = ReadVarInt64 (i);
        break;

      case CRYPTO:
        m_offset = ReadVarInt64 (i);
        m_length = ReadVarInt64 (i);
        break;

      case ACK:
      case ACK_ECN:
        m_largestAcknowledged = ReadVarInt64 (i);
        m_ackDelay = ReadVarInt64 (i);
        m_ackBlockCount = ReadVarInt64 (i);
        m_firstAckBlock = ReadVarInt64 (i);
        m_gaps.clear ();
        m_additionalAckBlocks.clear ();
        for (uint64_t j = 0; j < m_ackBlockCount; j++)
          {
            m_gaps.push_back (ReadVarInt64 (i));
            m_additionalAckBlocks.push_back (ReadVarInt64 (i));
          }
        if (m_frameType == ACK_ECN)
          {
            ReadVarInt64 (i); // ECT(0) count
            ReadVarInt64 (i); // ECT(1) count
            ReadVarInt64 (i); // ECN-CE count
          }
        break;

      case MAX_DATA:
        m_maxData = ReadVarInt64 (i);
        break;

      case MAX_STREAM_DATA:
        m_streamId = ReadVarInt64 (i);
        m_maxStreamData = ReadVarInt64 (i);
        break;

      case MAX_STREAMS_BIDI:
      case MAX_STREAMS_UNI:
        m_maxStreamId = ReadVarInt64 (i);
        break;

      case DATA_BLOCKED:
        m_offset = ReadVarInt64 (i); // Data Limit
        break;

      case STREAM_DATA_BLOCKED:
        m_streamId = ReadVarInt64 (i);
        m_offset = ReadVarInt64 (i); // Stream Data Limit
        break;

      case STREAMS_BLOCKED_BIDI:
      case STREAMS_BLOCKED_UNI:
        m_maxStreamId = ReadVarInt64 (i);
        break;

      case NEW_CONNECTION_ID:
        m_sequence = ReadVarInt64 (i);
        ReadVarInt64 (i); // Retire Prior To
        {
          uint8_t len = i.ReadU8 ();
          if (len == 8) m_connectionId = i.ReadNtohU64 ();
          else i.Next (len);
        }
        for (int j = 0; j < 16; j++) m_statelessResetToken[j] = i.ReadU8 (); // Stateless Reset Token
        break;

      case RETIRE_CONNECTION_ID:
        m_sequence = ReadVarInt64 (i);
        break;

      case PATH_CHALLENGE:
      case PATH_RESPONSE:
        m_data = i.ReadNtohU64 ();
        break;

      case CONNECTION_CLOSE:
      case APPLICATION_CLOSE:
        m_errorCode = ReadVarInt64 (i);
        if (m_frameType == CONNECTION_CLOSE)
          {
            ReadVarInt64 (i); // Frame Type
          }
        m_reasonPhraseLength = ReadVarInt64 (i);
        m_reasonPhrase.clear ();
        for (uint64_t j = 0; j < m_reasonPhraseLength; j++)
          {
            m_reasonPhrase.push_back (i.ReadU8 ());
          }
        break;
    }

  NS_LOG_INFO ("Deserialized a subheader of size " << GetSerializedSize ());
  return GetSerializedSize ();
}

void
QuicSubheader::Print (std::ostream &os) const
{
  NS_LOG_FUNCTION (this << (uint32_t) m_frameType);

  os << "|" << FrameTypeToString () << "|\n";

  if (IsStream ())
    {
      os << "|Stream Id " << m_streamId << "|\n";
      if (m_frameType & 0x04) os << "|Offset " << m_offset << "|\n";
      if (m_frameType & 0x02) os << "|Length " << m_length << "|\n";
      if (m_frameType & 0x01) os << "|FIN|\n";
      return;
    }

  switch (m_frameType)
    {
      case PADDING:
      case PING:
      case HANDSHAKE_DONE:
        break;

      case RESET_STREAM:
        os << "|Stream Id " << m_streamId << "|\n";
        os << "|Application Error Code " << m_errorCode << "|\n";
        os << "|Final Size " << m_offset << "|\n";
        break;

      case STOP_SENDING:
        os << "|Stream Id " << m_streamId << "|\n";
        os << "|Application Error Code " << m_errorCode << "|\n";
        break;

      case CRYPTO:
        os << "|Offset " << m_offset << "|\n";
        os << "|Length " << m_length << "|\n";
        break;

      case ACK:
      case ACK_ECN:
        os << "|Largest Acknowledged " << m_largestAcknowledged << "|\n";
        os << "|Ack Delay " << m_ackDelay << "|\n";
        os << "|Ack Block Count " << m_ackBlockCount << "|\n";
        os << "|First Ack Block " << m_firstAckBlock << "|\n";
        for (uint64_t j = 0; j < m_ackBlockCount; j++)
          {
            os << "|Gap " << m_gaps[j] << "|\n";
            os << "|Additional Ack Block " << m_additionalAckBlocks[j] << "|\n";
          }
        break;

      case MAX_DATA:
        os << "|Maximum Data " << m_maxData << "|\n";
        break;

      case MAX_STREAM_DATA:
        os << "|Stream Id " << m_streamId << "|\n";
        os << "|Maximum Stream Data " << m_maxStreamData << "|\n";
        break;

      case MAX_STREAMS_BIDI:
      case MAX_STREAMS_UNI:
        os << "|Maximum Streams " << m_maxStreamId << "|\n";
        break;

      case DATA_BLOCKED:
        os << "|Data Limit " << m_offset << "|\n";
        break;

      case STREAM_DATA_BLOCKED:
        os << "|Stream Id " << m_streamId << "|\n";
        os << "|Stream Data Limit " << m_offset << "|\n";
        break;

      case STREAMS_BLOCKED_BIDI:
      case STREAMS_BLOCKED_UNI:
        os << "|Stream Limit " << m_maxStreamId << "|\n";
        break;

      case NEW_CONNECTION_ID:
        os << "|Sequence " << m_sequence << "|\n";
        os << "|Connection Id " << m_connectionId << "|\n";
        break;

      case RETIRE_CONNECTION_ID:
        os << "|Sequence " << m_sequence << "|\n";
        break;

      case PATH_CHALLENGE:
      case PATH_RESPONSE:
        os << "|Data " << m_offset << "|\n";
        break;

      case CONNECTION_CLOSE:
      case APPLICATION_CLOSE:
        os << "|Error Code " << m_errorCode << "|\n";
        os << "|Reason Phrase Length " << m_reasonPhraseLength << "|\n";
        os << "|Reason Phrase ";
        for (auto& elem : m_reasonPhrase)
          {
            os << elem;
          }
        os << "|\n";
        break;
    }
}

bool
QuicSubheader::IsPadding () const
{
  return m_frameType == PADDING;
}

bool
QuicSubheader::IsRstStream () const
{
  return m_frameType == RESET_STREAM;
}

bool
QuicSubheader::IsConnectionClose () const
{
  return m_frameType == CONNECTION_CLOSE;
}

bool
QuicSubheader::IsApplicationClose () const
{
  return m_frameType == APPLICATION_CLOSE;
}

bool
QuicSubheader::IsMaxData () const
{
  return m_frameType == MAX_DATA;
}

bool
QuicSubheader::IsMaxStreamData () const
{
  return m_frameType == MAX_STREAM_DATA;
}

bool
QuicSubheader::IsMaxStreamId () const
{
  return m_frameType == MAX_STREAMS_BIDI or m_frameType == MAX_STREAMS_UNI;
}

bool
QuicSubheader::IsPing () const
{
  return m_frameType == PING;
}

bool
QuicSubheader::IsBlocked () const
{
  return m_frameType == DATA_BLOCKED;
}

bool
QuicSubheader::IsStreamBlocked () const
{
  return m_frameType == STREAM_DATA_BLOCKED;
}

bool
QuicSubheader::IsStreamIdBlocked () const
{
  return m_frameType == STREAMS_BLOCKED_BIDI or m_frameType == STREAMS_BLOCKED_UNI;
}

bool
QuicSubheader::IsNewConnectionId () const
{
  return m_frameType == NEW_CONNECTION_ID;
}

bool
QuicSubheader::IsStopSending () const
{
  return m_frameType == STOP_SENDING;
}

bool
QuicSubheader::IsAck () const
{
  return m_frameType == ACK or m_frameType == ACK_ECN;
}

bool
QuicSubheader::IsPathChallenge () const
{
  return m_frameType == PATH_CHALLENGE;
}

bool
QuicSubheader::IsPathResponse () const
{
  return m_frameType == PATH_RESPONSE;
}

bool
operator== (const QuicSubheader &lhs, const QuicSubheader &rhs)
{
  return (lhs.m_frameType == rhs.m_frameType);
}

std::ostream&
operator<< (std::ostream& os, QuicSubheader& tc)
{
  tc.Print (os);
  return os;
}


void
QuicSubheader::WriteVarInt64 (Buffer::Iterator& i, uint64_t varInt64) const
{
  //NS_LOG_FUNCTION(this);

  uint8_t mask = 0x00;
  if (varInt64 <= 63)
    {
      uint8_t buffer[1];
      buffer[0] = (uint8_t)varInt64;
      i.WriteU8 (buffer[0]);
    }
  else if (varInt64 <= 16383)
    {
      mask = 0x40;
      uint8_t buffer[2];
      buffer[0] = (uint8_t)(varInt64 >> 8);
      buffer[1] = (uint8_t)varInt64;
      buffer[0] |= mask;

      for (int j = 0; j < 2; j++)
        {
          i.WriteU8 (buffer[j]);
        }
    }
  else if (varInt64 <= 1073741823)
    {
      mask = 0x80;
      uint8_t buffer[4];
      for (int i = 0; i < 4; i++)
        {
          buffer[i] = (uint8_t)(varInt64 >> (8 * (3 - i)));
          //NS_LOG_INFO("WriteVarInt64 - buffer[i] " << (uint64_t)buffer[i]);
        }

      buffer[0] |= mask;

      for (int j = 0; j < 4; j++)
        {
          i.WriteU8 (buffer[j]);
        }

    }
  else if (varInt64 <= 4611686018427387903)
    {
      mask = 0xC0;
      uint8_t buffer[8];

      for (int i = 0; i < 8; i++)
        {
          buffer[i] = (uint8_t)(varInt64 >> (8 * (7 - i)));
          //NS_LOG_INFO("WriteVarInt64 - buffer[i] " << (uint64_t)buffer[i]);
        }

      buffer[0] |= mask;

      for (int j = 0; j < 8; j++)
        {
          i.WriteU8 (buffer[j]);
        }
    }
  else
    {
      return;           // Error too much large
    }

  //NS_LOG_INFO("WriteVarInt64 - bytestream32 " << (uint64_t)bytestream32 << " varInt64 " << varInt64 << " mask " << mask);

}

uint64_t
QuicSubheader::ReadVarInt64 (Buffer::Iterator& i)
{
  //NS_LOG_FUNCTION(this);

  uint8_t bytestream8 = i.ReadU8 ();
  uint8_t mask = bytestream8 & 0b11000000;
  bytestream8 &= 0b00111111;

  uint64_t bytestream64 = 0;

  if (mask == 0x00)
    {
      bytestream64 = (uint64_t)bytestream8;
    }
  else if (mask == 0x40)
    {
      bytestream64 = ((uint64_t)bytestream8 << 8) | (uint64_t)i.ReadU8 ();
    }
  else if (mask == 0x80)
    {
      bytestream64 = ((uint64_t)bytestream8 << 24) | ((uint64_t)i.ReadU8 () << 16) | ((uint64_t)i.ReadU8 () << 8) | (uint64_t)i.ReadU8 ();
    }
  else if (mask == 0xC0)
    {
      bytestream64 = ((uint64_t)bytestream8 << 56) | ((uint64_t)i.ReadU8 () << 48) | ((uint64_t)i.ReadU8 () << 40) | ((uint64_t)i.ReadU8 () << 32) | ((uint64_t)i.ReadU8 () << 24) | ((uint64_t)i.ReadU8 () << 16) | ((uint64_t)i.ReadU8 () << 8) | (uint64_t)i.ReadU8 ();
    }

  //NS_LOG_INFO("ReadVarInt64 - bytestream8 " << (uint64_t)bytestream8 << " bytestream64 " << bytestream64 << " mask " << (uint64_t)mask);

  return bytestream64;
}

uint32_t
QuicSubheader::GetVarInt64Size (uint64_t varInt64)
{

  //NS_LOG_FUNCTION(this);

  if (varInt64 <= 63)
    {
      return (uint32_t) 8;
    }
  else if (varInt64 <= 16383)
    {
      return (uint32_t) 16;
    }
  else if (varInt64 <= 1073741823)
    {
      return (uint32_t) 32;
    }
  else if (varInt64 <= 4611686018427387903)
    {
      return (uint32_t) 64;
    }
  else
    {
      return 0;
    }

}

QuicSubheader
QuicSubheader::CreatePadding (void)
{
  NS_LOG_INFO ("Created Padding Header");

  QuicSubheader sub;
  sub.SetFrameType (PADDING);

  return sub;
}

QuicSubheader
QuicSubheader::CreateRstStream (uint64_t streamId, uint16_t applicationErrorCode, uint64_t finalOffset)
{
  NS_LOG_INFO ("Created RstStream Header");

  QuicSubheader sub;
  sub.SetFrameType (RESET_STREAM);
  sub.SetStreamId (streamId);
  sub.SetErrorCode (applicationErrorCode);
  sub.SetOffset (finalOffset);

  return sub;
}

QuicSubheader
QuicSubheader::CreateConnectionClose (uint16_t errorCode, const char* reasonPhrase)
{
  NS_LOG_INFO ("Created ConnectionClose Header");

  QuicSubheader sub;
  sub.SetFrameType (CONNECTION_CLOSE);
  sub.SetErrorCode (errorCode);

  std::vector<uint8_t> rpvec;
  for (int i = 0; reasonPhrase[i] != '\0'; i++)
    {
      rpvec.push_back ((uint8_t)reasonPhrase[i]);
    }

  sub.SetReasonPhraseLength (rpvec.size ());
  sub.SetReasonPhrase (rpvec);

  return sub;
}


QuicSubheader
QuicSubheader::CreateApplicationClose (uint16_t errorCode, const char* reasonPhrase)
{
  NS_LOG_INFO ("Created ApplicationClose Header");

  QuicSubheader sub;
  sub.SetFrameType (APPLICATION_CLOSE);
  sub.SetErrorCode (errorCode);

  std::vector<uint8_t> rpvec;
  for (int i = 0; reasonPhrase[i] != '\0'; i++)
    {
      rpvec.push_back ((uint8_t)reasonPhrase[i]);
    }

  sub.SetReasonPhraseLength (rpvec.size ());
  sub.SetReasonPhrase (rpvec);

  return sub;
}


QuicSubheader
QuicSubheader::CreateMaxData (uint64_t maxData)
{
  NS_LOG_INFO ("Created MaxData Header");

  QuicSubheader sub;
  sub.SetFrameType (MAX_DATA);
  sub.SetMaxData (maxData);
  sub.SetLength (0);

  return sub;
}

QuicSubheader
QuicSubheader::CreateMaxStreamData (uint64_t streamId, uint64_t maxStreamData)
{
  NS_LOG_INFO ("Created MaxStreamData Header");

  QuicSubheader sub;
  sub.SetFrameType (MAX_STREAM_DATA);
  sub.SetStreamId (streamId);
  sub.SetMaxStreamData (maxStreamData);

  return sub;
}

QuicSubheader
QuicSubheader::CreateMaxStreamId (uint64_t maxStreamId)
{
  NS_LOG_INFO ("Created MaxStreamId Header");

  QuicSubheader sub;
  sub.SetFrameType (MAX_STREAMS_BIDI);
  sub.SetMaxStreamId (maxStreamId);

  return sub;
}

QuicSubheader
QuicSubheader::CreatePing (void)
{
  NS_LOG_INFO ("Created Ping Header");

  QuicSubheader sub;
  sub.SetFrameType (PING);

  return sub;
}

QuicSubheader
QuicSubheader::CreateHandshakeDone (void)
{
  NS_LOG_INFO ("Created HandshakeDone Header");

  QuicSubheader sub;
  sub.SetFrameType (HANDSHAKE_DONE);

  return sub;
}

QuicSubheader
QuicSubheader::CreateBlocked (uint64_t offset)
{
  NS_LOG_INFO ("Created Blocked Header");

  QuicSubheader sub;
  sub.SetFrameType (DATA_BLOCKED);
  sub.SetOffset (offset);

  return sub;
}

QuicSubheader
QuicSubheader::CreateStreamBlocked (uint64_t streamId, uint64_t offset)
{
  NS_LOG_INFO ("Created StreamBlocked Header");

  QuicSubheader sub;
  sub.SetFrameType (STREAM_DATA_BLOCKED);
  sub.SetStreamId (streamId);
  sub.SetOffset (offset);

  return sub;
}

QuicSubheader
QuicSubheader::CreateStreamIdBlocked (uint64_t streamId)
{
  NS_LOG_INFO ("Created StreamIdBlocked Header");

  QuicSubheader sub;
  sub.SetFrameType (STREAMS_BLOCKED_BIDI);
  sub.SetMaxStreamId (streamId);

  return sub;
}

QuicSubheader
QuicSubheader::CreateNewConnectionId (uint64_t sequence, uint64_t connectionId, const uint8_t token[16])
{
  NS_LOG_INFO ("Created NewConnectionId Header");

  QuicSubheader sub;
  sub.SetFrameType (NEW_CONNECTION_ID);
  sub.SetSequence (sequence);
  sub.SetConnectionId (connectionId);
  sub.SetStatelessResetToken (token);

  return sub;
}

QuicSubheader
QuicSubheader::CreateStopSending (uint64_t streamId, uint16_t applicationErrorCode)
{
  NS_LOG_INFO ("Created StopSending Header");

  QuicSubheader sub;
  sub.SetFrameType (STOP_SENDING);
  sub.SetStreamId (streamId);
  sub.SetErrorCode (applicationErrorCode);

  return sub;
}

QuicSubheader
QuicSubheader::CreateAck (uint32_t largestAcknowledged, uint64_t ackDelay, uint32_t firstAckBlock, std::vector<uint32_t>& gaps, std::vector<uint32_t>& additionalAckBlocks)
{
  NS_LOG_INFO ("Created Ack Header");

  QuicSubheader sub;
  sub.SetFrameType (ACK);
  sub.SetLargestAcknowledged (largestAcknowledged);
  sub.SetAckDelay (ackDelay);
  sub.SetAckBlockCount (gaps.size ());
  sub.SetFirstAckBlock (firstAckBlock);
  sub.SetGaps (gaps);
  sub.SetAdditionalAckBlocks (additionalAckBlocks);

  return sub;
}

QuicSubheader
QuicSubheader::CreatePathChallenge (uint64_t data)
{
  NS_LOG_INFO ("Created PathChallenge Header");

  QuicSubheader sub;
  sub.SetFrameType (PATH_CHALLENGE);
  sub.SetData (data);

  return sub;
}

QuicSubheader
QuicSubheader::CreatePathResponse (uint64_t data)
{
  NS_LOG_INFO ("Created PathResponse Header");

  QuicSubheader sub;
  sub.SetFrameType (PATH_RESPONSE);
  sub.SetData (data);

  return sub;
}

QuicSubheader
QuicSubheader::CreateCrypto (uint64_t offset, uint64_t length)
{
  NS_LOG_INFO ("Created Crypto Header");

  QuicSubheader sub;
  sub.SetFrameType (CRYPTO);
  sub.SetOffset (offset);
  sub.SetLength (length);

  return sub;
}

QuicSubheader
QuicSubheader::CreateStreamSubHeader (uint64_t streamId, uint64_t offset, uint64_t length, bool offBit, bool lengthBit, bool finBit)
{
  NS_LOG_INFO ("Created Stream SubHeader");

  QuicSubheader sub;

  uint8_t frameType = 0x08 | (offBit << 2) | (lengthBit << 1) | (finBit);

  sub.SetFrameType (frameType);
  sub.SetStreamId (streamId);

  if (offBit)
    {
      sub.SetOffset (offset);
    }
  else
    {
      sub.SetOffset (0);
    }
  if (lengthBit)
    {
      sub.SetLength (length);
    }
  else
    {
      sub.SetLength (0);
    }

  return sub;
}

bool
QuicSubheader::IsCrypto () const
{
  return m_frameType == CRYPTO;
}

bool
QuicSubheader::IsStream () const
{
  return m_frameType >= STREAM and m_frameType <= 0x0f;
}

bool
QuicSubheader::IsStreamFin () const
{
  return IsStream () and (m_frameType & 0x01);
}

uint32_t QuicSubheader::GetAckBlockCount () const
{
  return m_ackBlockCount;
}

void QuicSubheader::SetAckBlockCount (uint32_t ackBlockCount)
{
  m_ackBlockCount = ackBlockCount;
}

const std::vector<uint32_t>& QuicSubheader::GetAdditionalAckBlocks () const
{
  return m_additionalAckBlocks;
}

void QuicSubheader::SetAdditionalAckBlocks (const std::vector<uint32_t>& ackBlocks)
{
  m_additionalAckBlocks = ackBlocks;
}

uint64_t QuicSubheader::GetAckDelay () const
{
  return m_ackDelay;
}

void QuicSubheader::SetAckDelay (uint64_t ackDelay)
{
  m_ackDelay = ackDelay;
}

uint64_t QuicSubheader::GetConnectionId () const
{
  return m_connectionId;
}

void QuicSubheader::SetConnectionId (uint64_t connectionId)
{
  m_connectionId = connectionId;
}

uint64_t QuicSubheader::GetData () const
{
  return m_data;
}

void QuicSubheader::SetData (uint64_t data)
{
  m_data = data;
}

uint16_t QuicSubheader::GetErrorCode () const
{
  return m_errorCode;
}

void
QuicSubheader::SetPing ()
{
  NS_LOG_FUNCTION (this);
  m_frameType = PING;
}

void
QuicSubheader::SetHandshakeDone ()
{
  NS_LOG_FUNCTION (this);
  m_frameType = HANDSHAKE_DONE;
}

bool
QuicSubheader::IsHandshakeDone () const
{
  return (m_frameType == HANDSHAKE_DONE);
}

void
QuicSubheader::SetErrorCode (uint16_t errorCode)
{
  m_errorCode = errorCode;
}

uint8_t QuicSubheader::GetFrameType () const
{
  return m_frameType;
}

void QuicSubheader::SetFrameType (uint8_t frameType)
{
  m_frameType = frameType;
}

const std::vector<uint32_t>& QuicSubheader::GetGaps () const
{
  return m_gaps;
}

void QuicSubheader::SetGaps (const std::vector<uint32_t>& gaps)
{
  m_gaps = gaps;
}

uint32_t QuicSubheader::GetLargestAcknowledged () const
{
  return m_largestAcknowledged;
}

void QuicSubheader::SetLargestAcknowledged (uint32_t largestAcknowledged)
{
  m_largestAcknowledged = largestAcknowledged;
}

uint64_t QuicSubheader::GetLength () const
{
  return m_length;
}

void QuicSubheader::SetLength (uint64_t length)
{
  m_length = length;
}

uint64_t QuicSubheader::GetMaxData () const
{
  return m_maxData;
}

void QuicSubheader::SetMaxData (uint64_t maxData)
{
  m_maxData = maxData;
}

uint64_t QuicSubheader::GetMaxStreamData () const
{
  return m_maxStreamData;
}

void QuicSubheader::SetMaxStreamData (uint64_t maxStreamData)
{
  m_maxStreamData = maxStreamData;
}

uint64_t QuicSubheader::GetMaxStreamId () const
{
  return m_maxStreamId;
}

void QuicSubheader::SetMaxStreamId (uint64_t maxStreamId)
{
  m_maxStreamId = maxStreamId;
}

uint64_t QuicSubheader::GetOffset () const
{
  return m_offset;
}

void QuicSubheader::SetOffset (uint64_t offset)
{
  m_offset = offset;
}

const std::vector<uint8_t>& QuicSubheader::GetReasonPhrase () const
{
  return m_reasonPhrase;
}

void QuicSubheader::SetReasonPhrase (const std::vector<uint8_t>& reasonPhrase)
{
  m_reasonPhrase = reasonPhrase;
}

uint64_t QuicSubheader::GetReasonPhraseLength () const
{
  return m_reasonPhraseLength;
}

void QuicSubheader::SetReasonPhraseLength (uint64_t reasonPhraseLength)
{
  m_reasonPhraseLength = reasonPhraseLength;
}

uint64_t QuicSubheader::GetSequence () const
{
  return m_sequence;
}

void QuicSubheader::SetSequence (uint64_t sequence)
{
  m_sequence = sequence;
}

uint64_t QuicSubheader::GetStreamId () const
{
  return m_streamId;
}

void QuicSubheader::SetStreamId (uint64_t streamId)
{
  m_streamId = streamId;
}

void QuicSubheader::GetStatelessResetToken (uint8_t token[16]) const
{
  for (int i = 0; i < 16; i++) token[i] = m_statelessResetToken[i];
}

void QuicSubheader::SetStatelessResetToken (const uint8_t token[16])
{
  for (int i = 0; i < 16; i++) m_statelessResetToken[i] = token[i];
}

uint64_t QuicSubheader::GetFirstAckBlock () const
{
  return m_firstAckBlock;
}

void QuicSubheader::SetFirstAckBlock (uint64_t firstAckBlock)
{
  m_firstAckBlock = firstAckBlock;
}

} // namespace ns3


