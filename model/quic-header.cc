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
#include "quic-header.h"
#include "ns3/buffer.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicHeader");

NS_OBJECT_ENSURE_REGISTERED (QuicHeader);

QuicHeader::QuicHeader ()
  : m_form (SHORT),
  m_c (true), // Default to true for CID present in ns-3
  m_k (PHASE_ZERO),
  m_type (0),
  m_connectionId (0),
  m_packetNumber (0),
  m_version (0)
{
}


QuicHeader::~QuicHeader ()
{
}

std::string
QuicHeader::TypeToString () const
{
  static const char* longTypeNames[6] = {
    "Initial",
    "0-RTT",
    "Handshake",
    "Retry",
    "Version Negotiation",
    "None"
  };
  static const char* pnLenNames[4] = {
    "1 Byte",
    "2 Bytes",
    "3 Bytes",
    "4 Bytes"
  };

  std::string typeDescription = "";

  if (IsLong ())
    {
      typeDescription.append (longTypeNames[m_type]);
    }
  else
    {
      typeDescription.append (pnLenNames[m_type]);
    }
  return typeDescription;
}

TypeId
QuicHeader::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicHeader")
    .SetParent<Header> ()
    .SetGroupName ("Internet")
    .AddConstructor<QuicHeader> ()
  ;
  return tid;
}

TypeId
QuicHeader::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

uint32_t
QuicHeader::GetSerializedSize (void) const
{
  NS_ASSERT (m_type != NONE or m_form == SHORT);

  uint32_t serializesSize = CalculateHeaderLength ();
  NS_LOG_INFO ("Serialized Size " << serializesSize);

  return serializesSize;
}

uint32_t
QuicHeader::CalculateHeaderLength () const
{
  uint32_t len;

  if (IsLong ()) 
    {
      /**
       * RFC 9000 Section 17.2: Long Header bit breakdown
       * - Flags: 8 bits
       * - Version: 32 bits
       * - DCID Length: 8 bits
       * - DCID: 64 bits (CID_LENGTH * 8)
       * - SCID Length: 8 bits (Value is 0, so no SCID follows)
       */
      len = 8 + 32 + 8 + (CID_LENGTH * 8) + 8;
      if (!IsVersionNegotiation ()) 
        {
          len += GetPacketNumLen ();
        }
    }
  else
    {
      /**
       * RFC 9000 Section 17.3: Short Header bit breakdown
       * - Flags: 8 bits
       * - DCID: 64 bits (if present)
       * - Packet Number: variable (1-4 bytes)
       */
      len = 8 + (CID_LENGTH * 8) * HasConnectionId () + GetPacketNumLen ();
    }
  return len / 8;
}

uint32_t
QuicHeader::GetPacketNumLen () const
{
  if (IsLong ()) 
    {
      return 32;
    }

  switch (m_type)
    {
    case PN_1_BYTE:
      return 8;
    case PN_2_BYTES:
      return 16;
    case PN_3_BYTES:
      return 24;
    case PN_4_BYTES:
      return 32;
    }
  NS_FATAL_ERROR ("Invalid packet number length type " << (uint32_t)m_type);
  return 0;
}

void
QuicHeader::Serialize (Buffer::Iterator start) const
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT (m_type != NONE or m_form == SHORT);
  NS_LOG_INFO ("Serialize::Serialized Size " << CalculateHeaderLength ());

  Buffer::Iterator i = start;

  if (m_form == LONG)
    {
      // RFC 9000 Section 17.2: Long Header Form
      uint8_t t = 0xC0; // Long form + Fixed bit
      if (IsVersionNegotiation ()) 
        {
          t = 0x80;
        }
      else
        {
          t |= (m_type << 4);
          t |= 0x03; // PN Length encoded as 4 bytes (0x03)
        }
      i.WriteU8 (t);
      i.WriteHtonU32 (m_version);
      // DCID Length and Value
      i.WriteU8 (CID_LENGTH);
      i.WriteHtonU64 (m_connectionId);
      // SCID Length (Value is 0, so no SCID follows)
      i.WriteU8 (0);

      if (!IsVersionNegotiation ()) 
        {
          i.WriteHtonU32 (m_packetNumber.GetValue ());
        }
    }
  else
    {
      // RFC 9000 Section 17.3: Short Header Form
      uint8_t t = 0x40; // Fixed bit
      t |= (m_k << 2);
      t |= (m_type & 0x03); // PN Length
      i.WriteU8 (t);

      if (m_c)
        {
          i.WriteHtonU64 (m_connectionId);
        }

      uint32_t pn = m_packetNumber.GetValue ();
      switch (m_type)
        {
        case PN_1_BYTE:
          i.WriteU8 ((uint8_t)pn);
          break;
        case PN_2_BYTES:
          i.WriteHtonU16 ((uint16_t)pn);
          break;
        case PN_3_BYTES:
          i.WriteU8 ((uint8_t)(pn >> 16));
          i.WriteHtonU16 ((uint16_t)pn);
          break;
        case PN_4_BYTES:
          i.WriteHtonU32 ((uint32_t)pn);
          break;
        }
    }
}

uint32_t
QuicHeader::Deserialize (Buffer::Iterator start)
{
  NS_LOG_FUNCTION (this);

  Buffer::Iterator i = start;

  uint8_t t = i.ReadU8 ();

  m_form = (t & 0x80) >> 7;

  if (IsShort ()) 
    {
      // RFC 9000 Section 17.3.1: 1-RTT Packet (Short Header)
      m_k = (t & 0x04) >> 2;
      SetTypeByte (t & 0x03);
      // m_c must be set before Deserialize for Short Headers if no CID is present
    }
  else
    {
      // RFC 9000 Section 17.2: Long Header
      if ((t & 0x40) == 0) 
        {
          SetTypeByte (VERSION_NEGOTIATION);
        }
      else
        {
          SetTypeByte ((t & 0x30) >> 4);
        }
    }
  
  if (IsLong ()) 
    {
      SetVersion (i.ReadNtohU32 ());
      uint8_t dcidLen = i.ReadU8 ();
      if (dcidLen == CID_LENGTH) 
        {
          SetConnectionID (i.ReadNtohU64 ());
        }
      else
        {
          i.Next (dcidLen);
        }
      uint8_t scidLen = i.ReadU8 ();
      i.Next (scidLen);

      if (!IsVersionNegotiation ()) 
        {
          SetPacketNumber (SequenceNumber32 (i.ReadNtohU32 ()));
        }
    }
  else
    {
      if (m_c)
        {
          m_connectionId = i.ReadNtohU64 ();
        }

      uint32_t pn = 0;
      switch (m_type)
        {
        case PN_1_BYTE:
          pn = i.ReadU8 ();
          break;
        case PN_2_BYTES:
          pn = i.ReadNtohU16 ();
          break;
        case PN_3_BYTES:
          pn = i.ReadU8 ();
          pn = (pn << 16) | i.ReadNtohU16 ();
          break;
        case PN_4_BYTES:
          pn = i.ReadNtohU32 ();
          break;
        }
      m_packetNumber = SequenceNumber32 (pn);
    }

  NS_LOG_INFO ("Deserialize::Serialized Size " << CalculateHeaderLength ());

  return GetSerializedSize ();
}

void
QuicHeader::Print (std::ostream &os) const
{
  NS_ASSERT (m_type != NONE or m_form == SHORT);

  os << "|" << m_form << "|";

  if (IsShort ()) 
    {
      os << m_c << "|" << m_k << "|" << "1|0|";
    }

  os << TypeToString () << "|\n|";

  if (HasConnectionId ()) 
    {
      os << "ConnectionID " << m_connectionId << "|\n|";
    }
  if (IsShort ()) 
    {
      os << "PacketNumber " << m_packetNumber << "|\n";
    }
  else
    {
      os << "Version " << (uint64_t)m_version << "|\n";
      os << "PacketNumber " << m_packetNumber << "|\n|";
    }

}

QuicHeader
QuicHeader::CreateInitial (uint64_t connectionId, uint32_t version, SequenceNumber32 packetNumber)
{
  NS_LOG_INFO ("Create Initial Helper called");

  QuicHeader head;
  head.SetFormat (QuicHeader::LONG);
  head.SetTypeByte (QuicHeader::INITIAL);
  head.SetConnectionID (connectionId);
  head.SetVersion (version);
  head.SetPacketNumber (packetNumber);

  return head;
}


QuicHeader
QuicHeader::CreateRetry (uint64_t connectionId, uint32_t version, SequenceNumber32 packetNumber)
{
  NS_LOG_INFO ("Create Retry Helper called");

  QuicHeader head;
  head.SetFormat (QuicHeader::LONG);
  head.SetTypeByte (QuicHeader::RETRY);
  head.SetConnectionID (connectionId);
  head.SetVersion (version);
  head.SetPacketNumber (packetNumber);

  return head;
}

QuicHeader
QuicHeader::CreateHandshake (uint64_t connectionId, uint32_t version, SequenceNumber32 packetNumber)
{
  NS_LOG_INFO ("Create Handshake Helper called ");

  QuicHeader head;
  head.SetFormat (QuicHeader::LONG);
  head.SetTypeByte (QuicHeader::HANDSHAKE);
  head.SetConnectionID (connectionId);
  head.SetVersion (version);
  head.SetPacketNumber (packetNumber);

  return head;
}

QuicHeader
QuicHeader::Create0RTT (uint64_t connectionId, uint32_t version, SequenceNumber32 packetNumber)
{
  NS_LOG_INFO ("Create 0RTT Helper called");

  QuicHeader head;
  head.SetFormat (QuicHeader::LONG);
  head.SetTypeByte (QuicHeader::ZERO_RTT);
  head.SetConnectionID (connectionId);
  head.SetVersion (version);
  head.SetPacketNumber (packetNumber);

  return head;
}

QuicHeader
QuicHeader::CreateShort (uint64_t connectionId, SequenceNumber32 packetNumber, bool connectionIdFlag, bool keyPhaseBit)
{
  NS_LOG_INFO ("Create Short Helper called");

  QuicHeader head;
  head.SetFormat (QuicHeader::SHORT);
  head.SetKeyPhaseBit (keyPhaseBit);
  head.SetConnectionIdFlag (connectionIdFlag);
  head.SetPacketNumber (packetNumber);

  if (connectionIdFlag)
    {
      head.SetConnectionID (connectionId);
    }

  return head;
}

QuicHeader
QuicHeader::CreateVersionNegotiation (uint64_t connectionId, uint32_t version, std::vector<uint32_t>& supportedVersions)
{
  NS_LOG_INFO ("Create Version Negotiation Helper called");

  QuicHeader head;
  head.SetFormat (QuicHeader::LONG);
  head.SetTypeByte (QuicHeader::VERSION_NEGOTIATION);
  head.SetConnectionID (connectionId);
  head.SetVersion (version);

  return head;
}

uint8_t
QuicHeader::GetTypeByte () const
{
  return m_type;
}

void
QuicHeader::SetTypeByte (uint8_t typeByte)
{
  m_type = typeByte;
}

uint8_t
QuicHeader::GetFormat () const
{
  return m_form;
}

void
QuicHeader::SetFormat (bool form)
{
  m_form = form;
}

uint64_t
QuicHeader::GetConnectionId () const
{
  NS_ASSERT (HasConnectionId ());
  return m_connectionId;
}

void
QuicHeader::SetConnectionID (uint64_t connID)
{
  m_connectionId = connID;
  m_c = true;
}

SequenceNumber32
QuicHeader::GetPacketNumber () const
{
  return m_packetNumber;
}

void
QuicHeader::SetPacketNumber (SequenceNumber32 packNum)
{
  NS_LOG_INFO (packNum);
  m_packetNumber = packNum;
  if (IsShort ()) 
    {
      uint32_t val = packNum.GetValue ();
      if (val < 256) 
        {
          SetTypeByte (PN_1_BYTE);
        }
      else if (val < 65536) 
        {
          SetTypeByte (PN_2_BYTES);
        }
      else if (val < 16777216) 
        {
          SetTypeByte (PN_3_BYTES);
        }
      else
        {
          SetTypeByte (PN_4_BYTES);
        }
    }
}

uint32_t
QuicHeader::GetVersion () const
{
  NS_ASSERT (HasVersion ());
  return m_version;
}

void
QuicHeader::SetVersion (uint32_t version)
{
  m_version = version;
}

bool
QuicHeader::GetKeyPhaseBit () const
{
  NS_ASSERT (IsShort ());
  return m_k;
}

void
QuicHeader::SetKeyPhaseBit (bool keyPhaseBit)
{
  NS_ASSERT (IsShort ());
  m_k = keyPhaseBit;
}

bool QuicHeader::IsShort () const
{
  return m_form == SHORT;
}

bool
QuicHeader::IsVersionNegotiation () const
{
  return m_type == VERSION_NEGOTIATION;
}

bool
QuicHeader::IsInitial () const
{
  return m_type == INITIAL;
}

bool
QuicHeader::IsRetry () const
{
  return m_type == RETRY;
}

bool
QuicHeader::IsHandshake () const
{
  return m_type == HANDSHAKE;
}

bool
QuicHeader::IsORTT () const
{
  return m_type == ZERO_RTT;
}

bool QuicHeader::HasVersion () const
{
  return IsLong ();
}

bool QuicHeader::HasConnectionId () const
{
  return m_c;
}

void
QuicHeader::SetConnectionIdFlag (bool connectionIdFlag)
{
  m_c = connectionIdFlag;
}

bool
operator== (const QuicHeader &lhs, const QuicHeader &rhs)
{
  return (
    lhs.m_form == rhs.m_form
    && lhs.m_c == rhs.m_c
    && lhs.m_k  == rhs.m_k
    && lhs.m_type == rhs.m_type
    && lhs.m_connectionId == rhs.m_connectionId
    && lhs.m_packetNumber == rhs.m_packetNumber
    && lhs.m_version == rhs.m_version
    );
}

std::ostream&
operator<< (std::ostream& os, QuicHeader& tc)
{
  tc.Print (os);
  return os;
}

} // namespace ns3