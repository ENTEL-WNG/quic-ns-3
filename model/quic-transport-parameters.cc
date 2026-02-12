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
#include "quic-transport-parameters.h"
#include "ns3/buffer.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicTransportParameters");

NS_OBJECT_ENSURE_REGISTERED (QuicTransportParameters);

QuicTransportParameters::QuicTransportParameters ()
  : m_initial_max_stream_data (0),
  m_initial_max_data (0),
  m_initial_max_stream_id_bidi (0),
  m_idleTimeout (300),
  m_omit_connection (false),
  m_max_packet_size (65527),
  m_ack_delay_exponent (3),
  m_max_ack_delay (25),
  m_initial_max_stream_id_uni (0),
  m_disableActiveMigration (false),
  m_hasInitialSourceConnectionId (false),
  m_hasOriginalDestinationConnectionId (false),
  m_hasStatelessResetToken (false)
{
}


QuicTransportParameters::~QuicTransportParameters ()
{
}

TypeId
QuicTransportParameters::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicTransportParameters")
    .SetParent<Header> ()
    .SetGroupName ("Internet")
    .AddConstructor<QuicTransportParameters> ()
  ;
  return tid;
}

TypeId
QuicTransportParameters::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

uint32_t
QuicTransportParameters::GetSerializedSize (void) const
{
  return CalculateHeaderLength ();
}

uint32_t
QuicTransportParameters::CalculateHeaderLength () const
{
  uint32_t len = 0;
  auto paramLen = [](uint64_t val) {
    if (val <= 63) return 1+1+1;
    if (val <= 16383) return 1+1+2;
    if (val <= 1073741823) return 1+1+4;
    return 1+1+8;
  };

  len += paramLen (m_initial_max_stream_data);
  len += paramLen (m_initial_max_data);
  len += paramLen (m_initial_max_stream_id_bidi);
  len += paramLen (m_idleTimeout * 1000);
  len += paramLen (m_max_packet_size);
  len += paramLen (m_ack_delay_exponent);
  len += paramLen (m_max_ack_delay);
  len += paramLen (m_initial_max_stream_id_uni);

  if (m_disableActiveMigration)
    {
      len += 1 + 1; // ID + Length(0)
    }
  
  // For CIDs, we output 1 byte ID + 1 byte Len + 8 bytes CID (fixed length for now)
  if (m_hasInitialSourceConnectionId)
    {
      len += 1 + 1 + 8; 
    }
  if (m_hasOriginalDestinationConnectionId)
    {
       len += 1 + 1 + 8;
    }

  return len;
}


void
QuicTransportParameters::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  // Helper lambda to write a Transport Parameter with VLI Value
  auto writeParam = [&](uint64_t id, uint64_t val) {
    // Write ID (Assuming ID < 64 for now, complying with current list)
    i.WriteU8 ((uint8_t)id);

    // Calculate VLI length of the VALUE
    uint8_t vliLen = 0;
    if (val <= 63) vliLen = 1;
    else if (val <= 16383) vliLen = 2;
    else if (val <= 1073741823) vliLen = 4;
    else vliLen = 8;
    
    // Write Length of the value (As a VLI itself, but since length is small (1,2,4,8), it fits in 1 byte VLI)
    i.WriteU8 (vliLen); 

    // Write Value as VLI (RFC 9000 standard encoding)
    if (vliLen == 1) {
      i.WriteU8 ((uint8_t)val);
    } else if (vliLen == 2) {
       uint8_t buf[2];
       buf[0] = (uint8_t)((val >> 8) | 0x40);
       buf[1] = (uint8_t)val;
       i.Write (buf, 2);
    } else if (vliLen == 4) {
       uint8_t buf[4];
       buf[0] = (uint8_t)((val >> 24) | 0x80);
       buf[1] = (uint8_t)(val >> 16);
       buf[2] = (uint8_t)(val >> 8);
       buf[3] = (uint8_t)val;
       i.Write (buf, 4);
    } else {
       uint8_t buf[8];
       buf[0] = (uint8_t)((val >> 56) | 0xC0);
       buf[1] = (uint8_t)(val >> 48);
       buf[2] = (uint8_t)(val >> 40);
       buf[3] = (uint8_t)(val >> 32);
       buf[4] = (uint8_t)(val >> 24);
       buf[5] = (uint8_t)(val >> 16);
       buf[6] = (uint8_t)(val >> 8);
       buf[7] = (uint8_t)val;
       i.Write (buf, 8);
    }
  };

  writeParam (INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, m_initial_max_stream_data);
  writeParam (INITIAL_MAX_DATA, m_initial_max_data);
  writeParam (INITIAL_MAX_STREAMS_BIDI, m_initial_max_stream_id_bidi);
  writeParam (MAX_IDLE_TIMEOUT, m_idleTimeout * 1000);
  writeParam (MAX_UDP_PAYLOAD_SIZE, m_max_packet_size);
  writeParam (ACK_DELAY_EXPONENT, m_ack_delay_exponent);
  writeParam (MAX_ACK_DELAY, m_max_ack_delay);
  writeParam (INITIAL_MAX_STREAMS_UNI, m_initial_max_stream_id_uni);

  if (m_disableActiveMigration)
  {
    i.WriteU8 ((uint8_t)DISABLE_ACTIVE_MIGRATION);
    i.WriteU8 (0);
  }

  if (m_hasInitialSourceConnectionId)
  {
    i.WriteU8 ((uint8_t)INITIAL_SOURCE_CONNECTION_ID);
    i.WriteU8 (8); // CID Length
    i.WriteHtonU64 (m_initialSourceConnectionId);
  }

  if (m_hasOriginalDestinationConnectionId)
  {
    i.WriteU8 ((uint8_t)ORIGINAL_DESTINATION_CONNECTION_ID);
    i.WriteU8 (8); // CID Length
    i.WriteHtonU64 (m_originalDestinationConnectionId);
  }
}

uint32_t
QuicTransportParameters::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint32_t readBytes = 0;
  
  while (i.GetRemainingSize() >= 2)
  {
    uint8_t id = i.ReadU8();
    uint8_t len = i.ReadU8(); 
    
    if (i.GetRemainingSize() < len) break;
    
    uint64_t val = 0;
    
    // Read Value (VLI Decoded) if len > 0
    if (len > 0)
      {
        uint8_t firstByte = i.PeekU8 ();
        uint8_t prefix = firstByte >> 6;
        uint8_t lengthInfo = 1 << prefix; // 00->1, 01->2, 10->4, 11->8
        
        // Sanity check: The VLI encoded length MUST match the parameter length
        if (lengthInfo != len && id != ORIGINAL_DESTINATION_CONNECTION_ID && id != INITIAL_SOURCE_CONNECTION_ID) 
        {
          // Special case checking: The generic reader expects integer values to be VLI.
          // CIDs are raw bytes, not VLI.
        }

        if (len == 1) val = i.ReadU8 () & 0x3F; // Mask out VLI bits? No, VLI(1) has 00 prefix so standard ReadU8 is fine if value < 64.
        else if (len == 2) val = i.ReadNtohU16 () & 0x3FFF;
        else if (len == 4) val = i.ReadNtohU32 () & 0x3FFFFFFF;
        else if (len == 8) val = i.ReadNtohU64 () & 0x3FFFFFFFFFFFFFFF;
        else 
        {
           // For non-integer types (like CID), just read raw or skip
           // We handle CIDs specifically in switch
           if (id != ORIGINAL_DESTINATION_CONNECTION_ID && id != INITIAL_SOURCE_CONNECTION_ID) i.Next (len);
        }
      }

    readBytes += 2 + len;

    switch (id) {
      case INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: m_initial_max_stream_data = (uint32_t)val; break;
      case INITIAL_MAX_DATA: m_initial_max_data = (uint32_t)val; break;
      case INITIAL_MAX_STREAMS_BIDI: m_initial_max_stream_id_bidi = (uint32_t)val; break;
      case MAX_IDLE_TIMEOUT: m_idleTimeout = (uint16_t)(val / 1000); break;
      case MAX_UDP_PAYLOAD_SIZE: m_max_packet_size = (uint16_t)val; break;
      case ACK_DELAY_EXPONENT: m_ack_delay_exponent = (uint8_t)val; break;
      case MAX_ACK_DELAY: m_max_ack_delay = (uint16_t)val; break;
      case INITIAL_MAX_STREAMS_UNI: m_initial_max_stream_id_uni = (uint32_t)val; break;
      case STATELESS_RESET_TOKEN: m_hasStatelessResetToken = true; break;
      case DISABLE_ACTIVE_MIGRATION: m_disableActiveMigration = true; break;
      case ORIGINAL_DESTINATION_CONNECTION_ID: 
          if (len == 8) {
            // Go back and read raw
             i.Prev(len); // Reset to start of value
             m_originalDestinationConnectionId = i.ReadNtohU64();
             m_hasOriginalDestinationConnectionId = true;
          }
          break;
      case INITIAL_SOURCE_CONNECTION_ID:
           if (len == 8) {
             i.Prev(len);
             m_initialSourceConnectionId = i.ReadNtohU64();
             m_hasInitialSourceConnectionId = true;
           }
           break;
    }
    if (readBytes >= 500) break;
  }

  return readBytes;
}

void
QuicTransportParameters::Print (std::ostream &os) const
{
  os << "[initial_max_stream_data " << m_initial_max_stream_data << "|\n";
  os << "|initial_max_data " << m_initial_max_data << "|\n";
  os << "|initial_max_stream_id_bidi " << m_initial_max_stream_id_bidi << "|\n";
  os << "|idleTimeout " << m_idleTimeout << "|\n";
  os << "|max_packet_size " << m_max_packet_size << "|\n";
  os << "|ack_delay_exponent " << (uint16_t)m_ack_delay_exponent << "|\n";
  os << "|max_ack_delay " << m_max_ack_delay << "|\n";
  os << "|initial_max_stream_id_uni " << m_initial_max_stream_id_uni << "|\n";
  os << "|disable_active_migration " << m_disableActiveMigration << "]\n";
}

QuicTransportParameters
QuicTransportParameters::CreateTransportParameters (uint32_t initial_max_stream_data, uint32_t initial_max_data, uint32_t initial_max_stream_id_bidi, uint16_t idleTimeout,
                                                    uint8_t omit_connection, uint16_t max_packet_size, uint8_t ack_delay_exponent, uint16_t max_ack_delay, uint32_t initial_max_stream_id_uni, bool disable_migration)
{
  QuicTransportParameters transport;
  transport.SetInitialMaxStreamData (initial_max_stream_data);
  transport.SetInitialMaxData (initial_max_data);
  transport.SetInitialMaxStreamIdBidi (initial_max_stream_id_bidi);
  transport.SetIdleTimeout (idleTimeout);
  transport.SetOmitConnection (omit_connection);
  transport.SetMaxPacketSize (max_packet_size);
  transport.SetAckDelayExponent (ack_delay_exponent);
  transport.SetMaxAckDelay (max_ack_delay);
  transport.SetInitialMaxStreamIdUni (initial_max_stream_id_uni);
  transport.SetDisableActiveMigration (disable_migration);

  return transport;
}


bool
operator== (const QuicTransportParameters &lhs, const QuicTransportParameters &rhs)
{
  return (
    lhs.m_initial_max_stream_data == rhs.m_initial_max_stream_data
    && lhs.m_initial_max_data == rhs.m_initial_max_data
    && lhs.m_initial_max_stream_id_bidi  == rhs.m_initial_max_stream_id_bidi
    && lhs.m_idleTimeout == rhs.m_idleTimeout
    && lhs.m_omit_connection == rhs.m_omit_connection
    && lhs.m_max_packet_size == rhs.m_max_packet_size
    && lhs.m_ack_delay_exponent == rhs.m_ack_delay_exponent
    && lhs.m_max_ack_delay == rhs.m_max_ack_delay
    && lhs.m_initial_max_stream_id_uni == rhs.m_initial_max_stream_id_uni
    && lhs.m_hasStatelessResetToken == rhs.m_hasStatelessResetToken
    && lhs.m_disableActiveMigration == rhs.m_disableActiveMigration
    );
}

std::ostream&
operator<< (std::ostream& os, const QuicTransportParameters& tc)
{
  tc.Print (os);
  return os;
}

uint8_t QuicTransportParameters::GetAckDelayExponent () const { return m_ack_delay_exponent; }
void QuicTransportParameters::SetAckDelayExponent (uint8_t ackDelayExponent) { m_ack_delay_exponent = ackDelayExponent; }
uint16_t QuicTransportParameters::GetMaxAckDelay () const { return m_max_ack_delay; }
void QuicTransportParameters::SetMaxAckDelay (uint16_t maxAckDelay) { m_max_ack_delay = maxAckDelay; }
uint16_t QuicTransportParameters::GetIdleTimeout () const { return m_idleTimeout; }
void QuicTransportParameters::SetIdleTimeout (uint16_t idleTimeout) { m_idleTimeout = idleTimeout; }
uint32_t QuicTransportParameters::GetInitialMaxData () const { return m_initial_max_data; }
void QuicTransportParameters::SetInitialMaxData (uint32_t initialMaxData) { m_initial_max_data = initialMaxData; }
uint32_t QuicTransportParameters::GetInitialMaxStreamData () const { return m_initial_max_stream_data; }
void QuicTransportParameters::SetInitialMaxStreamData (uint32_t initialMaxStreamData) { m_initial_max_stream_data = initialMaxStreamData; }
uint32_t QuicTransportParameters::GetInitialMaxStreamIdBidi () const { return m_initial_max_stream_id_bidi; }
void QuicTransportParameters::SetInitialMaxStreamIdBidi (uint32_t initialMaxStreamIdBidi) { m_initial_max_stream_id_bidi = initialMaxStreamIdBidi; }
uint32_t QuicTransportParameters::GetInitialMaxStreamIdUni () const { return m_initial_max_stream_id_uni; }
void QuicTransportParameters::SetInitialMaxStreamIdUni (uint32_t initialMaxStreamIdUni) { m_initial_max_stream_id_uni = initialMaxStreamIdUni; }
uint16_t QuicTransportParameters::GetMaxPacketSize () const { return m_max_packet_size; }
void QuicTransportParameters::SetMaxPacketSize (uint16_t maxPacketSize) { m_max_packet_size = maxPacketSize; }
uint8_t QuicTransportParameters::GetOmitConnection () const { return m_omit_connection; }
void QuicTransportParameters::SetOmitConnection (uint8_t omitConnection) { m_omit_connection = omitConnection; }
bool QuicTransportParameters::HasStatelessResetToken () const { return m_hasStatelessResetToken; }
void QuicTransportParameters::SetHasStatelessResetToken (bool hasStatelessResetToken) { m_hasStatelessResetToken = hasStatelessResetToken; }
void QuicTransportParameters::SetDisableActiveMigration (bool disable) { m_disableActiveMigration = disable; }
bool QuicTransportParameters::GetDisableActiveMigration () const { return m_disableActiveMigration; }
void QuicTransportParameters::SetInitialSourceConnectionId (uint64_t cid) { m_initialSourceConnectionId = cid; m_hasInitialSourceConnectionId = true; }
uint64_t QuicTransportParameters::GetInitialSourceConnectionId () const { return m_initialSourceConnectionId; }
void QuicTransportParameters::SetOriginalDestinationConnectionId (uint64_t cid) { m_originalDestinationConnectionId = cid; m_hasOriginalDestinationConnectionId = true; }
uint64_t QuicTransportParameters::GetOriginalDestinationConnectionId () const { return m_originalDestinationConnectionId; }
bool QuicTransportParameters::HasInitialSourceConnectionId () const { return m_hasInitialSourceConnectionId; }
bool QuicTransportParameters::HasOriginalDestinationConnectionId () const { return m_hasOriginalDestinationConnectionId; }

} // namespace ns3