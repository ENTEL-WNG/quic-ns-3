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

  return len;
}


void
QuicTransportParameters::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  auto writeParam = [&](uint64_t id, uint64_t val) {
    i.WriteU8 ((uint8_t)id);
    if (val <= 63) {
      i.WriteU8 (1);
      i.WriteU8 ((uint8_t)val);
    } else if (val <= 16383) {
      i.WriteU8 (2);
      i.WriteHtonU16 ((uint16_t)val);
    } else if (val <= 1073741823) {
      i.WriteU8 (4);
      i.WriteHtonU32 ((uint32_t)val);
    } else {
      i.WriteU8 (8);
      i.WriteHtonU64 (val);
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
}

uint32_t
QuicTransportParameters::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint32_t readBytes = 0;
  
  while (readBytes < 20)
  {
    if (i.GetRemainingSize() < 2) break;
    uint8_t id = i.ReadU8();
    uint8_t len = i.ReadU8();
    if (i.GetRemainingSize() < len) break;
    
    uint64_t val = 0;
    if (len == 1) val = i.ReadU8();
    else if (len == 2) val = i.ReadNtohU16();
    else if (len == 4) val = i.ReadNtohU32();
    else if (len == 8) val = i.ReadNtohU64();
    else i.Next(len);
    
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
    }
    if (readBytes >= 60) break;
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
  os << "|initial_max_stream_id_uni " << m_initial_max_stream_id_uni << "]\n";
}

QuicTransportParameters
QuicTransportParameters::CreateTransportParameters (uint32_t initial_max_stream_data, uint32_t initial_max_data, uint32_t initial_max_stream_id_bidi, uint16_t idleTimeout,
                                                    uint8_t omit_connection, uint16_t max_packet_size, uint8_t ack_delay_exponent, uint16_t max_ack_delay, uint32_t initial_max_stream_id_uni)
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

} // namespace ns3