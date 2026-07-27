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

#ifndef QUICTRANSPORTPARAMETERS_H
#define QUICTRANSPORTPARAMETERS_H

#include <stdint.h>
#include <vector>
#include <iostream>
#include "ns3/header.h"
#include "ns3/buffer.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv6-address.h"
#include "ns3/sequence-number.h"

namespace ns3 {

/**
 * \ingroup quic
 * \brief Transport Parameters for the QUIC Protocol (RFC 9000)
 *
 * This class has fields corresponding to those in QUIC Transport Parameters
 * as well as methods for serialization to and deserialization from a buffer.
 *
 * Transport Parameters [RFC 9000 Section 18.2]
 * --------------------------------------------------------------
 *
 * During connection establishment, both endpoints make authenticated
 * declarations of their transport parameters. These declarations are
 * made unilaterally by each endpoint. Endpoints are required to comply
 * with the restrictions implied by these parameters; the description
 * of each parameter includes rules for its handling. QUIC encodes
 * transport parameters into a sequence of TLVs (Type-Length-Value).
 *
 */
class QuicTransportParameters : public Header
{
public:
  /**
   * \brief Quic Transport Parameter IDs (RFC 9000 Section 18.2)
   */
  typedef enum
  {
    MAX_IDLE_TIMEOUT = 0x01,
    STATELESS_RESET_TOKEN = 0x02,
    MAX_UDP_PAYLOAD_SIZE = 0x03,
    INITIAL_MAX_DATA = 0x04,
    INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05,
    INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06,
    INITIAL_MAX_STREAM_DATA_UNI = 0x07,
    INITIAL_MAX_STREAMS_BIDI = 0x08,
    INITIAL_MAX_STREAMS_UNI = 0x09,
    ACK_DELAY_EXPONENT = 0x0a,
    MAX_ACK_DELAY = 0x0b,
    DISABLE_ACTIVE_MIGRATION = 0x0c,
    ORIGINAL_DESTINATION_CONNECTION_ID = 0x00,
    INITIAL_SOURCE_CONNECTION_ID = 0x0f,
    ACTIVE_CONNECTION_ID_LIMIT = 0x0e
  } TransportParameterId_t;

  QuicTransportParameters ();
  virtual ~QuicTransportParameters ();

  // Inherited from Header
  static TypeId GetTypeId (void);
  virtual TypeId GetInstanceTypeId (void) const;
  virtual void Print (std::ostream &os) const;
  virtual uint32_t GetSerializedSize (void) const;
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);

  /**
   * \brief Print Quic Transport Parameters into an output stream
   *
   * \param os output stream
   * \param tc Quic Transport Parameters to print
   * \return The ostream passed as first argument
   */
  friend std::ostream& operator<< (std::ostream& os, const QuicTransportParameters & tc);

  /**
   * Create the Transport Parameters block
   *
   * \param initial_max_stream_data the initial value for the maximum data that can be sent on any newly created stream
   * \param initial_max_data the initial value for the maximum amount of data that can be sent on the connection
   * \param initial_max_stream_id_bidi the initial maximum number of application-owned bidirectional streams the peer may initiate
   * \param idleTimeout the idle timeout value in seconds
   * \param max_packet_size the limit on the size of packets that the endpoint is willing to receive
   * \param ack_delay_exponent the exponent used to decode the ack delay field in the ACK frame
   * \param initial_max_stream_id_uni the initial maximum number of application-owned unidirectional streams the peer may initiate
   * \param disable_migration true if migration should be disabled
   * \return the generated QuicTransportParameters
   */
  static QuicTransportParameters CreateTransportParameters (uint32_t initial_max_stream_data, uint32_t initial_max_data, uint32_t initial_max_stream_id_bidi, uint32_t idleTimeout,
                                                            uint16_t max_packet_size, uint8_t ack_delay_exponent, uint16_t max_ack_delay, uint32_t initial_max_stream_id_uni, bool disable_migration = true);

  // Getters, Setters and Controls

  /**
   * \brief Get the ack delay exponent
   * \return The ack delay exponent for this QuicTransportParameters
   */
  uint8_t GetAckDelayExponent () const;

  /**
   * \brief Set the ack delay exponent
   * \param ackDelayExponent the ack delay exponent for this QuicTransportParameters
   */
  void SetAckDelayExponent (uint8_t ackDelayExponent);

  /**
   * \brief Get the idle timeout
   * \return The idle timeout for this QuicTransportParameters
   */
  uint32_t GetIdleTimeout () const;

  /**
   * \brief Set the idle timeout
   * \param idleTimeout the idle timeout for this QuicTransportParameters
   */
  void SetIdleTimeout (uint32_t idleTimeout);

  /**
   * \brief Get the initial max data limit
   * \return The initial max data limit for this QuicTransportParameters
   */
  uint32_t GetInitialMaxData () const;

  /**
   * \brief Set the initial max data limit
   * \param initialMaxData the initial max data limit for this QuicTransportParameters
   */
  void SetInitialMaxData (uint32_t initialMaxData);

  /**
   * \brief Get the initial max stream data limit
   * \return The initial max stream data limit for this QuicTransportParameters
   */
  uint32_t GetInitialMaxStreamData () const;

  /**
   * \brief Set the initial max stream data limit
   * \param initialMaxStreamData the initial max stream data limit for this QuicTransportParameters
   */
  void SetInitialMaxStreamData (uint32_t initialMaxStreamData);

  /**
   * \brief Get the initial max bidirectional stream id limit
   * \return The initial max bidirectional stream id limit for this QuicTransportParameters
   */
  uint32_t GetInitialMaxStreamIdBidi () const;

  /**
   * \brief Set the initial max bidirectional stream id limit
   * \param initialMaxStreamIdBidi the initial max bidirectional stream id limit for this QuicTransportParameters
   */
  void SetInitialMaxStreamIdBidi (uint32_t initialMaxStreamIdBidi);

  /**
   * \brief Get the initial max unidirectional stream id limit
   * \return The initial max unidirectional stream id limit for this QuicTransportParameters
   */
  uint32_t GetInitialMaxStreamIdUni () const;

  /**
   * \brief Set the initial max unidirectional stream id limit
   * \param initialMaxStreamIdUni the initial max unidirectional stream id limit for this QuicTransportParameters
   */
  void SetInitialMaxStreamIdUni (uint32_t initialMaxStreamIdUni);

  /**
   * \brief Get the max packet size limit
   * \return The max packet size limit for this QuicTransportParameters
   */
  uint16_t GetMaxPacketSize () const;

  /**
   * \brief Set the max packet size limit
   * \param maxPacketSize the max packet size limit for this QuicTransportParameters
   */
  void SetMaxPacketSize (uint16_t maxPacketSize);

  /**
   * \brief Check if the stateless reset token was provided
   * \return true if the stateless reset token was provided, false otherwise
   */
  bool HasStatelessResetToken () const;

  /**
   * \brief Set the stateless reset token flag
   * \param hasStatelessResetToken true if the stateless reset token was provided, false otherwise
   */
  void SetHasStatelessResetToken (bool hasStatelessResetToken);

  /**
   * \brief Get the max ack delay
   * \return The max ack delay for this QuicTransportParameters
   */
  uint16_t GetMaxAckDelay () const;

  /**
   * \brief Set the max ack delay
   * \param maxAckDelay the max ack delay for this QuicTransportParameters
   */
  /**
   * \brief Set the max ack delay
   * \param maxAckDelay the max ack delay for this QuicTransportParameters
   */
  void SetMaxAckDelay (uint16_t maxAckDelay);

  /**
   * \brief Set the disable active migration flag
   * \param disable true to disable migration
   */
  void SetDisableActiveMigration (bool disable);

  /**
   * \brief Get the disable active migration flag
   * \return true if migration is disabled
   */
  bool GetDisableActiveMigration () const;

  /**
   * \brief Get the active connection ID limit
   * \return The active connection ID limit for this QuicTransportParameters
   */
  uint32_t GetActiveConnectionIdLimit () const;

  /**
   * \brief Set the active connection ID limit
   * \param activeConnectionIdLimit the maximum number of active connection IDs the peer will store
   */
  void SetActiveConnectionIdLimit (uint32_t activeConnectionIdLimit);

  /**
   * \brief Set the initial source connection ID
   * \param cid the connection ID
   */
  void SetInitialSourceConnectionId (uint64_t cid);

  /**
   * \brief Get the initial source connection ID
   * \return the connection ID
   */
  uint64_t GetInitialSourceConnectionId () const;

  /**
   * \brief Set the original destination connection ID
   * \param cid the connection ID
   */
  void SetOriginalDestinationConnectionId (uint64_t cid);

  /**
   * \brief Get the original destination connection ID
   * \return the connection ID
   */
  uint64_t GetOriginalDestinationConnectionId () const;

  /**
   * \brief Check if initial source CID is set
   */
  bool HasInitialSourceConnectionId () const;

  /**
   * \brief Check if original destination CID is set
   */
  bool HasOriginalDestinationConnectionId () const;

  /**
   * Comparison operator
   * \param lhs left operand
   * \param rhs right operand
   * \return true if the operands are equal
   */
  friend bool operator== (const QuicTransportParameters &lhs, const QuicTransportParameters &rhs);

private:
  /**
   * \brief Calculates the Transport Parameters block length (in bytes)
   *
   * Given the standard size of the Transport Parameters block, the method checks for options
   * and calculates the real length (in bytes).
   *
   * \return Transport Parameters block length in bytes
   */
  uint32_t CalculateHeaderLength () const;

  uint32_t m_initial_max_stream_data;     //!< The initial value for the maximum data that can be sent on any newly created stream
  uint32_t m_initial_max_data;            //!< The initial value for the maximum amount of data that can be sent on the connection
  uint32_t m_initial_max_stream_id_bidi;  //!< The initial maximum number of application-owned bidirectional streams the peer may initiate
  uint32_t m_idleTimeout;                 //!< The idle timeout value in seconds
  uint16_t m_max_packet_size;             //!< The limit on the size of packets that the endpoint is willing to receive
  uint8_t m_ack_delay_exponent;           //!< The exponent used to decode the ack delay field in the ACK frame
  uint16_t m_max_ack_delay;               //!< The maximum amount of time in milliseconds by which the endpoint will delay sending acknowledgments
  uint32_t m_initial_max_stream_id_uni;   //!< The initial maximum number of application-owned unidirectional streams the peer may initiate
  uint32_t m_activeConnectionIdLimit;     //!< The maximum number of active connection IDs the endpoint is willing to store
  bool m_disableActiveMigration = false;  //!< If true, the endpoint does not support migration
  uint64_t m_initialSourceConnectionId = 0;
  bool m_hasInitialSourceConnectionId = false;
  uint64_t m_originalDestinationConnectionId = 0;
  bool m_hasOriginalDestinationConnectionId = false;
  bool m_hasStatelessResetToken;          //!< Flag to indicate if a stateless reset token was provided
};

} // namespace ns3

#endif /* QUIC_TRANSPORT_PARAMETERS_H_ */
