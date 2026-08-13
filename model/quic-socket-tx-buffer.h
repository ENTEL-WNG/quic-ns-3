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
 */

#ifndef QUICSOCKETTXBUFFER_H
#define QUICSOCKETTXBUFFER_H

#include "ns3/object.h"
#include "ns3/traced-value.h"
#include "ns3/sequence-number.h"
#include "ns3/nstime.h"
#include "quic-subheader.h"
#include "ns3/packet.h"
#include "ns3/tcp-socket-base.h"
#include "ns3/data-rate.h"
#include "quic-socket-tx-scheduler.h"
#include "quic-socket.h"

namespace ns3 {

class QuicSocketState;
class QuicSocketBase;

struct RateSample
{
  DataRate m_deliveryRate;         //!< The delivery rate sample
  bool m_isAppLimited { false };       //!< Indicates whether the rate sample is application-limited
  Time m_interval;             //!< The length of the sampling interval
  uint32_t m_delivered { 0 };       //!< The amount of data marked as delivered over the sampling interval
  uint32_t m_priorDelivered { 0 };       //!< The delivered count of the most recent packet delivered
  Time m_priorTime;       //!< The delivered time of the most recent packet delivered
  Time m_sendElapsed;       //!< Send time interval calculated from the most recent packet delivered
  Time m_ackElapsed;       //!< ACK time interval calculated from the most recent packet delivered
  uint32_t m_packetLoss;
  uint32_t m_priorInFlight;
  uint32_t m_ackBytesSent { 0 };       //!< amount of ACK-only bytes sent over the sampling interval
  uint32_t m_priorAckBytesSent { 0 };       //!< amount of ACK-only bytes sent up to a flight ago
  uint8_t m_ackBytesMaxWin { 0 };
};


/**
 * \ingroup quic
 *
 * \brief Item that uses the application packet and some flags for it
 */
class QuicSocketTxItem : public Object
{
public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);

  QuicSocketTxItem ();
  QuicSocketTxItem (const QuicSocketTxItem &other);

  /**
   * \brief Get the payload size of the STREAM frame.
   *
   * This method returns the payload size specifically for STREAM frames.
   * If the QuicSocketTxItem does not represent a STREAM frame (i.e., m_isStream is false),
   * it returns 0 as non-STREAM frames do not count towards flow control in this context.
   *
   * \return The payload size of the STREAM frame in bytes, or 0 if it's not a STREAM frame.
   */
  uint32_t GetStreamPayloadSize () const;

  /**
   * \brief Merge two QuicSocketTxItem
   *
   * Merge t2 in t1. It consists in copying the lastSent field if t2 is more
   * recent than t1. Retransmitted field is copied only if it set in t2 but not
   * in t1. Sacked is copied only if it is true in both items.
   *
   * \param t1 first item
   * \param t2 second item
   */
  static void MergeItems (QuicSocketTxItem &t1, QuicSocketTxItem &t2);

  // Available only for streams
  static void SplitItems (QuicSocketTxItem &t1, QuicSocketTxItem &t2,
                          uint32_t size);

  /**
   * \brief Print the Item
   * \param os ostream
   */
  void Print (std::ostream &os) const;

  Ptr<Packet> m_packet;                           //!< packet associated to this QuicSocketTxItem
  SequenceNumber32 m_packetNumber;                //!< sequence number
  PacketNumberSpace m_space { APPLICATION_DATA }; //!< Packet number space
  bool m_lost;                                    //!< true if the packet is lost
  bool m_retrans;                                 //!< true if it is a retx
  bool m_sacked;                                  //!< true if already acknowledged
  bool m_acked;                                   //!< true if already passed to the application
  bool m_isStream;                                //!< true if the packet contains STREAM frames (application data)
  bool m_isCrypto;                                //!< true if the packet contains CRYPTO frames (handshake data)
  Time m_lastSent;                                //!< time at which it was sent
  Time m_ackTime;                                 //!< time at which the packet was first acked (if m_sacked is true)
  Time m_generated;                               //!< expiration deadline for the TX item

  uint64_t m_delivered;                           //!< Connection's delivered data at the time the packet was sent
  Time m_deliveredTime;                           //!< Connection's delivered time at the time the packet was sent
  Time m_firstSentTime;                           //!< Connection's first sent time at the time the packet was sent
  bool m_isAppLimited;                            //!< Connection's app limited at the time the packet was sent
  uint32_t m_ackBytesSent;                        //!< Connection's ACK-only bytes sent at the time the packet was sent
  uint32_t m_wireBytes;                           //!< Full wire size (including headers)
  uint32_t m_payloadBytes;                        //!< Total STREAM frame payload bytes within this packet.
};

/**
 * \ingroup quic
 *
 * \brief Tx socket buffer for QUIC
 */
class QuicSocketTxBuffer : public Object
{
public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);

  QuicSocketTxBuffer ();
  virtual ~QuicSocketTxBuffer (void);

  /**
   * Print the buffer information to a string,
   * including the list of sent packets
   *
   * \param os the std::ostream object
   */
  void Print (std::ostream &os) const;
  //friend std::ostream & operator<< (std::ostream & os, QuicSocketTxBuffer const & quicTxBuf);

  /**
   * Add a packet to the tx buffer
   *
   * \param p a smart pointer to a packet
   * \return true if the insertion was successful
   */
  bool Add (Ptr<Packet> p, PacketNumberSpace space = APPLICATION_DATA);

  /**
   * \brief Request the next packet to transmit
   *
   * \param numBytes the number of bytes of the next packet to transmit requested
   * \param seq the sequence number of the next packet to transmit
   * \return the next packet to transmit
   */
  Ptr<Packet> NextSequence (uint32_t numBytes, const SequenceNumber32 seq, PacketNumberSpace space);

  /**
   * \brief Get a block of data not transmitted yet and move it into SentList
   *
   * \param numBytes number of bytes of the QuicSocketTxItem requested
   * \param space the packet number space
   * \return the item that contains the right packet
   */
  Ptr<QuicSocketTxItem> GetNewSegment (uint32_t numBytes, PacketNumberSpace space);

  /**
   * Process an acknowledgment, set the packets in the send buffer as acknowledged, mark
   * lost packets (according to the QUIC IETF draft) and return pointers to the newly
   * acked packets
   *
   * \brief Process an ACK
   *
   * \param tcb The state of the socket (used for loss detection)
   * \param largestAcknowledged The largest acknowledged sequence number
   * \param additionalAckBlocks The sequence numbers that were just acknowledged
   * \param gaps The gaps in the acknowledgment
   * \return a vector containing the newly acked packets for congestion control purposes
   */
  std::vector<Ptr<QuicSocketTxItem> > OnAckUpdate (Ptr<TcpSocketState> tcb,
                                                   const uint32_t largestAcknowledged,
                                                   const std::vector<uint32_t> &additionalAckBlocks,
                                                   const std::vector<uint32_t> &gaps,
                                                   PacketNumberSpace space);

  /**
   * Get the max size of the buffer
   *
   * \return the maximum buffer size in bytes
   */
  uint32_t GetMaxBufferSize (void) const;

  /**
   * Set the max size of the buffer
   *
   * \param n the maximum buffer size in bytes
   */
  void SetMaxBufferSize (uint32_t n);

  /**
   * \brief Get all the packets marked as lost
   *
   * \return a vector containing the packets marked as lost
   */
  std::vector<Ptr<QuicSocketTxItem> > DetectLostPackets (Ptr<TcpSocketState> tcb, PacketNumberSpace space);

  /**
   * \brief Count the amount of lost bytes
   *
   * \return the number of bytes considered lost
   */
  uint32_t GetLost ();

  /**
   * Compute the available space in the buffer
   *
   * \return the available space in the buffer
   */
  uint32_t Available (void) const;

  /**
   * Returns the total number of bytes in the application buffer
   *
   * \return the total number of bytes in the application buffer
   */
  uint32_t AppSize (void) const;

  /**
   * \brief Return total bytes in flight (all retransmittable packets)
   *
   * \returns total bytes in flight
   */
  uint32_t BytesInFlight () const;
  uint32_t BytesInFlight (PacketNumberSpace space) const;

  /**
   * \brief Return bytes in flight subject to congestion control (excluding Initial/Handshake)
   *
   * \returns congestion controlled bytes in flight
   */
  uint32_t GetCongestionControlledBytesInFlight () const;

  /**
    * \brief Return bytes in flight for Handshake/Initial packets
    *
    * \returns handshake bytes in flight
    */
  uint32_t GetHandshakeInFlight () const;

  /**
   * Return the number of CRYPTO frames in the buffer
   *
   * \return the number of CRYPTO frames in the buffer
   */
  uint32_t GetNumCryptoFramesInBuffer (PacketNumberSpace space) const;

  /**
   * Return the next CRYPTO frame to be sent
   * and add this packet to the sent list
   *
   * \param seq the sequence number of the packet
   * \return a smart pointer to the packet, 0 if there are no CRYPTO frames
   */
  Ptr<Packet> NextCryptoSequence (const SequenceNumber32 seq, PacketNumberSpace space);

  /**
   * \brief Reset the sent list
   *
   * Move all but the first 'keepItems' packets from the sent list to the
   * appList.  By default, the HEAD of the sent list is kept and all others
   * moved to the appList.  All items kept on the sent list
   * are then marked as un-sacked, un-retransmitted, and lost.
   *
   * \param keepItems Keep a number of items at the front of the sent list
   */
  void ResetSentList (uint32_t keepItems = 1);

  /**
   * Mark a packet as lost
   * \param the sequence number of the packet
   * \return true if the packet is in the send buffer
   */
  bool MarkAsLost (const SequenceNumber32 seq, PacketNumberSpace space);

  /**
   * Put the lost packets at the beginning of the application buffer to retransmit them
   * \param the sequence number of the retransmitted packet
   * \return the number of lost bytes
   */
  uint32_t Retransmission (SequenceNumber32 packetNumber, PacketNumberSpace space);

  /**
   * Set the TcpSocketState (tcb)
   * \param The TcpSocketState object
   */
  void SetQuicSocketState (Ptr<QuicSocketState> tcb);

  /**
   * Set the socket scheduler
   * \param The scheduler object
   */
  void SetScheduler (Ptr<QuicSocketTxScheduler> sched);

  /**
   * Set the QuicSocketBase
   * \param The socket object
   */
  void SetSocket (Ptr<QuicSocketBase> socket);

  /**
   * Updates per packet variables required for rate sampling on each packet transmission
   * \param The sequence number of the sent packet
   * \param The size of the sent packet
   */
  void UpdatePacketSent (SequenceNumber32 seq, uint32_t sz, PacketNumberSpace space);

  /**
   * Updates ACK related variables required by RateSample to discount the delivery rate.
   * \param The sequence number of the sent ACK packet
   * \param The size of the sent ACK packet
   */
  void UpdateAckSent (SequenceNumber32 seq, uint32_t sz, PacketNumberSpace space);

  /**
   * \brief Discard all packets in a packet number space
   * \param space the packet number space
   */
  void DiscardSpace (PacketNumberSpace space);

  /**
   * Get the current rate sample
   * \return A pointer to the current rate sample
   */
  struct RateSample* GetRateSample ();

  /**
   * Updates rate samples rate on arrival of each acknowledgement.
   * \param The QuicSocketTxItem containing the acknowledgment
   */
  void UpdateRateSample (Ptr<QuicSocketTxItem> pps);

  /**
   * Calculates delivery rate on arrival of each acknowledgement.
   * \return True if the calculation is performed correctly
   */
  bool GenerateRateSample ();

  /**
   * Set the latency bound for a specified stream
   *
   * \param streamId The stream ID
   * \param latency The stream's maximum latency
   */
  void SetLatency (uint32_t streamId, Time latency);

  /**
   * Get the latency bound for a specified stream
   *
   * \param streamId The stream ID
   * \return The stream's maximum latency, or 0 if the stream is not registered
   */
  Time GetLatency (uint32_t streamId);

  /**
   * Set the default latency bound
   *
   * \param latency The default maximum latency
   */
  void SetDefaultLatency (Time latency);

  /**
   * Get the default latency bound
   *
   * \param streamId The stream ID
   * \return The default maximum latency
   */
  Time GetDefaultLatency ();

    /**
   * \brief Return the total number of STREAM payload bytes in flight.
   *
   * This method calculates the sum of payload bytes for all packets
   * that have been sent but not yet acknowledged and are not marked as lost.
   * This value represents the amount of application data currently awaiting
   * acknowledgment.
   *
   * \return The total number of payload bytes in flight.
   */
  uint32_t GetPayloadBytesInFlight () const;

private:
  typedef std::list<Ptr<QuicSocketTxItem> > QuicTxPacketList;      //!< container for data stored in the buffer

  QuicTxPacketList m_sentList[3];        //!< List of sent packets with additional info per space
  QuicTxPacketList m_cryptoList[3];      //!< List of waiting CRYPTO frame packets with additional info per space (only 0 and 1 used)
  uint32_t m_maxBuffer;                  //!< Max number of data bytes in buffer (SND.WND)
  uint32_t m_cryptoSize;                 //!< Size of all CRYPTO frame data in the buffer
  uint32_t m_sentSize;                   //!< Total wire size of all packets currently in the sent list.
  uint32_t m_numCryptoFramesInBuffer;    //!< Number of CRYPTO frames buffered

  Ptr<QuicSocketTxScheduler> m_scheduler { nullptr };         //!< Scheduler
  Ptr<QuicSocketState> m_tcb { nullptr };
  Ptr<QuicSocketBase> m_socket { nullptr };
  struct RateSample m_rs;
};

} // namepsace ns3

#endif /* QUIC_SOCKET_TX_BUFFER_H */
