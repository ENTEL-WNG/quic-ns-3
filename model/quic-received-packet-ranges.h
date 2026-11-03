/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#ifndef QUIC_RECEIVED_PACKET_RANGES_H
#define QUIC_RECEIVED_PACKET_RANGES_H

#include <cstdint>
#include <vector>

namespace ns3 {

/**
 * \ingroup quic
 * \brief The received packet numbers of a packet number space, as disjoint ranges
 *
 * Two sets are kept. The received set remembers every packet number, so that a
 * late packet in an old gap can still be told apart from a duplicate and
 * accepted. The unreported set is the part of it the peer is not known to have
 * seen: pruning (RFC 9000 Sec. 13.2.4) removes from it only, so it stops ACKs
 * from repeating old ranges without refusing late packets.
 *
 * The received set is limited: beyond the limit its oldest range is forgotten,
 * and packets numbered at or below it are refused from then on (RFC 9000 Sec.
 * 13.2.3). That is what the floor tracks.
 */
class QuicReceivedPacketRanges
{
public:
  /// Packet numbers from low to high, both included
  struct Range
  {
    uint32_t low;   //!< Smallest packet number
    uint32_t high;  //!< Largest packet number
  };

  /**
   * \return true if no packet was ever received
   */
  bool IsEmpty () const;

  /**
   * \brief Record a received packet number, unless it is below the floor
   * \param packetNumber the packet number
   * \param maxRanges the most received ranges to remember, the oldest being forgotten first
   * \return true if the packet number had not been received before
   */
  bool Add (uint32_t packetNumber, uint32_t maxRanges);

  /**
   * \brief Note that the peer has seen some ranges, so they need no more reporting
   * \param ranges the ranges, in any order
   */
  void MarkReported (const std::vector<Range> &ranges);

  /**
   * \brief Get the ranges an ACK frame should report
   *
   * The largest packet number comes first, with the received packets below it
   * down to the lowest one the peer is not known to have seen, then the newest
   * unreported ranges below.
   *
   * \param maxRanges the most ranges to return
   * \return the ranges, in descending order, disjoint and not adjacent
   */
  std::vector<Range> GetRangesToReport (uint32_t maxRanges) const;

  /**
   * \param packetNumber a packet number
   * \return true if the packet number is too old to be accepted
   */
  bool IsBelowFloor (uint32_t packetNumber) const;

  /**
   * \return the received ranges, in ascending order
   */
  const std::vector<Range> &GetRanges () const;

  /**
   * \return the received ranges the peer is not known to have seen, in ascending order
   */
  const std::vector<Range> &GetUnreportedRanges () const;

private:
  std::vector<Range> m_received;    //!< Disjoint and non-adjacent, in ascending order
  std::vector<Range> m_unreported;  //!< A subset of m_received, in the same form
  uint32_t m_floor {0};             //!< The smallest packet number still accepted
};

} // namespace ns3

#endif /* QUIC_RECEIVED_PACKET_RANGES_H */
