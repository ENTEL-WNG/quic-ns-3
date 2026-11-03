/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#include "quic-received-packet-ranges.h"

#include <algorithm>
#include <iterator>

namespace ns3 {

namespace {

/**
 * Add a packet number to a set of ranges
 * \return false if it was already in the set
 */
bool
Insert (std::vector<QuicReceivedPacketRanges::Range> &ranges, uint32_t packetNumber)
{
  // Packets mostly arrive in order, so search from the newest range
  auto it = ranges.end ();
  while (it != ranges.begin () && std::prev (it)->low > packetNumber)
    {
      --it;
    }
  // it is the first range above the packet number, if any

  if (it != ranges.begin () && std::prev (it)->high >= packetNumber)
    {
      return false;
    }

  bool extendsBelow = it != ranges.begin () && std::prev (it)->high + 1 == packetNumber;
  bool extendsAbove = it != ranges.end () && packetNumber + 1 == it->low;

  if (extendsBelow && extendsAbove)
    {
      std::prev (it)->high = it->high;
      ranges.erase (it);
    }
  else if (extendsBelow)
    {
      std::prev (it)->high = packetNumber;
    }
  else if (extendsAbove)
    {
      it->low = packetNumber;
    }
  else
    {
      ranges.insert (it, QuicReceivedPacketRanges::Range {packetNumber, packetNumber});
    }
  return true;
}

/// Remove a range of packet numbers from a set of ranges
void
Subtract (std::vector<QuicReceivedPacketRanges::Range> &ranges, QuicReceivedPacketRanges::Range removed)
{
  std::vector<QuicReceivedPacketRanges::Range> kept;
  for (const auto &r : ranges)
    {
      if (r.high < removed.low || r.low > removed.high)
        {
          kept.push_back (r);
          continue;
        }
      if (r.low < removed.low)
        {
          kept.push_back ({r.low, removed.low - 1});
        }
      if (r.high > removed.high)
        {
          kept.push_back ({removed.high + 1, r.high});
        }
    }
  ranges.swap (kept);
}

} // namespace

bool
QuicReceivedPacketRanges::IsEmpty () const
{
  return m_received.empty ();
}

bool
QuicReceivedPacketRanges::Add (uint32_t packetNumber, uint32_t maxRanges)
{
  if (IsBelowFloor (packetNumber) || !Insert (m_received, packetNumber))
    {
      return false;
    }
  Insert (m_unreported, packetNumber);

  if (m_received.size () > std::max<uint32_t> (maxRanges, 1))
    {
      m_floor = m_received.front ().high + 1;
      m_received.erase (m_received.begin ());
      Subtract (m_unreported, {0, m_floor - 1});
    }
  return true;
}

void
QuicReceivedPacketRanges::MarkReported (const std::vector<Range> &ranges)
{
  for (const auto &r : ranges)
    {
      Subtract (m_unreported, r);
    }
}

std::vector<QuicReceivedPacketRanges::Range>
QuicReceivedPacketRanges::GetRangesToReport (uint32_t maxRanges) const
{
  std::vector<Range> out;
  if (m_received.empty () || maxRanges == 0)
    {
      return out;
    }

  // The largest packet number is always reported. Its range starts at the lowest
  // packet in it the peer is not known to have seen, so that a long run of
  // reported packets is not repeated: a shorter First ACK Range encodes in fewer
  // bytes. Below it, the unreported ranges are separated from it, and from each
  // other, by at least one missing or reported packet.
  const Range &largest = m_received.back ();
  Range first {largest.high, largest.high};
  auto it = m_unreported.rbegin ();
  for (; it != m_unreported.rend () && it->high >= largest.low; ++it)
    {
      first.low = std::max (it->low, largest.low);
    }
  out.push_back (first);
  for (; it != m_unreported.rend () && out.size () < maxRanges; ++it)
    {
      out.push_back (*it);
    }
  return out;
}

bool
QuicReceivedPacketRanges::IsBelowFloor (uint32_t packetNumber) const
{
  return packetNumber < m_floor;
}

const std::vector<QuicReceivedPacketRanges::Range> &
QuicReceivedPacketRanges::GetRanges () const
{
  return m_received;
}

const std::vector<QuicReceivedPacketRanges::Range> &
QuicReceivedPacketRanges::GetUnreportedRanges () const
{
  return m_unreported;
}

} // namespace ns3
