/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * QUIC handshake tests over a real link: retransmitted Initial packets must not
 * kill the connection (RFC 9000 Sec. 14.1), and a close sent during the
 * handshake must reach a client that has already finished it (Sec. 10.2.3).
 */

#include "ns3/test.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/quic-helper.h"
#include "ns3/quic-header.h"
#include "ns3/quic-subheader.h"
#include "ns3/quic-socket-base.h"
#include "ns3/quic-socket-factory.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicHandshakeTest");

struct QuicHandshakeScenario
{
  std::string name;
  Time oneWayDelay;
  int dropAtServer;     //!< index of the packet the server's link drops; negative for none
  int dropAtClient;     //!< index of the packet the client's link drops; negative for none
  QuicSocketBase::PtoProbeMode probeMode;
  Time serverAbort;     //!< when the server aborts, from the start; negative for never
  bool zeroRtt = false; //!< whether the client writes its data in 0-RTT
  bool serverOpens = true; //!< whether the server should finish the handshake
};

class QuicHandshakeTestCase : public TestCase
{
public:
  QuicHandshakeTestCase (const QuicHandshakeScenario &scenario)
    : TestCase ("QUIC handshake: " + scenario.name),
      m_scenario (scenario)
  {
  }

private:
  virtual void DoRun (void);
  void OnConnected (Ptr<Socket> socket);
  void OnSendReady (Ptr<Socket> socket, uint32_t available);
  void OnAccepted (Ptr<Socket> socket, const Address &from);
  void OnServerRecv (Ptr<Socket> socket);
  void AbortServer ();
  void OnRetransmit (uint32_t packets, uint32_t bytes, uint8_t reason);

  QuicHandshakeScenario m_scenario;
  Ptr<QuicSocketBase> m_server;
  uint32_t m_written {0};
  uint32_t m_received {0};
  uint32_t m_lossRetransmissions {0};
  const uint32_t m_dataBytes {20000};
};

void
QuicHandshakeTestCase::OnSendReady (Ptr<Socket> socket, uint32_t available)
{
  while (m_written < m_dataBytes && socket->GetTxAvailable () >= 1000
         && socket->Send (Create<Packet> (1000), 0) > 0)
    {
      m_written += 1000;
    }
}

void
QuicHandshakeTestCase::OnConnected (Ptr<Socket> socket)
{
  OnSendReady (socket, 0);
}

void
QuicHandshakeTestCase::OnAccepted (Ptr<Socket> socket, const Address &from)
{
  m_server = DynamicCast<QuicSocketBase> (socket);
  socket->SetRecvCallback (MakeCallback (&QuicHandshakeTestCase::OnServerRecv, this));
}

void
QuicHandshakeTestCase::OnServerRecv (Ptr<Socket> socket)
{
  Ptr<Packet> p;
  Address from;
  while ((p = socket->RecvFrom (from)) && p->GetSize () > 0)
    {
      m_received += p->GetSize ();
    }
}

void
QuicHandshakeTestCase::AbortServer ()
{
  NS_TEST_EXPECT_MSG_EQ (m_server->GetSocketState (), QuicSocket::CONNECTING_SVR,
                         "The scenario should abort while the server is in the handshake");
  m_server->AbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION, "Test abort");
}

void
QuicHandshakeTestCase::OnRetransmit (uint32_t packets, uint32_t bytes, uint8_t reason)
{
  if (reason == QuicSocketBase::RETRANSMIT_LOSS)
    {
      m_lossRetransmissions += packets;
    }
}

void
QuicHandshakeTestCase::DoRun (void)
{
  Config::SetDefault ("ns3::QuicSocketBase::PtoProbeMode", EnumValue (m_scenario.probeMode));
  Config::SetDefault ("ns3::QuicL4Protocol::0RTT-Handshake", BooleanValue (m_scenario.zeroRtt));
  RngSeedManager::SetSeed (1);
  RngSeedManager::SetRun (1);

  NodeContainer nodes;
  nodes.Create (2);
  QuicHelper stack;
  stack.InstallQuic (nodes);

  PointToPointHelper link;
  link.SetDeviceAttribute ("DataRate", StringValue ("10Mbps"));
  link.SetChannelAttribute ("Delay", TimeValue (m_scenario.oneWayDelay));
  NetDeviceContainer devices = link.Install (nodes);

  if (m_scenario.dropAtServer >= 0)
    {
      Ptr<ReceiveListErrorModel> em = CreateObject<ReceiveListErrorModel> ();
      em->SetList ({static_cast<uint32_t> (m_scenario.dropAtServer)});
      devices.Get (1)->SetAttribute ("ReceiveErrorModel", PointerValue (em));
    }
  if (m_scenario.dropAtClient >= 0)
    {
      Ptr<ReceiveListErrorModel> em = CreateObject<ReceiveListErrorModel> ();
      em->SetList ({static_cast<uint32_t> (m_scenario.dropAtClient)});
      devices.Get (0)->SetAttribute ("ReceiveErrorModel", PointerValue (em));
    }

  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces = address.Assign (devices);

  const uint16_t port = 5000;
  Ptr<Socket> listener = Socket::CreateSocket (nodes.Get (1), QuicSocketFactory::GetTypeId ());
  listener->Bind (InetSocketAddress (Ipv4Address::GetAny (), port));
  listener->Listen ();
  listener->SetAcceptCallback (MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
                               MakeCallback (&QuicHandshakeTestCase::OnAccepted, this));

  Ptr<QuicSocketBase> client =
    DynamicCast<QuicSocketBase> (Socket::CreateSocket (nodes.Get (0), QuicSocketFactory::GetTypeId ()));
  client->SetConnectCallback (MakeCallback (&QuicHandshakeTestCase::OnConnected, this),
                              MakeNullCallback<void, Ptr<Socket>> ());
  client->SetSendCallback (MakeCallback (&QuicHandshakeTestCase::OnSendReady, this));
  client->TraceConnectWithoutContext ("Retransmit", MakeCallback (&QuicHandshakeTestCase::OnRetransmit, this));
  client->Bind ();
  client->Connect (InetSocketAddress (interfaces.GetAddress (1), port));

  if (m_scenario.serverAbort.IsStrictlyPositive ())
    {
      Simulator::Schedule (m_scenario.serverAbort, &QuicHandshakeTestCase::AbortServer, this);
    }

  Simulator::Stop (Seconds (120));
  Simulator::Run ();

  NS_TEST_EXPECT_MSG_NE (m_server, nullptr, "The connection should have been accepted");
  if (m_scenario.serverAbort.IsStrictlyPositive ())
    {
      NS_TEST_EXPECT_MSG_EQ (client->GetSocketState (), QuicSocket::IDLE,
                             "The client should learn of the close and be released");
    }
  else
    {
      NS_TEST_EXPECT_MSG_EQ (client->GetSocketState (), QuicSocket::OPEN, "The client should be connected");
      if (m_scenario.serverOpens)
        {
          NS_TEST_EXPECT_MSG_EQ (m_server->GetSocketState (), QuicSocket::OPEN, "The server should be connected");
        }
      NS_TEST_EXPECT_MSG_EQ (m_received, m_dataBytes, "All the data should arrive");
      if (m_scenario.zeroRtt)
        {
          NS_TEST_EXPECT_MSG_EQ (m_lossRetransmissions, 0, "Nothing is lost on a lossless path");
        }
    }

  Simulator::Destroy ();
  m_server = nullptr;
  Config::SetDefault ("ns3::QuicL4Protocol::0RTT-Handshake", BooleanValue (false));
}

class QuicHandshakeTestSuite : public TestSuite
{
public:
  QuicHandshakeTestSuite ()
    : TestSuite ("quic-handshake", UNIT)
  {
    const Time never = Seconds (-1);
    const auto newData = QuicSocketBase::PTO_PROBE_NEW_DATA;
    const auto retx = QuicSocketBase::PTO_PROBE_RETRANSMIT;
    const auto ping = QuicSocketBase::PTO_PROBE_PING_ONLY;
    // name, one-way delay, drop at server, drop at client, probe mode, server abort
    AddTestCase (new QuicHandshakeTestCase ({"short path", MilliSeconds (10), -1, -1, newData, never}), TestCase::QUICK);
    AddTestCase (new QuicHandshakeTestCase ({"RTT above the first PTO", MilliSeconds (600), -1, -1, newData, never}), TestCase::QUICK);
    AddTestCase (new QuicHandshakeTestCase ({"long RTT, PING probes", MilliSeconds (600), -1, -1, ping, never}), TestCase::QUICK);
    AddTestCase (new QuicHandshakeTestCase ({"long RTT, retransmit probes", MilliSeconds (600), -1, -1, retx, never}), TestCase::QUICK);
    AddTestCase (new QuicHandshakeTestCase ({"very long RTT", Seconds (5), -1, -1, newData, never}), TestCase::QUICK);
    AddTestCase (new QuicHandshakeTestCase ({"first Initial lost", MilliSeconds (10), 0, -1, newData, never}), TestCase::QUICK);
    AddTestCase (new QuicHandshakeTestCase ({"first Initial lost, retransmit probes", MilliSeconds (10), 0, -1, retx, never}), TestCase::QUICK);
    AddTestCase (new QuicHandshakeTestCase ({"server's first packet lost", MilliSeconds (10), -1, 0, newData, never}), TestCase::QUICK);
    AddTestCase (new QuicHandshakeTestCase ({"server's second packet lost", MilliSeconds (10), -1, 1, newData, never}), TestCase::QUICK);
    AddTestCase (new QuicHandshakeTestCase ({"close during the handshake", MilliSeconds (500), -1, -1, newData, Seconds (1.3)}), TestCase::QUICK);
    // The data does not fit the first flight, so the client still has some to send
    // when the handshake completes and the discarded Initial frees part of the window
    AddTestCase (new QuicHandshakeTestCase ({"0-RTT, short path", MilliSeconds (10), -1, -1, newData, never, true}), TestCase::QUICK);
    AddTestCase (new QuicHandshakeTestCase ({"0-RTT, long RTT", MilliSeconds (600), -1, -1, newData, never, true}), TestCase::QUICK);
    AddTestCase (new QuicHandshakeTestCase ({"0-RTT, very long RTT", Seconds (5), -1, -1, newData, never, true}), TestCase::QUICK);
    // The client's only Handshake packet is its second one. Its data must get through
    // without it, although nothing yet recovers the server's handshake
    AddTestCase (new QuicHandshakeTestCase ({"client's Handshake ACK lost", MilliSeconds (10), 1, -1, newData, never, false, false}), TestCase::QUICK);
  }
};

static QuicHandshakeTestSuite quicHandshakeTestSuite;

} // namespace ns3
