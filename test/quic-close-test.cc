/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * QUIC connection close tests - RFC 9000 Sec. 10.2
 *
 * Runs real connections over a point-to-point link, closes them, and checks
 * that the close exchange ends and that both sockets are released.
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

NS_LOG_COMPONENT_DEFINE ("QuicCloseTest");

/**
 * Who closes the connection, how much is pending, and what the link does.
 */
struct QuicCloseScenario
{
  std::string name;
  uint32_t dataBytes;   //!< written by the client once connected
  bool flushOnClose;
  double errorRate;     //!< applied to the packets the server receives
  Time clientClose;     //!< delay from the connection being up; negative to never close
  Time serverClose;     //!< delay from the connection being up; negative to never close
  Time linkFailure;     //!< delay from the connection being up; negative to never fail
  Time idleTimeout;
};

class QuicCloseTestCase : public TestCase
{
public:
  QuicCloseTestCase (const QuicCloseScenario &scenario);

private:
  virtual void DoRun (void);

  void CheckResults ();

  void OnConnected (Ptr<Socket> socket);
  void OnSendReady (Ptr<Socket> socket, uint32_t available);
  void OnAccepted (Ptr<Socket> socket, const Address &from);
  void OnServerRecv (Ptr<Socket> socket);
  void OnClientTx (const Ptr<const Packet> p, const QuicHeader &h, Ptr<const QuicSocketBase> s);
  void OnServerTx (const Ptr<const Packet> p, const QuicHeader &h, Ptr<const QuicSocketBase> s);

  void WriteData (Ptr<Socket> socket);
  void CloseSocket (Ptr<Socket> socket);
  void FailLink (Ptr<NetDevice> device);

  QuicCloseScenario m_scenario;
  Ptr<QuicSocketBase> m_client;
  Ptr<QuicSocketBase> m_listener;
  Ptr<QuicSocketBase> m_server;
  uint32_t m_written {0};
  uint32_t m_received {0};
  uint32_t m_clientCloses {0};
  uint32_t m_serverCloses {0};
  uint32_t m_clientPacketsAfterPeerClose {0};
  Time m_lastClose {Seconds (0)};
  Ptr<NetDevice> m_serverDevice;
};

QuicCloseTestCase::QuicCloseTestCase (const QuicCloseScenario &scenario)
  : TestCase ("QUIC connection close: " + scenario.name),
    m_scenario (scenario)
{
}

static bool
CarriesConnectionClose (Ptr<const Packet> p)
{
  // SendPacket() has prepended the QUIC header by the time the trace fires
  Ptr<Packet> copy = p->Copy ();
  QuicHeader header;
  copy->RemoveHeader (header);
  while (copy->GetSize () > 0)
    {
      QuicSubheader sub;
      copy->RemoveHeader (sub);
      if (sub.IsConnectionClose () || sub.IsApplicationClose ())
        {
          return true;
        }
      copy->RemoveAtStart (sub.GetLength ());
    }
  return false;
}

void
QuicCloseTestCase::OnClientTx (const Ptr<const Packet> p, const QuicHeader &h, Ptr<const QuicSocketBase> s)
{
  if (CarriesConnectionClose (p))
    {
      ++m_clientCloses;
      m_lastClose = Simulator::Now ();
    }
  else if (m_serverCloses > 0)
    {
      ++m_clientPacketsAfterPeerClose;
    }
}

void
QuicCloseTestCase::OnServerTx (const Ptr<const Packet> p, const QuicHeader &h, Ptr<const QuicSocketBase> s)
{
  if (CarriesConnectionClose (p))
    {
      ++m_serverCloses;
      m_lastClose = Simulator::Now ();
    }
}

void
QuicCloseTestCase::WriteData (Ptr<Socket> socket)
{
  while (m_written < m_scenario.dataBytes)
    {
      uint32_t chunk = std::min<uint32_t> (1000, m_scenario.dataBytes - m_written);
      if (socket->GetTxAvailable () < chunk || socket->Send (Create<Packet> (chunk), 0) <= 0)
        {
          return; // resumed by the send callback
        }
      m_written += chunk;
    }
}

void
QuicCloseTestCase::CloseSocket (Ptr<Socket> socket)
{
  socket->Close ();
}

void
QuicCloseTestCase::FailLink (Ptr<NetDevice> device)
{
  Ptr<RateErrorModel> em = CreateObject<RateErrorModel> ();
  em->SetUnit (RateErrorModel::ERROR_UNIT_PACKET);
  em->SetRate (1.0);
  device->SetAttribute ("ReceiveErrorModel", PointerValue (em));
}

void
QuicCloseTestCase::OnConnected (Ptr<Socket> socket)
{
  WriteData (socket);
  if (!m_scenario.clientClose.IsStrictlyNegative ())
    {
      Simulator::Schedule (m_scenario.clientClose, &QuicCloseTestCase::CloseSocket, this, socket);
    }
  if (!m_scenario.linkFailure.IsStrictlyNegative ())
    {
      Simulator::Schedule (m_scenario.linkFailure, &QuicCloseTestCase::FailLink, this, m_serverDevice);
    }
}

void
QuicCloseTestCase::OnSendReady (Ptr<Socket> socket, uint32_t available)
{
  WriteData (socket);
}

void
QuicCloseTestCase::OnAccepted (Ptr<Socket> socket, const Address &from)
{
  m_server = DynamicCast<QuicSocketBase> (socket);
  socket->SetRecvCallback (MakeCallback (&QuicCloseTestCase::OnServerRecv, this));
  m_server->TraceConnectWithoutContext ("Tx", MakeCallback (&QuicCloseTestCase::OnServerTx, this));
  if (!m_scenario.serverClose.IsStrictlyNegative ())
    {
      Simulator::Schedule (m_scenario.serverClose, &QuicCloseTestCase::CloseSocket, this, socket);
    }
}

void
QuicCloseTestCase::OnServerRecv (Ptr<Socket> socket)
{
  Ptr<Packet> p;
  Address from;
  while ((p = socket->RecvFrom (from)) && p->GetSize () > 0)
    {
      m_received += p->GetSize ();
    }
}

void
QuicCloseTestCase::DoRun (void)
{
  Config::SetDefault ("ns3::QuicSocketBase::FlushOnClose", BooleanValue (m_scenario.flushOnClose));
  Config::SetDefault ("ns3::QuicSocketBase::IdleTimeout", TimeValue (m_scenario.idleTimeout));
  RngSeedManager::SetSeed (1);
  RngSeedManager::SetRun (1);

  NodeContainer nodes;
  nodes.Create (2);
  QuicHelper stack;
  stack.InstallQuic (nodes);

  PointToPointHelper link;
  link.SetDeviceAttribute ("DataRate", StringValue ("10Mbps"));
  link.SetChannelAttribute ("Delay", StringValue ("10ms"));
  NetDeviceContainer devices = link.Install (nodes);
  m_serverDevice = devices.Get (1);

  if (m_scenario.errorRate > 0)
    {
      Ptr<RateErrorModel> em = CreateObject<RateErrorModel> ();
      em->SetUnit (RateErrorModel::ERROR_UNIT_PACKET);
      em->SetRate (m_scenario.errorRate);
      m_serverDevice->SetAttribute ("ReceiveErrorModel", PointerValue (em));
    }

  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces = address.Assign (devices);

  const uint16_t port = 5000;
  m_listener = DynamicCast<QuicSocketBase> (Socket::CreateSocket (nodes.Get (1), QuicSocketFactory::GetTypeId ()));
  m_listener->Bind (InetSocketAddress (Ipv4Address::GetAny (), port));
  m_listener->Listen ();
  m_listener->SetAcceptCallback (MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
                                 MakeCallback (&QuicCloseTestCase::OnAccepted, this));

  m_client = DynamicCast<QuicSocketBase> (Socket::CreateSocket (nodes.Get (0), QuicSocketFactory::GetTypeId ()));
  m_client->TraceConnectWithoutContext ("Tx", MakeCallback (&QuicCloseTestCase::OnClientTx, this));
  m_client->SetConnectCallback (MakeCallback (&QuicCloseTestCase::OnConnected, this),
                                MakeNullCallback<void, Ptr<Socket>> ());
  m_client->SetSendCallback (MakeCallback (&QuicCloseTestCase::OnSendReady, this));
  m_client->Bind ();
  m_client->Connect (InetSocketAddress (interfaces.GetAddress (1), port));

  Simulator::Stop (Seconds (120));
  Simulator::Run ();

  CheckResults ();

  Simulator::Destroy ();
  m_client = nullptr;
  m_server = nullptr;
  m_listener = nullptr;
  m_serverDevice = nullptr;
}

void
QuicCloseTestCase::CheckResults ()
{
  NS_TEST_ASSERT_MSG_NE (m_server, nullptr, "The connection should have been accepted");
  NS_TEST_EXPECT_MSG_EQ (m_client->GetSocketState (), QuicSocket::IDLE, "The client socket should be released");

  if (!m_scenario.linkFailure.IsStrictlyNegative ())
    {
      // The peer is unreachable: only the idle timeout can end the flush, silently
      NS_TEST_EXPECT_MSG_EQ (m_clientCloses, 0, "An idle timeout should close silently");
      return;
    }

  NS_TEST_EXPECT_MSG_EQ (m_server->GetSocketState (), QuicSocket::IDLE, "The server socket should be released");

  if (m_scenario.flushOnClose && m_scenario.serverClose.IsStrictlyNegative ())
    {
      NS_TEST_EXPECT_MSG_EQ (m_written, m_scenario.dataBytes, "Everything should have been written");
      NS_TEST_EXPECT_MSG_EQ (m_received, m_scenario.dataBytes, "A flush should deliver everything");
    }

  if (m_scenario.serverClose.IsStrictlyNegative ())
    {
      // Sent only once all data is acknowledged, or with a few answers to what is in flight
      NS_TEST_EXPECT_MSG_GT_OR_EQ (m_clientCloses, 1, "The client should send CONNECTION_CLOSE");
      NS_TEST_EXPECT_MSG_LT_OR_EQ (m_clientCloses, 10, "CONNECTION_CLOSE answers should be rate limited");
      NS_TEST_EXPECT_MSG_EQ (m_serverCloses, 0, "RFC 9000 10.2.2: a draining peer must not send");
    }
  else
    {
      NS_TEST_EXPECT_MSG_GT_OR_EQ (m_serverCloses, 1, "The server should send CONNECTION_CLOSE");
      NS_TEST_EXPECT_MSG_LT_OR_EQ (m_serverCloses, 12, "CONNECTION_CLOSE answers should be rate limited");
      NS_TEST_EXPECT_MSG_EQ (m_clientCloses, 0, "RFC 9000 10.2.2: a draining peer must not send");
    }

  // Well before the end of the run: the exchange finishes on its own
  NS_TEST_EXPECT_MSG_LT (m_lastClose.GetSeconds (), 30.0, "The close exchange should have ended");
}

class QuicCloseTestSuite : public TestSuite
{
public:
  QuicCloseTestSuite ()
    : TestSuite ("quic-close", UNIT)
  {
    const Time never = Seconds (-1);
    const Time idle = Seconds (300);
    // name, bytes, flush, loss, client close, server close, link failure, idle timeout
    AddTestCase (new QuicCloseTestCase ({"nothing pending", 0, true, 0.0, Seconds (1), never, never, idle}),
                 TestCase::QUICK);
    AddTestCase (new QuicCloseTestCase ({"flush with pending data", 120000, true, 0.0, Seconds (0), never, never, idle}),
                 TestCase::QUICK);
    AddTestCase (new QuicCloseTestCase ({"flush under loss", 120000, true, 0.02, Seconds (0), never, never, idle}),
                 TestCase::QUICK);
    AddTestCase (new QuicCloseTestCase ({"no flush", 120000, false, 0.0, Seconds (0.05), never, never, idle}),
                 TestCase::QUICK);
    AddTestCase (new QuicCloseTestCase ({"peer closes during transfer", 100000000, true, 0.0, never, Seconds (0.5), never, idle}),
                 TestCase::QUICK);
    AddTestCase (new QuicCloseTestCase ({"peer closes during flush", 120000, true, 0.0, Seconds (0), Seconds (0.03), never, idle}),
                 TestCase::QUICK);
    AddTestCase (new QuicCloseTestCase ({"flush to a dead peer", 120000, true, 0.0, Seconds (0), never, Seconds (0.01), Seconds (2)}),
                 TestCase::QUICK);
  }
};

static QuicCloseTestSuite quicCloseTestSuite;

} // namespace ns3
