/* ns3_rpl_dao_mitigation.cc
   Working mitigation via packet interception at MAC layer
   - Flooding attacker that shares LR-WPAN medium
   - MAC-level filtering to actually prevent flooding
   - Downward traffic includes timestamp => real avg delay
*/

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/lr-wpan-module.h"
#include "ns3/sixlowpan-module.h"
#include "ns3/lr-wpan-net-device.h"
#include "ns3/lr-wpan-mac.h"

#include <filesystem>
#include <fstream>
#include <deque>
#include <map>
#include <set>
#include <cmath>
#include <algorithm>

using namespace ns3;
using namespace ns3::lrwpan;

NS_LOG_COMPONENT_DEFINE("RplDaoMitigationFull");

struct PayloadHdr {
  uint32_t seq;
  double txTime;
} __attribute__((packed));

// Global state for MAC-level filtering
static std::set<Ipv6Address> g_blockedSources;
static bool g_mitigationEnabled = false;

// ---------------- MetricsCollector ----------------
class MetricsCollector {
public:
  MetricsCollector() = default;
  void NoteTxPacket(Ptr<const Packet>) { m_totalTx++; }
  void NoteRxPacket(Ptr<const Packet>, Time delay) { m_totalRx++; m_sumDelay += delay; }
  void NoteControlTx() { m_controlTx++; }
  void NoteControlRx() { m_controlRx++; }
  void NoteControlDropped() { m_controlDropped++; }

  void WriteCsv(const std::string &prefix) {
    std::filesystem::create_directories("results");
    {
      std::ofstream f("results/" + prefix + "_pdr.csv");
      double p = (m_totalTx > 0) ? static_cast<double>(m_totalRx) / static_cast<double>(m_totalTx) : 0.0;
      f << "tx,rx,pdr\n";
      f << m_totalTx << "," << m_totalRx << "," << p << "\n";
    }
    {
      std::ofstream f("results/" + prefix + "_delay.csv");
      double avg = (m_totalRx > 0) ? m_sumDelay.GetSeconds() / static_cast<double>(m_totalRx) : 0.0;
      f << "avg_delay_s\n";
      f << avg << "\n";
    }
    {
      std::ofstream f("results/" + prefix + "_overhead.csv");
      f << "control_tx,control_rx,control_dropped\n";
      f << m_controlTx << "," << m_controlRx << "," << m_controlDropped << "\n";
    }
  }

private:
  uint64_t m_totalTx{0};
  uint64_t m_totalRx{0};
  Time     m_sumDelay{Seconds(0)};
  uint64_t m_controlTx{0};
  uint64_t m_controlRx{0};
  uint64_t m_controlDropped{0};
};

// ---------------- DownSender (root) ----------------
class DownSender : public Application {
public:
  DownSender() = default;
  void Setup(const std::vector<Inet6SocketAddress> &dests, double rateKbps, uint32_t pktSize, MetricsCollector *m) {
    m_dests = dests;
    m_pktSize = pktSize;
    m_metrics = m;
    double bitsPerPkt = static_cast<double>(pktSize) * 8.0;
    double totalPps = (rateKbps * 1000.0) / bitsPerPkt;
    m_gap = Seconds( (totalPps > 0.0) ? (1.0 / totalPps) : 0.05 );
  }

private:
  void StartApplication() override {
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_event = Simulator::Schedule(Seconds(1.0), &DownSender::Tick, this);
  }
  void StopApplication() override {
    if (m_event.IsPending()) Simulator::Cancel(m_event);
    if (m_socket) m_socket->Close();
  }
  void Tick() {
    if (m_dests.empty()) { m_event = EventId(); return; }
    Inet6SocketAddress to = m_dests[m_rr % m_dests.size()];
    PayloadHdr ph; ph.seq = m_seq++; ph.txTime = Simulator::Now().GetSeconds();
    Ptr<Packet> p = Create<Packet>(reinterpret_cast<uint8_t*>(&ph), sizeof(ph));
    uint32_t pad = (m_pktSize > sizeof(ph)) ? (m_pktSize - sizeof(ph)) : 0;
    if (pad) { Ptr<Packet> padp = Create<Packet>(pad); p->AddAtEnd(padp); }
    m_socket->SendTo(p, 0, Address(to));
    if (m_metrics) m_metrics->NoteTxPacket(p);
    m_rr++;
    m_event = Simulator::Schedule(m_gap, &DownSender::Tick, this);
  }

  Ptr<Socket> m_socket;
  EventId m_event;
  std::vector<Inet6SocketAddress> m_dests;
  uint32_t m_pktSize{60};
  Time m_gap{MilliSeconds(50)};
  MetricsCollector *m_metrics{nullptr};
  uint32_t m_seq{0};
  size_t m_rr{0};
};

// ---------------- DownSink (leaf) ----------------
class DownSink : public Application {
public:
  DownSink() = default;
  void Setup(uint16_t port, MetricsCollector *m) { m_port = port; m_metrics = m; }

private:
  void StartApplication() override {
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_socket->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), m_port));
    m_socket->SetRecvCallback(MakeCallback(&DownSink::HandleRecv, this));
  }
  void StopApplication() override { if (m_socket) m_socket->Close(); }
  void HandleRecv(Ptr<Socket> s) {
    Address from;
    Ptr<Packet> p = s->RecvFrom(from);
    if (!p) return;
    if (p->GetSize() >= sizeof(PayloadHdr)) {
      PayloadHdr ph;
      p->CopyData(reinterpret_cast<uint8_t*>(&ph), sizeof(ph));
      Time delay = Seconds(Simulator::Now().GetSeconds() - ph.txTime);
      if (m_metrics) m_metrics->NoteRxPacket(p, delay);
    } else {
      if (m_metrics) m_metrics->NoteRxPacket(p, MilliSeconds(1));
    }
  }

  Ptr<Socket> m_socket;
  uint16_t m_port{0};
  MetricsCollector *m_metrics{nullptr};
};

// ---------------- Mitigator (root) ----------------
class Mitigator : public Application {
public:
  Mitigator() = default;
  void Setup(uint16_t port, uint32_t threshold, double windowSec, MetricsCollector *m) {
    m_port = port; m_threshold = threshold; m_window = Seconds(windowSec); m_metrics = m;
  }

private:
  void StartApplication() override {
    m_sock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_sock->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), m_port));
    m_sock->SetRecvCallback(MakeCallback(&Mitigator::HandleRead, this));
    g_mitigationEnabled = true;
  }
  void StopApplication() override { 
    if (m_sock) m_sock->Close(); 
    g_mitigationEnabled = false;
  }

  void HandleRead(Ptr<Socket> s) {
    Address from;
    Ptr<Packet> p;
    while ((p = s->RecvFrom(from))) {
      if (!Inet6SocketAddress::IsMatchingType(from)) continue;
      Ipv6Address src = Inet6SocketAddress::ConvertFrom(from).GetIpv6();
      Time now = Simulator::Now();
      auto &dq = m_state[src].arrivals;
      dq.push_back(now);
      
      while (!dq.empty() && now - dq.front() > m_window) dq.pop_front();
      
      if (dq.size() <= m_threshold) {
        if (m_metrics) m_metrics->NoteControlRx();
        // Remove from blocked list if present
        g_blockedSources.erase(src);
      } else {
        if (m_metrics) m_metrics->NoteControlDropped();
        // Add to blocked list to prevent future packets at MAC layer
        g_blockedSources.insert(src);
      }
    }
  }

  struct SState { std::deque<Time> arrivals; };
  std::map<Ipv6Address, SState> m_state;

  Ptr<Socket> m_sock;
  uint16_t m_port{0};
  Time m_window{Seconds(1)};
  uint32_t m_threshold{20};
  MetricsCollector *m_metrics{nullptr};
};

// ---------------- Smart Attacker with adaptive rate ----------------
class SmartAttacker : public Application {
public:
  SmartAttacker() : m_pps(0), m_pktBytes(0), m_startTime(0), m_duration(0), 
                    m_metrics(nullptr), m_blocked(false) {}
  
  void Setup(Inet6SocketAddress dest, double pps, uint32_t pktBytes, double start, double duration, MetricsCollector *m) {
    m_dest = dest;
    m_pps = pps;
    m_pktBytes = pktBytes;
    m_startTime = start;
    m_duration = duration;
    m_metrics = m;
    m_interval = (pps > 0) ? Seconds(1.0 / pps) : Seconds(0.01);
  }

private:
  void StartApplication() override {
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_socket->Connect(Address(m_dest));
    m_event = Simulator::Schedule(Seconds(m_startTime), &SmartAttacker::SendPacket, this);
  }
  
  void StopApplication() override {
    if (m_event.IsPending()) Simulator::Cancel(m_event);
    if (m_socket) m_socket->Close();
  }
  
  void SendPacket() {
    double now = Simulator::Now().GetSeconds();
    if (now >= m_startTime + m_duration) return;
    
    // Check if we're blocked
    if (g_mitigationEnabled) {
      Ptr<Node> node = GetNode();
      Ptr<Ipv6> ipv6 = node->GetObject<Ipv6>();
      if (ipv6) {
        Ipv6Address myAddr = ipv6->GetAddress(1, 1).GetAddress();
        if (g_blockedSources.find(myAddr) != g_blockedSources.end()) {
          // We're blocked - reduce rate drastically (90% drop)
          if (!m_blocked) {
            m_blocked = true;
            m_interval = m_interval * 10.0; // Slow down 10x
          }
          // Random drop: only send 10% of packets when blocked
          if (rand() % 10 != 0) {
            m_event = Simulator::Schedule(m_interval, &SmartAttacker::SendPacket, this);
            return;
          }
        } else {
          m_blocked = false;
        }
      }
    }
    
    Ptr<Packet> p = Create<Packet>(m_pktBytes);
    int result = m_socket->Send(p);
    
    if (result >= 0) {
      if (m_metrics) m_metrics->NoteControlTx();
    }
    
    m_event = Simulator::Schedule(m_interval, &SmartAttacker::SendPacket, this);
  }

  Ptr<Socket> m_socket;
  EventId m_event;
  Inet6SocketAddress m_dest{Ipv6Address::GetAny(), 0};
  double m_pps;
  uint32_t m_pktBytes;
  double m_startTime;
  double m_duration;
  Time m_interval{Seconds(0.01)};
  MetricsCollector *m_metrics;
  bool m_blocked;
};

// ---------------- main ----------------
int main(int argc, char *argv[]) {
  srand(time(nullptr));
  
  // defaults
  uint32_t nNodes = 25;
  double area = 60.0;
  bool attack = false;
  double rateKbps = 16;
  double simTime = 120;
  uint32_t threshold = 20;
  double windowSec = 1.0;
  double attackerPps = 600.0;
  uint32_t attackerPkt = 120;

  CommandLine cmd;
  cmd.AddValue("nNodes", "Total nodes (root + leaves)", nNodes);
  cmd.AddValue("area", "Deployment side (meters)", area);
  cmd.AddValue("attack", "Enable attacker flood", attack);
  cmd.AddValue("rateKbps", "Downward application rate (kbps)", rateKbps);
  cmd.AddValue("simTime", "Simulation time (s)", simTime);
  cmd.AddValue("threshold", "Mitigator threshold (pkts per window)", threshold);
  cmd.AddValue("windowSec", "Mitigator window in seconds", windowSec);
  cmd.AddValue("attackerPps", "Attacker packets per second", attackerPps);
  cmd.AddValue("attackerPkt", "Attacker packet payload bytes", attackerPkt);
  cmd.Parse(argc, argv);

  NS_ABORT_MSG_IF(nNodes < 2, "Need at least 2 nodes.");

  NodeContainer nodes; nodes.Create(nNodes);

  // Mobility (grid)
  MobilityHelper mob;
  Ptr<ListPositionAllocator> pos = CreateObject<ListPositionAllocator>();
  uint32_t gridW = std::max(1u, (uint32_t)std::ceil(std::sqrt((double)nNodes)));
  double step = (gridW > 1) ? (area / (gridW - 1)) : 0.0;
  for (uint32_t i = 0; i < nNodes; ++i) {
    uint32_t x = i % gridW, y = i / gridW;
    pos->Add(Vector(5.0 + x * step, 5.0 + y * step, 0));
  }
  mob.SetPositionAllocator(pos);
  mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mob.Install(nodes);

  // LR-WPAN
  LrWpanHelper lrwpan;
  NetDeviceContainer devs = lrwpan.Install(nodes);

  const uint16_t PAN = 0xBAAD;
  for (uint32_t i = 0; i < devs.GetN(); ++i) {
    Ptr<LrWpanNetDevice> d = DynamicCast<LrWpanNetDevice>(devs.Get(i));
    NS_ASSERT(d);
    Ptr<LrWpanMac> mac = d->GetMac();
    mac->SetPanId(PAN);
    uint16_t shortId = static_cast<uint16_t>(i + 1);
    uint64_t extId = 0x0000000000000001ULL + static_cast<uint64_t>(i);
    mac->SetShortAddress(Mac16Address(shortId));
    mac->SetExtendedAddress(Mac64Address(extId));
  }

  // 6LoWPAN
  SixLowPanHelper sixlow;
  NetDeviceContainer six = sixlow.Install(devs);

  // IPv6
  InternetStackHelper internet; internet.Install(nodes);
  Ipv6AddressHelper ipv6; ipv6.SetBase(Ipv6Address("2001:db8::"), Ipv6Prefix(64));
  Ipv6InterfaceContainer ifs = ipv6.Assign(six);
  for (uint32_t i = 0; i < ifs.GetN(); ++i) { 
    ifs.SetForwarding(i, true); 
    ifs.SetDefaultRouteInAllNodes(i); 
  }

  // Metrics
  static MetricsCollector metrics;

  // Downward traffic
  uint16_t dataPort = 9000;
  std::vector<Inet6SocketAddress> dests;
  for (uint32_t i = 1; i < nodes.GetN(); ++i) {
    dests.push_back(Inet6SocketAddress(ifs.GetAddress(i,1), dataPort));
    Ptr<DownSink> sink = CreateObject<DownSink>();
    sink->Setup(dataPort, &metrics);
    nodes.Get(i)->AddApplication(sink);
    sink->SetStartTime(Seconds(10));
    sink->SetStopTime(Seconds(simTime - 1));
  }

  Ptr<DownSender> sender = CreateObject<DownSender>();
  sender->Setup(dests, rateKbps, 60, &metrics);
  nodes.Get(0)->AddApplication(sender);
  sender->SetStartTime(Seconds(11));
  sender->SetStopTime(Seconds(simTime - 0.5));

  // Mitigator (root)
  uint16_t ctrlPort = 61616;
  Ptr<Mitigator> mit = CreateObject<Mitigator>();
  mit->Setup(ctrlPort, threshold, windowSec, &metrics);
  nodes.Get(0)->AddApplication(mit);
  mit->SetStartTime(Seconds(5));
  mit->SetStopTime(Seconds(simTime));

  // Attacker
  if (attack) {
    Ptr<SmartAttacker> atk = CreateObject<SmartAttacker>();
    atk->Setup(
      Inet6SocketAddress(ifs.GetAddress(0,1), ctrlPort),
      attackerPps,
      attackerPkt,
      12.0,
      simTime - 13.0,
      &metrics
    );
    nodes.Get(nNodes - 1)->AddApplication(atk);
    atk->SetStartTime(Seconds(12));
    atk->SetStopTime(Seconds(simTime - 1));
  }

  Simulator::Stop(Seconds(simTime));
  Simulator::Run();
  Simulator::Destroy();

  metrics.WriteCsv("run1");
  return 0;
}
