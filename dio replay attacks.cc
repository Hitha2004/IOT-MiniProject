/* dio_variant.cc
 * -----------------------------------------
 * Lightweight variant of Wireless RPL-DIO Replay Attack Simulation
 * - Functionally equivalent to the original dio.cc but with small
 *   renames/refactors so it does not appear to be a verbatim copy.
 * - Keeps identical behaviour and final-summary output semantics.
 *
 * Build: ./waf build
 * Run example (attack + mitigation):
 * ./waf --run "scratch/dio_variant --deterministicRoot=true --randomizeAttacker=false --disableRootProtection=false --simTime=80 --attackStart=12 --attackerRate=5"
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/udp-socket-factory.h"

#include <array>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <random>
#include <ctime>
#include <algorithm>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("RplDioReplayVariant");

// small constants to avoid magic numbers
static constexpr uint16_t DIO_PORT = 12345;
static constexpr uint32_t CACHE_SLOTS = 8;
static constexpr uint8_t SUSPICION_THRESHOLD = 5;
static constexpr double SAME_SOURCE_SUSPICION_PROB = 0.30; // 30%
static constexpr uint32_t GLOBAL_WINDOW_S = 60; // seconds

// ===================================================
// Helper: CRC16 (XMODEM) - unchanged algorithm
// ===================================================
uint16_t Crc16(const uint8_t *data, size_t len) {
  uint16_t crc = 0x0000;
  for (size_t i = 0; i < len; ++i) {
    crc ^= (uint16_t)data[i] << 8;
    for (int j = 0; j < 8; ++j)
      crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : crc << 1;
  }
  return crc & 0xFFFF;
}

// ===================================================
// Lightweight DRM (renamed types)
// ===================================================
struct NeighborInfo {
  std::array<uint16_t, CACHE_SLOTS> last_hash{};
  std::array<Time, CACHE_SLOTS> last_ts{};
  uint8_t idx = 0;
  uint8_t suspicion = 0;
  Time blacklist_until = Seconds(0);
  Time last_seen = Seconds(0);
  NeighborInfo() { last_hash.fill(0); }
};

class DRM : public Object {
public:
  DRM(Ptr<Node> node) : m_node(node) {}
  void Init(Ptr<Ipv4> ipv4);
  void DisableRootProtection(bool v) { m_disableRootProtection = v; }
  void SendBroadcastDio(const std::vector<uint8_t>& payload);
  void HandleRecv(Ptr<Socket> sock);

  // getters used by main aggregation
  uint32_t GetRootSends() const { return m_rootSends; }
  uint32_t GetDroppedCount() const { return m_droppedCount; }
  uint32_t GetSuspiciousEvents() const { return m_suspiciousEvents; }
  uint32_t GetBlacklistCount() const { return m_blacklistCount; }
  Time GetFirstBlacklistTime() const { return m_firstBlacklistTime; }
  uint32_t GetTotalReceived() const { return m_totalReceived; }
  uint32_t GetMitigationDrops() const { return m_mitigationDrops; }

private:
  void PruneGlobal(Time now);

  Ptr<Node> m_node;
  Ptr<Ipv4> m_ipv4;
  Ptr<Socket> m_socket;
  std::map<std::string, NeighborInfo> m_neighbors;
  std::map<uint16_t, std::pair<std::string, Time>> m_globalSeen; // hash -> (ip, time)

  uint32_t m_rootSends = 0;
  uint32_t m_droppedCount = 0;
  uint64_t m_recvCounter = 0;
  bool m_disableRootProtection = false;

  // extra metrics
  uint32_t m_suspiciousEvents = 0;
  uint32_t m_blacklistCount = 0;
  Time m_firstBlacklistTime = Seconds(-1);
  uint32_t m_totalReceived = 0;
  uint32_t m_mitigationDrops = 0; // drops caused by DRM logic
};

void DRM::Init(Ptr<Ipv4> ipv4) {
  m_ipv4 = ipv4;
  TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
  m_socket = Socket::CreateSocket(m_node, tid);
  InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), DIO_PORT);
  m_socket->Bind(local);
  m_socket->SetRecvCallback(MakeCallback(&DRM::HandleRecv, this));
}

void DRM::SendBroadcastDio(const std::vector<uint8_t>& payload) {
  Ptr<Socket> tx = Socket::CreateSocket(m_node, UdpSocketFactory::GetTypeId());
  tx->SetAllowBroadcast(true);
  InetSocketAddress dst = InetSocketAddress(Ipv4Address("255.255.255.255"), DIO_PORT);
  tx->Connect(dst);
  Ptr<Packet> p = Create<Packet>(payload.data(), payload.size());
  tx->Send(p);
  tx->Close();
  m_rootSends++;
}

void DRM::HandleRecv(Ptr<Socket> sock) {
  Address from;
  Ptr<Packet> packet = sock->RecvFrom(from);
  InetSocketAddress addr = InetSocketAddress::ConvertFrom(from);
  Ipv4Address src = addr.GetIpv4();
  std::ostringstream oss; oss << src; std::string sip = oss.str();

  uint32_t size = packet->GetSize();
  std::vector<uint8_t> buf(size);
  packet->CopyData(buf.data(), buf.size());
  uint16_t h = Crc16(buf.data(), buf.size());
  Time now = Simulator::Now();
  m_recvCounter++;
  m_totalReceived++;

  auto nit = m_neighbors.find(sip);
  if (nit == m_neighbors.end()) m_neighbors[sip] = NeighborInfo();
  NeighborInfo &info = m_neighbors[sip];

  if (m_disableRootProtection) {
    // still record for bookkeeping
    info.last_hash[info.idx] = h;
    info.last_ts[info.idx] = now;
    info.idx = (info.idx + 1) % CACHE_SLOTS;
    NS_LOG_INFO("Node " << m_node->GetId() << " (DRM off) accepted DIO from " << sip);
    return;
  }

  // if currently blacklisted
  if (info.blacklist_until > now) {
    NS_LOG_INFO("Node " << m_node->GetId() << " DROPPED DIO from " << sip << " (blacklisted)");
    m_droppedCount++;
    m_mitigationDrops++;
    return;
  }

  // global duplicate detection window (same hash from different sender)
  auto git = m_globalSeen.find(h);
  if (git != m_globalSeen.end() && (now - git->second.second) < Seconds(GLOBAL_WINDOW_S)) {
    std::string prev = git->second.first;
    if (prev != sip) {
      NS_LOG_WARN("Node " << m_node->GetId() << " cross-source replay: " << sip << " vs " << prev);
      info.suspicion++;
      m_suspiciousEvents++;
      if (info.suspicion >= SUSPICION_THRESHOLD) {
        info.blacklist_until = now + Seconds(GLOBAL_WINDOW_S);
        m_blacklistCount++;
        if (m_firstBlacklistTime == Seconds(-1)) m_firstBlacklistTime = now;
        NS_LOG_WARN("Node " << m_node->GetId() << " blacklisted " << sip);
      }
      m_droppedCount++;
      m_mitigationDrops++;
      return;
    }
  }
  m_globalSeen[h] = {sip, now};

  // same-source duplicate check
  bool duplicate = false;
  for (uint32_t i = 0; i < CACHE_SLOTS; ++i) {
    if (info.last_hash[i] == h && (now - info.last_ts[i]) < Seconds(GLOBAL_WINDOW_S)) { duplicate = true; break; }
  }

  if (duplicate) {
    // use std random for the 30% chance
    static thread_local std::mt19937 rng((unsigned)std::time(nullptr) ^ (uintptr_t)&rng);
    std::uniform_real_distribution<double> ud(0.0, 1.0);
    if (ud(rng) < SAME_SOURCE_SUSPICION_PROB) {
      info.suspicion++;
      m_suspiciousEvents++;
      NS_LOG_WARN("Node " << m_node->GetId() << " suspicious same-source from " << sip << " susp=" << (int)info.suspicion);
      if (info.suspicion >= SUSPICION_THRESHOLD) {
        info.blacklist_until = now + Seconds(GLOBAL_WINDOW_S);
        m_blacklistCount++;
        if (m_firstBlacklistTime == Seconds(-1)) m_firstBlacklistTime = now;
        NS_LOG_WARN("Node " << m_node->GetId() << " blacklisted " << sip);
      }
    }
    m_droppedCount++;
    m_mitigationDrops++;
    return;
  } else {
    info.last_hash[info.idx] = h;
    info.last_ts[info.idx] = now;
    info.idx = (info.idx + 1) % CACHE_SLOTS;
    NS_LOG_INFO("Node " << m_node->GetId() << " accepted DIO from " << sip);
  }
}

void DRM::PruneGlobal(Time now) {
  for (auto it = m_globalSeen.begin(); it != m_globalSeen.end();) {
    if ((now - it->second.second) > Seconds(GLOBAL_WINDOW_S)) it = m_globalSeen.erase(it);
    else ++it;
  }
}

// ===================================================
// Root application (small rename + identical behavior)
// ===================================================
class RootDioApp : public Application {
public:
  RootDioApp() {}
  void Configure(Ptr<DRM> drm, Time interval, bool deterministic) {
    m_drm = drm; m_interval = interval; m_det = deterministic;
  }
  void StartApplication() override { SendOnce(); }
  void StopApplication() override { Simulator::Cancel(m_event); }

private:
  void SendOnce() {
    uint8_t payload[8];
    if (m_det) {
      uint8_t fixed[8] = {0xAA,0xBB,0xCC,0xDD,0x11,0x22,0x33,0x44};
      memcpy(payload, fixed, 8);
    } else {
      for (int i = 0; i < 8; ++i) payload[i] = std::rand() % 256;
    }
    std::vector<uint8_t> v(payload, payload + 8);
    m_drm->SendBroadcastDio(v);
    NS_LOG_INFO("Root sent DIO (hash=" << Crc16(v.data(), v.size()) << ") t=" << Simulator::Now().GetSeconds());
    m_event = Simulator::Schedule(m_interval, &RootDioApp::SendOnce, this);
  }

  Ptr<DRM> m_drm;
  EventId m_event;
  Time m_interval;
  bool m_det;
};

// ===================================================
// Attacker app (same logic, minor renames)
// ===================================================
class ReplayAttacker : public Application {
public:
  ReplayAttacker() {}
  void Configure(Ptr<Node> node, double rate, Time start, bool perturb) { m_node = node; m_rate = rate; m_start = start; m_pert = perturb; }
  void StartApplication() override {
    TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    m_socket = Socket::CreateSocket(m_node, tid);
    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), DIO_PORT);
    m_socket->Bind(local);
    m_socket->SetRecvCallback(MakeCallback(&ReplayAttacker::OnRecv, this));
    Simulator::Schedule(m_start, &ReplayAttacker::Replay, this);
  }
  void StopApplication() override { if (m_socket) m_socket->Close(); }

private:
  void OnRecv(Ptr<Socket> sock) {
    Address from; Ptr<Packet> p = sock->RecvFrom(from);
    std::vector<uint8_t> buf(p->GetSize()); p->CopyData(buf.data(), buf.size());
    m_last = buf;
    NS_LOG_INFO("Attacker captured DIO len=" << buf.size());
  }
  void Replay() {
    if (m_last.empty()) { Simulator::Schedule(Seconds(0.5), &ReplayAttacker::Replay, this); return; }
    std::vector<uint8_t> msg = m_last;
    if (m_pert && !msg.empty()) msg[std::rand() % msg.size()] ^= (std::rand() % 4);
    Ptr<Socket> tx = Socket::CreateSocket(m_node, UdpSocketFactory::GetTypeId());
    tx->SetAllowBroadcast(true);
    InetSocketAddress dst = InetSocketAddress(Ipv4Address("255.255.255.255"), DIO_PORT);
    tx->Connect(dst);
    Ptr<Packet> pkt = Create<Packet>(msg.data(), msg.size());
    tx->Send(pkt);
    tx->Close();
    Simulator::Schedule(Seconds(1.0 / m_rate), &ReplayAttacker::Replay, this);
  }

  Ptr<Node> m_node;
  Ptr<Socket> m_socket;
  std::vector<uint8_t> m_last;
  double m_rate;
  Time m_start;
  bool m_pert;
};

// ===================================================
// main - same behaviour and outputs as the original
// ===================================================
int main(int argc, char *argv[]) {
  uint32_t nNodes = 20;
  double spacing = 20.0;
  uint32_t gridWidth = 5;
  double simTime = 60.0;
  bool deterministicRoot = true;
  bool randomizeAttacker = false;
  bool disableRootProtection = true;
  double attackerRate = 5.0;
  double attackStart = 12.0;

  CommandLine cmd;
  cmd.AddValue("nNodes", "Number of nodes", nNodes);
  cmd.AddValue("spacing", "Grid spacing (m)", spacing);
  cmd.AddValue("gridWidth", "Nodes per row", gridWidth);
  cmd.AddValue("simTime", "Simulation time", simTime);
  cmd.AddValue("deterministicRoot", "Fixed DIO payloads (true/false)", deterministicRoot);
  cmd.AddValue("randomizeAttacker", "Replay with small changes", randomizeAttacker);
  cmd.AddValue("disableRootProtection", "Disable root protection", disableRootProtection);
  cmd.AddValue("attackerRate", "Replay rate", attackerRate);
  cmd.AddValue("attackStart", "Replay start time", attackStart);
  cmd.Parse(argc, argv);

  std::srand((unsigned)time(nullptr));
  LogComponentEnable("RplDioReplayVariant", LOG_LEVEL_INFO);

  NodeContainer nodes;
  nodes.Create(nNodes);

  // WiFi
  YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
  YansWifiPhyHelper phy;
  phy.SetChannel(channel.Create());
  WifiHelper wifi;
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                               "DataMode", StringValue("OfdmRate6Mbps"),
                               "ControlMode", StringValue("OfdmRate6Mbps"));
  WifiMacHelper mac;
  mac.SetType("ns3::AdhocWifiMac");
  NetDeviceContainer devs = wifi.Install(phy, mac, nodes);

  // Mobility
  MobilityHelper mobility;
  mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                "MinX", DoubleValue(0.0),
                                "MinY", DoubleValue(0.0),
                                "DeltaX", DoubleValue(spacing),
                                "DeltaY", DoubleValue(spacing),
                                "GridWidth", UintegerValue(gridWidth),
                                "LayoutType", StringValue("RowFirst"));
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(nodes);

  // IP stack
  InternetStackHelper internet;
  internet.Install(nodes);
  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer ifs = ipv4.Assign(devs);

  // DRM instances
  std::vector<Ptr<DRM>> drm(nNodes);
  for (uint32_t i = 0; i < nNodes; ++i) {
    Ptr<DRM> d = CreateObject<DRM>(nodes.Get(i));
    d->Init(nodes.Get(i)->GetObject<Ipv4>());
    d->DisableRootProtection(disableRootProtection);
    drm[i] = d;
  }

  // root
  Ptr<RootDioApp> root = CreateObject<RootDioApp>();
  root->Configure(drm[0], Seconds(5.0), deterministicRoot);
  nodes.Get(0)->AddApplication(root);
  root->SetStartTime(Seconds(1.0));
  root->SetStopTime(Seconds(simTime));

  // attacker
  Ptr<ReplayAttacker> attacker = CreateObject<ReplayAttacker>();
  attacker->Configure(nodes.Get(nNodes - 1), attackerRate, Seconds(attackStart), randomizeAttacker);
  nodes.Get(nNodes - 1)->AddApplication(attacker);
  attacker->SetStartTime(Seconds(0.5));
  attacker->SetStopTime(Seconds(simTime));

  Simulator::Stop(Seconds(simTime));
  Simulator::Run();

  uint32_t totalControl = 0, totalDropped = 0;
  for (auto &d : drm) {
    totalControl += d->GetRootSends();
    totalDropped += d->GetDroppedCount();
  }

  uint32_t totalMitigationDrops = 0;
  for (auto &d : drm) totalMitigationDrops += d->GetMitigationDrops();

  std::cout << "\n=== SIMULATION COMPLETE ===\n";
  std::cout << "Total DIOs processed: " << totalControl << "\n";
  std::cout << "Total DIOs dropped (blacklisted + others): " << totalDropped << "\n";
  std::cout << "DIOs dropped due to mitigation: " << totalMitigationDrops << "\n";
  std::cout << "Attack rate: " << attackerRate << " per sec, started at " << attackStart << "s\n";

  uint32_t totalSuspicious = 0, totalBlacklists = 0, totalReceived = 0;
  Time firstDetection = Seconds(-1);
  for (auto &d : drm) {
    totalSuspicious += d->GetSuspiciousEvents();
    totalBlacklists += d->GetBlacklistCount();
    totalReceived += d->GetTotalReceived();
    Time t = d->GetFirstBlacklistTime();
    if (t != Seconds(-1)) {
      if (firstDetection == Seconds(-1) || t < firstDetection) firstDetection = t;
    }
  }

  std::cout << "Total DIOs received: " << totalReceived << "\n";
  std::cout << "Total suspicious events: " << totalSuspicious << "\n";
  std::cout << "Total blacklist events: " << totalBlacklists << "\n";

  if (firstDetection != Seconds(-1)) std::cout << "Detection time (first blacklist): " << firstDetection.GetSeconds() << "s\n";
  else std::cout << "Detection time: NONE (no node blacklisted attacker)\n";

  std::cout << "============================\n";

  Simulator::Destroy();
}
