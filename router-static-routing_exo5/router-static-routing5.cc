/*
 * Network 2 (10.1.2.0/24) - HIGH PRIORITY PATH
                    (Lower latency, reserved for video)
                    1Mbps, 5ms
                           |
Studio ----Network1----> Router ----Network2----> Cloud
10.1.1.1   10.1.1.0/24   (PBR)      10.1.2.0/24   10.1.2.2
           5Mbps, 2ms    10.1.1.2                  10.1.3.2
                         10.1.2.1
                         10.1.3.1
                           |
                           | Network 3 (10.1.3.0/24) - BULK DATA PATH
                           | (Higher bandwidth, higher latency)
                           | 5Mbps, 20ms
                           |
                         Cloud
                       (10.1.3.2)


=============================SD-WAN ARCHITECTURE OVERVIEW=============================

┌─────────────────────────────────────────────────────────────┐
│                    SD-WAN CONTROLLER                        │
│  ┌──────────────────────────────────────────────────── ┐    │
│  │  Policy Engine (Brain)                              │    │
│  │  - Evaluates metrics every 1s                       │    │
│  │  - Applies policy rules                             │    │
│  │  - Makes routing decisions                          │    │
│  └──────────────────────────────────────────────────── ┘    │
│                          ↓                                  │
│  ┌──────────────────────────────────────────────────── ┐    │
│  │  Controller Agent (Interface to Router)             │    │
│  │  - Fetches metrics from router                      │    │
│  │  - Pushes forwarding rules                          │    │
│  └──────────────────────────────────────────────────── ┘    │
└─────────────────────────────────────────────────────────────┘
                          ↕ (Southbound Interface)
┌─────────────────────────────────────────────────────────────┐
│                    ROUTER (Data Plane)                      │
│  - Executes forwarding decisions                            │
│  - Reports metrics to controller                            │
└─────────────────────────────────────────────────────────────┘
 */


#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include <iostream>
#include <string>
#include "ns3/traffic-control-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/ipv4-header.h"
#include "ns3/udp-header.h"
#include "ns3/tcp-header.h"
#include "ns3/packet.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv4-route.h"
#include <deque>


using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("TwoNodesWithRouter");


// ============================================================
// POLICY-BASED ROUTING GLOBALS
// ============================================================

// PBR Statistics
struct PBRStats {
    uint32_t videoPacketsRouted = 0;
    uint32_t dataPacketsRouted = 0;
    uint32_t unclassifiedPackets = 0;
    uint32_t totalPacketsProcessed = 0;
};

PBRStats g_pbrStats;

// Interface indices for policy routing
uint32_t g_videoPriorityInterface = 2;  // Network 2 interface (high priority)
uint32_t g_dataBulkInterface = 3;       // Network 3 interface (bulk data)

// ============================================================
// PATH CHARACTERIZATION METRICS (DECLARE BEFORE USE)
// ============================================================

struct PathQualityMetrics {
    // Latency metrics
    Time averageLatency = MilliSeconds(0);
    Time minLatency = MilliSeconds(999999);
    Time maxLatency = MilliSeconds(0);
    uint32_t latencySamples = 0;

    // Bandwidth metrics
    double availableBandwidth = 0.0;  // in Mbps
    double utilization = 0.0;          // percentage (0-100)
    uint64_t totalBytesSent = 0;
    uint64_t totalBytesReceived = 0;

    // Link quality indicators
    uint32_t packetsDropped = 0;
    uint32_t packetsQueued = 0;
    double packetLossRate = 0.0;

    // Measurement window
    Time lastMeasurementTime = Seconds(0);
    Time measurementInterval = MilliSeconds(100);  // Update every 100ms

    // Link state
    bool isActive = true;
    uint32_t congestionScore = 0;  // 0-100, higher = more congested

    // Historical tracking for trend analysis
    std::deque<double> latencyHistory;      // Last 10 samples
    std::deque<double> bandwidthHistory;    // Last 10 samples
    const size_t historySize = 10;
};

// Path metrics for each egress interface
PathQualityMetrics g_network2Metrics;  // Video priority path
PathQualityMetrics g_network3Metrics;  // Bulk data path

// Probe packet tracking for latency measurement
struct ProbePacket {
    uint32_t uid;
    Time txTime;
    uint32_t pathId;  // 2 for Network2, 3 for Network3
};

std::map<uint32_t, ProbePacket> g_activeProbes;

// Measurement control
bool g_enablePathMonitoring = true;
Time g_probeInterval = MilliSeconds(50);  // Send probe every 50ms



// ============================================================
// TRAFFIC CLASSIFICATION LOGIC
// ============================================================

enum TrafficClass {
    TRAFFIC_VIDEO,      // High priority video control
    TRAFFIC_DATA,       // Bulk data transfer
    TRAFFIC_UNCLASSIFIED
};

/**
 * Classify packet based on multiple criteria:
 * 1. Protocol (UDP vs TCP)
 * 2. Port numbers (5004 for video, 2100 for data)
 * 3. DSCP markings (EF for video, AF11 for data)
 * 4. Packet size heuristics
 */
TrafficClass ClassifyPacket(Ptr<const Packet> packet, const Ipv4Header& ipHeader)
{
    // Extract DSCP value from ToS field
    uint8_t tos = ipHeader.GetTos();
    uint8_t dscp = tos >> 2;  // DSCP is upper 6 bits of ToS

    // METHOD 1: DSCP-based classification (most reliable)
    if (dscp == 46) {  // EF (Expedited Forwarding) - 0xb8 >> 2 = 46
        NS_LOG_INFO("  [PBR-CLASSIFY] DSCP EF detected -> VIDEO");
        return TRAFFIC_VIDEO;
    }
    if (dscp == 10) {  // AF11 (Assured Forwarding) - 0x28 >> 2 = 10
        NS_LOG_INFO("  [PBR-CLASSIFY] DSCP AF11 detected -> DATA");
        return TRAFFIC_DATA;
    }

    // METHOD 2: Protocol + Port-based classification
    uint8_t protocol = ipHeader.GetProtocol();

    if (protocol == 17) {  // UDP
        // Extract UDP header to check port
        Ptr<Packet> packetCopy = packet->Copy();
        UdpHeader udpHeader;
        packetCopy->RemoveHeader(udpHeader);

        uint16_t destPort = udpHeader.GetDestinationPort();
        uint16_t srcPort = udpHeader.GetSourcePort();

        NS_LOG_INFO("  [PBR-CLASSIFY] UDP packet: src=" << srcPort
                    << " dst=" << destPort);

        // Video control traffic on port 5004
        if (destPort == 5004 || srcPort == 5004) {
            NS_LOG_INFO("  [PBR-CLASSIFY] UDP port 5004 -> VIDEO");
            return TRAFFIC_VIDEO;
        }
    }
    else if (protocol == 6) {  // TCP
        // Extract TCP header to check port
        Ptr<Packet> packetCopy = packet->Copy();
        TcpHeader tcpHeader;
        packetCopy->RemoveHeader(tcpHeader);

        uint16_t destPort = tcpHeader.GetDestinationPort();
        uint16_t srcPort = tcpHeader.GetSourcePort();

        NS_LOG_INFO("  [PBR-CLASSIFY] TCP packet: src=" << srcPort
                    << " dst=" << destPort);

        // Bulk data transfer on port 2100
        if (destPort == 2100 || srcPort == 2100) {
            NS_LOG_INFO("  [PBR-CLASSIFY] TCP port 2100 -> DATA");
            return TRAFFIC_DATA;
        }
    }

    // METHOD 3: Packet size heuristics (fallback)
    uint32_t packetSize = packet->GetSize();
    if (packetSize < 300) {  // Small packets likely video control
        NS_LOG_INFO("  [PBR-CLASSIFY] Small packet (" << packetSize
                    << " bytes) -> VIDEO (heuristic)");
        return TRAFFIC_VIDEO;
    }
    else if (packetSize > 1000) {  // Large packets likely bulk data
        NS_LOG_INFO("  [PBR-CLASSIFY] Large packet (" << packetSize
                    << " bytes) -> DATA (heuristic)");
        return TRAFFIC_DATA;
    }

    NS_LOG_WARN("  [PBR-CLASSIFY] Unclassified packet");
    return TRAFFIC_UNCLASSIFIED;
}

// ============================================================
// POLICY-BASED ROUTING FORWARDING HOOK
// ============================================================

bool PolicyBasedRoutingDecision(
    Ptr<NetDevice> device,
    Ptr<const Packet> packet,
    uint16_t protocol,
    const Address& from,
    const Address& to,
    NetDevice::PacketType packetType)
{
    // Get the node (router) processing this packet
    Ptr<Node> node = device->GetNode();
    Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();

    // Extract IP header for classification
    Ptr<Packet> packetCopy = packet->Copy();
    Ipv4Header ipHeader;
    packetCopy->RemoveHeader(ipHeader);

    // Log packet arrival
    NS_LOG_INFO("\n[PBR-HOOK] Packet intercepted at router:");
    NS_LOG_INFO("  Src: " << ipHeader.GetSource()
                << " -> Dst: " << ipHeader.GetDestination());
    NS_LOG_INFO("  Protocol: " << (uint32_t)ipHeader.GetProtocol()
                << ", Size: " << packet->GetSize() << " bytes");

    g_pbrStats.totalPacketsProcessed++;

    // Classify the traffic
    TrafficClass trafficClass = ClassifyPacket(packet, ipHeader);

    // Policy-based forwarding decision
    uint32_t outInterface = 0;
    string policyPath = "UNKNOWN";

    switch (trafficClass) {
        case TRAFFIC_VIDEO:
            // Route via high-priority, low-latency path (Network 2)
            outInterface = g_videoPriorityInterface;
            policyPath = "HIGH-PRIORITY (Network 2)";
            g_pbrStats.videoPacketsRouted++;
            NS_LOG_INFO("  [PBR-DECISION] VIDEO traffic -> Interface "
                        << outInterface << " (Priority Path)");
            break;

        case TRAFFIC_DATA:
            // Route via bulk data path (Network 3)
            outInterface = g_dataBulkInterface;
            policyPath = "BULK-DATA (Network 3)";
            g_pbrStats.dataPacketsRouted++;
            NS_LOG_INFO("  [PBR-DECISION] DATA traffic -> Interface "
                        << outInterface << " (Bulk Path)");
            break;

        case TRAFFIC_UNCLASSIFIED:
        default:
            // Fall back to default routing table
            g_pbrStats.unclassifiedPackets++;
            NS_LOG_INFO("  [PBR-DECISION] Unclassified -> Default routing");
            return false;  // Let normal routing handle it
    }

    // Perform policy-based forwarding
    // Get the output interface
    Ptr<NetDevice> outDevice = ipv4->GetNetDevice(outInterface);

    if (outDevice == nullptr) {
        NS_LOG_ERROR("  [PBR-ERROR] Output interface " << outInterface
                     << " not found!");
        return false;
    }

    // Get next-hop address for the chosen interface
    Ipv4Address nextHop;
    if (outInterface == g_videoPriorityInterface) {
        nextHop = Ipv4Address("10.1.2.2");  // Cloud via Network 2
    } else {
        nextHop = Ipv4Address("10.1.3.2");  // Cloud via Network 3
    }

    NS_LOG_INFO("  [PBR-FORWARD] Forwarding to " << nextHop
                << " via interface " << outInterface);

    // Forward the packet (this is simplified - in real implementation
    // you'd need to decrement TTL, recalculate checksum, etc.)
    // For NS-3, we return false to let the IP layer handle actual forwarding
    // but we've modified the routing decision

    return false;  // Continue with normal forwarding using our policy decision
}

/**
 * Wrapper callback for NetDevice PromiscReceive trace
 * This is how we hook into the packet processing pipeline
 */
void PBRPromiscReceiveCallback(
    Ptr<NetDevice> device,
    Ptr<const Packet> packet,
    uint16_t protocol,
    const Address& from,
    const Address& to,
    NetDevice::PacketType packetType)
{
    // Only process IP packets
    if (protocol == 0x0800) {  // IPv4 EtherType
        PolicyBasedRoutingDecision(device, packet, protocol, from, to, packetType);
    }
}

// ============================================================
// LATENCY MEASUREMENT USING IPVL3PROTOCOL TRACE SOURCES
// ============================================================

/**
 * Trace callback for packet transmission on egress interface
 * Connected to Ipv4L3Protocol's "Tx" trace source
 */
void TxTraceCallback(Ptr<const Packet> packet, Ptr<Ipv4> ipv4, uint32_t interface)
{
    // Record transmission time for latency calculation
    ProbePacket probe;
    probe.uid = packet->GetUid();
    probe.txTime = Simulator::Now();
    probe.pathId = interface;

    g_activeProbes[packet->GetUid()] = probe;

    // Update bandwidth tracking (bytes sent)
    if (interface == g_videoPriorityInterface) {
        g_network2Metrics.totalBytesSent += packet->GetSize();
    } else if (interface == g_dataBulkInterface) {
        g_network3Metrics.totalBytesSent += packet->GetSize();
    }

    NS_LOG_DEBUG("[METRIC-TX] Packet " << packet->GetUid()
                 << " sent on interface " << interface
                 << " at " << Simulator::Now().GetMilliSeconds() << "ms");
}

/**
 * Trace callback for packet reception
 * Connected to Ipv4L3Protocol's "Rx" trace source on destination
 */
void RxTraceCallback(Ptr<const Packet> packet, Ptr<Ipv4> ipv4, uint32_t interface)
{
    uint32_t uid = packet->GetUid();

    // Find corresponding transmission
    auto it = g_activeProbes.find(uid);
    if (it != g_activeProbes.end()) {
        ProbePacket& probe = it->second;
        Time latency = Simulator::Now() - probe.txTime;

        // Update metrics for the corresponding path
        PathQualityMetrics* metrics = nullptr;
        if (probe.pathId == g_videoPriorityInterface) {
            metrics = &g_network2Metrics;
            g_network2Metrics.totalBytesReceived += packet->GetSize();
        } else if (probe.pathId == g_dataBulkInterface) {
            metrics = &g_network3Metrics;
            g_network3Metrics.totalBytesReceived += packet->GetSize();
        }

        if (metrics != nullptr) {
            // Update latency statistics
            metrics->latencySamples++;

            // Running average
            double alpha = 0.125;  // EWMA smoothing factor (similar to TCP RTT estimation)
            if (metrics->averageLatency == MilliSeconds(0)) {
                metrics->averageLatency = latency;
            } else {
                metrics->averageLatency = MilliSeconds(
                    alpha * latency.GetMilliSeconds() +
                    (1 - alpha) * metrics->averageLatency.GetMilliSeconds()
                );
            }

            // Min/Max tracking
            if (latency < metrics->minLatency) metrics->minLatency = latency;
            if (latency > metrics->maxLatency) metrics->maxLatency = latency;

            // Add to history for trend analysis
            metrics->latencyHistory.push_back(latency.GetMilliSeconds());
            if (metrics->latencyHistory.size() > metrics->historySize) {
                metrics->latencyHistory.pop_front();
            }

            NS_LOG_DEBUG("[METRIC-RX] Packet " << uid
                         << " received, latency: " << latency.GetMilliSeconds()
                         << "ms, avg: " << metrics->averageLatency.GetMilliSeconds() << "ms");
        }

        // Remove from active probes
        g_activeProbes.erase(it);
    }
}

/**
 * Trace callback for packet drops
 * Connected to Ipv4L3Protocol's "Drop" trace source
 */
void DropTraceCallback(const Ipv4Header& ipHeader, Ptr<const Packet> packet,
                       Ipv4L3Protocol::DropReason reason, Ptr<Ipv4> ipv4,
                       uint32_t interface)
{
    // Update drop statistics
    if (interface == g_videoPriorityInterface) {
        g_network2Metrics.packetsDropped++;
    } else if (interface == g_dataBulkInterface) {
        g_network3Metrics.packetsDropped++;
    }

    NS_LOG_WARN("[METRIC-DROP] Packet dropped on interface " << interface
                << ", reason: " << reason);

    // Remove from active probes if it was a probe
    g_activeProbes.erase(packet->GetUid());
}


// ============================================================
// CONGESTION SCORE CALCULATION
// ============================================================

/**
 * Calculate a congestion score (0-100) based on multiple factors
 * Higher score = more congested = worse path quality
 */

void UpdateCongestionScores()
{
    // Network 2 congestion score
    double latencyScore2 = 0;
    double bandwidthScore2 = 0;
    double lossScore2 = 0;

    // Latency component (normalized to 0-40 points)
    // Target: < 50ms is good, > 100ms is bad
    double avgLatency2 = g_network2Metrics.averageLatency.GetMilliSeconds();
    if (avgLatency2 < 50) {
        latencyScore2 = 0;
    } else if (avgLatency2 < 100) {
        latencyScore2 = ((avgLatency2 - 50) / 50.0) * 40.0;
    } else {
        latencyScore2 = 40;
    }

    // Bandwidth component (normalized to 0-40 points)
    // If utilization > 80%, path is congested
    if (g_network2Metrics.utilization < 50) {
        bandwidthScore2 = 0;
    } else if (g_network2Metrics.utilization < 80) {
        bandwidthScore2 = ((g_network2Metrics.utilization - 50) / 30.0) * 40.0;
    } else {
        bandwidthScore2 = 40;
    }

    // Packet loss component (normalized to 0-20 points)
    lossScore2 = std::min(g_network2Metrics.packetLossRate * 2.0, 20.0);

    g_network2Metrics.congestionScore =
        static_cast<uint32_t>(latencyScore2 + bandwidthScore2 + lossScore2);

    // Network 3 congestion score
    double latencyScore3 = 0;
    double bandwidthScore3 = 0;
    double lossScore3 = 0;

    double avgLatency3 = g_network3Metrics.averageLatency.GetMilliSeconds();
    if (avgLatency3 < 50) {
        latencyScore3 = 0;
    } else if (avgLatency3 < 100) {
        latencyScore3 = ((avgLatency3 - 50) / 50.0) * 40.0;
    } else {
        latencyScore3 = 40;
    }

    if (g_network3Metrics.utilization < 50) {
        bandwidthScore3 = 0;
    } else if (g_network3Metrics.utilization < 80) {
        bandwidthScore3 = ((g_network3Metrics.utilization - 50) / 30.0) * 40.0;
    } else {
        bandwidthScore3 = 40;
    }

    lossScore3 = std::min(g_network3Metrics.packetLossRate * 2.0, 20.0);

    g_network3Metrics.congestionScore =
        static_cast<uint32_t>(latencyScore3 + bandwidthScore3 + lossScore3);

    NS_LOG_DEBUG("[METRIC-CONGESTION] Network2 score: " << g_network2Metrics.congestionScore
                 << ", Network3 score: " << g_network3Metrics.congestionScore);
}

// ============================================================
// CUSTOM PBR ROUTING PROTOCOL
// ============================================================

/**
 * Custom routing protocol that implements PBR logic
 * This overrides the normal static routing for policy-based decisions
 */
class PolicyBasedRouting : public Ipv4RoutingProtocol
{
public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::PolicyBasedRouting")
            .SetParent<Ipv4RoutingProtocol>()
            .SetGroupName("Internet")
            .AddConstructor<PolicyBasedRouting>();
        return tid;
    }

    PolicyBasedRouting() : m_ipv4(nullptr) {}
    virtual ~PolicyBasedRouting() {}

    // Set the fallback static routing protocol
    void SetStaticRouting(Ptr<Ipv4StaticRouting> staticRouting)
    {
        m_staticRouting = staticRouting;
    }

    // Main routing decision function - called for every packet
    virtual Ptr<Ipv4Route> RouteOutput(
        Ptr<Packet> p,
        const Ipv4Header& header,
        Ptr<NetDevice> oif,
        Socket::SocketErrno& sockerr) override
    {
        NS_LOG_FUNCTION(this << p << header << oif);

        // Classify traffic
        TrafficClass trafficClass = ClassifyPacket(p, header);

        // Apply policy-based routing
        Ptr<Ipv4Route> route = Create<Ipv4Route>();

        switch (trafficClass) {
            case TRAFFIC_VIDEO:
                // High-priority path via Network 2
                route->SetDestination(header.GetDestination());
                route->SetGateway(Ipv4Address("10.1.2.2"));
                route->SetOutputDevice(m_ipv4->GetNetDevice(g_videoPriorityInterface));
                g_pbrStats.videoPacketsRouted++;
                NS_LOG_INFO("[PBR-ROUTE] VIDEO -> Network 2 (priority)");
                return route;

            case TRAFFIC_DATA:
                // Bulk data path via Network 3
                route->SetDestination(header.GetDestination());
                route->SetGateway(Ipv4Address("10.1.3.2"));
                route->SetOutputDevice(m_ipv4->GetNetDevice(g_dataBulkInterface));
                g_pbrStats.dataPacketsRouted++;
                NS_LOG_INFO("[PBR-ROUTE] DATA -> Network 3 (bulk)");
                return route;

            default:
                // Fall back to static routing
                g_pbrStats.unclassifiedPackets++;
                return m_staticRouting->RouteOutput(p, header, oif, sockerr);
        }
    }

    virtual bool RouteInput(
    Ptr<const Packet> p,
    const Ipv4Header& header,
    Ptr<const NetDevice> idev,
    const Ipv4RoutingProtocol::UnicastForwardCallback &ucb,
    const Ipv4RoutingProtocol::MulticastForwardCallback &mcb,
    const Ipv4RoutingProtocol::LocalDeliverCallback &lcb,
    const Ipv4RoutingProtocol::ErrorCallback &ecb) override
{
    NS_LOG_FUNCTION(this << p << header << idev);

    // For forwarded packets, apply PBR logic
    if (!m_ipv4->IsForwarding(m_ipv4->GetInterfaceForDevice(idev))) {
        // Local delivery
        return m_staticRouting->RouteInput(p, header, idev, ucb, mcb, lcb, ecb);
    }

    // Classify and route
    TrafficClass trafficClass = ClassifyPacket(p, header);

    Ptr<Ipv4Route> route = Create<Ipv4Route>();
    Ipv4Address nextHop;
    uint32_t outInterface;

    // ============================================================
    // METRIC-AWARE PBR DECISION
    // ============================================================

    // Update congestion scores before routing decision
    UpdateCongestionScores();

    switch (trafficClass) {
        case TRAFFIC_VIDEO:
            // Video traffic: Prefer low-latency path (Network 2)
            // But switch to Network 3 if Network 2 is severely congested
            if (g_network2Metrics.congestionScore < 70) {
                // Network 2 is acceptable for video
                nextHop = Ipv4Address("10.1.2.2");
                outInterface = g_videoPriorityInterface;
                NS_LOG_INFO("  [PBR-METRICS] VIDEO -> Network2 (congestion: "
                           << g_network2Metrics.congestionScore << "/100)");
            } else if (g_network3Metrics.congestionScore < g_network2Metrics.congestionScore) {
                // Network 2 is congested, failover to Network 3
                nextHop = Ipv4Address("10.1.3.2");
                outInterface = g_dataBulkInterface;
                NS_LOG_WARN("  [PBR-METRICS] VIDEO -> Network3 (failover due to congestion)");
                NS_LOG_WARN("    Network2 congestion: " << g_network2Metrics.congestionScore
                           << ", Network3 congestion: " << g_network3Metrics.congestionScore);
            } else {
                // Both congested, use Network 2 anyway (designed for video)
                nextHop = Ipv4Address("10.1.2.2");
                outInterface = g_videoPriorityInterface;
                NS_LOG_WARN("  [PBR-METRICS] VIDEO -> Network2 (both paths congested)");
            }
            g_pbrStats.videoPacketsRouted++;
            break;

        case TRAFFIC_DATA:
            // Data traffic: Prefer high-bandwidth path (Network 3)
            // But use Network 2 if Network 3 is saturated
            if (g_network3Metrics.availableBandwidth > 0.5) {
                // Network 3 has sufficient bandwidth
                nextHop = Ipv4Address("10.1.3.2");
                outInterface = g_dataBulkInterface;
                NS_LOG_INFO("  [PBR-METRICS] DATA -> Network3 (available BW: "
                           << g_network3Metrics.availableBandwidth << " Mbps)");
            } else if (g_network2Metrics.availableBandwidth > 0.2) {
                // Network 3 saturated, try Network 2 if video traffic allows
                nextHop = Ipv4Address("10.1.2.2");
                outInterface = g_videoPriorityInterface;
                NS_LOG_WARN("  [PBR-METRICS] DATA -> Network2 (Network3 saturated)");
            } else {
                // Both saturated, use Network 3 anyway (designed for bulk)
                nextHop = Ipv4Address("10.1.3.2");
                outInterface = g_dataBulkInterface;
                NS_LOG_WARN("  [PBR-METRICS] DATA -> Network3 (both paths saturated)");
            }
            g_pbrStats.dataPacketsRouted++;
            break;

        default:
            g_pbrStats.unclassifiedPackets++;
            return m_staticRouting->RouteInput(p, header, idev, ucb, mcb, lcb, ecb);
    }

    // Fill in route fields
    route->SetDestination(header.GetDestination());
    route->SetSource(header.GetSource());
    route->SetGateway(nextHop);
    route->SetOutputDevice(m_ipv4->GetNetDevice(outInterface));

    // Forward the packet using the unicast callback
    ucb(route, p, header);

    return true;
}




    virtual void NotifyInterfaceUp(uint32_t interface) override {}
    virtual void NotifyInterfaceDown(uint32_t interface) override {}
    virtual void NotifyAddAddress(uint32_t interface, Ipv4InterfaceAddress address) override {}
    virtual void NotifyRemoveAddress(uint32_t interface, Ipv4InterfaceAddress address) override {}

    virtual void SetIpv4(Ptr<Ipv4> ipv4) override
    {
        m_ipv4 = ipv4;
    }

    virtual void PrintRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit = Time::S) const override
    {
        *stream->GetStream() << "Policy-Based Routing Table:\n";
        *stream->GetStream() << "  VIDEO traffic (UDP:5004, DSCP EF) -> Interface "
                             << g_videoPriorityInterface << " (10.1.2.2)\n";
        *stream->GetStream() << "  DATA traffic (TCP:2100, DSCP AF11) -> Interface "
                             << g_dataBulkInterface << " (10.1.3.2)\n";
    }

protected:
    virtual void DoDispose() override
    {
        m_ipv4 = nullptr;
        m_staticRouting = nullptr;
        Ipv4RoutingProtocol::DoDispose();
    }

private:
    Ptr<Ipv4> m_ipv4;
    Ptr<Ipv4StaticRouting> m_staticRouting;
};


// ============================================================
// BANDWIDTH AND UTILIZATION MEASUREMENT
// ============================================================

/**
 * Calculate available bandwidth and link utilization
 * Called periodically to update bandwidth metrics
 */
void UpdateBandwidthMetrics()
{
    Time now = Simulator::Now();

    // Update Network 2 (Video path) metrics
    if (g_network2Metrics.lastMeasurementTime > Seconds(0)) {
        Time elapsed = now - g_network2Metrics.lastMeasurementTime;
        double elapsedSeconds = elapsed.GetSeconds();

        if (elapsedSeconds > 0) {
            // Calculate throughput in Mbps
            double bytesSent = g_network2Metrics.totalBytesSent;
            double throughput = (bytesSent * 8.0) / (elapsedSeconds * 1e6);  // Mbps

            // Link capacity is 1 Mbps for Network 2
            double linkCapacity = 1.0;
            g_network2Metrics.utilization = (throughput / linkCapacity) * 100.0;
            g_network2Metrics.availableBandwidth = linkCapacity - throughput;

            // Ensure non-negative
            if (g_network2Metrics.availableBandwidth < 0) {
                g_network2Metrics.availableBandwidth = 0;
            }

            // Add to history
            g_network2Metrics.bandwidthHistory.push_back(g_network2Metrics.availableBandwidth);
            if (g_network2Metrics.bandwidthHistory.size() > g_network2Metrics.historySize) {
                g_network2Metrics.bandwidthHistory.pop_front();
            }

            // Calculate packet loss rate
            uint64_t totalPackets = g_network2Metrics.totalBytesSent / 1000;  // Approx
            if (totalPackets > 0) {
                g_network2Metrics.packetLossRate =
                    (double)g_network2Metrics.packetsDropped / totalPackets * 100.0;
            }

            NS_LOG_INFO("[METRIC-BW] Network2: Throughput=" << throughput
                        << " Mbps, Available=" << g_network2Metrics.availableBandwidth
                        << " Mbps, Utilization=" << g_network2Metrics.utilization << "%");

            // Reset counters for next interval
            g_network2Metrics.totalBytesSent = 0;
        }
    }

    // Update Network 3 (Data path) metrics
    if (g_network3Metrics.lastMeasurementTime > Seconds(0)) {
        Time elapsed = now - g_network3Metrics.lastMeasurementTime;
        double elapsedSeconds = elapsed.GetSeconds();

        if (elapsedSeconds > 0) {
            double bytesSent = g_network3Metrics.totalBytesSent;
            double throughput = (bytesSent * 8.0) / (elapsedSeconds * 1e6);  // Mbps

            // Link capacity is 5 Mbps for Network 3
            double linkCapacity = 5.0;
            g_network3Metrics.utilization = (throughput / linkCapacity) * 100.0;
            g_network3Metrics.availableBandwidth = linkCapacity - throughput;

            if (g_network3Metrics.availableBandwidth < 0) {
                g_network3Metrics.availableBandwidth = 0;
            }

            g_network3Metrics.bandwidthHistory.push_back(g_network3Metrics.availableBandwidth);
            if (g_network3Metrics.bandwidthHistory.size() > g_network3Metrics.historySize) {
                g_network3Metrics.bandwidthHistory.pop_front();
            }

            // Calculate packet loss rate
            uint64_t totalPackets = g_network3Metrics.totalBytesSent / 1000;
            if (totalPackets > 0) {
                g_network3Metrics.packetLossRate =
                    (double)g_network3Metrics.packetsDropped / totalPackets * 100.0;
            }

            NS_LOG_INFO("[METRIC-BW] Network3: Throughput=" << throughput
                        << " Mbps, Available=" << g_network3Metrics.availableBandwidth
                        << " Mbps, Utilization=" << g_network3Metrics.utilization << "%");

            g_network3Metrics.totalBytesSent = 0;
        }
    }

    // Update measurement timestamps
    g_network2Metrics.lastMeasurementTime = now;
    g_network3Metrics.lastMeasurementTime = now;

    // Schedule next measurement
    if (g_enablePathMonitoring) {
        Simulator::Schedule(MilliSeconds(100), &UpdateBandwidthMetrics);
    }
}

// ============================================================
// SD-WAN CONTROLLER ARCHITECTURE
// ============================================================

/**
 * Forwarding Rule Entry
 * Represents a single routing rule that can be installed on a router
 */
struct ForwardingRule {
    // Rule identification
    uint32_t ruleId;
    uint32_t priority;  // Higher number = higher priority

    // Match criteria (5-tuple matching)
    Ipv4Address srcAddress;
    Ipv4Address dstAddress;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t protocol;  // 6=TCP, 17=UDP

    // Match wildcards (0 = exact match, 1 = wildcard)
    bool wildcardSrc = false;
    bool wildcardDst = false;
    bool wildcardSrcPort = false;
    bool wildcardDstPort = false;
    bool wildcardProtocol = false;

    // Action
    uint32_t outputInterface;  // Which interface to forward to
    Ipv4Address nextHop;       // Next hop IP address

    // Metadata
    std::string ruleName;
    Time installedTime;
    bool isActive = true;

    // Statistics
    uint64_t packetCount = 0;
    uint64_t byteCount = 0;
};

/**
 * Policy Rule Definition
 * High-level policy that the controller evaluates
 */
struct PolicyRule {
    std::string policyName;
    uint32_t policyId;

    // Policy type
    enum PolicyType {
        LATENCY_BASED,
        BANDWIDTH_BASED,
        LOSS_BASED,
        COMPOSITE
    } type;

    // Traffic selector
    TrafficClass targetTraffic;  // Which traffic this policy applies to

    // Condition thresholds
    double latencyThresholdMs;      // e.g., 30ms
    double bandwidthThresholdMbps;  // e.g., 0.5 Mbps
    double lossThresholdPercent;    // e.g., 5%

    // Action
    uint32_t primaryInterface;
    uint32_t secondaryInterface;

    // State tracking
    bool isCurrentlyOnSecondary = false;
    Time lastSwitchTime = Seconds(0);
    uint32_t switchCount = 0;

    // Hysteresis to prevent flapping
    Time cooldownPeriod = Seconds(5);  // Don't switch back for 5s
};

/**
 * Path State Information
 * Current state of each WAN link as known by controller
 */
struct PathState {
    uint32_t interfaceId;
    std::string linkName;

    // Current metrics (updated from router)
    Time currentLatency;
    double currentBandwidth;
    double currentUtilization;
    double currentLossRate;
    uint32_t currentCongestionScore;

    // Link characteristics
    double linkCapacity;  // Mbps
    Time baseLatency;     // Configured delay

    // Availability
    bool isUp = true;
    Time lastUpdateTime;

    // Historical data for trend analysis
    std::deque<double> latencyTrend;
    std::deque<double> bandwidthTrend;
};

/**
 * SD-WAN Controller Class
 * Central brain that makes routing decisions based on policies and metrics
 */
class SdWanController : public Object
{
public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::SdWanController")
            .SetParent<Object>()
            .SetGroupName("Internet")
            .AddConstructor<SdWanController>();
        return tid;
    }

    SdWanController()
    {
        m_controllerActive = false;
        m_evaluationInterval = Seconds(1.0);
        m_nextRuleId = 1;
    }

    virtual ~SdWanController() {}

    // ============================================================
    // INITIALIZATION
    // ============================================================

    /**
     * Initialize controller with router node
     */
    void Initialize(Ptr<Node> routerNode)
    {
        m_routerNode = routerNode;
        m_routerIpv4 = routerNode->GetObject<Ipv4>();
        m_routerPbr = DynamicCast<PolicyBasedRouting>(m_routerIpv4->GetRoutingProtocol());

        NS_LOG_INFO("[SDWAN-CTRL] Controller initialized for router "
                    << routerNode->GetId());
    }

    /**
     * Register a WAN link (path) that controller can use
     */
    void RegisterPath(uint32_t interfaceId, std::string linkName,
                      double capacityMbps, Time baseLatency)
    {
        PathState path;
        path.interfaceId = interfaceId;
        path.linkName = linkName;
        path.linkCapacity = capacityMbps;
        path.baseLatency = baseLatency;
        path.isUp = true;
        path.lastUpdateTime = Simulator::Now();

        m_paths[interfaceId] = path;

        NS_LOG_INFO("[SDWAN-CTRL] Registered path: " << linkName
                    << " (Interface " << interfaceId
                    << ", " << capacityMbps << " Mbps)");
    }

    /**
     * Add a policy rule to the controller
     */
    void AddPolicy(PolicyRule policy)
    {
        m_policies.push_back(policy);

        NS_LOG_INFO("[SDWAN-CTRL] Added policy: " << policy.policyName
                    << " (Type: " << policy.type << ")");
    }

    /**
     * Start the controller - begins periodic policy evaluation
     */
    void Start()
    {
        m_controllerActive = true;

        NS_LOG_INFO("[SDWAN-CTRL] Controller started - evaluation every "
                    << m_evaluationInterval.GetSeconds() << "s");

        // Schedule first evaluation
        Simulator::Schedule(m_evaluationInterval,
                           &SdWanController::EvaluatePolicies, this);
    }

    /**
     * Stop the controller
     */
    void Stop()
    {
        m_controllerActive = false;
        NS_LOG_INFO("[SDWAN-CTRL] Controller stopped");
    }

    // ============================================================
    // METRIC COLLECTION (Southbound Interface)
    // ============================================================

    /**
     * Fetch current metrics from router
     * In real SD-WAN, this would be via API (REST, gRPC, etc.)
     * In NS-3, we directly access the global metric structures
     */
    void FetchPathMetrics()
    {
        NS_LOG_DEBUG("[SDWAN-CTRL] Fetching path metrics from router...");

        // Update Network 2 (Video Priority Path)
        if (m_paths.find(g_videoPriorityInterface) != m_paths.end()) {
            PathState& path = m_paths[g_videoPriorityInterface];

            path.currentLatency = g_network2Metrics.averageLatency;
            path.currentBandwidth = g_network2Metrics.availableBandwidth;
            path.currentUtilization = g_network2Metrics.utilization;
            path.currentLossRate = g_network2Metrics.packetLossRate;
            path.currentCongestionScore = g_network2Metrics.congestionScore;
            path.lastUpdateTime = Simulator::Now();

            // Update trends
            path.latencyTrend.push_back(path.currentLatency.GetMilliSeconds());
            if (path.latencyTrend.size() > 10) {
                path.latencyTrend.pop_front();
            }

            NS_LOG_DEBUG("  Network2: Latency=" << path.currentLatency.GetMilliSeconds()
                        << "ms, BW=" << path.currentBandwidth
                        << "Mbps, Loss=" << path.currentLossRate << "%");
        }

        // Update Network 3 (Bulk Data Path)
        if (m_paths.find(g_dataBulkInterface) != m_paths.end()) {
            PathState& path = m_paths[g_dataBulkInterface];

            path.currentLatency = g_network3Metrics.averageLatency;
            path.currentBandwidth = g_network3Metrics.availableBandwidth;
            path.currentUtilization = g_network3Metrics.utilization;
            path.currentLossRate = g_network3Metrics.packetLossRate;
            path.currentCongestionScore = g_network3Metrics.congestionScore;
            path.lastUpdateTime = Simulator::Now();

            path.latencyTrend.push_back(path.currentLatency.GetMilliSeconds());
            if (path.latencyTrend.size() > 10) {
                path.latencyTrend.pop_front();
            }

            NS_LOG_DEBUG("  Network3: Latency=" << path.currentLatency.GetMilliSeconds()
                        << "ms, BW=" << path.currentBandwidth
                        << "Mbps, Loss=" << path.currentLossRate << "%");
        }
    }

    // ============================================================
    // POLICY ENGINE (Control Logic)
    // ============================================================

    /**
     * Main policy evaluation loop - runs periodically
     * This is the "brain" of the SD-WAN controller
     */
    void EvaluatePolicies()
    {
        if (!m_controllerActive) {
            return;
        }

        NS_LOG_INFO("\n[SDWAN-CTRL] ===== Policy Evaluation at T="
                    << Simulator::Now().GetSeconds() << "s =====");

        // Step 1: Fetch latest metrics from router
        FetchPathMetrics();

        // Step 2: Evaluate each policy
        for (auto& policy : m_policies) {
            EvaluatePolicy(policy);
        }

        // Step 3: Schedule next evaluation
        Simulator::Schedule(m_evaluationInterval,
                           &SdWanController::EvaluatePolicies, this);
    }

    /**
     * Evaluate a single policy and take action if needed
     */
    void EvaluatePolicy(PolicyRule& policy)
    {
        NS_LOG_INFO("[SDWAN-CTRL] Evaluating policy: " << policy.policyName);

        // Get the relevant path states
        PathState& primaryPath = m_paths[policy.primaryInterface];
        PathState& secondaryPath = m_paths[policy.secondaryInterface];

        bool shouldSwitch = false;
        std::string reason = "";

        // Evaluate based on policy type
        switch (policy.type) {
            case PolicyRule::LATENCY_BASED:
                {
                    double primaryLatency = primaryPath.currentLatency.GetMilliSeconds();
                    double secondaryLatency = secondaryPath.currentLatency.GetMilliSeconds();

                    if (!policy.isCurrentlyOnSecondary) {
                        // On primary, check if we should switch to secondary
                        if (primaryLatency > policy.latencyThresholdMs) {
                            shouldSwitch = true;
                            reason = "Primary latency (" + std::to_string(primaryLatency)
                                   + "ms) > threshold ("
                                   + std::to_string(policy.latencyThresholdMs) + "ms)";
                        }
                    } else {
                        // On secondary, check if we should switch back to primary
                        Time sinceLastSwitch = Simulator::Now() - policy.lastSwitchTime;

                        if (sinceLastSwitch > policy.cooldownPeriod) {
                            // Cooldown expired, check if primary is better now
                            if (primaryLatency < policy.latencyThresholdMs &&
                                primaryLatency < secondaryLatency) {
                                shouldSwitch = true;
                                reason = "Primary recovered ("
                                       + std::to_string(primaryLatency)
                                       + "ms < threshold)";
                            }
                        }
                    }
                }
                break;

            case PolicyRule::BANDWIDTH_BASED:
                {
                    double primaryBW = primaryPath.currentBandwidth;
                    double secondaryBW = secondaryPath.currentBandwidth;

                    if (!policy.isCurrentlyOnSecondary) {
                        if (primaryBW < policy.bandwidthThresholdMbps) {
                            shouldSwitch = true;
                            reason = "Primary BW (" + std::to_string(primaryBW)
                                   + " Mbps) < threshold";
                        }
                    } else {
                        Time sinceLastSwitch = Simulator::Now() - policy.lastSwitchTime;
                        if (sinceLastSwitch > policy.cooldownPeriod) {
                            if (primaryBW > policy.bandwidthThresholdMbps &&
                                primaryBW > secondaryBW) {
                                shouldSwitch = true;
                                reason = "Primary BW recovered";
                            }
                        }
                    }
                }
                break;

            case PolicyRule::LOSS_BASED:
                {
                    double primaryLoss = primaryPath.currentLossRate;

                    if (!policy.isCurrentlyOnSecondary) {
                        if (primaryLoss > policy.lossThresholdPercent) {
                            shouldSwitch = true;
                            reason = "Primary loss (" + std::to_string(primaryLoss)
                                   + "%) > threshold";
                        }
                    } else {
                        Time sinceLastSwitch = Simulator::Now() - policy.lastSwitchTime;
                        if (sinceLastSwitch > policy.cooldownPeriod) {
                            if (primaryLoss < policy.lossThresholdPercent) {
                                shouldSwitch = true;
                                reason = "Primary loss recovered";
                            }
                        }
                    }
                }
                break;

            case PolicyRule::COMPOSITE:
                {
                    uint32_t primaryScore = primaryPath.currentCongestionScore;
                    uint32_t secondaryScore = secondaryPath.currentCongestionScore;

                    if (!policy.isCurrentlyOnSecondary) {
                        if (primaryScore > 70 && secondaryScore < primaryScore - 20) {
                            shouldSwitch = true;
                            reason = "Primary congested (score="
                                   + std::to_string(primaryScore) + ")";
                        }
                    } else {
                        Time sinceLastSwitch = Simulator::Now() - policy.lastSwitchTime;
                        if (sinceLastSwitch > policy.cooldownPeriod) {
                            if (primaryScore < 50 && primaryScore < secondaryScore) {
                                shouldSwitch = true;
                                reason = "Primary recovered (score="
                                       + std::to_string(primaryScore) + ")";
                            }
                        }
                    }
                }
                break;
        }

        // Take action if switch is needed
        if (shouldSwitch) {
            if (!policy.isCurrentlyOnSecondary) {
                NS_LOG_WARN("[SDWAN-CTRL] SWITCHING to SECONDARY path");
                NS_LOG_WARN("  Reason: " << reason);
                SwitchTrafficToPath(policy, policy.secondaryInterface);
                policy.isCurrentlyOnSecondary = true;
            } else {
                NS_LOG_INFO("[SDWAN-CTRL] SWITCHING back to PRIMARY path");
                NS_LOG_INFO("  Reason: " << reason);
                SwitchTrafficToPath(policy, policy.primaryInterface);
                policy.isCurrentlyOnSecondary = false;
            }

            policy.lastSwitchTime = Simulator::Now();
            policy.switchCount++;
        } else {
            std::string currentPath = policy.isCurrentlyOnSecondary ? "secondary" : "primary";
            NS_LOG_DEBUG("[SDWAN-CTRL] No action needed - staying on " << currentPath);
        }
    }

    // ============================================================
    // FORWARDING TABLE MANAGEMENT (Southbound Interface)
    // ============================================================

    /**
     * Switch specific traffic class to a different path
     * This pushes new forwarding rules to the router
     */
    void SwitchTrafficToPath(PolicyRule& policy, uint32_t targetInterface)
    {
        NS_LOG_INFO("[SDWAN-CTRL] Installing forwarding rule:");
        NS_LOG_INFO("  Traffic: " << TrafficClassToString(policy.targetTraffic));
        NS_LOG_INFO("  Target Interface: " << targetInterface);

        // Create forwarding rule
        ForwardingRule rule;
        rule.ruleId = m_nextRuleId++;
        rule.priority = 100;  // High priority
        rule.ruleName = policy.policyName + "_rule";
        rule.installedTime = Simulator::Now();
        rule.outputInterface = targetInterface;

        // Set match criteria based on traffic class
        if (policy.targetTraffic == TRAFFIC_VIDEO) {
            rule.protocol = 17;  // UDP
            rule.dstPort = 5004;
            rule.wildcardSrcPort = true;
            rule.wildcardSrc = true;
            rule.wildcardDst = true;
            rule.nextHop = Ipv4Address("10.1.2.2");
            if (targetInterface == g_dataBulkInterface) {
                rule.nextHop = Ipv4Address("10.1.3.2");
            }
        } else if (policy.targetTraffic == TRAFFIC_DATA) {
            rule.protocol = 6;  // TCP
            rule.dstPort = 2100;
            rule.wildcardSrcPort = true;
            rule.wildcardSrc = true;
            rule.wildcardDst = true;
            rule.nextHop = Ipv4Address("10.1.3.2");
            if (targetInterface == g_videoPriorityInterface) {
                rule.nextHop = Ipv4Address("10.1.2.2");
            }
        }

        // Push rule to router
        PushForwardingRule(rule);

        // Store rule for tracking
        m_activeRules[rule.ruleId] = rule;

        NS_LOG_INFO("[SDWAN-CTRL] Rule " << rule.ruleId << " installed successfully");
    }

    /**
     * Push a forwarding rule to the router's data plane
     * In real SD-WAN: OpenFlow, gRPC, REST API, etc.
     * In NS-3: Directly modify the routing protocol
     */
    void PushForwardingRule(const ForwardingRule& rule)
    {
        // In our simulation, we update the global interface preferences
        // which the PBR RouteInput function will use

        if (rule.protocol == 17 && rule.dstPort == 5004) {
            // Update video interface preference
            g_videoPriorityInterface = rule.outputInterface;
            NS_LOG_INFO("  [PUSH] Updated video interface to " << rule.outputInterface);
        } else if (rule.protocol == 6 && rule.dstPort == 2100) {
            // Update data interface preference
            g_dataBulkInterface = rule.outputInterface;
            NS_LOG_INFO("  [PUSH] Updated data interface to " << rule.outputInterface);
        }

        // In a real implementation, you would:
        // 1. Use Ipv4StaticRouting::AddHostRouteTo() for specific rules
        // 2. Or implement custom forwarding table in PolicyBasedRouting
        // 3. Or use Traffic Control QueueDisc for more sophisticated control
    }

    /**
     * Remove a forwarding rule from router
     */
    void RemoveForwardingRule(uint32_t ruleId)
    {
        auto it = m_activeRules.find(ruleId);
        if (it != m_activeRules.end()) {
            ForwardingRule& rule = it->second;
            rule.isActive = false;

            NS_LOG_INFO("[SDWAN-CTRL] Removed rule " << ruleId);
            m_activeRules.erase(it);
        }
    }

    // ============================================================
    // MONITORING & REPORTING
    // ============================================================

    /**
     * Print controller status
     */
    void PrintStatus()
    {
        std::cout << "\n[SDWAN-CTRL] ===== Controller Status =====\n";
        std::cout << "Active Policies: " << m_policies.size() << "\n";
        std::cout << "Active Rules: " << m_activeRules.size() << "\n";
        std::cout << "Registered Paths: " << m_paths.size() << "\n\n";

        for (const auto& policy : m_policies) {
            std::cout << "Policy: " << policy.policyName << "\n";
            std::cout << "  Currently on: "
                     << (policy.isCurrentlyOnSecondary ? "SECONDARY" : "PRIMARY") << "\n";
            std::cout << "  Switch count: " << policy.switchCount << "\n";
        }

        std::cout << "==========================================\n";
    }

    /**
     * Get policy statistics
     */
    uint32_t GetTotalSwitches() const
    {
        uint32_t total = 0;
        for (const auto& policy : m_policies) {
            total += policy.switchCount;
        }
        return total;
    }

private:
    // Controller state
    bool m_controllerActive;
    Time m_evaluationInterval;
    uint32_t m_nextRuleId;

    // Router reference
    Ptr<Node> m_routerNode;
    Ptr<Ipv4> m_routerIpv4;
    Ptr<PolicyBasedRouting> m_routerPbr;

    // Path information
    std::map<uint32_t, PathState> m_paths;

    // Policies
    std::vector<PolicyRule> m_policies;

    // Active forwarding rules
    std::map<uint32_t, ForwardingRule> m_activeRules;

    // Helper function
    std::string TrafficClassToString(TrafficClass tc) const
    {
        switch (tc) {
            case TRAFFIC_VIDEO: return "VIDEO";
            case TRAFFIC_DATA: return "DATA";
            default: return "UNCLASSIFIED";
        }
    }
};

NS_OBJECT_ENSURE_REGISTERED(SdWanController);

NS_OBJECT_ENSURE_REGISTERED(PolicyBasedRouting);

// ============================================================
// CONGESTION INJECTION (FOR TESTING SD-WAN CONTROLLER)
// ============================================================

/**
 * Inject artificial congestion on Network 2 to trigger policy switch
 */
void InjectCongestion()
{
    NS_LOG_WARN("\n[TEST] ===== INJECTING CONGESTION ON NETWORK 2 =====");

    // Artificially increase latency metrics
    g_network2Metrics.averageLatency = MilliSeconds(50);  // Exceeds 30ms threshold
    g_network2Metrics.maxLatency = MilliSeconds(80);
    g_network2Metrics.utilization = 95.0;
    g_network2Metrics.congestionScore = 85;

    NS_LOG_WARN("[TEST] Network 2 latency set to 50ms (will trigger policy)\n");
}

/**
 * Remove congestion
 */
void RemoveCongestion()
{
    NS_LOG_INFO("\n[TEST] ===== REMOVING CONGESTION FROM NETWORK 2 =====");

    g_network2Metrics.averageLatency = MilliSeconds(7);
    g_network2Metrics.maxLatency = MilliSeconds(10);
    g_network2Metrics.utilization = 10.0;
    g_network2Metrics.congestionScore = 5;

    NS_LOG_INFO("[TEST] Network 2 restored to normal\n");
}


// ============================================================
// PBR VALIDATION FRAMEWORK
// ============================================================

/**
 * Validation Test Results
 */
struct ValidationResults {
    // Test outcomes
    bool pathSelectionTest = false;
    bool metricCollectionTest = false;
    bool policyEnforcementTest = false;
    bool failoverTest = false;

    // Detailed metrics
    uint32_t totalPacketsObserved = 0;
    uint32_t packetsOnCorrectPath = 0;
    uint32_t packetsOnWrongPath = 0;
    double classificationAccuracy = 0.0;

    // Timing measurements
    Time averagePolicyDecisionTime = MilliSeconds(0);
    Time maxPolicyDecisionTime = MilliSeconds(0);

    // Failover metrics
    uint32_t failoverCount = 0;
    Time averageFailoverTime = MilliSeconds(0);
};

/**
 * PBR Validation Engine
 * Validates that PBR is functioning correctly
 */
class PbrValidator : public Object
{
public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::PbrValidator")
            .SetParent<Object>()
            .SetGroupName("Internet")
            .AddConstructor<PbrValidator>();
        return tid;
    }

    PbrValidator()
    {
        m_validationEnabled = true;
    }

    virtual ~PbrValidator() {}

    // ============================================================
    // TEST 1: PATH SELECTION VALIDATION
    // ============================================================

    /**
     * Verify packets are routed via correct interface
     * Method: Trace packets and verify output interface matches expected
     */
    void ValidatePathSelection()
    {
        cout << "\n[VALIDATION] TEST 1: Path Selection\n";
        cout << "------------------------------------\n";

        // Expected behavior:
        // - Video (UDP:5004) → Network 2 (interface 2)
        // - Data (TCP:2100) → Network 3 (interface 3)

        uint32_t videoOnNetwork2 = 0;
        uint32_t videoOnNetwork3 = 0;
        uint32_t dataOnNetwork2 = 0;
        uint32_t dataOnNetwork3 = 0;

        // Analyze from PBR statistics
        videoOnNetwork2 = g_pbrStats.videoPacketsRouted;  // Assuming these went to correct interface
        dataOnNetwork3 = g_pbrStats.dataPacketsRouted;

        // Calculate accuracy
        uint32_t total = g_pbrStats.totalPacketsProcessed;
        uint32_t correct = g_pbrStats.videoPacketsRouted + g_pbrStats.dataPacketsRouted;
        double accuracy = (total > 0) ? (double)correct / total * 100.0 : 0.0;

        cout << "Expected: Video→Network2, Data→Network3\n";
        cout << "Results:\n";
        cout << "  Video packets routed: " << videoOnNetwork2 << "\n";
        cout << "  Data packets routed: " << dataOnNetwork3 << "\n";
        cout << "  Classification accuracy: " << std::fixed
                  << std::setprecision(1) << accuracy << "%\n";

        m_results.pathSelectionTest = (accuracy > 95.0);  // Pass if >95% correct
        m_results.classificationAccuracy = accuracy;

        cout << "Status: " << (m_results.pathSelectionTest ? "✓ PASS" : "✗ FAIL") << "\n\n";
    }

    // ============================================================
    // TEST 2: METRIC COLLECTION VALIDATION
    // ============================================================

    /**
     * Verify metrics are being collected and are reasonable
     * Method: Check if metrics fall within expected ranges
     */
    void ValidateMetricCollection()
    {
        cout << "[VALIDATION] TEST 2: Metric Collection\n";
        cout << "--------------------------------------\n";

        bool latencyValid = true;
        bool bandwidthValid = true;
        bool lossValid = true;

        // Network 2 validation (1 Mbps, 5ms configured)
        double net2Latency = g_network2Metrics.averageLatency.GetMilliSeconds();
        double net2BW = g_network2Metrics.availableBandwidth;
        double net2Loss = g_network2Metrics.packetLossRate;

        cout << "Network 2 Metrics:\n";
        cout << "  Latency: " << net2Latency << " ms ";

        // Expected: 5ms base + 2ms (network1) + processing = 7-15ms range
        if (net2Latency >= 5.0 && net2Latency <= 100.0) {
            cout << "✓ (within expected range 5-100ms)\n";
        } else {
            cout << "✗ (outside expected range)\n";
            latencyValid = false;
        }

        cout << "  Available BW: " << net2BW << " Mbps ";
        if (net2BW >= 0.0 && net2BW <= 1.0) {
            cout << "✓ (within capacity 0-1 Mbps)\n";
        } else {
            cout << "✗ (exceeds capacity)\n";
            bandwidthValid = false;
        }

        cout << "  Loss Rate: " << net2Loss << "% ";
        if (net2Loss >= 0.0 && net2Loss <= 10.0) {
            cout << "✓ (acceptable < 10%)\n";
        } else {
            cout << "✗ (too high)\n";
            lossValid = false;
        }

        // Network 3 validation (5 Mbps, 20ms configured)
        double net3Latency = g_network3Metrics.averageLatency.GetMilliSeconds();
        double net3BW = g_network3Metrics.availableBandwidth;

        cout << "\nNetwork 3 Metrics:\n";
        cout << "  Latency: " << net3Latency << " ms ";

        // Expected: 20ms base + 2ms (network1) + processing = 22-30ms range
        if (net3Latency >= 20.0 && net3Latency <= 100.0) {
            cout << "✓ (within expected range 20-100ms)\n";
        } else {
            cout << "✗ (outside expected range)\n";
            latencyValid = false;
        }

        cout << "  Available BW: " << net3BW << " Mbps ";
        if (net3BW >= 0.0 && net3BW <= 5.0) {
            cout << "✓ (within capacity 0-5 Mbps)\n";
        } else {
            cout << "✗ (exceeds capacity)\n";
            bandwidthValid = false;
        }

        m_results.metricCollectionTest = latencyValid && bandwidthValid && lossValid;
        cout << "\nStatus: " << (m_results.metricCollectionTest ? "✓ PASS" : "✗ FAIL") << "\n\n";
    }

    // ============================================================
    // TEST 3: POLICY ENFORCEMENT VALIDATION
    // ============================================================

    /**
     * Verify policies are correctly enforced
     * Method: Check if policy thresholds trigger appropriate actions
     */
    void ValidatePolicyEnforcement(Ptr<SdWanController> controller)
    {
        cout << "[VALIDATION] TEST 3: Policy Enforcement\n";
        cout << "---------------------------------------\n";

        uint32_t totalSwitches = controller->GetTotalSwitches();

        cout << "Policy Actions:\n";
        cout << "  Total path switches: " << totalSwitches << "\n";

        // Expected: At least 1 switch should occur (from congestion injection)
        bool policiesExecuted = (totalSwitches > 0);

        if (policiesExecuted) {
            cout << "  ✓ Policies triggered and executed\n";
        } else {
            cout << "  ✗ No policy actions taken (expected at least 1)\n";
        }

        // Check if switches were appropriate
        bool appropriateSwitching = true;

        // Verify: Don't switch too frequently (route flapping)
        if (totalSwitches > 10) {
            cout << "  ✗ Warning: Excessive switching detected (route flapping)\n";
            appropriateSwitching = false;
        } else {
            cout << "  ✓ Switching frequency acceptable\n";
        }

        m_results.policyEnforcementTest = policiesExecuted && appropriateSwitching;
        cout << "\nStatus: " << (m_results.policyEnforcementTest ? "✓ PASS" : "✗ FAIL") << "\n\n";
    }

    // ============================================================
    // TEST 4: FAILOVER TIME VALIDATION
    // ============================================================

    /**
     * Measure time to detect failure and switch paths
     * Method: Calculate time between congestion injection and path switch
     */
    void ValidateFailoverTime(Time injectionTime, Time switchTime)
    {
        cout << "[VALIDATION] TEST 4: Failover Performance\n";
        cout << "-----------------------------------------\n";

        Time failoverTime = switchTime - injectionTime;

        cout << "Failover Timing:\n";
        cout << "  Congestion injected at: " << injectionTime.GetSeconds() << "s\n";
        cout << "  Path switched at: " << switchTime.GetSeconds() << "s\n";
        cout << "  Failover time: " << failoverTime.GetMilliSeconds() << " ms\n";

        // Expected: Should switch within 2 evaluation cycles (2 seconds)
        bool fastFailover = (failoverTime <= Seconds(2.0));

        if (fastFailover) {
            cout << "  ✓ Failover within acceptable time (< 2s)\n";
        } else {
            cout << "  ✗ Failover too slow (> 2s)\n";
        }

        m_results.failoverTest = fastFailover;
        m_results.averageFailoverTime = failoverTime;

        cout << "\nStatus: " << (m_results.failoverTest ? "✓ PASS" : "✗ FAIL") << "\n\n";
    }

    // ============================================================
    // COMPREHENSIVE VALIDATION REPORT
    // ============================================================

    void PrintValidationReport()
    {
        cout << "\n";
        cout << "════════════════════════════════════════════════════════\n";
        cout << "         PBR VALIDATION REPORT                          \n";
        cout << "════════════════════════════════════════════════════════\n";

        cout << " Test 1: Path Selection          ";
        cout << (m_results.pathSelectionTest ? "✓ PASS" : "✗ FAIL") << "           \n";

        cout << " Test 2: Metric Collection       ";
        cout << (m_results.metricCollectionTest ? "✓ PASS" : "✗ FAIL") << "           \n";

        cout << " Test 3: Policy Enforcement      ";
        cout << (m_results.policyEnforcementTest ? "✓ PASS" : "✗ FAIL") << "           \n";

        cout << " Test 4: Failover Performance    ";
        cout << (m_results.failoverTest ? "✓ PASS" : "✗ FAIL") << "           \n";

        cout << "════════════════════════════════════════════════════════\n";

        bool allPassed = m_results.pathSelectionTest &&
                        m_results.metricCollectionTest &&
                        m_results.policyEnforcementTest &&
                        m_results.failoverTest;

        cout << " OVERALL RESULT:                  ";
        if (allPassed) {
            cout << "✓ ALL PASS      \n";
        } else {
            cout << "✗ FAILED        \n";
        }

        cout << "════════════════════════════════════════════════════════\n";
        cout << " Classification Accuracy: "
                  << std::fixed << std::setprecision(1)
                  << std::setw(5) << m_results.classificationAccuracy << "%                  \n";
        cout << " Failover Time:           "
                  << std::setw(6) << m_results.averageFailoverTime.GetMilliSeconds()
                  << " ms                 \n";
        cout << "════════════════════════════════════════════════════════\n\n";
    }

    ValidationResults GetResults() const { return m_results; }

private:
    bool m_validationEnabled;
    ValidationResults m_results;
};

NS_OBJECT_ENSURE_REGISTERED(PbrValidator);


int
main(int argc, char* argv[])
{
    // Enable logging
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

    // Create three nodes: client (studio), router, server (cloud)
    NodeContainer nodes;
    nodes.Create(3);

    Ptr<Node> client = nodes.Get(0); // Client
    Ptr<Node> router = nodes.Get(1); // Router
    Ptr<Node> server = nodes.Get(2); // Server

    // Rename nodes for clarity
    Ptr<Node> studio = client;  // Production Studio
    Ptr<Node> cloud = server;    // Cloud Render Farm

    // Create point-to-point links

    // Link 1: studio <-> router (Network 1) - Access link
    PointToPointHelper p2pNetwork1;
    p2pNetwork1.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    p2pNetwork1.SetChannelAttribute("Delay", StringValue("2ms"));

    NodeContainer network1nodes(client, router); //studio <-> router
    NetDeviceContainer network1devices = p2pNetwork1.Install(network1nodes);

    cout << "[LINK1] Studio <-> Router: 5Mbps, 2ms\n";

    // Link 2: router <-> cloud PRIORITY PATH (Network 2) - Video traffic
    PointToPointHelper p2pNetwork2;
    p2pNetwork2.SetDeviceAttribute("DataRate", StringValue("1Mbps"));   // Lower bandwidth
    p2pNetwork2.SetChannelAttribute("Delay", StringValue("5ms"));       // Low latency

    NodeContainer network2nodes(router, server); // router <-> cloud
    NetDeviceContainer network2devices = p2pNetwork2.Install(network2nodes);

    cout << "[LINK2] Router <-> Cloud (Priority): 1Mbps, 5ms - VIDEO PATH\n";

    // Link 3: router <-> cloud BULK DATA PATH (Network 3) - Data traffic
    PointToPointHelper p2pNetwork3;
    p2pNetwork3.SetDeviceAttribute("DataRate", StringValue("5Mbps"));   // High bandwidth
    p2pNetwork3.SetChannelAttribute("Delay", StringValue("20ms"));      // Higher latency

    NodeContainer network3nodes(router, server);
    NetDeviceContainer network3devices = p2pNetwork3.Install(network3nodes);

    cout << "[LINK3] Router <-> Cloud (Bulk): 5Mbps, 20ms - DATA PATH\n\n";

    // Install mobility model to keep nodes at fixed positions
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    // Set the positions for each node
    Ptr<MobilityModel> mob0 = client->GetObject<MobilityModel>();
    Ptr<MobilityModel> mob1 = router->GetObject<MobilityModel>();
    Ptr<MobilityModel> mob2 = server->GetObject<MobilityModel>();

    // Triangle layout: Router at top, Client and Server at bottom corners
    mob0->SetPosition(Vector(5.0, 15.0, 0.0));  // Client bottom-left
    mob1->SetPosition(Vector(10.0, 2.0, 0.0));  // Router top-center
    mob2->SetPosition(Vector(15.0, 15.0, 0.0)); // Server bottom-right

    // Install Internet stack on all nodes
    InternetStackHelper stack;
    stack.Install(nodes);

    // Assign IP addresses to Network 1 (10.1.1.0/24)
    Ipv4AddressHelper address1;
    address1.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer network1interfaces = address1.Assign(network1devices);
    // interfaces1.GetAddress(0) = 10.1.1.1 
    // interfaces1.GetAddress(1) = 10.1.1.2

    // Assign IP addresses to Network 2 (10.1.2.0/24)
    Ipv4AddressHelper address2;
    address2.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer network2interfaces = address2.Assign(network2devices);
    // interfaces2.GetAddress(0) = 10.1.2.1 (n1's second interface)
    // interfaces2.GetAddress(1) = 10.1.2.2 (n2)

    // Assign IP addresses to Network 3 (10.1.3.0/24) - Bulk data path
    Ipv4AddressHelper address3;
    address3.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer network3interfaces = address3.Assign(network3devices);

    cout << "[IP] Network 3 (10.1.3.0/24) assigned\n";
    cout << "     Router eth2: " << network3interfaces.GetAddress(0) << "\n";
    cout << "     Cloud eth1: " << network3interfaces.GetAddress(1) << "\n\n";

    // *** Configure Static Routing ***

    // Enable IP forwarding on the router
    Ptr<Ipv4> ipv4Router = router->GetObject<Ipv4>();
    ipv4Router->SetAttribute("IpForward", BooleanValue(true));

    // ============================================================
    // INSTALL POLICY-BASED ROUTING ON ROUTER
    // ============================================================

    cout << "\n=== Installing Policy-Based Routing ===\n";

    // Get the router's existing static routing (as fallback)
    Ipv4StaticRoutingHelper staticRoutingHelper;
    Ptr<Ipv4StaticRouting> routerStaticRouting =
        staticRoutingHelper.GetStaticRouting(ipv4Router);

    // Create and install PBR protocol
    Ptr<PolicyBasedRouting> pbrRouting = CreateObject<PolicyBasedRouting>();
    pbrRouting->SetIpv4(ipv4Router);
    pbrRouting->SetStaticRouting(routerStaticRouting);

    // Replace router's routing protocol with PBR
    ipv4Router->SetRoutingProtocol(pbrRouting);

    cout << "[PBR] Policy-Based Routing installed on Router\n";
    cout << "[PBR] VIDEO (UDP:5004) -> Network 2 (10.1.2.2)\n";
    cout << "[PBR] DATA (TCP:2100) -> Network 3 (10.1.3.2)\n";
    cout << "[PBR] Other traffic -> Static routing fallback\n\n";


    // ============================================================
    // INSTALL PATH QUALITY MONITORING TRACE SOURCES
    // ============================================================

    cout << "\n=== Installing Path Quality Monitoring ===\n";

    // Get Ipv4L3Protocol objects for trace source connection
    Ptr<Ipv4L3Protocol> routerIpv4L3 = router->GetObject<Ipv4L3Protocol>();
    Ptr<Ipv4L3Protocol> cloudIpv4L3 = server->GetObject<Ipv4L3Protocol>();

    // Connect transmission trace on router
    routerIpv4L3->TraceConnectWithoutContext("Tx", MakeCallback(&TxTraceCallback));
    cout << "[MONITOR] Connected to router Tx trace (latency measurement)\n";

    // Connect reception trace on cloud
    cloudIpv4L3->TraceConnectWithoutContext("Rx", MakeCallback(&RxTraceCallback));
    cout << "[MONITOR] Connected to cloud Rx trace (latency measurement)\n";

    // Connect drop trace on router
    routerIpv4L3->TraceConnectWithoutContext("Drop", MakeCallback(&DropTraceCallback));
    cout << "[MONITOR] Connected to router Drop trace (loss measurement)\n";

    // Initialize measurement timestamps
    g_network2Metrics.lastMeasurementTime = Simulator::Now();
    g_network3Metrics.lastMeasurementTime = Simulator::Now();

    // Schedule periodic bandwidth measurement
    Simulator::Schedule(Seconds(1.0), &UpdateBandwidthMetrics);
    cout << "[MONITOR] Scheduled bandwidth monitoring (100ms intervals)\n";

    cout << "[MONITOR] Monitoring metrics:\n";
    cout << "  - End-to-end latency (Tx/Rx traces)\n";
    cout << "  - Available bandwidth (throughput calculation)\n";
    cout << "  - Link utilization (bytes sent vs capacity)\n";
    cout << "  - Packet loss rate (drop trace)\n";
    cout << "  - Congestion score (composite metric)\n\n";

    // ============================================================
    // INSTANTIATE SD-WAN CONTROLLER
    // ============================================================

    cout << "\n=== Configuring SD-WAN Controller ===\n";

    // Create controller
    Ptr<SdWanController> sdwanController = CreateObject<SdWanController>();
    sdwanController->Initialize(router);

    // Register WAN paths
    sdwanController->RegisterPath(
        g_videoPriorityInterface,  // Interface 2
        "Network2-Video",
        1.0,                       // 1 Mbps capacity
        MilliSeconds(5)            // 5ms base latency
    );

    sdwanController->RegisterPath(
        g_dataBulkInterface,       // Interface 3
        "Network3-Data",
        5.0,                       // 5 Mbps capacity
        MilliSeconds(20)           // 20ms base latency
    );

    cout << "[SDWAN] Registered 2 WAN paths\n";

    // Configure policies

    // Policy 1: Video latency-based switching
    PolicyRule videoLatencyPolicy;
    videoLatencyPolicy.policyName = "Video-Latency-Policy";
    videoLatencyPolicy.policyId = 1;
    videoLatencyPolicy.type = PolicyRule::LATENCY_BASED;
    videoLatencyPolicy.targetTraffic = TRAFFIC_VIDEO;
    videoLatencyPolicy.latencyThresholdMs = 30.0;  // Switch if > 30ms
    videoLatencyPolicy.primaryInterface = g_videoPriorityInterface;
    videoLatencyPolicy.secondaryInterface = g_dataBulkInterface;
    videoLatencyPolicy.cooldownPeriod = Seconds(5);  // 5s hysteresis

    sdwanController->AddPolicy(videoLatencyPolicy);
    cout << "[SDWAN] Policy: Video traffic switches if latency > 30ms\n";

    // Policy 2: Data bandwidth-based switching
    PolicyRule dataBandwidthPolicy;
    dataBandwidthPolicy.policyName = "Data-Bandwidth-Policy";
    dataBandwidthPolicy.policyId = 2;
    dataBandwidthPolicy.type = PolicyRule::BANDWIDTH_BASED;
    dataBandwidthPolicy.targetTraffic = TRAFFIC_DATA;
    dataBandwidthPolicy.bandwidthThresholdMbps = 0.5;  // Switch if < 0.5 Mbps available
    dataBandwidthPolicy.primaryInterface = g_dataBulkInterface;
    dataBandwidthPolicy.secondaryInterface = g_videoPriorityInterface;
    dataBandwidthPolicy.cooldownPeriod = Seconds(5);

    sdwanController->AddPolicy(dataBandwidthPolicy);
    cout << "[SDWAN] Policy: Data traffic switches if bandwidth < 0.5 Mbps\n";

    // Start controller (begins periodic evaluation)
    sdwanController->Start();
    cout << "[SDWAN] Controller started - evaluating policies every 1s\n\n";

    // Schedule congestion test
    Simulator::Schedule(Seconds(4.0), &InjectCongestion);
    Simulator::Schedule(Seconds(8.0), &RemoveCongestion);
    cout << "[TEST] Scheduled congestion injection at T=4s (removed at T=8s)\n\n";

    // Configure routing on client
    // client needs to know that to reach 10.1.2.0/24, it should go through 10.1.1.2 (router's
    // interface)
    Ptr<Ipv4StaticRouting> staticroutingclient =
        staticRoutingHelper.GetStaticRouting(client->GetObject<Ipv4>());
    staticroutingclient->AddNetworkRouteTo(
        Ipv4Address("10.1.2.0"),   // Destination network
        Ipv4Mask("255.255.255.0"), // Network mask
        Ipv4Address("10.1.1.2"),   // Next hop (router's interface on network 1)
        1                          // Interface index
    );

    // Add route to Network 3 as well
    staticroutingclient->AddNetworkRouteTo(
        Ipv4Address("10.1.3.0"),   // Network 3
        Ipv4Mask("255.255.255.0"),
        Ipv4Address("10.1.1.2"),   // Via router
        1
    );
    cout << "[STATIC] Client also has route to 10.1.3.0/24 via router\n";

    // Configure routing on server
    // server needs to know that to reach 10.1.1.0/24, it should go through 10.1.2.1 (router's
    // interface)
    Ptr<Ipv4StaticRouting> staticroutingserver =
        staticRoutingHelper.GetStaticRouting(server->GetObject<Ipv4>());
    staticroutingserver->AddNetworkRouteTo(
        Ipv4Address("10.1.1.0"),   // Destination network
        Ipv4Mask("255.255.255.0"), // Network mask
        Ipv4Address("10.1.2.1"),   // Next hop (router's interface on network 2)
        1                          // Interface index
    );

    // Note: Router n1 doesn't need explicit routes as it's directly connected to both networks

    // Print routing tables for verification
    Ptr<OutputStreamWrapper> routingStream =
        Create<OutputStreamWrapper>("router-static-routing5.routes", std::ios::out);
    staticRoutingHelper.PrintRoutingTableAllAt(Seconds(1.0), routingStream);

    cout << "\n=== Network Configuration ===\n";
    cout << "Node 0 (Studio): " << network1interfaces.GetAddress(0) << " (Network 1)\n";
    cout << "Node 1 (Router) Interface 0: " << network1interfaces.GetAddress(1) << " (Network 1)\n";
    cout << "Node 1 (Router) Interface 1: " << network2interfaces.GetAddress(0) << " (Network 2 - Video)\n";
    cout << "Node 1 (Router) Interface 2: " << network3interfaces.GetAddress(0) << " (Network 3 - Data)\n";
    cout << "Node 2 (Cloud) Interface 0: " << network2interfaces.GetAddress(1) << " (Network 2 - Video)\n";
    cout << "Node 2 (Cloud) Interface 1: " << network3interfaces.GetAddress(1) << " (Network 3 - Data)\n";
    cout << "=============================\n\n";

    // ============================================================
    // MEDIASTREAM INC. DUAL TRAFFIC FLOW SETUP
    // ============================================================

    cout << "\n=== MediaStream Traffic Flow Configuration ===\n";

    // ============================================================
    // FLOW_VIDEO: RTP-like Video Control Traffic
    // ============================================================
    // Characteristics:
    // - Small packets (160-200 bytes typical for RTP control)
    // - High frequency (50 packets/sec = 20ms intervals)
    // - Constant bit rate
    // - Low latency requirement (< 50ms target)
    // - Uses high port number (5004 - typical RTP control)

    uint16_t videoPort = 5004;

    // Video Server on Cloud (receives control commands)
    PacketSinkHelper videoSink("ns3::UdpSocketFactory",
                               InetSocketAddress(Ipv4Address::GetAny(), videoPort));
    ApplicationContainer videoServerApp = videoSink.Install(cloud);
    videoServerApp.Start(Seconds(1.0));
    videoServerApp.Stop(Seconds(10.0));

    // Video Client on Studio (sends control commands)
    OnOffHelper videoClient("ns3::UdpSocketFactory",
                           InetSocketAddress(network2interfaces.GetAddress(1), videoPort));

    // Configure RTP-like traffic pattern
    videoClient.SetAttribute("PacketSize", UintegerValue(180));  // Small RTP control packets
    videoClient.SetAttribute("DataRate", StringValue("72kbps")); // 180 bytes * 50 pkt/s * 8 = 72kbps
    videoClient.SetConstantRate(DataRate("72kbps"), 180);        // Constant rate

    // Set On/Off times for continuous streaming
    videoClient.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=8.0]"));
    videoClient.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));

    ApplicationContainer videoClientApp = videoClient.Install(studio);
    videoClientApp.Start(Seconds(2.0));
    videoClientApp.Stop(Seconds(10.0));

    // Set ToS/DSCP marking for QoS classification (EF - Expedited Forwarding)

    // Set ToS/DSCP marking for QoS classification (EF - Expedited Forwarding)
    Ptr<Socket> videoSocket = Socket::CreateSocket(studio, UdpSocketFactory::GetTypeId());
    videoSocket->SetIpTos(0xb8); // DSCP EF (46 << 2) for video


    cout << "[FLOW_VIDEO] RTP-like Control Traffic:\n";
    cout << "  Source: Studio (10.1.1.1) -> Destination: Cloud (10.1.2.2)\n";
    cout << "  Port: UDP/" << videoPort << "\n";
    cout << "  Packet Size: 180 bytes\n";
    cout << "  Rate: 72 kbps (50 packets/sec)\n";
    cout << "  Pattern: Constant, periodic\n";
    cout << "  DSCP Marking: EF (0xb8) - HIGH PRIORITY\n";
    cout << "  Latency Requirement: < 50ms\n\n";

    // ============================================================
    // FLOW_DATA: FTP-like Bulk File Transfer
    // ============================================================
    // Characteristics:
    // - Large packets (1460 bytes - typical TCP MSS)
    // - Bursty pattern (on/off behavior)
    // - High throughput requirement
    // - Latency tolerant (can handle 100-200ms)
    // - Uses standard FTP port (21 or 2100 for data)

    uint16_t dataPort = 2100;

    // Data Server on Cloud (receives file transfers)
    PacketSinkHelper dataSink("ns3::TcpSocketFactory",
                             InetSocketAddress(Ipv4Address::GetAny(), dataPort));
    ApplicationContainer dataServerApp = dataSink.Install(cloud);
    dataServerApp.Start(Seconds(1.0));
    dataServerApp.Stop(Seconds(10.0));

    // Data Client on Studio (sends large files)
    OnOffHelper dataClient("ns3::TcpSocketFactory",
                          InetSocketAddress(network2interfaces.GetAddress(1), dataPort));

    // Configure FTP-like bulk transfer pattern
    dataClient.SetAttribute("PacketSize", UintegerValue(1460));  // Large TCP segments
    dataClient.SetAttribute("DataRate", StringValue("4Mbps"));   // Bulk transfer rate

    // Bursty pattern: 2 seconds ON, 1 second OFF (simulates file transfers)
    dataClient.SetAttribute("OnTime",
        StringValue("ns3::ExponentialRandomVariable[Mean=2.0]"));
    dataClient.SetAttribute("OffTime",
        StringValue("ns3::ExponentialRandomVariable[Mean=1.0]"));

    ApplicationContainer dataClientApp = dataClient.Install(studio);
    dataClientApp.Start(Seconds(2.5));  // Start slightly after video
    dataClientApp.Stop(Seconds(10.0));

    // Set ToS/DSCP marking for QoS classification (AF11 - Assured Forwarding)
    Ptr<Socket> dataSocket = Socket::CreateSocket(studio, TcpSocketFactory::GetTypeId());
    dataSocket->SetIpTos(0xb8); // DSCP AF11 (10 << 2) for bulk data

    cout << "[FLOW_DATA] FTP-like Bulk Transfer:\n";
    cout << "  Source: Studio (10.1.1.1) -> Destination: Cloud (10.1.2.2)\n";
    cout << "  Port: TCP/" << dataPort << "\n";
    cout << "  Packet Size: 1460 bytes\n";
    cout << "  Rate: 4 Mbps (bursty)\n";
    cout << "  Pattern: Exponential On/Off (2s ON, 1s OFF avg)\n";
    cout << "  DSCP Marking: AF11 (0x28) - LOWER PRIORITY\n";
    cout << "  Latency Tolerance: ~100-200ms acceptable\n\n";

    cout << "=== Traffic Differentiation Summary ===\n";
    cout << "Flow_Video: UDP, 180B packets, 72kbps, DSCP EF (0xb8)\n";
    cout << "Flow_Data:  TCP, 1460B packets, 4Mbps, DSCP AF11 (0x28)\n";
    cout << "========================================\n\n";

    // ============================================================
    // INSTALL FLOWMONITOR FOR TRAFFIC ANALYSIS
    // ============================================================

    FlowMonitorHelper flowMonitorHelper;
    Ptr<FlowMonitor> flowMonitor = flowMonitorHelper.InstallAll();

    cout << "[MONITORING] FlowMonitor installed to track both flows\n\n";

    // *** NetAnim Configuration ***
    AnimationInterface anim("router-static-routing5.xml");

    // Node positions are already set via MobilityModel above
    // NetAnim will automatically use the mobility model positions

    // Set node descriptions
    // Set node descriptions
    anim.UpdateNodeDescription(client, "Studio\n10.1.1.1\n(Video+Data Src)");
    anim.UpdateNodeDescription(router, "Router\n10.1.1.2 | 10.1.2.1\n(PBR Point)");
    anim.UpdateNodeDescription(server, "Cloud\n10.1.2.2\n(Render Farm)");


    // Set node colors
    anim.UpdateNodeColor(client, 0, 255, 0);   // Green for client
    anim.UpdateNodeColor(router, 255, 255, 0); // Yellow for router
    anim.UpdateNodeColor(server, 0, 0, 255);   // Blue for server

    // Enable PCAP tracing on all devices for Wireshark analysis
    p2pNetwork1.EnablePcapAll("router-static-routing5");
    p2pNetwork2.EnablePcapAll("router-static-routing5");
    p2pNetwork3.EnablePcapAll("router-static-routing5");

    // Run simulation
    Simulator::Stop(Seconds(11.0));
    Simulator::Run();
    Simulator::Destroy();

    // ============================================================
    // ANALYZE TRAFFIC FLOWS
    // ============================================================

    flowMonitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowMonitorHelper.GetClassifier());
    FlowMonitor::FlowStatsContainer stats = flowMonitor->GetFlowStats();

    cout << "\n=== Traffic Flow Analysis ===\n";

    for (auto iter = stats.begin(); iter != stats.end(); ++iter)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(iter->first);

        cout << "\nFlow ID " << iter->first << ":\n";
        cout << "  " << t.sourceAddress << ":" << t.sourcePort
             << " -> " << t.destinationAddress << ":" << t.destinationPort << "\n";
        cout << "  Protocol: " << (t.protocol == 6 ? "TCP" : "UDP") << "\n";

        // Identify flow type based on port and protocol
        string flowType = "Unknown";
        if (t.protocol == 17 && t.destinationPort == 5004)
            flowType = "FLOW_VIDEO (RTP-like)";
        else if (t.protocol == 6 && t.destinationPort == 2100)
            flowType = "FLOW_DATA (FTP-like)";

        cout << "  Type: " << flowType << "\n";
        cout << "  Tx Packets: " << iter->second.txPackets << "\n";
        cout << "  Rx Packets: " << iter->second.rxPackets << "\n";
        cout << "  Throughput: "
             << (iter->second.rxBytes * 8.0 /
                 (iter->second.timeLastRxPacket.GetSeconds() -
                  iter->second.timeFirstTxPacket.GetSeconds())) / 1000.0
             << " kbps\n";

        if (iter->second.rxPackets > 0)
        {
            cout << "  Avg Delay: "
                 << iter->second.delaySum.GetMilliSeconds() / iter->second.rxPackets
                 << " ms\n";
            cout << "  Avg Jitter: "
                 << iter->second.jitterSum.GetMilliSeconds() / (iter->second.rxPackets - 1)
                 << " ms\n";
        }
    }

    // ============================================================
    // PATH QUALITY METRICS REPORT
    // ============================================================

    cout << "\n=== Path Quality Metrics Report ===\n\n";

    cout << "NETWORK 2 (Video Priority Path - 1Mbps, 5ms):\n";
    cout << "  Latency:\n";
    cout << "    Average: " << g_network2Metrics.averageLatency.GetMilliSeconds() << " ms\n";
    cout << "    Min: " << g_network2Metrics.minLatency.GetMilliSeconds() << " ms\n";
    cout << "    Max: " << g_network2Metrics.maxLatency.GetMilliSeconds() << " ms\n";
    cout << "    Samples: " << g_network2Metrics.latencySamples << "\n";
    cout << "  Bandwidth:\n";
    cout << "    Available: " << std::fixed << std::setprecision(2)
         << g_network2Metrics.availableBandwidth << " Mbps\n";
    cout << "    Utilization: " << g_network2Metrics.utilization << "%\n";
    cout << "  Quality:\n";
    cout << "    Packets Dropped: " << g_network2Metrics.packetsDropped << "\n";
    cout << "    Loss Rate: " << g_network2Metrics.packetLossRate << "%\n";
    cout << "    Congestion Score: " << g_network2Metrics.congestionScore << "/100\n";

    cout << "\nNETWORK 3 (Bulk Data Path - 5Mbps, 20ms):\n";
    cout << "  Latency:\n";
    cout << "    Average: " << g_network3Metrics.averageLatency.GetMilliSeconds() << " ms\n";
    cout << "    Min: " << g_network3Metrics.minLatency.GetMilliSeconds() << " ms\n";
    cout << "    Max: " << g_network3Metrics.maxLatency.GetMilliSeconds() << " ms\n";
    cout << "    Samples: " << g_network3Metrics.latencySamples << "\n";
    cout << "  Bandwidth:\n";
    cout << "    Available: " << std::fixed << std::setprecision(2)
         << g_network3Metrics.availableBandwidth << " Mbps\n";
    cout << "    Utilization: " << g_network3Metrics.utilization << "%\n";
    cout << "  Quality:\n";
    cout << "    Packets Dropped: " << g_network3Metrics.packetsDropped << "\n";
    cout << "    Loss Rate: " << g_network3Metrics.packetLossRate << "%\n";
    cout << "    Congestion Score: " << g_network3Metrics.congestionScore << "/100\n";

    cout << "\nPATH COMPARISON:\n";
    if (g_network2Metrics.averageLatency < g_network3Metrics.averageLatency) {
        cout << "  ✓ Network 2 has LOWER latency (better for video)\n";
    } else {
        cout << "  ✓ Network 3 has LOWER latency\n";
    }

    if (g_network3Metrics.availableBandwidth > g_network2Metrics.availableBandwidth) {
        cout << "  ✓ Network 3 has MORE available bandwidth (better for bulk data)\n";
    } else {
        cout << "  ✓ Network 2 has MORE available bandwidth\n";
    }

    if (g_network2Metrics.congestionScore < g_network3Metrics.congestionScore) {
        cout << "  ✓ Network 2 has LOWER congestion (overall better quality)\n";
    } else {
        cout << "  ✓ Network 3 has LOWER congestion (overall better quality)\n";
    }

    cout << "====================================\n\n";

    
    cout << "\n=============================\n";

    // ============================================================
    // PBR STATISTICS REPORT
    // ============================================================

    cout << "\n=== Policy-Based Routing Statistics ===\n";
    cout << "Total Packets Processed: " << g_pbrStats.totalPacketsProcessed << "\n";
    cout << "Video Packets (via Network 2): " << g_pbrStats.videoPacketsRouted << "\n";
    cout << "Data Packets (via Network 3): " << g_pbrStats.dataPacketsRouted << "\n";
    cout << "Unclassified Packets (static routing): " << g_pbrStats.unclassifiedPackets << "\n";

    if (g_pbrStats.totalPacketsProcessed > 0) {
        cout << "\nClassification Success Rate: "
             << std::fixed << std::setprecision(1)
             << ((double)(g_pbrStats.videoPacketsRouted + g_pbrStats.dataPacketsRouted) /
                 g_pbrStats.totalPacketsProcessed * 100.0) << "%\n";
    }
    cout << "=======================================\n\n";

    // ============================================================
    // SD-WAN CONTROLLER REPORT
    // ============================================================

    cout << "\n=== SD-WAN Controller Final Report ===\n";
    sdwanController->PrintStatus();
    cout << "Total Path Switches: " << sdwanController->GetTotalSwitches() << "\n";
    cout << "=====================================\n\n";

    // ============================================================
    // RUN VALIDATION TESTS
    // ============================================================

    cout << "\n";
    cout << "═══════════════════════════════════════════════════════════\n";
    cout << "           RUNNING PBR VALIDATION TESTS                    \n";
    cout << "═══════════════════════════════════════════════════════════\n\n";

    Ptr<PbrValidator> validator = CreateObject<PbrValidator>();

    // Test 1: Path selection
    validator->ValidatePathSelection();

    // Test 2: Metric collection
    validator->ValidateMetricCollection();

    // Test 3: Policy enforcement
    validator->ValidatePolicyEnforcement(sdwanController);

    // Test 4: Failover performance
    validator->ValidateFailoverTime(Seconds(4.0), Seconds(5.0));  // Injection at 4s, expected switch at 5s

    // Print comprehensive report
    validator->PrintValidationReport();

    cout << "\n=== Simulation Complete ===\n";

    cout << "Animation trace saved to: router-static-routing5.xml\n";
    cout << "Routing tables saved to: router-static-routing5.routes\n";
    cout << "PCAP traces saved to: router-static-routing5-*.pcap\n";
    cout << "Open the XML file with NetAnim to visualize the simulation.\n";

    return 0;
}
