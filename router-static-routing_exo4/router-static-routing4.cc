/*
 * RegionalBank Multi-Hop WAN Resilient Network Simulation
 * 
 * Topology:
 *                    Network 2 (10.1.2.0/24)
 *                    Primary Production Link
 *                    5Mbps, 10ms (longer distance)
 *                           |
 * Branch-C ----Network1----> DC-A ----Network2----> DR-B
 * (Client)    10.1.1.0/24   (Router)  10.1.2.0/24  (Server)
 * 10.1.1.1    5Mbps, 2ms    10.1.1.2  5Mbps, 10ms  10.1.2.2
 *                            10.1.2.1               10.1.3.2
 *                            10.1.3.1
 *                               |
 *                               | Network 3 (10.1.3.0/24)
 *                               | Backup/DR Link
 *                               | 10Mbps, 5ms (dedicated fiber)
 *                               |
 *                            DR-B
 *                          (10.1.3.2)
 * 
 * Features:
 * 1. Static routing with manual failover (default)
 * 2. OSPF dynamic routing with automatic failover (optional)
 * 3. Simulated link failure at T=5s and recovery at T=15s
 * 4. Convergence time comparison between static and OSPF
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/error-model.h"
#include "ns3/internet-apps-module.h"
#include <iostream>
#include <string>
#include <fstream>
#include "ns3/flow-monitor-module.h"
#include <iomanip>

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("RegionalBankWAN");

// ============================================================
// GLOBAL VARIABLES FOR LINK FAILURE MANAGEMENT
// ============================================================

// Link failure management
Ptr<RateErrorModel> g_primaryLinkErrorModel;
Ptr<NetDevice> g_dcaToDrbPrimaryDevice;
Ptr<NetDevice> g_drbToDcaPrimaryDevice;
Ptr<Ipv4StaticRouting> g_drBRouting;
bool g_primaryLinkActive = true;

// Routing mode selection
bool g_useOSPF = true;  // Set to false to use static routing instead of OSPF

// Convergence tracking
Time g_failureTime;
Time g_convergenceTime;
bool g_convergenceDetected = false;
uint32_t g_packetsBeforeFailure = 0;
uint32_t g_packetsAfterFailure = 0;
uint32_t g_packetsLostDuringFailover = 0;

// ============================================================
// PACKET TRACKING FOR CONVERGENCE ANALYSIS
// ============================================================

void PacketSentCallback(Ptr<const Packet> packet)
{
    if (!g_primaryLinkActive && !g_convergenceDetected)
    {
        g_packetsLostDuringFailover++;
    }
    else if (g_primaryLinkActive && Simulator::Now() < g_failureTime)
    {
        g_packetsBeforeFailure++;
    }
}

void PacketReceivedCallback(Ptr<const Packet> packet, const Address& address)
{
    // If we receive a packet after link failure, convergence has occurred
    if (!g_primaryLinkActive && !g_convergenceDetected)
    {
        g_convergenceDetected = true;
        g_convergenceTime = Simulator::Now() - g_failureTime;
        
        cout << "\n═══════════════════════════════════════════════════════════\n";
        cout << "  CONVERGENCE DETECTED!                                    \n";
        cout << "  Time to restore connectivity: " 
                  << g_convergenceTime.GetMilliSeconds() << " ms                \n";
        cout << "═══════════════════════════════════════════════════════════\n\n";
    }
    
    if (g_primaryLinkActive || g_convergenceDetected)
    {
        g_packetsAfterFailure++;
    }
}

// ============================================================
// ROUTING TABLE MODIFICATION FUNCTIONS (STATIC ROUTING)
// ============================================================

void FailoverToBackupRoute()
{
    if (g_useOSPF)
    {
        cout << "[OSPF] Automatic failover in progress (handled by OSPF)...\n";
        return;  // OSPF handles this automatically
    }
    
    cout << "\n[STATIC ROUTING] Manual failover to backup path...\n";
    
    // Print routing table BEFORE failover
    cout << "\n--- DR-B Routing Table BEFORE Failover ---\n";
    Ptr<OutputStreamWrapper> routingStream = 
        Create<OutputStreamWrapper>(&std::cout);
    g_drBRouting->PrintRoutingTable(routingStream);
    
    // Remove primary route (route to 10.1.1.0/24 via 10.1.2.1)
    uint32_t numRoutes = g_drBRouting->GetNRoutes();
    for (uint32_t i = 0; i < numRoutes; i++)
    {
        Ipv4RoutingTableEntry route = g_drBRouting->GetRoute(i);
        if (route.GetGateway() == Ipv4Address("10.1.2.1") && 
            route.GetDest() == Ipv4Address("10.1.1.0"))
        {
            g_drBRouting->RemoveRoute(i);
            cout << "[REMOVED] Route to 10.1.1.0/24 via 10.1.2.1 (Primary)\n";
            break;
        }
    }
    
    // Add backup route (route to 10.1.1.0/24 via 10.1.3.1)
    g_drBRouting->AddNetworkRouteTo(
        Ipv4Address("10.1.1.0"),
        Ipv4Mask("255.255.255.0"),
        Ipv4Address("10.1.3.1"),  // Next hop: DC-A's backup interface
        2                          // Interface: eth1 (backup)
    );
    cout << "[ADDED] Route to 10.1.1.0/24 via 10.1.3.1 (Backup)\n";
    
    // Print routing table AFTER failover
    cout << "\n--- DR-B Routing Table AFTER Failover ---\n";
    g_drBRouting->PrintRoutingTable(routingStream);
    cout << std::endl;
}

void RecoverToPrimaryRoute()
{
    if (g_useOSPF)
    {
        cout << "[OSPF] Automatic recovery in progress (handled by OSPF)...\n";
        return;  // OSPF handles this automatically
    }
    
    cout << "\n[STATIC ROUTING] Manual recovery to primary path...\n";
    
    // Print routing table BEFORE recovery
    cout << "\n--- DR-B Routing Table BEFORE Recovery ---\n";
    Ptr<OutputStreamWrapper> routingStream = 
        Create<OutputStreamWrapper>(&std::cout);
    g_drBRouting->PrintRoutingTable(routingStream);
    
    // Remove backup route
    uint32_t numRoutes = g_drBRouting->GetNRoutes();
    for (uint32_t i = 0; i < numRoutes; i++)
    {
        Ipv4RoutingTableEntry route = g_drBRouting->GetRoute(i);
        if (route.GetGateway() == Ipv4Address("10.1.3.1") && 
            route.GetDest() == Ipv4Address("10.1.1.0"))
        {
            g_drBRouting->RemoveRoute(i);
            std::cout << "[REMOVED] Route to 10.1.1.0/24 via 10.1.3.1 (Backup)\n";
            break;
        }
    }
    
    // Restore primary route
    g_drBRouting->AddNetworkRouteTo(
        Ipv4Address("10.1.1.0"),
        Ipv4Mask("255.255.255.0"),
        Ipv4Address("10.1.2.1"),  // Next hop: DC-A's primary interface
        1                          // Interface: eth0 (primary)
    );
    cout << "[ADDED] Route to 10.1.1.0/24 via 10.1.2.1 (Primary)\n";
    
    // Print routing table AFTER recovery
    cout << "\n--- DR-B Routing Table AFTER Recovery ---\n";
    g_drBRouting->PrintRoutingTable(routingStream);
    cout << endl;
}

// ============================================================
// LINK FAILURE SIMULATION FUNCTIONS
// ============================================================

void SimulatePrimaryLinkFailure()
{
    if (!g_primaryLinkActive) return;  // Already failed
    
    g_failureTime = Simulator::Now();
    g_convergenceDetected = false;
    
    cout << "\n═══════════════════════════════════════════════════════════\n";
    cout << "  [T=" << Simulator::Now().GetSeconds() 
              << "s] PRIMARY LINK FAILURE                     \n";
    cout << "  Network 2 (DC-A ↔ DR-B) is now DOWN                     \n";
    cout << "═══════════════════════════════════════════════════════════\n";
    
    // Create error model that drops ALL packets (simulates physical link failure)
    Ptr<RateErrorModel> errorModel = CreateObject<RateErrorModel>();
    errorModel->SetAttribute("ErrorRate", DoubleValue(1.0));  // 100% packet loss
    errorModel->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
    

    Ptr<PointToPointNetDevice> dev1 = g_dcaToDrbPrimaryDevice->GetObject<PointToPointNetDevice>();
    Ptr<PointToPointNetDevice> dev2 = g_drbToDcaPrimaryDevice->GetObject<PointToPointNetDevice>();

    dev1->SetReceiveErrorModel(errorModel);
    dev2->SetReceiveErrorModel(errorModel);

    g_primaryLinkErrorModel = errorModel;
    g_primaryLinkActive = false;

    
    cout << "[LINK] DC-A eth1 (10.1.2.1) → Status: DOWN\n";
    cout << "[LINK] DR-B eth0 (10.1.2.2) → Status: DOWN\n";
    
    if (g_useOSPF)
    {
        cout << "[OSPF] Detecting link failure and recalculating routes...\n";
        cout << "[OSPF] LSA flooding in progress...\n";
        // OSPF will automatically handle failover
    }
    else
    {
        cout << "[STATIC] Manual failover required - calling FailoverToBackupRoute()\n";
        // Trigger manual routing table update
        FailoverToBackupRoute();
    }
    
    cout << "──────────────────────────────────────────────────────────\n\n";
}

void SimulatePrimaryLinkRecovery()
{
    if (g_primaryLinkActive) return;  // Already active
    
    cout << "\n═══════════════════════════════════════════════════════════\n";
    cout << "  [T=" << Simulator::Now().GetSeconds() 
              << "s] PRIMARY LINK RECOVERY                    \n";
    cout << "  Network 2 (DC-A ↔ DR-B) is now UP                       \n";
    cout << "═══════════════════════════════════════════════════════════\n";
    
    Ptr<RateErrorModel> errorModel = CreateObject<RateErrorModel>();
    errorModel->SetAttribute("ErrorRate", DoubleValue(1.0));  // 100% packet loss
    errorModel->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));

    Ptr<PointToPointNetDevice> dev1 = g_dcaToDrbPrimaryDevice->GetObject<PointToPointNetDevice>();
    Ptr<PointToPointNetDevice> dev2 = g_drbToDcaPrimaryDevice->GetObject<PointToPointNetDevice>();

    dev1->SetReceiveErrorModel(errorModel);
    dev2->SetReceiveErrorModel(errorModel);

    g_primaryLinkErrorModel = errorModel;
    g_primaryLinkActive = true;

    
    cout << "[LINK] DC-A eth1 (10.1.2.1) → Status: UP\n";
    cout << "[LINK] DR-B eth0 (10.1.2.2) → Status: UP\n";
    
    if (g_useOSPF)
    {
        cout << "[OSPF] Detecting link recovery and recalculating routes...\n";
        // OSPF will automatically handle recovery
    }
    else
    {
        cout << "[STATIC] Manual recovery - calling RecoverToPrimaryRoute()\n";
        RecoverToPrimaryRoute();
    }
    
    cout << "──────────────────────────────────────────────────────────\n\n";
}

// FlowMonitor
Ptr<FlowMonitor> g_flowMonitor;
FlowMonitorHelper g_flowMonitorHelper;

// Custom trace sink data structures
struct PathMetrics {
    uint32_t txPackets = 0;
    uint32_t rxPackets = 0;
    Time firstTxTime = Seconds(0);
    Time lastRxTime = Seconds(0);
};

PathMetrics g_primaryPathMetrics;
PathMetrics g_backupPathMetrics;
std::map<uint32_t, Time> g_packetTxTimes;  // Track per-packet delays

// ============================================================
// CUSTOM TRACE SINKS FOR PATH VERIFICATION
// ============================================================

// Trace sink for Network 2 (Primary path) - DC-A to DR-B
void PrimaryPathTxTrace(Ptr<const Packet> packet)
{
    g_primaryPathMetrics.txPackets++;
    if (g_primaryPathMetrics.firstTxTime == Seconds(0))
    {
        g_primaryPathMetrics.firstTxTime = Simulator::Now();
    }

    // Store packet ID and timestamp for delay calculation
    g_packetTxTimes[packet->GetUid()] = Simulator::Now();

    NS_LOG_INFO("[PRIMARY PATH] Packet transmitted at T="
                << Simulator::Now().GetSeconds() << "s, UID=" << packet->GetUid());
}

void PrimaryPathRxTrace(Ptr<const Packet> packet)
{
    g_primaryPathMetrics.rxPackets++;
    g_primaryPathMetrics.lastRxTime = Simulator::Now();

    NS_LOG_INFO("[PRIMARY PATH] Packet received at T="
                << Simulator::Now().GetSeconds() << "s, UID=" << packet->GetUid());
}

// Trace sink for Network 3 (Backup path) - DC-A to DR-B
void BackupPathTxTrace(Ptr<const Packet> packet)
{
    g_backupPathMetrics.txPackets++;
    if (g_backupPathMetrics.firstTxTime == Seconds(0))
    {
        g_backupPathMetrics.firstTxTime = Simulator::Now();
    }

    NS_LOG_INFO("[BACKUP PATH] Packet transmitted at T="
                << Simulator::Now().GetSeconds() << "s, UID=" << packet->GetUid());
}

void BackupPathRxTrace(Ptr<const Packet> packet)
{
    g_backupPathMetrics.rxPackets++;
    g_backupPathMetrics.lastRxTime = Simulator::Now();

    NS_LOG_INFO("[BACKUP PATH] Packet received at T="
                << Simulator::Now().GetSeconds() << "s, UID=" << packet->GetUid());
}


// ============================================================
// FLOWMONITOR ANALYSIS AND REPORTING
// ============================================================

void PrintFlowMonitorStats()
{
    cout << "\nâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n";
    cout << "          FLOWMONITOR DETAILED ANALYSIS                    \n";
    cout << "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n\n";

    g_flowMonitor->CheckForLostPackets();

    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(g_flowMonitorHelper.GetClassifier());

    FlowMonitor::FlowStatsContainer stats = g_flowMonitor->GetFlowStats();

    double totalDelay = 0;
    uint32_t totalRxPackets = 0;
    uint32_t totalTxPackets = 0;
    uint32_t totalLostPackets = 0;

    for (auto iter = stats.begin(); iter != stats.end(); ++iter)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(iter->first);

        cout << "Flow ID: " << iter->first << "\n";
        cout << "  Src: " << t.sourceAddress << ":" << t.sourcePort << "\n";
        cout << "  Dst: " << t.destinationAddress << ":" << t.destinationPort << "\n";
        cout << "  Protocol: " << (t.protocol == 17 ? "UDP" : "Other") << "\n";
        cout << "  ---\n";
        cout << "  Tx Packets: " << iter->second.txPackets << "\n";
        cout << "  Rx Packets: " << iter->second.rxPackets << "\n";
        cout << "  Lost Packets: " << iter->second.lostPackets << "\n";
        cout << "  Packet Loss Ratio: "
             << std::fixed << std::setprecision(2)
             << (iter->second.txPackets > 0 ?
                 (double)iter->second.lostPackets / iter->second.txPackets * 100.0 : 0)
             << "%\n";

        if (iter->second.rxPackets > 0)
        {
            double avgDelay = iter->second.delaySum.GetMilliSeconds() /
                              iter->second.rxPackets;
            cout << "  Average Delay: " << avgDelay << " ms\n";
            cout << "  Average Jitter: "
                 << iter->second.jitterSum.GetMilliSeconds() / (iter->second.rxPackets - 1)
                 << " ms\n";

            totalDelay += iter->second.delaySum.GetMilliSeconds();
        }
        else
        {
            cout << "  Average Delay: N/A (no packets received)\n";
            cout << "  Average Jitter: N/A\n";
        }

        cout << "  Throughput: "
             << std::fixed << std::setprecision(2)
             << (iter->second.rxBytes * 8.0 /
                 (iter->second.timeLastRxPacket.GetSeconds() -
                  iter->second.timeFirstTxPacket.GetSeconds())) / 1024.0
             << " Kbps\n";
        cout << "\n";

        totalRxPackets += iter->second.rxPackets;
        totalTxPackets += iter->second.txPackets;
        totalLostPackets += iter->second.lostPackets;
    }

    cout << "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n";
    cout << "  AGGREGATE STATISTICS:                                    \n";
    cout << "  Total Tx Packets: " << totalTxPackets << "\n";
    cout << "  Total Rx Packets: " << totalRxPackets << "\n";
    cout << "  Total Lost Packets: " << totalLostPackets << "\n";
    cout << "  Overall Loss Rate: "
         << std::fixed << std::setprecision(2)
         << (totalTxPackets > 0 ?
             (double)totalLostPackets / totalTxPackets * 100.0 : 0)
         << "%\n";
    cout << "  Average E2E Delay: "
         << (totalRxPackets > 0 ? totalDelay / totalRxPackets : 0)
         << " ms\n";
    cout << "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n\n";

    // Export to XML for further analysis
    string xmlFile = g_useOSPF ? "flowmon-ospf.xml" : "flowmon-static.xml";
    g_flowMonitor->SerializeToXmlFile(xmlFile, true, true);
    cout << "[FLOWMONITOR] Detailed XML report: " << xmlFile << "\n\n";
}

void PrintPathVerificationReport()
{
    cout << "\nâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n";
    cout << "          PATH VERIFICATION REPORT                         \n";
    cout << "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n\n";

    cout << "PRIMARY PATH (Network 2: 10.1.2.0/24):\n";
    cout << "  Packets Transmitted: " << g_primaryPathMetrics.txPackets << "\n";
    cout << "  Packets Received: " << g_primaryPathMetrics.rxPackets << "\n";
    cout << "  First Activity: " << g_primaryPathMetrics.firstTxTime.GetSeconds() << "s\n";
    cout << "  Last Activity: " << g_primaryPathMetrics.lastRxTime.GetSeconds() << "s\n";
    cout << "  Status: " << (g_primaryPathMetrics.txPackets > 0 ? "ACTIVE" : "INACTIVE") << "\n\n";

    cout << "BACKUP PATH (Network 3: 10.1.3.0/24):\n";
    cout << "  Packets Transmitted: " << g_backupPathMetrics.txPackets << "\n";
    cout << "  Packets Received: " << g_backupPathMetrics.rxPackets << "\n";
    cout << "  First Activity: " << g_backupPathMetrics.firstTxTime.GetSeconds() << "s\n";
    cout << "  Last Activity: " << g_backupPathMetrics.lastRxTime.GetSeconds() << "s\n";
    cout << "  Status: " << (g_backupPathMetrics.txPackets > 0 ? "ACTIVE" : "INACTIVE") << "\n\n";

    cout << "INTERPRETATION:\n";
    if (g_primaryPathMetrics.txPackets > 0 && g_backupPathMetrics.txPackets == 0)
    {
        cout << "  ✓ Traffic ONLY used primary path (expected before failure)\n";
    }
    else if (g_primaryPathMetrics.txPackets > 0 && g_backupPathMetrics.txPackets > 0)
    {
        cout << "  ✓ Traffic used BOTH paths (failover occurred)\n";
        cout << "    - Primary active: T=" << g_primaryPathMetrics.firstTxTime.GetSeconds()
             << "s to ~5s\n";
        cout << "    - Backup active: T=" << g_backupPathMetrics.firstTxTime.GetSeconds()
             << "s onwards\n";
    }
    else if (g_backupPathMetrics.txPackets > 0 && g_primaryPathMetrics.txPackets == 0)
    {
        cout << "  ✓ Traffic ONLY used backup path\n";
    }
    else
    {
        cout << "  ✗ No traffic detected on either path\n";
    }

    cout << "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n\n";
}


// ============================================================
// MAIN SIMULATION
// ============================================================

int main(int argc, char* argv[])
{
    // Command line parameters
    CommandLine cmd;
    cmd.AddValue("useOSPF", "Use OSPF dynamic routing (true) or static routing (false)", 
                 g_useOSPF);
    cmd.Parse(argc, argv);
    
    // Enable logging
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);
    
    // Display simulation mode
    cout << "\n═══════════════════════════════════════════════════════════\n";
    cout << "     RegionalBank WAN Resilience Simulation                \n";
    cout << "═══════════════════════════════════════════════════════════\n";
    cout << "  Routing Mode: " 
              << (g_useOSPF ? "OSPF (Dynamic)        " : "Static Routing        ") 
              << "                   \n";
    cout << "═══════════════════════════════════════════════════════════\n\n";
    
    // ============================================================
    // STEP 1: CREATE NODES
    // ============================================================
    
    NodeContainer nodes;
    nodes.Create(3);
    
    Ptr<Node> branchC = nodes.Get(0);  // Branch-C (Client)
    Ptr<Node> dcA = nodes.Get(1);       // DC-A (Main Router)
    Ptr<Node> drB = nodes.Get(2);       // DR-B (DR Server)
    
    cout << "[TOPOLOGY] Created 3 nodes: Branch-C, DC-A, DR-B\n";
    
    // ============================================================
    // STEP 2: CREATE POINT-TO-POINT LINKS
    // ============================================================
    
    // Link 1: Branch-C <-> DC-A (Network 1)
    // Short distance, standard speed
    PointToPointHelper p2pNetwork1;
    p2pNetwork1.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    p2pNetwork1.SetChannelAttribute("Delay", StringValue("2ms"));
    
    NodeContainer network1nodes(branchC, dcA);
    NetDeviceContainer network1devices = p2pNetwork1.Install(network1nodes);
    
    cout << "[LINK] Network 1: Branch-C ↔ DC-A (5Mbps, 2ms)\n";
    
    // Link 2: DC-A <-> DR-B Primary (Network 2)
    // Longer distance (City A to City B), higher latency
    PointToPointHelper p2pNetwork2;
    p2pNetwork2.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2pNetwork2.SetChannelAttribute("Delay", StringValue("5ms"));  // Longer WAN link
    
    NodeContainer network2nodes(dcA, drB);
    NetDeviceContainer network2devices = p2pNetwork2.Install(network2nodes);
    
    // Store devices for failure simulation
    g_dcaToDrbPrimaryDevice = network2devices.Get(0);  // DC-A's interface
    g_drbToDcaPrimaryDevice = network2devices.Get(1);  // DR-B's interface
    
    std::cout << "[LINK] Network 2: DC-A ↔ DR-B Primary (5Mbps, 10ms) [FAILURE TARGET]\n";
    
    // Link 3: DC-A <-> DR-B Backup (Network 3)
    // High-speed dedicated fiber backup link
    PointToPointHelper p2pNetwork3;
    p2pNetwork3.SetDeviceAttribute("DataRate", StringValue("10Mbps"));  // Better backup
    p2pNetwork3.SetChannelAttribute("Delay", StringValue("5ms"));       // Lower latency
    
    NodeContainer network3nodes(dcA, drB);
    NetDeviceContainer network3devices = p2pNetwork3.Install(network3nodes);
    
    cout << "[LINK] Network 3: DC-A ↔ DR-B Backup (10Mbps, 5ms) [REDUNDANT PATH]\n\n";
    
    // ============================================================
    // STEP 3: INSTALL INTERNET STACK
    // ============================================================
    
    InternetStackHelper stack;
    
    if (g_useOSPF)
    {
        // OSPF Configuration
        // Key NS-3 Helper Class: Ipv4GlobalRoutingHelper
        // This enables OSPF-like dynamic routing in NS-3
        
        cout << "[ROUTING] Installing Internet Stack with OSPF support...\n";
        
        // Note: NS-3 doesn't have a native OSPF implementation
        // We use Ipv4GlobalRoutingHelper which provides similar functionality:
        // - Automatic route calculation based on link state
        // - Dijkstra's shortest path algorithm (same as OSPF)
        // - Automatic convergence on topology changes
        
        Ipv4GlobalRoutingHelper globalRouting;
        stack.SetRoutingHelper(globalRouting);
        stack.Install(nodes);
        
        cout << "[OSPF] Global routing enabled (simulates OSPF behavior)\n";
        cout << "[OSPF] Link state database will be maintained\n";
        cout << "[OSPF] Automatic SPF recalculation on link changes\n\n";
    }
    else
    {
        // Static Routing Configuration
        cout << "[ROUTING] Installing Internet Stack with static routing...\n";
        
        Ipv4StaticRoutingHelper staticRouting;
        stack.SetRoutingHelper(staticRouting);
        stack.Install(nodes);
        
        cout << "[STATIC] Manual route configuration required\n";
        cout << "[STATIC] No automatic failover - manual intervention needed\n\n";
    }
    
    // ============================================================
    // STEP 4: ASSIGN IP ADDRESSES
    // ============================================================
    
    // Network 1: Branch-C <-> DC-A (10.1.1.0/24)
    Ipv4AddressHelper network1address;
    network1address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer network1interfaces = network1address.Assign(network1devices);
    
    cout << "[IP] Network 1 (10.1.1.0/24):\n";
    cout << "     Branch-C: " << network1interfaces.GetAddress(0) << "\n";
    cout << "     DC-A eth0: " << network1interfaces.GetAddress(1) << "\n";
    
    // Network 2: DC-A <-> DR-B Primary (10.1.2.0/24)
    Ipv4AddressHelper network2address;
    network2address.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer network2interfaces = network2address.Assign(network2devices);
    
    cout << "[IP] Network 2 (10.1.2.0/24) [PRIMARY]:\n";
    cout << "     DC-A eth1: " << network2interfaces.GetAddress(0) << "\n";
    cout << "     DR-B eth0: " << network2interfaces.GetAddress(1) << "\n";
    
    // Network 3: DC-A <-> DR-B Backup (10.1.3.0/24)
    Ipv4AddressHelper network3address;
    network3address.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer network3interfaces = network3address.Assign(network3devices);
    
    cout << "[IP] Network 3 (10.1.3.0/24) [BACKUP]:\n";
    cout << "     DC-A eth2: " << network3interfaces.GetAddress(0) << "\n";
    cout << "     DR-B eth1: " << network3interfaces.GetAddress(1) << "\n\n";
    
    // ============================================================
    // STEP 5: CONFIGURE ROUTING
    // ============================================================
    
    // Enable IP forwarding on DC-A (router functionality)
    Ptr<Ipv4> ipv4DcA = dcA->GetObject<Ipv4>();
    ipv4DcA->SetAttribute("IpForward", BooleanValue(true));
    
    if (g_useOSPF)
    {
        // OSPF: Populate routing tables automatically
        cout << "[OSPF] Populating routing tables...\n";
        
        // This is the KEY function for OSPF-like behavior in NS-3
        // It builds a global routing database and computes shortest paths
        Ipv4GlobalRoutingHelper::PopulateRoutingTables();
        
        cout << "[OSPF] Initial SPF calculation complete\n";
        cout << "[OSPF] All routers have converged\n";
        cout << "[OSPF] Cost metrics:\n";
        cout << "       Network 2 (Primary): Cost based on 10ms delay\n";
        cout << "       Network 3 (Backup): Cost based on 5ms delay\n";
        cout << "       Primary preferred due to established routes\n\n";
    }
    else
    {
        // Static Routing: Manual configuration
        cout << "[STATIC] Configuring manual routes...\n";
        
        Ipv4StaticRoutingHelper staticRoutingHelper;
        
        // Branch-C routing
        Ptr<Ipv4StaticRouting> branchCRouting = 
            staticRoutingHelper.GetStaticRouting(branchC->GetObject<Ipv4>());
        
        // Route to DR-B primary network
        branchCRouting->AddNetworkRouteTo(
            Ipv4Address("10.1.2.0"),
            Ipv4Mask("255.255.255.0"),
            Ipv4Address("10.1.1.2"),  // Via DC-A
            1
        );
        
        // Route to DR-B backup network
        branchCRouting->AddNetworkRouteTo(
            Ipv4Address("10.1.3.0"),
            Ipv4Mask("255.255.255.0"),
            Ipv4Address("10.1.1.2"),  // Via DC-A
            1
        );
        
        cout << "[STATIC] Branch-C routes configured:\n";
        cout << "         10.1.2.0/24 via 10.1.1.2\n";
        cout << "         10.1.3.0/24 via 10.1.1.2\n";
        
        // DR-B routing - PRIMARY route only initially
        g_drBRouting = staticRoutingHelper.GetStaticRouting(drB->GetObject<Ipv4>());
        
        // Add PRIMARY route (will be manually switched to backup on failure)
        g_drBRouting->AddNetworkRouteTo(
            Ipv4Address("10.1.1.0"),
            Ipv4Mask("255.255.255.0"),
            Ipv4Address("10.1.2.1"),  // Primary path via Network 2
            1                          // Interface eth0
        );
        
        cout << "[STATIC] DR-B routes configured:\n";
        cout << "         10.1.1.0/24 via 10.1.2.1 (Primary only)\n";
        cout << "         Backup route will be added during failover\n\n";
        
        // DC-A doesn't need explicit routes (directly connected to all networks)
    }
    
    // ============================================================
    // STEP 6: SETUP APPLICATIONS
    // ============================================================
    
    cout << "[APP] Setting up UDP Echo applications...\n";
    
    // UDP Echo Server on DR-B
    uint16_t port = 9;
    UdpEchoServerHelper echoServer(port);
    ApplicationContainer serverApps = echoServer.Install(drB);
    serverApps.Start(Seconds(1.0));
    serverApps.Stop(Seconds(25.0));
    
    cout << "[APP] UDP Echo Server: DR-B:" << port << "\n";
    
    // UDP Echo Client on Branch-C
    UdpEchoClientHelper echoClient(network2interfaces.GetAddress(1), port);
    echoClient.SetAttribute("MaxPackets", UintegerValue(30));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    echoClient.SetAttribute("PacketSize", UintegerValue(1024));
    
    ApplicationContainer clientApps = echoClient.Install(branchC);
    clientApps.Start(Seconds(2.0));
    clientApps.Stop(Seconds(25.0));
    
    cout << "[APP] UDP Echo Client: Branch-C → DR-B:" << port << "\n";
    cout << "[APP] Sending 1 packet/second for 23 seconds\n\n";
    
    // Attach callbacks for convergence tracking
    clientApps.Get(0)->TraceConnectWithoutContext("Tx", 
        MakeCallback(&PacketSentCallback));
    serverApps.Get(0)->TraceConnectWithoutContext("Rx", 
        MakeCallback(&PacketReceivedCallback));

    // ============================================================
    // ATTACH CUSTOM TRACE SINKS TO NETWORK DEVICES
    // ============================================================

    cout << "[TRACE] Attaching path verification trace sinks...\n";

    // Network 2 (Primary path) - Monitor both directions
    network2devices.Get(0)->TraceConnectWithoutContext("PhyTxEnd",
        MakeCallback(&PrimaryPathTxTrace));
    network2devices.Get(1)->TraceConnectWithoutContext("PhyRxEnd",
        MakeCallback(&PrimaryPathRxTrace));

    // Network 3 (Backup path) - Monitor both directions
    network3devices.Get(0)->TraceConnectWithoutContext("PhyTxEnd",
        MakeCallback(&BackupPathTxTrace));
    network3devices.Get(1)->TraceConnectWithoutContext("PhyRxEnd",
        MakeCallback(&BackupPathRxTrace));

    cout << "[TRACE] Primary and backup path monitoring enabled\n\n";

    // ============================================================
    // INSTALL FLOWMONITOR
    // ============================================================

    cout << "[FLOWMONITOR] Installing FlowMonitor...\n";
    g_flowMonitor = g_flowMonitorHelper.InstallAll();
    cout << "[FLOWMONITOR] Monitoring all flows for delay, jitter, and loss\n\n";
    
    // ============================================================
    // STEP 7: SETUP MOBILITY (FOR NETANIM VISUALIZATION)
    // ============================================================
    
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);
    
    Ptr<MobilityModel> mobBranchC = branchC->GetObject<MobilityModel>();
    Ptr<MobilityModel> mobDcA = dcA->GetObject<MobilityModel>();
    Ptr<MobilityModel> mobDrB = drB->GetObject<MobilityModel>();
    
    // Triangle topology showing redundant paths
    mobBranchC->SetPosition(Vector(5.0, 15.0, 0.0));   // Left
    mobDcA->SetPosition(Vector(10.0, 5.0, 0.0));       // Center (apex)
    mobDrB->SetPosition(Vector(15.0, 15.0, 0.0));      // Right
    
    // ============================================================
    // STEP 8: SCHEDULE LINK FAILURE EVENTS
    // ============================================================
    
    cout << "═══════════════════════════════════════════════════════════\n";
    cout << "          FAILURE SIMULATION SCHEDULE                      \n";
    cout << "═══════════════════════════════════════════════════════════\n";
    cout << "  T=0s   : Simulation starts (normal operation)            \n";
    cout << "  T=2s   : Client begins sending packets                   \n";
    cout << "  T=5s   : PRIMARY LINK FAILURE (Network 2 DOWN)           \n";
    cout << "  T=15s  : PRIMARY LINK RECOVERY (Network 2 UP)            \n";
    cout << "  T=25s  : Simulation ends                                 \n";
    cout << "═══════════════════════════════════════════════════════════\n\n";
    
    // Schedule link failure at T=5 seconds
    Simulator::Schedule(Seconds(5.0), &SimulatePrimaryLinkFailure);
    
    // Schedule link recovery at T=15 seconds
    Simulator::Schedule(Seconds(15.0), &SimulatePrimaryLinkRecovery);
    
    // ============================================================
    // STEP 9: NETANIM CONFIGURATION
    // ============================================================
    
    string animFile = g_useOSPF ? "regionalbank-ospf.xml" : "regionalbank-static.xml";
    AnimationInterface anim(animFile);
    
    anim.UpdateNodeDescription(branchC, "Branch-C\n(Client)\n10.1.1.1");
    anim.UpdateNodeDescription(dcA, "DC-A\n(Router)\n10.1.1.2|10.1.2.1|10.1.3.1");
    anim.UpdateNodeDescription(drB, "DR-B\n(DR Server)\n10.1.2.2|10.1.3.2");
    
    anim.UpdateNodeColor(branchC, 0, 255, 0);     // Green - Client
    anim.UpdateNodeColor(dcA, 255, 165, 0);       // Orange - Router
    anim.UpdateNodeColor(drB, 0, 100, 255);       // Blue - Server
    
    anim.UpdateNodeSize(branchC->GetId(), 5, 5);
    anim.UpdateNodeSize(dcA->GetId(), 7, 7);
    anim.UpdateNodeSize(drB->GetId(), 5, 5);
    
    // ============================================================
    // STEP 10: ENABLE PACKET CAPTURE
    // ============================================================
    
    string pcapPrefix = g_useOSPF ? "regionalbank-ospf" : "regionalbank-static";
    p2pNetwork1.EnablePcapAll(pcapPrefix);
    p2pNetwork2.EnablePcapAll(pcapPrefix);
    p2pNetwork3.EnablePcapAll(pcapPrefix);
    
    // ============================================================
    // STEP 11: PRINT INITIAL ROUTING TABLES
    // ============================================================
    
    cout << "\n═══════════════════════════════════════════════════════════\n";
    std::cout << "          INITIAL ROUTING TABLES (T=1s)                    \n";
    std::cout << "═══════════════════════════════════════════════════════════\n";
    string routesFile = g_useOSPF ? "regionalbank-ospf.routes" : "regionalbank-static.routes";
    Ptr<OutputStreamWrapper> routingStream =
        Create<OutputStreamWrapper>(routesFile, std::ios::out);

    if (g_useOSPF)
    {
       Ipv4GlobalRoutingHelper globalHelper;
       globalHelper.PrintRoutingTableAllAt(Seconds(1.0), routingStream);
    }
    else
    {
       Ipv4StaticRoutingHelper staticHelper;
       staticHelper.PrintRoutingTableAllAt(Seconds(1.0), routingStream);
    }

    cout << "Routing tables saved to: " << routesFile << "\n\n";

    // ============================================================
    // STEP 12: RUN SIMULATION
    // ============================================================

    Simulator::Stop(Seconds(26.0));

    cout << "═══════════════════════════════════════════════════════════\n";
    cout << "          STARTING SIMULATION                              \n";
    cout << "═══════════════════════════════════════════════════════════\n\n";

    Simulator::Run();
    Simulator::Destroy();

    // ============================================================
    // STEP 13: PRINT RESULTS AND CONVERGENCE ANALYSIS
    // ============================================================

    cout << "\n\n═══════════════════════════════════════════════════════════\n";
    cout << "          SIMULATION RESULTS                               \n";
    cout << "═══════════════════════════════════════════════════════════\n";
    cout << "  Routing Mode: "
             << (g_useOSPF ? "OSPF (Dynamic)        " : "Static Routing        ")
             << "                   \n";
    cout << "═══════════════════════════════════════════════════════════\n";
    cout << "  CONVERGENCE ANALYSIS:                                    \n";
    cout << "                                                           \n";
    cout << "  Packets sent before failure: " << g_packetsBeforeFailure << "                        \n";
    cout << "  Packets lost during failover: " << g_packetsLostDuringFailover << "                       \n";
    cout << "  Packets received after convergence: " << g_packetsAfterFailure << "                 \n";
    cout << "                                                           \n";

    if (g_convergenceDetected)
    {
       cout << "   Convergence Time: "
                 << std::fixed << std::setprecision(2)
                 << g_convergenceTime.GetMilliSeconds() << " ms                           \n";
    }
    else
    {
       cout << "   NO CONVERGENCE DETECTED                                \n";
       cout << "    (Network did not recover during simulation)            \n";
    }

    cout << "═══════════════════════════════════════════════════════════\n";
    cout << "  OUTPUT FILES:                                            \n";
    cout << "  - Animation: " << animFile << "                           \n";
    cout << "  - Routing tables: " << routesFile << "                    \n";
    cout << "  - PCAP traces: " << pcapPrefix << "-*.pcap                \n";
    cout << "═══════════════════════════════════════════════════════════\n\n";

    // ============================================================
    // STEP 13: COMPREHENSIVE RESULTS ANALYSIS
    // ============================================================

    // Print path verification first
    PrintPathVerificationReport();

    // Print FlowMonitor statistics
    PrintFlowMonitorStats();

    // Print existing convergence analysis
    cout << "\nâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n";
    cout << "          CONVERGENCE SUMMARY                              \n";
    cout << "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n";
    cout << "  Routing Mode: "
             << (g_useOSPF ? "OSPF (Dynamic)        " : "Static Routing        ")
             << "                   \n";
    cout << "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n";

    cout << "  Packets sent before failure: " << g_packetsBeforeFailure << "\n";
    cout << "  Packets lost during failover: " << g_packetsLostDuringFailover << "\n";
    cout << "  Packets received after convergence: " << g_packetsAfterFailure << "\n";
    cout << "\n";

    if (g_convergenceDetected)
    {
       cout << "  âœ Convergence Time: "<< std::fixed << std::setprecision(2) << g_convergenceTime.GetMilliSeconds() << " ms\n";
    }
    else
    {
       cout << "  âœ— NO CONVERGENCE DETECTED\n";
       cout << "    (Network did not recover during simulation)\n";
    }

    cout << "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n";
    cout << "  OUTPUT FILES:                                            \n";
    cout << "  - Animation: " << animFile << "\n";
    cout << "  - Routing tables: " << routesFile << "\n";
    cout << "  - PCAP traces: " << pcapPrefix << "-*.pcap\n";
    cout << "  - FlowMonitor XML: " << (g_useOSPF ? "flowmon-ospf.xml" : "flowmon-static.xml") << "\n";
    cout << "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n\n";

    return 0;

}
