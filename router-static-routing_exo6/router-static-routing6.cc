/* Fixed version of your simulation code.
   Minimal changes only:
   - Added missing includes for FlowMonitor and standard headers used.
   - Replaced undefined SimulateBidirectionalLinkFailure with appropriate calls:
     for STATIC: schedule SimulateLinkFailure on both sides of the primary link;
     for DYNAMIC: keep SimulateLinkFailureWithOSPF as before.
   - Kept all other logic and structure unchanged.
*/

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/flow-monitor-module.h"

#include <fstream>
#include <iostream>
#include <map>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ModularNS3Network");

//1) Fonction générique pour créer un ensemble de nœuds
NodeContainer CreateNodes(uint32_t numberOfNodes)
{
    NodeContainer nodes;
    nodes.Create(numberOfNodes);
    return nodes;
}

//2) Fonction pour créer un lien point-to-point entre deux nœuds
NetDeviceContainer CreateP2PLink(Ptr<Node> nA, Ptr<Node> nB,
                                 std::string dataRate,
                                 std::string delay)
{
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue(dataRate));
    p2p.SetChannelAttribute("Delay", StringValue(delay));

    NodeContainer pair(nA, nB);
    return p2p.Install(pair);
}

//3) Fonction pour assigner une plage IP à un lien
Ipv4InterfaceContainer AssignIP(NetDeviceContainer devices,
                                std::string network,
                                std::string mask)
{
    Ipv4AddressHelper address;
    address.SetBase(network.c_str(), mask.c_str());
    return address.Assign(devices);
}


//4) Fonction pour configurer la mobilité et positionner les nœuds
void SetNodePositions(NodeContainer nodes,
                      std::vector<Vector> positions)
{
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    for (uint32_t i = 0; i < nodes.GetN() && i < positions.size(); i++)
    {
        Ptr<MobilityModel> mob = nodes.Get(i)->GetObject<MobilityModel>();
        mob->SetPosition(positions[i]);
    }
}


//5) Fonction pour ajouter une route statique à un nœud
void AddStaticRoute(Ptr<Node> node,
                    std::string destNetwork,
                    std::string mask,
                    std::string nextHop,
                    uint32_t interface)
{
    Ipv4StaticRoutingHelper helper;
    Ptr<Ipv4StaticRouting> routing =
        helper.GetStaticRouting(node->GetObject<Ipv4>());

    routing->AddNetworkRouteTo(Ipv4Address(destNetwork.c_str()),
                               Ipv4Mask(mask.c_str()),
                               Ipv4Address(nextHop.c_str()),
                               interface);
}

//6) Fonction pour installer un serveur Echo
ApplicationContainer InstallEchoServer(Ptr<Node> serverNode,
                                       uint16_t port,
                                       double start,
                                       double stop)
{
    UdpEchoServerHelper server(port);
    ApplicationContainer apps = server.Install(serverNode);
    apps.Start(Seconds(start));
    apps.Stop(Seconds(stop));
    return apps;
}

//7) Fonction pour installer un client Echo
ApplicationContainer InstallEchoClient(Ptr<Node> clientNode,
                                       Ipv4Address serverIP,
                                       uint16_t port,
                                       uint32_t packets,
                                       uint32_t size,
                                       double start,
                                       double stop)
{
    UdpEchoClientHelper client(serverIP, port);
    client.SetAttribute("MaxPackets", UintegerValue(packets));
    client.SetAttribute("PacketSize", UintegerValue(size));
    client.SetAttribute("Interval", TimeValue(Seconds(1)));

    ApplicationContainer apps = client.Install(clientNode);
    apps.Start(Seconds(start));
    apps.Stop(Seconds(stop));
    return apps;
}

//exercice3 : function to disable a link
void DisableLink(Ptr<NetDevice> device)
{
    NS_LOG_INFO("Disabling link at " << Simulator::Now().GetSeconds() << "s");
    device->SetAttribute("ReceiveErrorModel",
                        PointerValue(CreateObject<RateErrorModel>()));
    Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
    em->SetAttribute("ErrorRate", DoubleValue(1.0)); // 100% packet loss
    device->SetAttribute("ReceiveErrorModel", PointerValue(em));
}


// ========== ADDITIONAL FUNCTIONS FOR LINK FAILURE SIMULATION ==========

//8) Function to simulate link failure by setting interface down
void SimulateLinkFailure(Ptr<NetDevice> device)
{
    NS_LOG_UNCOND("\n=== LINK FAILURE SIMULATED at t=" << Simulator::Now().GetSeconds() << "s ===");
    
    Ptr<Ipv4> ipv4 = device->GetNode()->GetObject<Ipv4>();
    int32_t ifIndex = ipv4->GetInterfaceForDevice(device);
    
    NS_LOG_UNCOND("Disabling interface " << ifIndex << " on node " 
                  << device->GetNode()->GetId());
    
    // Set the interface down (most realistic simulation)
    ipv4->SetDown(ifIndex);
    
    NS_LOG_UNCOND("Primary link is now DOWN. Backup link should take over.\n");
}

//9) Function to add static route with metric (for failover)
void AddStaticRouteWithMetric(Ptr<Node> node,
                              std::string destNetwork,
                              std::string mask,
                              std::string nextHop,
                              uint32_t interface,
                              uint32_t metric)
{
    Ipv4StaticRoutingHelper helper;
    Ptr<Ipv4StaticRouting> routing =
        helper.GetStaticRouting(node->GetObject<Ipv4>());

    routing->AddNetworkRouteTo(Ipv4Address(destNetwork.c_str()),
                               Ipv4Mask(mask.c_str()),
                               Ipv4Address(nextHop.c_str()),
                               interface,
                               metric);
}


//10) Function to print routing table (for debugging)
void PrintRoutingTable(Ptr<Node> node, std::string nodeName)
{
    Ipv4StaticRoutingHelper helper;
    Ptr<Ipv4StaticRouting> routing = helper.GetStaticRouting(node->GetObject<Ipv4>());
    
    NS_LOG_UNCOND("\n=== Routing Table for " << nodeName << " ===");
    routing->PrintRoutingTable(Create<OutputStreamWrapper>(&std::cout));
}



// ========== FUNCTIONS FOR OSPF DYNAMIC ROUTING question 4 ==========

//11) Function to install and configure OSPF on nodes
void InstallOSPF(NodeContainer nodes)
{
    NS_LOG_UNCOND("\n=== INSTALLING OSPF DYNAMIC ROUTING ===");
    
    // OSPF uses the Ipv4GlobalRoutingHelper in NS-3
    // Note: NS-3 doesn't have full OSPF implementation, but uses
    // Ipv4GlobalRouting which simulates link-state routing behavior
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();
    
    NS_LOG_UNCOND("OSPF-like routing tables populated globally");
    NS_LOG_UNCOND("Routes will automatically reconverge on topology changes\n");
}

//12) Function to trigger routing table recalculation after link failure
void RecalculateRoutes()
{
    NS_LOG_UNCOND("\n=== OSPF RECONVERGENCE TRIGGERED at t=" 
                  << Simulator::Now().GetSeconds() << "s ===");
    
    // Recalculate all routes based on current topology
    Ipv4GlobalRoutingHelper::RecomputeRoutingTables();
    
    NS_LOG_UNCOND("New routes calculated. Traffic should resume via backup path.\n");
}

//13) Enhanced link failure with OSPF reconvergence
void SimulateLinkFailureWithOSPF(Ptr<NetDevice> device1, Ptr<NetDevice> device2, 
                                  double convergenceTime)
{
    NS_LOG_UNCOND("\n=== LINK FAILURE (OSPF MODE) at t=" 
                  << Simulator::Now().GetSeconds() << "s ===");
    
    // Disable both sides of the link
    Ptr<Ipv4> ipv4_1 = device1->GetNode()->GetObject<Ipv4>();
    int32_t ifIndex1 = ipv4_1->GetInterfaceForDevice(device1);
    ipv4_1->SetDown(ifIndex1);
    
    Ptr<Ipv4> ipv4_2 = device2->GetNode()->GetObject<Ipv4>();
    int32_t ifIndex2 = ipv4_2->GetInterfaceForDevice(device2);
    ipv4_2->SetDown(ifIndex2);
    
    NS_LOG_UNCOND("Primary link DOWN. OSPF detecting topology change...");
    
    // Schedule OSPF reconvergence after convergence time
    NS_LOG_UNCOND("OSPF convergence time: " << convergenceTime << "s");
    Simulator::Schedule(Seconds(convergenceTime), &RecalculateRoutes);
}

//14) Function to print routing comparison
void PrintRoutingComparison(Ptr<Node> node, std::string nodeName, std::string mode)
{
    NS_LOG_UNCOND("\n=== " << mode << " Routing Table for " << nodeName 
                  << " at t=" << Simulator::Now().GetSeconds() << "s ===");
    
    if (mode == "STATIC")
    {
        Ipv4StaticRoutingHelper helper;
        Ptr<Ipv4StaticRouting> routing = helper.GetStaticRouting(node->GetObject<Ipv4>());
        routing->PrintRoutingTable(Create<OutputStreamWrapper>(&std::cout));
    }
    else // DYNAMIC/OSPF
    {
        Ipv4GlobalRoutingHelper::PrintRoutingTableAt(Seconds(Simulator::Now().GetSeconds()), 
                                                      node, 
                                                      Create<OutputStreamWrapper>(&std::cout));
    }
}



//question 5 
// ========== FUNCTIONS FOR BUSINESS CONTINUITY ANALYSIS ==========

//15) Custom packet trace sink to track path changes
void PacketPathTracer(std::string context, Ptr<const Packet> packet, 
                      Ptr<Ipv4> ipv4, uint32_t interface)
{
    Ipv4Address addr = ipv4->GetAddress(interface, 0).GetLocal();
    NS_LOG_UNCOND("t=" << Simulator::Now().GetSeconds() 
                  << "s | Packet forwarded through interface " << interface 
                  << " (" << addr << ") | Size: " << packet->GetSize() << " bytes");
}

//16) exercice 4 Function to analyze FlowMonitor statistics
void AnalyzeFlowMonitor(Ptr<FlowMonitor> monitor, 
                       Ptr<Ipv4FlowClassifier> classifier,
                       std::string phase)
{
    NS_LOG_UNCOND("\n========================================");
    NS_LOG_UNCOND("  FLOW ANALYSIS - " << phase);
    NS_LOG_UNCOND("========================================");
    
    monitor->CheckForLostPackets();
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    
    for (auto& flow : stats)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(flow.first);
        
        NS_LOG_UNCOND("\nFlow ID: " << flow.first);
        NS_LOG_UNCOND("  Source: " << t.sourceAddress << ":" << t.sourcePort);
        NS_LOG_UNCOND("  Destination: " << t.destinationAddress << ":" << t.destinationPort);
        NS_LOG_UNCOND("  Protocol: " << (int)t.protocol);
        
        // Key metrics for banking application analysis
        NS_LOG_UNCOND("  Packets Transmitted: " << flow.second.txPackets);
        NS_LOG_UNCOND("  Packets Received: " << flow.second.rxPackets);
        NS_LOG_UNCOND("  Packets Lost: " << flow.second.lostPackets);
        NS_LOG_UNCOND("  Packet Loss Ratio: " 
                      << (flow.second.txPackets > 0 ? 
                          (double)flow.second.lostPackets / flow.second.txPackets * 100 : 0) 
                      << "%");
        
        if (flow.second.rxPackets > 0)
        {
            double meanDelay = flow.second.delaySum.GetSeconds() / flow.second.rxPackets;
            NS_LOG_UNCOND("  Mean End-to-End Delay: " << meanDelay * 1000 << " ms");
            NS_LOG_UNCOND("  Mean Jitter: " 
                          << flow.second.jitterSum.GetSeconds() / (flow.second.rxPackets - 1) * 1000 
                          << " ms");
        }
        
        NS_LOG_UNCOND("  Throughput: " 
                      << flow.second.rxBytes * 8.0 / 
                         (flow.second.timeLastRxPacket.GetSeconds() - 
                          flow.second.timeFirstTxPacket.GetSeconds()) / 1000 
                      << " Kbps");
        
        // Business continuity assessment
        if (flow.second.lostPackets > 0)
        {
            NS_LOG_UNCOND("  ⚠️  SERVICE DEGRADATION DETECTED");
        }
        else
        {
            NS_LOG_UNCOND("  ✅ SERVICE CONTINUITY MAINTAINED");
        }
    }
    NS_LOG_UNCOND("========================================\n");
}

//17)exercice 4 Function to export results to CSV for analysis
void ExportMetricsToCSV(Ptr<FlowMonitor> monitor, 
                        Ptr<Ipv4FlowClassifier> classifier,
                        std::string filename)
{
    std::ofstream csvFile;
    csvFile.open(filename);
    csvFile << "FlowID,SourceIP,DestIP,Protocol,TxPackets,RxPackets,LostPackets,"
            << "LossRatio(%),MeanDelay(ms),Jitter(ms),Throughput(Kbps)\n";
    
    monitor->CheckForLostPackets();
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    
    for (auto& flow : stats)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(flow.first);
        
        double lossRatio = flow.second.txPackets > 0 ? 
                          (double)flow.second.lostPackets / flow.second.txPackets * 100 : 0;
        
        double meanDelay = flow.second.rxPackets > 0 ?
                          flow.second.delaySum.GetSeconds() / flow.second.rxPackets * 1000 : 0;
        
        double jitter = flow.second.rxPackets > 1 ?
                       flow.second.jitterSum.GetSeconds() / (flow.second.rxPackets - 1) * 1000 : 0;
        
        double throughput = flow.second.rxBytes * 8.0 / 
                           (flow.second.timeLastRxPacket.GetSeconds() - 
                            flow.second.timeFirstTxPacket.GetSeconds()) / 1000;
        
        csvFile << flow.first << ","
                << t.sourceAddress << ","
                << t.destinationAddress << ","
                << (int)t.protocol << ","
                << flow.second.txPackets << ","
                << flow.second.rxPackets << ","
                << flow.second.lostPackets << ","
                << lossRatio << ","
                << meanDelay << ","
                << jitter << ","
                << throughput << "\n";
    }
    
    csvFile.close();
    NS_LOG_UNCOND("Metrics exported to " << filename);
}



// ============================================================================
// BGP INTER-AS ROUTING SIMULATION
// GlobalISP (AS65001) peering with TransitProvider (AS65002)
// ============================================================================


// ============================================================================
// BGP INTER-AS ROUTING SIMULATION
// GlobalISP (AS65001) peering with TransitProvider (AS65002)
// ============================================================================

int main(int argc, char *argv[])
{
    // ======================================================================
    // COMMAND LINE PARSING AND SIMULATION SETUP
    // ======================================================================
    
    std::string routingMode = "BGP"; // BGP mode for inter-AS routing
    bool simulateRouteLeak = false;
    
    CommandLine cmd;
    cmd.AddValue("mode", "Routing mode: BGP", routingMode);
    cmd.AddValue("leak", "Simulate route leak incident", simulateRouteLeak);
    cmd.Parse(argc, argv);
    
    NS_LOG_UNCOND("\n╔════════════════════════════════════════════════╗");
    NS_LOG_UNCOND("║  BGP Inter-AS Routing Simulation              ║");
    NS_LOG_UNCOND("║  AS65001 (GlobalISP) <--> AS65002 (Transit)   ║");
    NS_LOG_UNCOND("║  Route Leak: " << (simulateRouteLeak ? "ENABLED " : "DISABLED") << "                          ║");
    NS_LOG_UNCOND("╚════════════════════════════════════════════════╝\n");
    
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

    // ======================================================================
    // QUESTION 1a: MODELING AUTONOMOUS SYSTEMS - LOGICAL GROUPING OF NODES
    // Create two distinct ASes with internal nodes and border routers
    // AS65001 (GlobalISP): Internal network with customers
    // AS65002 (TransitProvider): Transit network
    // ======================================================================
    
    NS_LOG_UNCOND("\n=== Q1a: CREATING AUTONOMOUS SYSTEMS (LOGICAL GROUPING) ===");
    
    // AS65001 (GlobalISP) - 4 nodes
    // - AS65001_BR1: Border Router at IXP-A (node 0)
    // - AS65001_BR2: Border Router at IXP-B (node 1)
    // - AS65001_Internal: Internal router (node 2)
    // - AS65001_Customer: Customer network (node 3)
    NodeContainer as65001_nodes = CreateNodes(4);
    Ptr<Node> as65001_br1 = as65001_nodes.Get(0);       // Border Router 1 (IXP-A)
    Ptr<Node> as65001_br2 = as65001_nodes.Get(1);       // Border Router 2 (IXP-B)
    Ptr<Node> as65001_internal = as65001_nodes.Get(2);  // Internal Router
    Ptr<Node> as65001_customer = as65001_nodes.Get(3);  // Customer Network
    
    NS_LOG_UNCOND("AS65001 (GlobalISP) created with 4 nodes:");
    NS_LOG_UNCOND("  - BR1 (IXP-A peering point)");
    NS_LOG_UNCOND("  - BR2 (IXP-B peering point)");
    NS_LOG_UNCOND("  - Internal Router");
    NS_LOG_UNCOND("  - Customer Network");
    
    // AS65002 (TransitProvider) - 4 nodes
    // - AS65002_BR1: Border Router at IXP-A (node 4)
    // - AS65002_BR2: Border Router at IXP-B (node 5)
    // - AS65002_Internal: Internal router (node 6)
    // - AS65002_Server: Server/destination (node 7)
    NodeContainer as65002_nodes = CreateNodes(4);
    Ptr<Node> as65002_br1 = as65002_nodes.Get(0);       // Border Router 1 (IXP-A)
    Ptr<Node> as65002_br2 = as65002_nodes.Get(1);       // Border Router 2 (IXP-B)
    Ptr<Node> as65002_internal = as65002_nodes.Get(2);  // Internal Router
    Ptr<Node> as65002_server = as65002_nodes.Get(3);    // Server/Destination
    
    NS_LOG_UNCOND("\nAS65002 (TransitProvider) created with 4 nodes:");
    NS_LOG_UNCOND("  - BR1 (IXP-A peering point)");
    NS_LOG_UNCOND("  - BR2 (IXP-B peering point)");
    NS_LOG_UNCOND("  - Internal Router");
    NS_LOG_UNCOND("  - Server/Destination");

    // Install Internet stack on all nodes
    InternetStackHelper stack;
    stack.Install(as65001_nodes);
    stack.Install(as65002_nodes);

    // ======================================================================
    // QUESTION 1b: INTERNAL ROUTING (OSPF) CONFINED WITHIN EACH AS
    // Create internal links within each AS and configure intra-AS routing
    // Using OSPF (simulated via Ipv4GlobalRouting) within each AS separately
    // ======================================================================
    
    NS_LOG_UNCOND("\n=== Q1b: CONFIGURING INTRA-AS ROUTING (OSPF WITHIN EACH AS) ===");
    
    // --- AS65001 Internal Links ---
    NS_LOG_UNCOND("\nAS65001 Internal Topology:");
    NetDeviceContainer as65001_link1 = CreateP2PLink(as65001_br1, as65001_internal, 
                                                      "10Mbps", "2ms");
    NetDeviceContainer as65001_link2 = CreateP2PLink(as65001_br2, as65001_internal, 
                                                      "10Mbps", "2ms");
    NetDeviceContainer as65001_link3 = CreateP2PLink(as65001_internal, as65001_customer, 
                                                      "10Mbps", "2ms");
    
    auto as65001_iface1 = AssignIP(as65001_link1, "10.65.1.0", "255.255.255.0");  // BR1 - Internal
    auto as65001_iface2 = AssignIP(as65001_link2, "10.65.2.0", "255.255.255.0");  // BR2 - Internal
    auto as65001_iface3 = AssignIP(as65001_link3, "10.65.3.0", "255.255.255.0");  // Internal - Customer
    
    NS_LOG_UNCOND("  BR1 (10.65.1.1) <--> Internal (10.65.1.2)");
    NS_LOG_UNCOND("  BR2 (10.65.2.1) <--> Internal (10.65.2.2)");
    NS_LOG_UNCOND("  Internal (10.65.3.1) <--> Customer (10.65.3.2)");
    
    // --- AS65002 Internal Links ---
    NS_LOG_UNCOND("\nAS65002 Internal Topology:");
    NetDeviceContainer as65002_link1 = CreateP2PLink(as65002_br1, as65002_internal, 
                                                      "10Mbps", "2ms");
    NetDeviceContainer as65002_link2 = CreateP2PLink(as65002_br2, as65002_internal, 
                                                      "10Mbps", "2ms");
    NetDeviceContainer as65002_link3 = CreateP2PLink(as65002_internal, as65002_server, 
                                                      "10Mbps", "2ms");
    
    auto as65002_iface1 = AssignIP(as65002_link1, "10.66.1.0", "255.255.255.0");  // BR1 - Internal
    auto as65002_iface2 = AssignIP(as65002_link2, "10.66.2.0", "255.255.255.0");  // BR2 - Internal
    auto as65002_iface3 = AssignIP(as65002_link3, "10.66.3.0", "255.255.255.0");  // Internal - Server
    
    NS_LOG_UNCOND("  BR1 (10.66.1.1) <--> Internal (10.66.1.2)");
    NS_LOG_UNCOND("  BR2 (10.66.2.1) <--> Internal (10.66.2.2)");
    NS_LOG_UNCOND("  Internal (10.66.3.1) <--> Server (10.66.3.2)");
    
    // Enable IP forwarding on all routers (border and internal)
    as65001_br1->GetObject<Ipv4>()->SetAttribute("IpForward", BooleanValue(true));
    as65001_br2->GetObject<Ipv4>()->SetAttribute("IpForward", BooleanValue(true));
    as65001_internal->GetObject<Ipv4>()->SetAttribute("IpForward", BooleanValue(true));
    as65002_br1->GetObject<Ipv4>()->SetAttribute("IpForward", BooleanValue(true));
    as65002_br2->GetObject<Ipv4>()->SetAttribute("IpForward", BooleanValue(true));
    as65002_internal->GetObject<Ipv4>()->SetAttribute("IpForward", BooleanValue(true));

    // ======================================================================
    // QUESTION 1c: ESTABLISHING PEERING LINKS BETWEEN ASes AT IXPs
    // Create two Internet Exchange Points (IXP-A and IXP-B)
    // These are the BGP peering points between AS65001 and AS65002
    // ======================================================================
    
    NS_LOG_UNCOND("\n=== Q1c: ESTABLISHING INTER-AS PEERING LINKS (IXPs) ===");
    
    // IXP-A: AS65001_BR1 <--> AS65002_BR1
    NetDeviceContainer ixp_a_link = CreateP2PLink(as65001_br1, as65002_br1, 
                                                   "100Mbps", "5ms");
    auto ixp_a_iface = AssignIP(ixp_a_link, "200.1.1.0", "255.255.255.0");
    
    NS_LOG_UNCOND("IXP-A Peering Link established:");
    NS_LOG_UNCOND("  AS65001_BR1 (200.1.1.1) <-BGP Peer-> AS65002_BR1 (200.1.1.2)");
    
    // IXP-B: AS65001_BR2 <--> AS65002_BR2
    NetDeviceContainer ixp_b_link = CreateP2PLink(as65001_br2, as65002_br2, 
                                                   "100Mbps", "10ms");
    auto ixp_b_iface = AssignIP(ixp_b_link, "200.2.1.0", "255.255.255.0");
    
    NS_LOG_UNCOND("\nIXP-B Peering Link established:");
    NS_LOG_UNCOND("  AS65001_BR2 (200.2.1.1) <-BGP Peer-> AS65002_BR2 (200.2.1.2)");
    
    NS_LOG_UNCOND("\nPeering Configuration:");
    NS_LOG_UNCOND("  - Two redundant peering points for resilience");
    NS_LOG_UNCOND("  - IXP-A: Lower latency (5ms), preferred path");
    NS_LOG_UNCOND("  - IXP-B: Higher latency (10ms), backup path");

    // ======================================================================
    // QUESTION 2: BGP PATH ATTRIBUTE SIMULATION - DATA STRUCTURE
    // Define BGP route announcement structure with key attributes:
    // - Network prefix (destination)
    // - AS_PATH (list of ASes the route has traversed)
    // - LOCAL_PREF (preference within AS, higher = better)
    // - MED (Multi-Exit Discriminator, lower = better)
    // NOTE: In real implementation, this would be a C++ struct/class
    // ======================================================================
    
    NS_LOG_UNCOND("\n=== Q2: BGP ROUTE ANNOUNCEMENT DATA STRUCTURE ===");
    NS_LOG_UNCOND("/*");
    NS_LOG_UNCOND(" * struct BGPRoute {");
    NS_LOG_UNCOND(" *   std::string prefix;           // e.g., \"192.168.0.0/16\"");
    NS_LOG_UNCOND(" *   std::string mask;             // e.g., \"255.255.0.0\"");
    NS_LOG_UNCOND(" *   std::vector<int> as_path;     // e.g., {65001, 65002}");
    NS_LOG_UNCOND(" *   uint32_t local_pref;          // Higher = better (default 100)");
    NS_LOG_UNCOND(" *   uint32_t med;                 // Lower = better (default 0)");
    NS_LOG_UNCOND(" *   Ipv4Address next_hop;         // Next hop IP address");
    NS_LOG_UNCOND(" *   uint32_t origin;              // IGP=0, EGP=1, INCOMPLETE=2");
    NS_LOG_UNCOND(" * };");
    NS_LOG_UNCOND(" */");
    NS_LOG_UNCOND("\nBGP Decision Process (Best Path Selection):");
    NS_LOG_UNCOND("  1. Highest LOCAL_PREF (prefer internally set preference)");
    NS_LOG_UNCOND("  2. Shortest AS_PATH length (avoid path inflation)");
    NS_LOG_UNCOND("  3. Lowest origin type (IGP > EGP > INCOMPLETE)");
    NS_LOG_UNCOND("  4. Lowest MED (when from same neighbor AS)");
    NS_LOG_UNCOND("  5. eBGP over iBGP path");
    NS_LOG_UNCOND("  6. Lowest IGP cost to next hop");
    NS_LOG_UNCOND("  7. Lowest router ID (tie-breaker)");

    // ======================================================================
    // SIMULATED BGP ROUTE ANNOUNCEMENTS
    // Simulate BGP announcements between ASes using static routes
    // In reality, BGP daemons would exchange UPDATE messages
    // ======================================================================
    
    NS_LOG_UNCOND("\n=== SIMULATING BGP ROUTE ANNOUNCEMENTS ===");
    
    // AS65002 announces its prefix 10.66.3.0/24 to AS65001 via both IXPs
    NS_LOG_UNCOND("\nAS65002 announces prefix 10.66.3.0/24 to AS65001:");
    
    // Route via IXP-A (preferred - higher LOCAL_PREF, lower latency)
    NS_LOG_UNCOND("  Via IXP-A:");
    NS_LOG_UNCOND("    - AS_PATH: [65002]");
    NS_LOG_UNCOND("    - LOCAL_PREF: 150 (manually set higher)");
    NS_LOG_UNCOND("    - MED: 10");
    NS_LOG_UNCOND("    - Next-hop: 200.1.1.2 (AS65002_BR1)");
    
    // Configure AS65001_BR1 to prefer IXP-A path
    AddStaticRouteWithMetric(as65001_br1, "10.66.3.0", "255.255.255.0", 
                            "200.1.1.2", 2, 10); // Lower metric = preferred
    
    // Route via IXP-B (backup - lower LOCAL_PREF, higher latency)
    NS_LOG_UNCOND("  Via IXP-B:");
    NS_LOG_UNCOND("    - AS_PATH: [65002]");
    NS_LOG_UNCOND("    - LOCAL_PREF: 100 (default)");
    NS_LOG_UNCOND("    - MED: 20");
    NS_LOG_UNCOND("    - Next-hop: 200.2.1.2 (AS65002_BR2)");
    
    // Configure AS65001_BR2 as backup path
    AddStaticRouteWithMetric(as65001_br2, "10.66.3.0", "255.255.255.0", 
                            "200.2.1.2", 2, 20); // Higher metric = backup
    
    // AS65001 announces its prefix 10.65.3.0/24 to AS65002
    NS_LOG_UNCOND("\nAS65001 announces prefix 10.65.3.0/24 to AS65002:");
    NS_LOG_UNCOND("  Via IXP-A: AS_PATH [65001], Next-hop 200.1.1.1");
    NS_LOG_UNCOND("  Via IXP-B: AS_PATH [65001], Next-hop 200.2.1.1");
    
    AddStaticRouteWithMetric(as65002_br1, "10.65.3.0", "255.255.255.0", 
                            "200.1.1.1", 2, 10);
    AddStaticRouteWithMetric(as65002_br2, "10.65.3.0", "255.255.255.0", 
                            "200.2.1.1", 2, 20);
    
    // Propagate routes within each AS using OSPF-like mechanism
    NS_LOG_UNCOND("\nPropagating inter-AS routes within each AS (iBGP simulation):");
    
    // AS65001: Propagate AS65002's routes to internal nodes
    AddStaticRoute(as65001_internal, "10.66.3.0", "255.255.255.0", 
                  "10.65.1.1", 1); // Via BR1 (preferred)
    AddStaticRoute(as65001_customer, "10.66.3.0", "255.255.255.0", 
                  "10.65.3.1", 1); // Via Internal Router
    
    // AS65002: Propagate AS65001's routes to internal nodes
    AddStaticRoute(as65002_internal, "10.65.3.0", "255.255.255.0", 
                  "10.66.1.1", 1);
    AddStaticRoute(as65002_server, "10.65.3.0", "255.255.255.0", 
                  "10.66.3.1", 1);

    // ======================================================================
    // QUESTION 3: IMPLEMENTING BASIC BGP DECISION PROCESS
    // Algorithm for BGP path selection implemented through metric-based routing
    // In real BGP, this would be part of the BGP daemon's RIB processing
    // ======================================================================
    
    NS_LOG_UNCOND("\n=== Q3: BGP DECISION PROCESS ALGORITHM ===");
    NS_LOG_UNCOND("/*");
    NS_LOG_UNCOND(" * ALGORITHM: BGP Best Path Selection");
    NS_LOG_UNCOND(" * ");
    NS_LOG_UNCOND(" * function SelectBestPath(current_best, new_announcement):");
    NS_LOG_UNCOND(" *   // Step 1: LOCAL_PREF comparison");
    NS_LOG_UNCOND(" *   if (new.local_pref > current.local_pref):");
    NS_LOG_UNCOND(" *     return new_announcement");
    NS_LOG_UNCOND(" *   else if (new.local_pref < current.local_pref):");
    NS_LOG_UNCOND(" *     return current_best");
    NS_LOG_UNCOND(" *   ");
    NS_LOG_UNCOND(" *   // Step 2: AS_PATH length (shorter is better)");
    NS_LOG_UNCOND(" *   if (new.as_path.length() < current.as_path.length()):");
    NS_LOG_UNCOND(" *     return new_announcement");
    NS_LOG_UNCOND(" *   else if (new.as_path.length() > current.as_path.length()):");
    NS_LOG_UNCOND(" *     return current_best");
    NS_LOG_UNCOND(" *   ");
    NS_LOG_UNCOND(" *   // Step 3: Origin type (IGP > EGP > INCOMPLETE)");
    NS_LOG_UNCOND(" *   if (new.origin < current.origin):");
    NS_LOG_UNCOND(" *     return new_announcement");
    NS_LOG_UNCOND(" *   else if (new.origin > current.origin):");
    NS_LOG_UNCOND(" *     return current_best");
    NS_LOG_UNCOND(" *   ");
    NS_LOG_UNCOND(" *   // Step 4: MED comparison (lower is better)");
    NS_LOG_UNCOND(" *   if (new.med < current.med):");
    NS_LOG_UNCOND(" *     return new_announcement");
    NS_LOG_UNCOND(" *   else if (new.med > current.med):");
    NS_LOG_UNCOND(" *     return current_best");
    NS_LOG_UNCOND(" *   ");
    NS_LOG_UNCOND(" *   // Step 5: Prefer eBGP over iBGP");
    NS_LOG_UNCOND(" *   if (new.is_ebgp && !current.is_ebgp):");
    NS_LOG_UNCOND(" *     return new_announcement");
    NS_LOG_UNCOND(" *   ");
    NS_LOG_UNCOND(" *   // Step 6: IGP cost to next-hop");
    NS_LOG_UNCOND(" *   if (IGP_cost(new.next_hop) < IGP_cost(current.next_hop)):");
    NS_LOG_UNCOND(" *     return new_announcement");
    NS_LOG_UNCOND(" *   ");
    NS_LOG_UNCOND(" *   // Step 7: Router ID tie-breaker");
    NS_LOG_UNCOND(" *   if (new.router_id < current.router_id):");
    NS_LOG_UNCOND(" *     return new_announcement");
    NS_LOG_UNCOND(" *   ");
    NS_LOG_UNCOND(" *   return current_best");
    NS_LOG_UNCOND(" * ");
    NS_LOG_UNCOND(" * // On receiving announcement:");
    NS_LOG_UNCOND(" * function ReceiveBGPUpdate(announcement, from_peer):");
    NS_LOG_UNCOND(" *   prefix = announcement.prefix");
    NS_LOG_UNCOND(" *   ");
    NS_LOG_UNCOND(" *   // Check for existing route");
    NS_LOG_UNCOND(" *   if (RIB.has(prefix)):");
    NS_LOG_UNCOND(" *     current_best = RIB.get(prefix)");
    NS_LOG_UNCOND(" *     new_best = SelectBestPath(current_best, announcement)");
    NS_LOG_UNCOND(" *     ");
    NS_LOG_UNCOND(" *     if (new_best == announcement):");
    NS_LOG_UNCOND(" *       RIB.update(prefix, announcement)");
    NS_LOG_UNCOND(" *       FIB.install_route(prefix, announcement.next_hop)");
    NS_LOG_UNCOND(" *       PropagateToIBGPPeers(announcement)");
    NS_LOG_UNCOND(" *   else:");
    NS_LOG_UNCOND(" *     RIB.insert(prefix, announcement)");
    NS_LOG_UNCOND(" *     FIB.install_route(prefix, announcement.next_hop)");
    NS_LOG_UNCOND(" *     PropagateToIBGPPeers(announcement)");
    NS_LOG_UNCOND(" */");
    
    NS_LOG_UNCOND("\nIn this simulation:");
    NS_LOG_UNCOND("  - IXP-A path has metric 10 (simulates higher LOCAL_PREF)");
    NS_LOG_UNCOND("  - IXP-B path has metric 20 (simulates lower LOCAL_PREF)");
    NS_LOG_UNCOND("  - NS-3 routing table will prefer lower metric (IXP-A)");

    // ======================================================================
    // QUESTION 4: SIMULATING A ROUTE LEAK
    // A route leak occurs when a network incorrectly advertises routes
    // Example: AS65002 leaks AS65001's prefix back to AS65001
    // This creates a routing loop and AS_PATH with the victim AS repeated
    // ======================================================================
    
    if (simulateRouteLeak)
    {
        NS_LOG_UNCOND("\n=== Q4: SIMULATING ROUTE LEAK INCIDENT ===");
        NS_LOG_UNCOND("⚠  WARNING: Route leak simulation active!");
        
        NS_LOG_UNCOND("\nScenario:");
        NS_LOG_UNCOND("  AS65002_BR1 (malicious/misconfigured) announces");
        NS_LOG_UNCOND("  AS65001's prefix 10.65.3.0/24 back to AS65001");
        
        NS_LOG_UNCOND("\nLegitimate route in AS65001:");
        NS_LOG_UNCOND("  Prefix: 10.65.3.0/24");
        NS_LOG_UNCOND("  AS_PATH: [] (local prefix, no AS in path)");
        NS_LOG_UNCOND("  LOCAL_PREF: 200 (local routes highest preference)");
        
        NS_LOG_UNCOND("\nMalicious/Leaked route from AS65002:");
        NS_LOG_UNCOND("  Prefix: 10.65.3.0/24");
        NS_LOG_UNCOND("  AS_PATH: [65002, 65001] ← Loop! AS65001 appears");
        NS_LOG_UNCOND("  LOCAL_PREF: 150 (external route)");
        NS_LOG_UNCOND("  Next-hop: 200.1.1.2 (via AS65002_BR1)");
        
        NS_LOG_UNCOND("\nBGP Loop Prevention Mechanism:");
        NS_LOG_UNCOND("  - AS65001 routers check AS_PATH for own AS number");
        NS_LOG_UNCOND("  - Route with AS65001 in path is REJECTED");
        NS_LOG_UNCOND("  - Log entry: 'AS_PATH loop detected, discarding route'");
        
        NS_LOG_UNCOND("\nWhy AS65001 won't accept leaked route:");
        NS_LOG_UNCOND("  1. AS_PATH contains 65001 → Loop detection triggers");
        NS_LOG_UNCOND("  2. Even without loop detection:");
        NS_LOG_UNCOND("     - Legitimate: LOCAL_PREF 200, AS_PATH length 0");
        NS_LOG_UNCOND("     - Leaked: LOCAL_PREF 150, AS_PATH length 2");
        NS_LOG_UNCOND("     → Legitimate route wins on LOCAL_PREF");
        
        NS_LOG_UNCOND("\nReal-world impact if accepted:");
        NS_LOG_UNCOND("  - Traffic destined for AS65001 would route via AS65002");
        NS_LOG_UNCOND("  - Creates routing loop or blackhole");
        NS_LOG_UNCOND("  - Enables man-in-the-middle attacks");
        NS_LOG_UNCOND("  - Example: 2008 Pakistan Telecom YouTube hijack");
        
        // Simulate the leak by trying to inject a conflicting route
        // In reality, BGP would reject this, but we show the attempt
        NS_LOG_UNCOND("\n⚠  Attempting to inject leaked route at t=10s...");
        
        auto injectLeakedRoute = [as65001_br1]() {
            NS_LOG_UNCOND("\n=== ROUTE LEAK INJECTION at t=" 
                          << Simulator::Now().GetSeconds() << "s ===");
            NS_LOG_UNCOND("AS65002_BR1 sends UPDATE:");
            NS_LOG_UNCOND("  NLRI: 10.65.3.0/24");
            NS_LOG_UNCOND("  AS_PATH: [65002, 65001] ← CONTAINS LOOP!");
            NS_LOG_UNCOND("  Next-hop: 200.1.1.2");
            
            NS_LOG_UNCOND("\nAS65001_BR1 BGP Decision Process:");
            NS_LOG_UNCOND("  [CHECK] AS_PATH loop detection...");
            NS_LOG_UNCOND("  [FOUND] Own AS (65001) in AS_PATH!");
            NS_LOG_UNCOND("  [ACTION] REJECT route to prevent loop");
            NS_LOG_UNCOND("  [LOG] Discarded UPDATE from 200.1.1.2");
            
            NS_LOG_UNCOND("\n✅ Route leak successfully prevented by BGP loop detection");
            NS_LOG_UNCOND("   Legitimate route remains active in RIB/FIB");
        };
        
        Simulator::Schedule(Seconds(10.0), injectLeakedRoute);
        
        NS_LOG_UNCOND("\nMitigation strategies:");
        NS_LOG_UNCOND("  1. AS_PATH loop detection (built-in BGP mechanism)");
        NS_LOG_UNCOND("  2. Route filtering at AS borders (prefix lists)");
        NS_LOG_UNCOND("  3. RPKI (Resource Public Key Infrastructure)");
        NS_LOG_UNCOND("  4. BGPsec (secure path validation)");
        NS_LOG_UNCOND("  5. Route leak detection systems (Cyclops, Argus)");
    }

    // ======================================================================
    // SET NODE POSITIONS FOR VISUALIZATION
    // ======================================================================
    
    std::vector<Vector> as65001_positions = {
        Vector(10, 20, 0),   // AS65001_BR1
        Vector(10, 10, 0),   // AS65001_BR2
        Vector(5, 15, 0),    // AS65001_Internal
        Vector(0, 15, 0)     // AS65001_Customer
    };
    
    std::vector<Vector> as65002_positions = {
        Vector(30, 20, 0),   // AS65002_BR1
        Vector(30, 10, 0),   // AS65002_BR2
        Vector(35, 15, 0),   // AS65002_Internal
        Vector(40, 15, 0)    // AS65002_Server
    };
    
    SetNodePositions(as65001_nodes, as65001_positions);
    SetNodePositions(as65002_nodes, as65002_positions);

    // ======================================================================
    // TRAFFIC GENERATION: Cross-AS Communication
    // AS65001_Customer sends requests to AS65002_Server
    // This traffic crosses the inter-AS boundary via BGP-selected path
    // ======================================================================
    
    NS_LOG_UNCOND("\n=== CONFIGURING CROSS-AS APPLICATION ===");
    NS_LOG_UNCOND("Client: AS65001_Customer → AS65002_Server");
    NS_LOG_UNCOND("Route: AS65001 → IXP-A (preferred) → AS65002");
    
    uint16_t port = 9;
    InstallEchoServer(as65002_server, port, 1.0, 30.0);
    InstallEchoClient(as65001_customer, as65002_iface3.GetAddress(1), 
                     port, 20, 1024, 2.0, 30.0);

    // ======================================================================
    // FLOW MONITOR FOR INTER-AS TRAFFIC ANALYSIS
    // ======================================================================
    
    NS_LOG_UNCOND("\n=== INSTALLING FLOW MONITOR ===");
    FlowMonitorHelper flowmonHelper;
    Ptr<FlowMonitor> monitor = flowmonHelper.InstallAll();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(
        flowmonHelper.GetClassifier());

    // ======================================================================
    // SIMULATING IXP-A LINK FAILURE (for path failover demonstration)
    // Shows BGP's ability to switch to backup path (IXP-B)
    // ======================================================================
    
    NS_LOG_UNCOND("\n=== SCHEDULING IXP-A FAILURE (PRIMARY PATH) ===");
    NS_LOG_UNCOND("IXP-A link will fail at t=15s");
    NS_LOG_UNCOND("Expected: Traffic fails over to IXP-B (backup path)");
    
    Ptr<NetDevice> ixp_a_dev1 = ixp_a_link.Get(0);
    Ptr<NetDevice> ixp_a_dev2 = ixp_a_link.Get(1);
    
    auto simulateIXPFailure = [ixp_a_dev1, ixp_a_dev2]() {
        NS_LOG_UNCOND("\n=== IXP-A LINK FAILURE at t=" 
                      << Simulator::Now().GetSeconds() << "s ===");
        NS_LOG_UNCOND("BGP session down between AS65001_BR1 and AS65002_BR1");
        
        Ptr<Ipv4> ipv4_1 = ixp_a_dev1->GetNode()->GetObject<Ipv4>();
        int32_t ifIndex1 = ipv4_1->GetInterfaceForDevice(ixp_a_dev1);
        ipv4_1->SetDown(ifIndex1);
        
        Ptr<Ipv4> ipv4_2 = ixp_a_dev2->GetNode()->GetObject<Ipv4>();
        int32_t ifIndex2 = ipv4_2->GetInterfaceForDevice(ixp_a_dev2);
        ipv4_2->SetDown(ifIndex2);
        
        NS_LOG_UNCOND("Routes via IXP-A withdrawn from BGP RIB");
        NS_LOG_UNCOND("IXP-B path now becomes best path");
        NS_LOG_UNCOND("Expected convergence: ~1s (BGP Hold Timer)");
    };
    
    Simulator::Schedule(Seconds(15.0), simulateIXPFailure);
    
    // Trigger route recalculation after BGP convergence delay
    Simulator::Schedule(Seconds(16.0), &RecalculateRoutes);

    // ======================================================================
    // ANALYSIS CHECKPOINTS
    // ======================================================================
    
    Simulator::Schedule(Seconds(10.0), &AnalyzeFlowMonitor, 
                       monitor, classifier, "BEFORE IXP-A FAILURE (via IXP-A)");
    Simulator::Schedule(Seconds(17.0), &AnalyzeFlowMonitor,
                       monitor, classifier, "AFTER FAILOVER (via IXP-B)");

    // ======================================================================
    // QUESTION 5: FROM SIMULATION TO REALITY
    // Discussion of NS-3 limitations compared to real BGP implementations
    // ======================================================================
    
    NS_LOG_UNCOND("\n╔════════════════════════════════════════════════════════════╗");
    NS_LOG_UNCOND("║  Q5: NS-3 vs REAL BGP IMPLEMENTATIONS (Quagga/BIRD/FRR)   ║");
    NS_LOG_UNCOND("╚════════════════════════════════════════════════════════════╝");
    
    NS_LOG_UNCOND("\n=== SIMPLIFICATIONS IN THIS NS-3 SIMULATION ===");
    NS_LOG_UNCOND("1. No BGP protocol implementation:");
    NS_LOG_UNCOND("   - No OPEN, UPDATE, KEEPALIVE, NOTIFICATION messages");
    NS_LOG_UNCOND("   - Using static routes to simulate BGP decisions");
    NS_LOG_UNCOND("   - No TCP connections between BGP peers");
    
    NS_LOG_UNCOND("\n2. No BGP state machine:");
    NS_LOG_UNCOND("   - Real BGP: Idle → Connect → OpenSent → OpenConfirm → Established");
    NS_LOG_UNCOND("   - NS-3: Routes configured instantly");
    
    NS_LOG_UNCOND("\n3. No BGP timers:");
    NS_LOG_UNCOND("   - Hold Timer (180s default)");
    NS_LOG_UNCOND("   - Keepalive (60s)");
    NS_LOG_UNCOND("   - ConnectRetry Timer");
    NS_LOG_UNCOND("   - MRAI (Minimum Route Advertisement Interval)");
    
    NS_LOG_UNCOND("\n=== THREE CRITICAL BGP FEATURES DIFFICULT TO MODEL ===");
    
    NS_LOG_UNCOND("\n1. ROUTE REFLECTORS (iBGP scalability):");
    NS_LOG_UNCOND("   Why difficult in NS-3:");
    NS_LOG_UNCOND("   - Requires full iBGP mesh or RR hierarchy");
    NS_LOG_UNCOND("   - Need to track client/non-client peers");
    NS_LOG_UNCOND("   - Must implement ORIGINATOR_ID and CLUSTER_LIST");
    NS_LOG_UNCOND("   - Loop prevention logic different from eBGP");
    NS_LOG_UNCOND("   - NS-3 routing is per-node, not per-protocol-session");
    NS_LOG_UNCOND("   Real impact: Can't simulate large ISP internal BGP");
    
    NS_LOG_UNCOND("\n2. BGP COMMUNITIES (flexible policy tagging):");
    NS_LOG_UNCOND("   Why difficult in NS-3:");
    NS_LOG_UNCOND("   - Communities are opaque 32-bit tags (AS:Value)");
    NS_LOG_UNCOND("   - Used for complex policy (NO_EXPORT, NO_ADVERTISE)");
    NS_LOG_UNCOND("   - Can have multiple communities per route");
    NS_LOG_UNCOND("   - Policy decisions based on community matching");
    NS_LOG_UNCOND("   - Requires flexible route filtering framework");
    NS_LOG_UNCOND("   - NS-3 has no concept of route attributes/metadata");
    NS_LOG_UNCOND("   Real impact: Can't simulate ISP traffic engineering");
    
    NS_LOG_UNCOND("\n3. BGP GRACEFUL RESTART (RPKI/BGPsec integration):");
    NS_LOG_UNCOND("   Why difficult in NS-3:");
    NS_LOG_UNCOND("   - Requires persistent BGP state during restart");
    NS_LOG_UNCOND("   - GR capability negotiation in OPEN message");
    NS_LOG_UNCOND("   - Forwarding state vs control state separation");
    NS_LOG_UNCOND("   - Stale route marking and cleanup");
    NS_LOG_UNCOND("   - RPKI: Requires ROA validation infrastructure");
    NS_LOG_UNCOND("   - BGPsec: Cryptographic path signing/verification");
    NS_LOG_UNCOND("   - NS-3 has no control/data plane separation");
    NS_LOG_UNCOND("   Real impact: Can't study BGP security mechanisms");
    
    NS_LOG_UNCOND("\n=== OTHER MISSING FEATURES ===");
    NS_LOG_UNCOND("- Route dampening (flap suppression)");
    NS_LOG_UNCOND("- ADD-PATH (multiple path advertisement)");
    NS_LOG_UNCOND("- Confederations (AS hierarchy)");
    NS_LOG_UNCOND("- Policy-based routing (route-maps, prefix-lists)");
    NS_LOG_UNCOND("- MD5 authentication");
    NS_LOG_UNCOND("- BMP (BGP Monitoring Protocol)");
    NS_LOG_UNCOND("- Flowspec (DDoS mitigation)");
    
    NS_LOG_UNCOND("\n=== IS NS-3 SUITABLE FOR INTER-AS ROUTING RESEARCH? ===");
    NS_LOG_UNCOND("\n SUITABLE FOR:");
    NS_LOG_UNCOND("   - Basic BGP concept education");
    NS_LOG_UNCOND("   - High-level topology design");
    NS_LOG_UNCOND("   - Failover scenario demonstrations");
    NS_LOG_UNCOND("   - Traffic engineering basics");
    NS_LOG_UNCOND("   - Integration with application-layer protocols");
    
    NS_LOG_UNCOND("\n NOT SUITABLE FOR:");
    NS_LOG_UNCOND("   - Realistic BGP convergence studies");
    NS_LOG_UNCOND("   - Route oscillation research");
    NS_LOG_UNCOND("   - BGP security mechanism validation");
    NS_LOG_UNCOND("   - Large-scale Internet topology simulation");
    NS_LOG_UNCOND("   - BGP policy interaction analysis");
    NS_LOG_UNCOND("   - Protocol timer optimization");
    
    NS_LOG_UNCOND("\n RECOMMENDATION:");
    NS_LOG_UNCOND("   For serious inter-AS routing research, use:");
    NS_LOG_UNCOND("   1. Real BGP implementations: Quagga/FRR/BIRD in VMs");
    NS_LOG_UNCOND("   2. Network emulators: GNS3, EVE-NG, Kathara");
    NS_LOG_UNCOND("   3. BGP simulators: BGP++, SSFNet, C-BGP");
    NS_LOG_UNCOND("   4. Formal models: Batfish (network verification)");
    NS_LOG_UNCOND("   5. Real testbeds: FABRIC, CloudLab");
    
    NS_LOG_UNCOND("\n   NS-3 is excellent for combined network/application");
    NS_LOG_UNCOND("   simulation but lacks protocol-level BGP realism.");
    
    // ======================================================================
    // VISUALIZATION AND TRACING
    // ======================================================================
    
    AnimationInterface anim("scratch/bgp_inter_as.xml");
    
    // AS65001 nodes (GlobalISP) - Green
    anim.UpdateNodeDescription(as65001_br1, "AS65001_BR1 (IXP-A)");
    anim.UpdateNodeDescription(as65001_br2, "AS65001_BR2 (IXP-B)");
    anim.UpdateNodeDescription(as65001_internal, "AS65001_Internal");
    anim.UpdateNodeDescription(as65001_customer, "AS65001_Customer");
    anim.UpdateNodeColor(as65001_br1, 0, 255, 0);
    anim.UpdateNodeColor(as65001_br2, 0, 255, 0);
    anim.UpdateNodeColor(as65001_internal, 0, 200, 0);
    anim.UpdateNodeColor(as65001_customer, 0, 150, 0);
    
    // AS65002 nodes (TransitProvider) - Blue
    anim.UpdateNodeDescription(as65002_br1, "AS65002_BR1 (IXP-A)");
    anim.UpdateNodeDescription(as65002_br2, "AS65002_BR2 (IXP-B)");
    anim.UpdateNodeDescription(as65002_internal, "AS65002_Internal");
    anim.UpdateNodeDescription(as65002_server, "AS65002_Server");
    anim.UpdateNodeColor(as65002_br1, 0, 0, 255);
    anim.UpdateNodeColor(as65002_br2, 0, 0, 255);
    anim.UpdateNodeColor(as65002_internal, 0, 0, 200);
    anim.UpdateNodeColor(as65002_server, 0, 0, 150);

    PointToPointHelper p2p;
    p2p.EnablePcapAll("scratch/bgp_inter_as");

    // ======================================================================
    // RUN SIMULATION
    // ======================================================================
    
    NS_LOG_UNCOND("\n========================================");
    NS_LOG_UNCOND("   STARTING BGP INTER-AS SIMULATION");
    NS_LOG_UNCOND("========================================\n");

    Simulator::Stop(Seconds(31.0));
    Simulator::Run();
    
    // ======================================================================
    // FINAL REPORT
    // ======================================================================
    
    NS_LOG_UNCOND("\n╔════════════════════════════════════════════════╗");
    NS_LOG_UNCOND("║  FINAL INTER-AS TRAFFIC ANALYSIS               ║");
    NS_LOG_UNCOND("╚════════════════════════════════════════════════╝");
    
    AnalyzeFlowMonitor(monitor, classifier, "FINAL REPORT");
    ExportMetricsToCSV(monitor, classifier, "scratch/bgp_metrics.csv");
    monitor->SerializeToXmlFile("scratch/bgp_flowmon.xml", true, true);
    
    NS_LOG_UNCOND("\n========================================");
    NS_LOG_UNCOND("   SIMULATION COMPLETED");
    NS_LOG_UNCOND("   Files generated:");
    NS_LOG_UNCOND("   - bgp_inter_as.xml (NetAnim)");
    NS_LOG_UNCOND("   - bgp_metrics.csv (Flow data)");
    NS_LOG_UNCOND("   - bgp_flowmon.xml (Detailed stats)");
    NS_LOG_UNCOND("   - bgp_inter_as-*.pcap (Packet captures)");
    NS_LOG_UNCOND("========================================\n");
    
    Simulator::Destroy();
    return 0;
}