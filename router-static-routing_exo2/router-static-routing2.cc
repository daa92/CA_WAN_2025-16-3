/*
 * Two nodes separated by a router with static routing
 *
 * Network Topology:
 *
 *   Network 1 (10.1.1.0/24)          Network 2 (10.1.2.0/24)
 *
 *   n0 -------------------- n1 (Router) -------------------- n2
 *      point-to-point                    point-to-point
 *      5Mbps, 2ms                        5Mbps, 2ms
 *
 * - n0 is on network 10.1.1.0/24 (IP: 10.1.1.1)
 * - n1 is the router with two interfaces:
 *     - Interface 1: 10.1.1.2 (connected to n0)
 *     - Interface 2: 10.1.2.1 (connected to n2)
 * - n2 is on network 10.1.2.0/24 (IP: 10.1.2.2)
 * - Static routes configured on n0 and n2 to reach each other through n1
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/ipv4-static-routing-helper.h"

#include "ns3/socket.h"                    // For Socket class
#include "ns3/udp-socket-factory.h"        // For UDP sockets
#include "ns3/tcp-socket-factory.h"        // For TCP sockets (FTP)
#include "ns3/udp-echo-client.h"           // For UdpEchoClient
#include "ns3/udp-client.h"                // For UdpClient (VoIP)
#include "ns3/bulk-send-application.h"     // For BulkSendApplication (FTP)
#include "ns3/traffic-control-module.h"  //for queue disciplines
#include "ns3/flow-monitor-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("DSCPSimulation");


// Structure to hold per-flow statistics
struct FlowStats
{
    std::string trafficType;
    uint32_t txPackets;
    uint32_t rxPackets;
    uint32_t lostPackets;
    double throughput;
    double avgDelay;
    double avgJitter;
    double packetLossRatio;
};

// Function to print formatted statistics table
void PrintStatisticsTable(const std::vector<FlowStats>& stats)
{
    std::cout << "\n╔════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                        QoS PERFORMANCE METRICS COMPARISON                      ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Traffic  │  Tx Pkts │  Rx Pkts │  Lost  │ Loss(%) │  Delay(ms) │ Jitter(ms) ║\n";
    std::cout << "║  Type    │          │          │        │         │            │            ║\n";
    std::cout << "╠══════════╪══════════╪══════════╪════════╪═════════╪════════════╪════════════╣\n";

    for (const auto& stat : stats)
    {
        std::cout << "║ " << std::left << std::setw(8) << stat.trafficType << " │ "
                  << std::right << std::setw(8) << stat.txPackets << " │ "
                  << std::setw(8) << stat.rxPackets << " │ "
                  << std::setw(6) << stat.lostPackets << " │ "
                  << std::setw(6) << std::fixed << std::setprecision(2) << stat.packetLossRatio << "% │ "
                  << std::setw(10) << std::fixed << std::setprecision(3) << stat.avgDelay << " │ "
                  << std::setw(10) << std::fixed << std::setprecision(3) << stat.avgJitter << " ║\n";
    }

    std::cout << "╚══════════╧══════════╧══════════╧════════╧═════════╧════════════╧════════════╝\n";

    // Print analysis
    std::cout << "\n╔════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                              QoS PRIORITY ANALYSIS                             ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ EXPECTED BEHAVIOR (High Priority → Low Priority):                             ║\n";
    std::cout << "║   1. VoIP (DSCP 46)  : LOWEST delay, LOWEST jitter, LOWEST loss              ║\n";
    std::cout << "║   2. FTP (DSCP 24)   : MEDIUM delay, MEDIUM jitter, MEDIUM loss              ║\n";
    std::cout << "║   3. UDP Echo (DSCP 0): HIGHEST delay, HIGHEST jitter, HIGHEST loss          ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ QoS VERIFICATION:                                                              ║\n";

    // Verify VoIP has best performance
    if (stats.size() >= 3)
    {
        bool voipBestDelay = (stats[0].avgDelay <= stats[1].avgDelay) && (stats[0].avgDelay <= stats[2].avgDelay);
        bool voipBestJitter = (stats[0].avgJitter <= stats[1].avgJitter) && (stats[0].avgJitter <= stats[2].avgJitter);
        bool voipBestLoss = (stats[0].packetLossRatio <= stats[1].packetLossRatio) && (stats[0].packetLossRatio <= stats[2].packetLossRatio);

        std::cout << "║   ✓ VoIP has lowest delay:  " << (voipBestDelay ? "YES ✓" : "NO ✗") << std::setw(47) << "║\n";
        std::cout << "║   ✓ VoIP has lowest jitter: " << (voipBestJitter ? "YES ✓" : "NO ✗") << std::setw(47) << "║\n";
        std::cout << "║   ✓ VoIP has lowest loss:   " << (voipBestLoss ? "YES ✓" : "NO ✗") << std::setw(47) << "║\n";

        if (voipBestDelay && voipBestJitter && voipBestLoss)
        {
            std::cout << "║                                                                                ║\n";
            std::cout << "║   QoS IS WORKING CORRECTLY! Priority scheduling is effective.             ║\n";
        }
        else
        {
            std::cout << "║                                                                                ║\n";
            std::cout << "║    QoS may not be working as expected. Check configuration.               ║\n";
        }
    }

    std::cout << "╚════════════════════════════════════════════════════════════════════════════════╝\n\n";
}


int
main(int argc, char* argv[])
{
   /* // Enable logging for udp echo packets
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpClient", LOG_LEVEL_INFO);
    LogComponentEnable("UdpServer", LOG_LEVEL_INFO);
 
    // for the VoIP
    LogComponentEnable("UdpClient", LOG_LEVEL_INFO);
    LogComponentEnable("UdpServer", LOG_LEVEL_INFO);

    //for FTP
    LogComponentEnable("TcpSocketBase", LOG_LEVEL_INFO); // ftp uses tcp protocol
    LogComponentEnable("Ipv4L3Protocol", LOG_LEVEL_INFO); // this is why these two lines appear here
    LogComponentEnable("BulkSendApplication", LOG_LEVEL_INFO);
    LogComponentEnable("PacketSink", LOG_LEVEL_INFO);*/

    // for the QoS (DSCP)
   // LogComponentEnable("TrafficQoSSimulation", LOG_LEVEL_INFO);


    LogComponentEnable("DSCPSimulation", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpClient", LOG_LEVEL_INFO);
    LogComponentEnable("UdpServer", LOG_LEVEL_INFO);
    LogComponentEnable("BulkSendApplication", LOG_LEVEL_INFO);
    LogComponentEnable("PacketSink", LOG_LEVEL_INFO);
    LogComponentEnable("PacketSink", LOG_LEVEL_INFO);

    // Create three nodes: n0 (client), n1 (router), n2 (server)
    NodeContainer nodes;
    nodes.Create(3);

    Ptr<Node> client = nodes.Get(0); // Client
    Ptr<Node> router = nodes.Get(1); // Router
    Ptr<Node> server = nodes.Get(2); // Server

    // Create point-to-point links
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("10ms")); //from 2 to 10 ms, for the congestion simulation

    // Link 1: n0 <-> n1 (Network 1)
    NodeContainer network1(client, router);
    NetDeviceContainer network1device = p2p.Install(network1);

    // Link 2: n1 <-> n2 (Network 2)
    NodeContainer network2(router, server);
    NetDeviceContainer network2device = p2p.Install(network2);

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
    
    // this part of the queue must be defined before assigning ip addresses
    // *** CRITICAL FIX 1: Install PrioQueueDisc BEFORE assigning IP addresses ***
    TrafficControlHelper tchPrio;
    
    // PrioQueueDisc uses the IP TOS field to determine priority
    // We just need to install it - it will automatically use DSCP values
    tchPrio.SetRootQueueDisc("ns3::PrioQueueDisc");
    
    // Install on router's interface to server (network2device.Get(0))
    QueueDiscContainer qdiscs = tchPrio.Install(network2device.Get(0));
    
    // Get the PrioQueueDisc and manually add child queues
    Ptr<QueueDisc> qdisc = qdiscs.Get(0);
    Ptr<PrioQueueDisc> prioQdisc = DynamicCast<PrioQueueDisc>(qdisc);
    
    if (prioQdisc)
    {
        // Create 3 child FIFO queues for 3 priority bands
        ObjectFactory factory;
        factory.SetTypeId("ns3::FifoQueueDisc");
        factory.Set("MaxSize", StringValue("20p")); // from 100 to 20 for the congestion simulation
        
        for (uint32_t i = 0; i < 3; i++)
        {
            Ptr<QueueDisc> childQdisc = factory.Create<QueueDisc>();
            Ptr<QueueDiscClass> qclass = CreateObject<QueueDiscClass>();
            qclass->SetQueueDisc(childQdisc);
            prioQdisc->AddQueueDiscClass(qclass);
        }
        
        NS_LOG_INFO("PrioQueueDisc with 3 bands installed successfully");
    }


    // Assign IP addresses to Network 1 (10.1.1.0/24)
    Ipv4AddressHelper address1;
    address1.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer network1interface = address1.Assign(network1device);
    // interfaces1.GetAddress(0) = 10.1.1.1 (n0)
    // interfaces1.GetAddress(1) = 10.1.1.2 (n1's first interface)

    // Assign IP addresses to Network 2 (10.1.2.0/24)
    Ipv4AddressHelper address2;
    address2.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer network2interface = address2.Assign(network2device);
    // interfaces2.GetAddress(0) = 10.1.2.1 (n1's second interface)
    // interfaces2.GetAddress(1) = 10.1.2.2 (n2)

    // *** Configure Static Routing ***

    // Enable IP forwarding on the router (n1)
    Ptr<Ipv4> ipv4Router = router->GetObject<Ipv4>();
    ipv4Router->SetAttribute("IpForward", BooleanValue(true));

    // Get static routing protocol helper
    Ipv4StaticRoutingHelper staticRoutingHelper;

    // Configure routing on n0 (client)
    // n0 needs to know that to reach 10.1.2.0/24, it should go through 10.1.1.2 (router's
    // interface)
    Ptr<Ipv4StaticRouting> staticRoutingClient =
        staticRoutingHelper.GetStaticRouting(client->GetObject<Ipv4>());
    staticRoutingClient->AddNetworkRouteTo(
        Ipv4Address("10.1.2.0"),   // Destination network
        Ipv4Mask("255.255.255.0"), // Network mask
        Ipv4Address("10.1.1.2"),   // Next hop (router's interface on network 1)
        1                          // Interface index
    );

    // Configure routing on n2 (server)
    // n2 needs to know that to reach 10.1.1.0/24, it should go through 10.1.2.1 (router's
    // interface)
    Ptr<Ipv4StaticRouting> staticRoutingServer =
        staticRoutingHelper.GetStaticRouting(server->GetObject<Ipv4>());
    staticRoutingServer->AddNetworkRouteTo(
        Ipv4Address("10.1.1.0"),   // Destination network
        Ipv4Mask("255.255.255.0"), // Network mask
        Ipv4Address("10.1.2.1"),   // Next hop (router's interface on network 2)
        1                          // Interface index
    );

    // Note: Router (n1) doesn't need explicit routes as it's directly connected to both networks

    // Print routing tables for verification
    Ptr<OutputStreamWrapper> routingStream =
        Create<OutputStreamWrapper>("router-static-routing2.routes", std::ios::out);
    staticRoutingHelper.PrintRoutingTableAllAt(Seconds(1.0), routingStream);

    std::cout << "\n=== Network Configuration ===\n";
    std::cout << "Node 0 (Client): " << network1interface.GetAddress(0) << " (Network 1)\n";
    std::cout << "Node 1 (Router) Interface 1: " << network1interface.GetAddress(1) << " (Network 1)\n";
    std::cout << "Node 1 (Router) Interface 2: " << network2interface.GetAddress(0) << " (Network 2)\n";
    std::cout << "Node 2 (Server): " << network2interface.GetAddress(1) << " (Network 2)\n";
    std::cout << "=============================\n\n";



    // Create UDP Echo Server on n2 (10.1.2.2)
    uint16_t port = 9;
    UdpEchoServerHelper echoServer(port);
    ApplicationContainer serverApps = echoServer.Install(server);
    serverApps.Start(Seconds(1.0));
    serverApps.Stop(Seconds(10.0));

    // Create UDP Echo Client on n0 targeting n2's IP address
    UdpEchoClientHelper echoClient(network2interface.GetAddress(1), port); // Server's IP on Network 2
    echoClient.SetAttribute("MaxPackets", UintegerValue(3));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    echoClient.SetAttribute("PacketSize", UintegerValue(1024));

    ApplicationContainer clientApps = echoClient.Install(client);
    clientApps.Start(Seconds(2.0));
    clientApps.Stop(Seconds(10.0));

    // SET DSCP FOR UDP Echo - BE (0) = 0x00
    Simulator::Schedule(Seconds(2.000), [&clientApps]() {
        Ptr<UdpEchoClient> app = DynamicCast<UdpEchoClient>(clientApps.Get(0));
        if (app) {
            Ptr<Socket> socket = app->GetSocket();
            if (socket) {
                socket->SetIpTos(0x00);  // DSCP 0 (BE)
                NS_LOG_INFO("UDP Echo: DSCP BE (0) = 0x00 - LOWEST PRIORITY (Best Effort)");
            }
        } else {
            NS_LOG_ERROR("Failed to set DSCP for UDP Echo");
        }
    });


    NS_LOG_INFO("\nUDP Echo applications configured\n\n");

    //==========VoIP config
    UdpServerHelper voipserver (5060); // port = 5060
    ApplicationContainer serverapps = voipserver.Install (server);
    serverapps.Start (Seconds (2.0));
    serverapps.Stop (Seconds (10.0));

    UdpClientHelper voipclient (network2interface.GetAddress (1), 5060);

    /*const int DSCP_EF = 46;
    voipclient.SetAttribute("SocketFactory", StringValue("ns3::UdpSocketFactory")); // Ensure UdpSocket is used
    voipclient.SetAttribute("Tos", UintegerValue(DSCP_EF << 2)); // Set TOS/DSCP field*/

    voipclient.SetAttribute ("MaxPackets", UintegerValue (20));
    voipclient.SetAttribute ("Interval", TimeValue (Seconds (0.02))); //20ms
    voipclient.SetAttribute ("PacketSize", UintegerValue (160)); //160b
    
    ApplicationContainer clientapps = voipclient.Install (client);
    clientapps.Start (Seconds (3.0)); // begins at +3s
    clientapps.Stop (Seconds (10));

    // SET DSCP FOR VoIP - EF (46) = 0xB8
    Simulator::Schedule(Seconds(3.000), [&clientapps]() {
        Ptr<UdpClient> app = DynamicCast<UdpClient>(clientapps.Get(0));
        if (app) {
            Ptr<Socket> socket = app->GetSocket();
            if (socket) {
                socket->SetIpTos(0xB8);  // DSCP 46 (EF)
                NS_LOG_INFO("VoIP: DSCP EF (46) = 0xB8 - HIGHEST PRIORITY");
            }
        } else {
            NS_LOG_ERROR("Failed to set DSCP for VoIP");
        }
    });

    NS_LOG_INFO("\nVoIP applications configured\n\n");



    // ============ FTP SERVER (PacketSink - receives data) ============
    uint16_t ftpPort = 21; // 21 is the port number of commands of FTP protocol
    PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), ftpPort));
    ApplicationContainer sinkApp = sinkHelper.Install(server);
    sinkApp.Start(Seconds(2.0));
    sinkApp.Stop(Seconds(10.0));

    // ============ FTP CLIENT - BURST 1 (BulkSend) ============
    BulkSendHelper ftpBurst1("ns3::TcpSocketFactory",
                             InetSocketAddress(network2interface.GetAddress(1), ftpPort));

    // Simulate transferring a 5MB file in first burst
    ftpBurst1.SetAttribute("MaxBytes", UintegerValue(5 * 1024 * 1024)); // 1.5kB
    ftpBurst1.SetAttribute("SendSize", UintegerValue(1500));            // 1.5KB packets

    ApplicationContainer burst1App = ftpBurst1.Install(client);
    burst1App.Start(Seconds(2.5));   // First burst at 2.5s
    burst1App.Stop(Seconds(10.0));


    // SET DSCP FOR FTP - CS3 (24) = 0x60
    Simulator::Schedule(Seconds(2.000), [&burst1App]() {
        Ptr<BulkSendApplication> app = DynamicCast<BulkSendApplication>(burst1App.Get(0));
        if (app) {
            Ptr<Socket> socket = app->GetSocket();
            if (socket) {
                socket->SetIpTos(0x60);  // DSCP 24 (CS3)
                NS_LOG_INFO("FTP: DSCP CS3 (24) = 0x60 - MEDIUM PRIORITY");
            }
        } else {
            NS_LOG_ERROR("Failed to set DSCP for FTP");
        }
    });

    NS_LOG_INFO("FTP Burst 1: 5MB file transfer (1-5s)");


    // ============ PERFORMANCE MEASUREMENT SETUP ============

    // Install FlowMonitor on all nodes
    FlowMonitorHelper flowmonHelper;
    Ptr<FlowMonitor> flowMonitor = flowmonHelper.InstallAll();


    // *** NetAnim Configuration ***
    AnimationInterface anim("router-static-routing2.xml");

    // Node positions are already set via MobilityModel above
    // NetAnim will automatically use the mobility model positions

    // Set node descriptions
    anim.UpdateNodeDescription(client, "Client\n10.1.1.1");
    anim.UpdateNodeDescription(router, "Router\n10.1.1.2 | 10.1.2.1");
    anim.UpdateNodeDescription(server, "Server\n10.1.2.2");

    // Set node colors     
    anim.UpdateNodeColor(client, 0, 255, 0);   // Green for client
    anim.UpdateNodeColor(router, 255, 255, 0); // Yellow for router
    anim.UpdateNodeColor(server, 0, 0, 255);   // Blue for server

    // Enable PCAP tracing on all devices for Wireshark analysis
    p2p.EnablePcapAll("router-static-routing2");

    // Run simulation
    Simulator::Run();
    Simulator::Destroy();

    std::cout << "\n=== Simulation Complete ===\n";
    std::cout << "Animation trace saved to: router-static-routing2.xml\n";
    std::cout << "Routing tables saved to: router-static-routing2.routes\n";
    std::cout << "PCAP traces saved to: router-static-routing2-*.pcap\n";
    std::cout << "Open the XML file with NetAnim to visualize the simulation.\n";

    // Get flow statistics
    flowMonitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmonHelper.GetClassifier());
    FlowMonitor::FlowStatsContainer stats = flowMonitor->GetFlowStats();

    std::vector<FlowStats> flowStats;

    for (auto const& [flowId, flowStat] : stats)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(flowId);
        FlowStats fs;

        // Identify traffic type based on port
        if (t.destinationPort == 9)
        {
            fs.trafficType = "UDP Echo";
        }
        else if (t.destinationPort == 5060)
        {
            fs.trafficType = "VoIP";
        }
        else if (t.destinationPort == 21)
        {
            fs.trafficType = "FTP";
        }
        else
        {
            continue;  // Skip other flows
        }

        fs.txPackets = flowStat.txPackets;
        fs.rxPackets = flowStat.rxPackets;
        fs.lostPackets = flowStat.lostPackets;
        fs.packetLossRatio = (fs.txPackets > 0) ? (fs.lostPackets * 100.0 / fs.txPackets) : 0.0;

        // Calculate throughput in Kbps
        double timeInterval = flowStat.timeLastRxPacket.GetSeconds() - flowStat.timeFirstTxPacket.GetSeconds();
        fs.throughput = (timeInterval > 0) ? (flowStat.rxBytes * 8.0 / timeInterval / 1000.0) : 0.0;

        // Calculate average delay in milliseconds
        fs.avgDelay = (flowStat.rxPackets > 0) ?
                      (flowStat.delaySum.GetMilliSeconds() / flowStat.rxPackets) : 0.0;

        // Calculate average jitter in milliseconds
        fs.avgJitter = (flowStat.rxPackets > 1) ?
                       (flowStat.jitterSum.GetMilliSeconds() / (flowStat.rxPackets - 1)) : 0.0;

        flowStats.push_back(fs);
    }

    // Sort by priority: VoIP, FTP, UDP Echo
    std::sort(flowStats.begin(), flowStats.end(), [](const FlowStats& a, const FlowStats& b) {
        const std::map<std::string, int> priority = {{"VoIP", 0}, {"FTP", 1}, {"UDP Echo", 2}};
        return priority.at(a.trafficType) < priority.at(b.trafficType);
    });

    //Ptr<PacketSink> ftpSink = DynamicCast<PacketSink>(sinkApp.Get(0));
    //std::cout << "║ FTP Total Bytes Received:    " << std::setw(45) << ftpSink->GetTotalRx() << " bytes ║\n";

    //Ptr<UdpServer> voipSink = DynamicCast<UdpServer>(voipserver);
    //Ptr<PacketSink> voipSink = DynamicCast<UdpServer>(voipserver.Get(0));
    //std::cout << "║ VoIP Packets Received:       " << std::setw(51) << voipSink->GetReceived() << " ║\n";
    //std::cout << "║ VoIP Packets Lost:           " << std::setw(51) << voipSink->GetLost() << " ║\n";

    std::cout << "╚════════════════════════════════════════════════════════════════════════════════╝\n";

    // Save detailed flow monitor statistics to XML file
    flowMonitor->SerializeToXmlFile("qos-flow-monitor.xml", true, true);

    return 0;
}
