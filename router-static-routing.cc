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


#include <iostream> //for outputs (cout)
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-module.h"
#include <string> //for string variables
#include "ns3/netanim-module.h" //for the animation via ./NetAnim
#include "ns3/mobility-module.h" //for setting the graphical position used by netanim (x, y, 0)
#include "ns3/flow-monitor-module.h" //for comparing the latency between the direct and the backup path


using namespace std; //avoid repeating std::cout<<....
using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("twonodeswithrouter");


string presentation (){
	string result = "";
	string part1 = "   Network 1 (10.1.1.0/24)                    Network 2 (10.1.2.0/24)\n\n";
	string part2 = "   client ------------------------- router ----------------------- server\n";
	string part3 = "              point-to-point                    point-to-point\n";
	string part4 = "               5Mbps, 2ms                        5Mbps, 2ms\n";
	result = part1 + part2 + part3 + part4;
	return ("\n=========================NETWORK PRESENTATION=========================\n"+result+"\n=======================================================================\n");
}


int main (int argc, char* argv[]){

	cout<<presentation ()<<endl; // this "GUI" representation is for more understanding

	CommandLine cmd (__FILE__);
	cmd.Parse (argc, argv);

	Time::SetResolution (Time::NS); //configuring the time at nanoseconds
	
	//enable logging: This will result in the application printing out messages as packets are sent and received during the simulation
	LogComponentEnable ("UdpEchoClientApplication", LOG_LEVEL_INFO);
	LogComponentEnable ("UdpEchoServerApplication", LOG_LEVEL_INFO);

	// creating 03 nodes: client router and server
	NodeContainer nodes;
	nodes.Create (3);

	Ptr <Node> client = nodes.Get (0);
	Ptr <Node> router = nodes.Get (1);
	Ptr <Node> server = nodes.Get (2);
	cout <<"Creation of 03 nodes (client, router & server) accomplished"<<endl;
	//NOTE: those '0', '1' and '2' are just the indexes of those nodes

	/*Alternatively, we could do this
	 * NodeContainer client;
	 * client.Create (1);
	 * NodeContainer router;
	 * router.Create (1);
	 * NodeContainer server;
	 * server.Create (1)*/

	//Installing internet stack (layer3 protocols) to the network_meaning all nodes (UDP, TCP, Socket...)
        InternetStackHelper stack;
        stack.Install (nodes);

	//creating layer2 protocol for linking those nodes (actually p2p)
	PointToPointHelper p2p;
	p2p.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
	p2p.SetChannelAttribute ("Delay", StringValue ("2ms"));

	cout <<"Setting up:\n\tDataRate to 5 Mega bits per second\n\tDelay to 2 milliseconds"<<endl;
	cout<<"#############################################################\n\n";
	Ipv4StaticRoutingHelper staticroutinghelper; // object which will allow the router the static routing

	//Now we are going to set up each network
	//==============network1============= client <---> router
	
	NodeContainer network1 (client, router); //yes, even networks are objects
						 //we directly assign nodes to each network
		//adding NIC to each node
	NetDeviceContainer network1devices = p2p.Install (network1);

		//Assigning IP (version 4)  addresses to the network
	Ipv4AddressHelper network1address;
        network1address.SetBase ("10.1.1.0", "255.255.255.0");
	Ipv4InterfaceContainer network1interface = network1address.Assign (network1devices);
	// it will be like this:
	// 0 client 1 <------> 1 router 0
	// index 0 is for the loopback (127.0.0.0)
	// index 1 (client) = 10.1.1.1 and then index 1 (router) = 10.1.1.2

	//==============End_network1=============
	


	//==============network2============= router <---> server

        NodeContainer network2 (router, server); //yes, even networks are objects
                                                 //we directly assign nodes to each network
                //adding NIC to each node
        NetDeviceContainer network2devices = p2p.Install (network2);

                //Assigning IP (version 4)  addresses to the network
        Ipv4AddressHelper network2address;
        network2address.SetBase ("10.1.2.0", "255.255.255.0");
        Ipv4InterfaceContainer network2interface = network2address.Assign (network2devices);
        // it will be like this:
        // 1 router 2 <------> 1 server 0
        // index 0 is for the loopback (127.0.0.0)
        // index 2 (router) = 10.1.2.1 and then index 1 (server) = 10.1.2.2


        //==============End_network2=============
	

	//==============network3============= client <---> server

        NodeContainer network3 (client, server); //yes, even networks are objects
                                                 //we directly assign nodes to each network
                //adding NIC to each node
        NetDeviceContainer network3devices = p2p.Install (network3);

                //Assigning IP (version 4)  addresses to the network
        Ipv4AddressHelper network3address;
        network3address.SetBase ("10.1.3.0", "255.255.255.0");
        Ipv4InterfaceContainer network3interface = network3address.Assign (network3devices);
        // it will be like this:
        // 0 client 2 <------> 2 server 0
        // index 0 is for the loopback (127.0.0.0)
        // index 2 (client) = 10.1.3.2 (server'ip)  and then index 2 (server) = 10.1.3.1 (client's ip)


        //==============End_network3=============
	
	

	// ***Static routing configuration***
        //enabling IP forwarding on the router
        Ptr <Ipv4> ipv4router = router-> GetObject <Ipv4> ();
        ipv4router->SetAttribute ("IpForward", BooleanValue (true));

        // Configure routing on the client
        // for now, client needs to know that to reach 10.1.2.0/24, it should go through 10.1.1.2 (router's interface)
        Ptr <Ipv4StaticRouting> staticroutingclient = staticroutinghelper.GetStaticRouting (client -> GetObject <Ipv4> ());


	// direct path client < ----- > server
	staticroutingclient->AddHostRouteTo (
                        Ipv4Address ("10.1.3.2"), //ip of the target node
                        2, // the interface attached to ( 0 client 2 -> 2 server 0 )
			1 // high priority (metric)
        );


        //backup path client < ------- > router < ------- > server
	staticroutingclient->AddHostRouteTo (
                        Ipv4Address ("10.1.3.2"), //ip of the target node
                        Ipv4Address ("10.1.1.2"), // the hop (intermediary)
                        1, // interface
			10 // metric (low-priority)
        ); 

	// Route to reach server's other interface (10.1.2.2) via router
	staticroutingclient->AddNetworkRouteTo(
    		Ipv4Address("10.1.2.0"), //target network
    		Ipv4Mask("255.255.255.0"), // subnet
    		Ipv4Address("10.1.1.2"), //hop 
    		1 // interface
	);

	// Configure routing on the server
        // server needs to know that to reach 10.1.1.0/24, it should go through 10.1.2.1 (router's interface)


        Ptr<Ipv4StaticRouting> staticroutingserver = staticroutinghelper.GetStaticRouting(server->GetObject<Ipv4>());

	//direct path server < ----- > client
        staticroutingserver->AddHostRouteTo(
                        Ipv4Address("10.1.3.1"),   // Destination node
                        2,			   // the interface attached to (0 client 2 -> 2 router 0)
                        1                          // high priority
               );

	//backup path server < ----- > router < ----- > client
        staticroutingserver->AddHostRouteTo(
                        Ipv4Address("10.1.3.1"),   // Destination ip
                        Ipv4Address("10.1.2.1"),   // the intermediary (router) (its ip address attached to the network2)
                        1,                          // the interface attached to ( 0 client 1 -> 1 router 0  -> 1 client )
			10
               );

	// Route to reach client's other interface (10.1.1.1) via router
	staticroutingserver->AddNetworkRouteTo(
    		Ipv4Address("10.1.1.0"),
    		Ipv4Mask("255.255.255.0"),
    		Ipv4Address("10.1.2.1"),
    		1
	);


	// ============ ROUTER ROUTING TABLE ============
	Ptr<Ipv4StaticRouting> staticroutingrouter = staticroutinghelper.GetStaticRouting(router->GetObject<Ipv4>());

	// Route to client's networks
	staticroutingrouter->AddNetworkRouteTo(
    		Ipv4Address("10.1.1.0"),
    		Ipv4Mask("255.255.255.0"),
    		1
	);

	staticroutingrouter->AddNetworkRouteTo(
    		Ipv4Address("10.1.3.0"),
    		Ipv4Mask("255.255.255.0"),
    		Ipv4Address("10.1.1.1"),       // Via client
    		1
	);

	// Route to server's networks
	staticroutingrouter->AddNetworkRouteTo(
    		Ipv4Address("10.1.2.0"),
    		Ipv4Mask("255.255.255.0"),
    		2
	);

	staticroutingrouter->AddNetworkRouteTo(
    		Ipv4Address("10.1.3.0"),
    		Ipv4Mask("255.255.255.0"),
    		Ipv4Address("10.1.2.2"),       // Via server
    		2
	);
	
	/* // ============ INSTALL FLOWMONITOR ============
	FlowMonitorHelper flowmonHelper;
	Ptr<FlowMonitor> monitor = flowmonHelper.InstallAll();*/


	// ============ UDP ECHO SERVER ============
	UdpEchoServerHelper echoServer(9); // Port 9
	ApplicationContainer serverApps = echoServer.Install(server);
	serverApps.Start(Seconds(1.0));
	serverApps.Stop(Seconds(20.0));

	// ============ UDP ECHO CLIENT (direct path) ============
	// Client sends to server's direct IP (10.1.3.2)
	UdpEchoClientHelper echoClient(Ipv4Address("10.1.3.2"), 9); // Server's IP on direct link
	echoClient.SetAttribute("MaxPackets", UintegerValue(10));     // Send 10 packets total
	echoClient.SetAttribute("Interval", TimeValue(Seconds(1.0))); // 1 packet per second
	echoClient.SetAttribute("PacketSize", UintegerValue(1024));   // 1024 bytes per packet

	ApplicationContainer clientApps = echoClient.Install(client);
	clientApps.Start(Seconds(2));  // Start at 2 seconds
	clientApps.Stop(Seconds(10.0));  // Stop at 10 seconds
				

	// ============ SIMULATE LINK FAILURE ============
	// Get Ipv4 objects
	Ptr<Ipv4> ipv4Client = client->GetObject<Ipv4>();
	Ptr<Ipv4> ipv4Server = server->GetObject<Ipv4>();

	// Get interface indices for the direct link devices
	uint32_t clientIfIndex = ipv4Client->GetInterfaceForDevice(network3devices.Get(0));
	uint32_t serverIfIndex = ipv4Server->GetInterfaceForDevice(network3devices.Get(1));

	// Set direct link DOWN at 4 seconds (forces backup path)
	Simulator::Schedule(Seconds(4.0), &Ipv4::SetDown, ipv4Client, clientIfIndex);
	Simulator::Schedule(Seconds(4.0), &Ipv4::SetDown, ipv4Server, serverIfIndex);

	// Set direct link UP at 7 seconds (restore direct path)
	Simulator::Schedule(Seconds(7.0), &Ipv4::SetUp, ipv4Client, clientIfIndex);
	Simulator::Schedule(Seconds(7.0), &Ipv4::SetUp, ipv4Server, serverIfIndex);



        // let's save the routing table of the router because the outputs only show the communication between the client and the server, not the intermediary
	Ptr <OutputStreamWrapper> routingstream = Create <OutputStreamWrapper>
	       	("router-static-routing.routes", std::ios::out);
        staticroutinghelper.PrintRoutingTableAllAt (Seconds (1.0), routingstream);	

	// Enable PCAP tracing on all devices for Wireshark analysis
        p2p.EnablePcapAll("router-static-routing");//	(commented because not really necessary
	                                                // at the moment)
	
	//============Netanim config
		//set the positions of each node via mobility-module
	MobilityHelper position;
	position.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
	position.Install (nodes);

	Ptr <MobilityModel> position1 = client -> GetObject <MobilityModel> (); //client's position
	Ptr <MobilityModel> position2 = router -> GetObject <MobilityModel> (); //router's position
	Ptr <MobilityModel> position3 = server -> GetObject <MobilityModel> (); //server's position
	
		/*Triangle layout:       router
		 *                      #      #
		 *                   #           #
		 *                #                 #
		 *          client #   #   #   #  #  Server
		 *
		 * */
	position1->SetPosition (Vector (3.0, 10.0, 0.0)); // client_bottom-left
	position2->SetPosition (Vector (6.0, 2.0, 0.0)); // router_top-center
	position3->SetPosition (Vector (9.0, 10.0, 0.0)); // server_bottom_right
	
		//creation of a .xml file for the animation
        AnimationInterface anim ("router-static-routing.xml");

		//Set node description
	anim.UpdateNodeDescription (client, "Client\n10.1.1.1");
	anim.UpdateNodeDescription (router, "10.1.1.2 | Router | 10.1.2.1");
	anim.UpdateNodeDescription (server, "Server\n10.1.2.2");

		//Set node color
	anim.UpdateNodeColor (client, 0, 255, 0); //green
	anim.UpdateNodeColor (router, 255, 255, 0); //yellow
	anim.UpdateNodeColor (server, 0, 0, 255); //blue	


	/* // ============ FLOWMONITOR ANALYSIS ============
	monitor->CheckForLostPackets();

	Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmonHelper.GetClassifier());
	FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();

	std::cout << "\n=== FLOW STATISTICS ===\n";
	std::cout << "Total Flows: " << stats.size() << "\n\n";

	double directPathLatency = 0.0;
	double backupPathLatency = 0.0;
	uint32_t directPathPackets = 0;
	uint32_t backupPathPackets = 0;

	for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin(); i != stats.end(); ++i)
	{
    		Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);

    		std::cout << "Flow ID: " << i->first << "\n";
    		std::cout << "  Source: " << t.sourceAddress << ":" << t.sourcePort << "\n";
    		std::cout << "  Destination: " << t.destinationAddress << ":" << t.destinationPort << "\n";
    		std::cout << "  Protocol: " << (uint32_t)t.protocol << "\n";
    		std::cout << "  Tx Packets: " << i->second.txPackets << "\n";
    		std::cout << "  Rx Packets: " << i->second.rxPackets << "\n";
    		std::cout << "  Lost Packets: " << i->second.lostPackets << "\n";

    		if (i->second.rxPackets > 0)
    		{
        		double avgDelay = i->second.delaySum.GetSeconds() / i->second.rxPackets;
        		std::cout << "  Average Delay: " << avgDelay * 1000 << " ms\n";
        		std::cout << "  Average Jitter: " << i->second.jitterSum.GetSeconds() / (i->second.rxPackets - 1) * 1000 << " ms\n";

        		// Identify Direct vs Backup path by destination IP
        		if (t.destinationAddress == Ipv4Address("10.1.3.2"))
        		{
            			directPathLatency += i->second.delaySum.GetSeconds();
            			directPathPackets += i->second.rxPackets;
            			std::cout << "  *** DIRECT PATH ***\n";
        		}
        		else if (t.destinationAddress == Ipv4Address("10.1.2.2"))
        		{
            			backupPathLatency += i->second.delaySum.GetSeconds();
            			backupPathPackets += i->second.rxPackets;
            			std::cout << "  *** BACKUP PATH ***\n";
        		}
    		}

    		std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds()) / 1000 << " Kbps\n";
    		std::cout << "\n";
	}

	// ============ COMPARISON ============
	std::cout << "\n=== LATENCY COMPARISON ===\n";

	if (directPathPackets > 0)
	{
    		double avgDirectLatency = (directPathLatency / directPathPackets) * 1000;
    		std::cout << "Direct Path Average Latency: " << avgDirectLatency << " ms\n";
	}

	if (backupPathPackets > 0)
	{
    		double avgBackupLatency = (backupPathLatency / backupPathPackets) * 1000;
    		std::cout << "Backup Path Average Latency: " << avgBackupLatency << " ms\n";
	}

	if (directPathPackets > 0 && backupPathPackets > 0)
	{
    		double directAvg = (directPathLatency / directPathPackets) * 1000;
    		double backupAvg = (backupPathLatency / backupPathPackets) * 1000;
    		double difference = backupAvg - directAvg;
    		double percentIncrease = (difference / directAvg) * 100;

    		std::cout << "\nLatency Increase (Backup vs Direct): " << difference << " ms\n";
    		std::cout << "Percentage Increase: " << percentIncrease << " %\n";
	}*/


	Simulator::Run ();
	Simulator::Destroy ();

	return 0;
}
