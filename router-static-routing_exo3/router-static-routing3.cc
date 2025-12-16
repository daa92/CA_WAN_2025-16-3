/*
 * Two nodes separated by a router with simulated IPSec VPN tunnels
 *
 * Network Topology:
 *
 *   Network 1 (10.1.1.0/24)          Network 2 (10.1.2.0/24)
 *
 *   n0 -------------------- n1 (VPN Gateway) -------------------- n2
 *      point-to-point                         point-to-point
 *      5Mbps, 2ms                             5Mbps, 2ms
 *      [VPN Tunnel]                           [VPN Tunnel]
 *
 * Simulated IPSec Features:
 * - ESP (Encapsulating Security Payload) overhead
 * - Encryption/Decryption processing delay
 * - Authentication overhead
 * - Tunnel mode encapsulation
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/traffic-control-module.h"
#include <iostream>
#include <cmath>
#include <iomanip>
#include <string>
#include <vector>
#include <set>
#include <map>

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("IPSecVPNSimulation");

// Custom application to simulate VPN encryption overhead
class VpnEncryptionDelayApp : public Application
{
  public:
    VpnEncryptionDelayApp()
        : m_encryptionDelay(MicroSeconds(50)),  // AES-256 encryption delay
          m_decryptionDelay(MicroSeconds(50)),  // AES-256 decryption delay
          m_hmacDelay(MicroSeconds(20))         // HMAC-SHA256 overhead
    {
    }

    void SetEncryptionDelay(Time delay) { m_encryptionDelay = delay; }
    void SetDecryptionDelay(Time delay) { m_decryptionDelay = delay; }
    void SetHmacDelay(Time delay) { m_hmacDelay = delay; }

  protected:
    virtual void StartApplication() override
    {
        NS_LOG_INFO("VPN Encryption Layer Active");
    }

    virtual void StopApplication() override
    {
        NS_LOG_INFO("VPN Encryption Layer Stopped");
    }

  private:
    Time m_encryptionDelay;
    Time m_decryptionDelay;
    Time m_hmacDelay;
};

// Custom NetDevice wrapper to add IPSec overhead
class IPSecNetDevice : public Object
{
  public:
    static constexpr uint32_t ESP_HEADER_SIZE = 8;      // ESP header
    static constexpr uint32_t ESP_TRAILER_SIZE = 2;     // ESP trailer
    static constexpr uint32_t ESP_AUTH_SIZE = 12;       // ICV (Integrity Check Value)
    static constexpr uint32_t ESP_IV_SIZE = 16;         // Initialization Vector (AES)
    static constexpr uint32_t IPSEC_PADDING = 0;        // Padding (0-255 bytes)
    static constexpr uint32_t NEW_IP_HEADER = 20;       // Tunnel mode: new outer IP header
    
    // Total IPSec ESP Tunnel Mode overhead
    static constexpr uint32_t TOTAL_OVERHEAD = 
        NEW_IP_HEADER + ESP_HEADER_SIZE + ESP_IV_SIZE + 
        ESP_TRAILER_SIZE + ESP_AUTH_SIZE + IPSEC_PADDING;
    
    static uint32_t GetOverhead() { return TOTAL_OVERHEAD; }
};

class EavesdropperApp : public Application
{
  public:
    EavesdropperApp()
        : m_packetsCaptured(0),
          m_bytesCaptured(0)
    {
    }

    void SetPromiscuousCallback(Ptr<NetDevice> device)
    {
        device->SetPromiscReceiveCallback(
            MakeCallback(&EavesdropperApp::PromiscuousSnifferCallback, this));
    }

  protected:
    virtual void StartApplication() override
    {
        NS_LOG_INFO("EAVESDROPPER ACTIVE - Sniffing traffic...");
        std::cout << "\n[ATTACK] Eavesdropper is now monitoring the network!\n" << std::endl;
    }

    virtual void StopApplication() override
    {
        NS_LOG_INFO("Eavesdropper stopped");
    }

  private:
    bool PromiscuousSnifferCallback(Ptr<NetDevice> device,
                                    Ptr<const Packet> packet,
                                    uint16_t protocol,
                                    const Address& from,
                                    const Address& to,
                                    NetDevice::PacketType packetType)
    {
        m_packetsCaptured++;
        m_bytesCaptured += packet->GetSize();

        // Extract packet data
        uint8_t buffer[2048];
        packet->CopyData(buffer, packet->GetSize());

        cout << "[INTERCEPTED] Packet #" << m_packetsCaptured
                  << "  Size: " << packet->GetSize() << " bytes" << endl;

        // Extract and display payload (sensitive data)
        cout << "    Payload (first 64 bytes): ";
        for (uint32_t i = 0; i < std::min(64u, packet->GetSize()); i++)
        {
            if (isprint(buffer[i]))
                cout << buffer[i];
            else
                cout << ".";
        }
        cout << endl;

        return true;
    }

    uint32_t m_packetsCaptured;
    uint32_t m_bytesCaptured;
};


// Global statistics for DDoS impact measurement
uint32_t g_legitimatePacketsSent = 0;
uint32_t g_legitimatePacketsReceived = 0;
uint32_t g_legitimatePacketsDropped = 0;
uint32_t g_attackPacketsSent = 0;
Time g_totalLegitimateDelay = Seconds(0);

// Callback to track legitimate traffic
void LegitimatePacketSent(Ptr<const Packet> packet)
{
    g_legitimatePacketsSent++;
}

void LegitimatePacketReceived(Ptr<const Packet> packet, const Address& address)
{
    g_legitimatePacketsReceived++;
}

// DDoS Attack Application - UDP Flood
class DDoSAttackApp : public Application
{
  public:
    DDoSAttackApp()
        : m_socket(0),
          m_packetsSent(0),
          m_packetSize(512),
          m_attackRate(DataRate("10Mbps")),
          m_running(false)
    {
    }

    void Setup(Address address, uint32_t packetSize, DataRate attackRate)
    {
        m_peer = address;
        m_packetSize = packetSize;
        m_attackRate = attackRate;
    }

    uint32_t GetPacketsSent() const { return m_packetsSent; }

  protected:
    virtual void StartApplication() override
    {
        m_running = true;
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->Bind();
        m_socket->Connect(m_peer);

        NS_LOG_INFO("DDoS Attacker Started - Flooding target...");

        ScheduleTransmit(Seconds(0.0));
    }

    virtual void StopApplication() override
    {
        m_running = false;
        if (m_socket)
        {
            m_socket->Close();
        }
        NS_LOG_INFO("DDoS Attacker Stopped");
    }

  private:
    void ScheduleTransmit(Time dt)
    {
        if (m_running)
        {
            m_sendEvent = Simulator::Schedule(dt, &DDoSAttackApp::SendPacket, this);
        }
    }

    void SendPacket()
    {
        Ptr<Packet> packet = Create<Packet>(m_packetSize);
        m_socket->Send(packet);
        m_packetsSent++;
        g_attackPacketsSent++;

        // Calculate inter-packet interval based on attack rate
        Time interPacketInterval = Seconds(m_packetSize * 8 / static_cast<double>(m_attackRate.GetBitRate()));
        ScheduleTransmit(interPacketInterval);
    }

    Ptr<Socket> m_socket;
    Address m_peer;
    uint32_t m_packetsSent;
    uint32_t m_packetSize;
    DataRate m_attackRate;
    EventId m_sendEvent;
    bool m_running;
};

// SYN Flood Attack Application
class SynFloodAttackApp : public Application
{
  public:
    SynFloodAttackApp()
        : m_socket(0),
          m_packetsSent(0),
          m_attackRate(1000), // packets per second
          m_running(false)
    {
    }

    void Setup(Address address, uint32_t attackRate)
    {
        m_peer = address;
        m_attackRate = attackRate;
    }

    uint32_t GetPacketsSent() const { return m_packetsSent; }

  protected:
    virtual void StartApplication() override
    {
        m_running = true;
        m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());

        NS_LOG_INFO("SYN Flood Attacker Started");

        ScheduleTransmit(Seconds(0.0));
    }

    virtual void StopApplication() override
    {
        m_running = false;
        if (m_socket)
        {
            m_socket->Close();
        }
    }

  private:
    void ScheduleTransmit(Time dt)
    {
        if (m_running)
        {
            m_sendEvent = Simulator::Schedule(dt, &SynFloodAttackApp::SendSynPacket, this);
        }
    }

    void SendSynPacket()
    {
        // Create new socket for each SYN (simulating spoofed source)
        m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
        m_socket->Bind();

        // Attempt connection (sends SYN) but never complete handshake
        m_socket->Connect(m_peer);

        m_packetsSent++;
        g_attackPacketsSent++;

        // Schedule next SYN packet
        Time interval = Seconds(1.0 / m_attackRate);
        ScheduleTransmit(interval);
    }

    Ptr<Socket> m_socket;
    Address m_peer;
    uint32_t m_packetsSent;
    uint32_t m_attackRate;
    EventId m_sendEvent;
    bool m_running;
};

// Simple ACL/Firewall implementation
class SimpleFirewall //: public Object
{
  public:
    SimpleFirewall()
        : m_blockedPackets(0),
          m_allowedPackets(0),
          m_enabled(false)
    {
    }

    void Enable() { m_enabled = true; }
    void Disable() { m_enabled = false; }

    // Add IP address to blocklist
    void BlockIPAddress(Ipv4Address addr)
    {
        m_blockedIPs.insert(addr);
        std::cout << "[FIREWALL] Blocked IP: " << addr << std::endl;
    }

    // Add IP subnet to blocklist
    void BlockIPSubnet(Ipv4Address network, Ipv4Mask mask)
    {
        m_blockedSubnets.push_back(std::make_pair(network, mask));
        std::cout << "[FIREWALL] Blocked subnet: " << network << "/" << mask << std::endl;
    }

    // Add port to blocklist
    void BlockPort(uint16_t port)
    {
        m_blockedPorts.insert(port);
        std::cout << "[FIREWALL] Blocked port: " << port << std::endl;
    }

    // Rate limiting per source IP
    void SetRateLimit(uint32_t packetsPerSecond)
    {
        m_rateLimit = packetsPerSecond;
        m_rateLimitEnabled = true;
    }

    // Check if packet should be dropped
    bool ShouldDropPacket(Ptr<const Packet> packet, Ipv4Address srcAddr, Ipv4Address dstAddr, uint16_t srcPort, uint16_t dstPort)
    {
        if (!m_enabled)
            return false;

        // Check IP blocklist
        if (m_blockedIPs.find(srcAddr) != m_blockedIPs.end())
        {
            m_blockedPackets++;
            return true;
        }

        // Check subnet blocklist
        for (auto& subnet : m_blockedSubnets)
        {
            if (subnet.second.IsMatch(srcAddr, subnet.first))
            {
                m_blockedPackets++;
                return true;
            }
        }

        // Check port blocklist
        if (m_blockedPorts.find(dstPort) != m_blockedPorts.end())
        {
            m_blockedPackets++;
            return true;
        }

        // Rate limiting
        if (m_rateLimitEnabled)
        {
            Time now = Simulator::Now();
            auto& record = m_rateLimitMap[srcAddr];

            // Reset counter if 1 second has passed
            if (now - record.lastReset >= Seconds(1.0))
            {
                record.packetCount = 0;
                record.lastReset = now;
            }

            record.packetCount++;

            if (record.packetCount > m_rateLimit)
            {
                m_blockedPackets++;
                return true; // Drop packet - rate limit exceeded
            }
        }

        m_allowedPackets++;
        return false;
    }

    uint32_t GetBlockedPackets() const { return m_blockedPackets; }
    uint32_t GetAllowedPackets() const { return m_allowedPackets; }

  private:
    struct RateLimitRecord
    {
        uint32_t packetCount = 0;
        Time lastReset = Seconds(0);
    };

    std::set<Ipv4Address> m_blockedIPs;
    std::vector<std::pair<Ipv4Address, Ipv4Mask>> m_blockedSubnets;
    std::set<uint16_t> m_blockedPorts;
    std::map<Ipv4Address, RateLimitRecord> m_rateLimitMap;

    uint32_t m_blockedPackets;
    uint32_t m_allowedPackets;
    bool m_enabled;
    bool m_rateLimitEnabled = false;
    uint32_t m_rateLimit = 100;
};


// Global firewall instance
//Ptr<SimpleFirewall> g_firewall = nullptr;
SimpleFirewall* g_firewall = nullptr;

// Packet filter callback for router
bool FirewallFilterCallback(Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol, const Address& from)
{
    if (!g_firewall || protocol != 0x0800) // 0x0800 = IPv4
        return true; // Allow non-IP packets

    // Extract IP header
    Ptr<Packet> copy = packet->Copy();
    Ipv4Header ipHeader;
    copy->RemoveHeader(ipHeader);

    Ipv4Address srcAddr = ipHeader.GetSource();
    Ipv4Address dstAddr = ipHeader.GetDestination();
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;

    // Extract port information based on protocol
    if (ipHeader.GetProtocol() == 17) // UDP
    {
        UdpHeader udpHeader;
        copy->PeekHeader(udpHeader);
        srcPort = udpHeader.GetSourcePort();
        dstPort = udpHeader.GetDestinationPort();
    }
    else if (ipHeader.GetProtocol() == 6) // TCP
    {
        TcpHeader tcpHeader;
        copy->PeekHeader(tcpHeader);
        srcPort = tcpHeader.GetSourcePort();
        dstPort = tcpHeader.GetDestinationPort();
    }

    // Check firewall rules
    bool shouldDrop = g_firewall->ShouldDropPacket(copy, srcAddr, dstAddr, srcPort, dstPort);

    return !shouldDrop; // Return true to allow, false to drop
}


int
main(int argc, char* argv[])
{
    // Command-line parameters
    bool enableVpn = true;
    double encryptionDelayUs = 50.0;  // microseconds
    double bandwidthReduction = 0.95;  // 5% reduction due to overhead
    
    CommandLine cmd;
    cmd.AddValue("enableVpn", "Enable VPN simulation (true/false)", enableVpn);
    cmd.AddValue("encryptionDelay", "Encryption delay in microseconds", encryptionDelayUs);
    cmd.AddValue("bandwidthReduction", "Bandwidth efficiency factor (0.0-1.0)", bandwidthReduction);
    cmd.Parse(argc, argv);

    // DDoS attack parameters
    bool enableDDoS = true;
    uint32_t numAttackers = 5;
    string attackType = "udp"; // "udp" or "syn"
    double attackRateMbps = 10.0;   // Mbps per attacker for UDP flood
    uint32_t synFloodRate = 1000;   // SYN packets per second per attacker

    cmd.AddValue("enableDDoS", "Enable DDoS attack simulation", enableDDoS);
    cmd.AddValue("numAttackers", "Number of attacking nodes", numAttackers);
    cmd.AddValue("attackType", "Attack type: 'udp' or 'syn'", attackType);
    cmd.AddValue("attackRate", "Attack rate in Mbps (for UDP flood)", attackRateMbps);
    cmd.AddValue("synRate", "SYN packets per second (for SYN flood)", synFloodRate);

    // Enable logging
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);
    LogComponentEnable("IPSecVPNSimulation", LOG_LEVEL_INFO);

    // ACL/Firewall parameters
    bool enableACL = true;
    bool blockAttackerIPs = true;
    bool enableRateLimit = true;
    uint32_t rateLimitPPS = 1000; // packets per second per IP

    cmd.AddValue("enableACL", "Enable Access Control List (firewall)", enableACL);
    cmd.AddValue("blockAttackerIPs", "Block known attacker IP addresses", blockAttackerIPs);
    cmd.AddValue("enableRateLimit", "Enable rate limiting per source IP", enableRateLimit);
    cmd.AddValue("rateLimit", "Rate limit in packets per second", rateLimitPPS);

    // Create three nodes
    NodeContainer nodes;
    nodes.Create(3);

    Ptr<Node> client = nodes.Get(0); // Client (VPN Endpoint 1)
    Ptr<Node> router = nodes.Get(1); // VPN Gateway/Router
    Ptr<Node> server = nodes.Get(2); // Server (VPN Endpoint 2)

    // Create eavesdropper node
    Ptr<Node> eavesdropper = CreateObject<Node>();

    // Create DDoS attacker nodes
    NodeContainer attackers;
    if (enableDDoS)
    {
       attackers.Create(numAttackers);
       cout << "\nCreating " << numAttackers << " DDoS attacker nodes...\n";
    }

    // Replace single server with server cluster
    NodeContainer serverCluster;
    serverCluster.Create(3);  // 3 anycast servers

    /*// Position them near each other
    for (uint32_t i = 0; i < 3; i++) {
       Ptr<MobilityModel> mobServer = serverCluster.Get(i)->GetObject<MobilityModel>();
       mobServer->SetPosition(Vector(15.0 + i*2, 15.0, 0.0));
    }*/

    // Calculate effective bandwidth after VPN overhead
    string effectiveDataRate = "5Mbps";
    if (enableVpn)
    {
        double baseBandwidth = 5.0; // Mbps
        double effectiveBandwidth = baseBandwidth * bandwidthReduction;
        effectiveDataRate = std::to_string(effectiveBandwidth) + "Mbps";
    }

    // Create point-to-point links with VPN-adjusted parameters
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue(effectiveDataRate));
    
    // Add extra delay for encryption/decryption if VPN enabled
    string totalDelay = "2ms";
    if (enableVpn)
    {
        double baseDelayMs = 2.0;
        double vpnDelayMs = encryptionDelayUs / 1000.0;
        double totalDelayMs = baseDelayMs + vpnDelayMs;
        totalDelay = std::to_string(totalDelayMs) + "ms";
    }
    p2p.SetChannelAttribute("Delay", StringValue(totalDelay));

    // Set MTU to account for IPSec overhead
    if (enableVpn)
    {
        // Standard MTU is 1500, reduce by IPSec overhead
        uint32_t standardMtu = 1500;
        uint32_t vpnMtu = standardMtu - IPSecNetDevice::GetOverhead();
        p2p.SetDeviceAttribute("Mtu", UintegerValue(vpnMtu));
    }

    // Link 1: client <-> router (VPN Tunnel 1)
    NodeContainer network1nodes(client, router);
    NetDeviceContainer network1devices = p2p.Install(network1nodes);

    // Link 2: router <-> server (VPN Tunnel 2)
    NodeContainer network2nodes(router, server);
    NetDeviceContainer network2devices = p2p.Install(network2nodes);

    // Install mobility model
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    Ptr<MobilityModel> mob0 = client->GetObject<MobilityModel>();
    Ptr<MobilityModel> mob1 = router->GetObject<MobilityModel>();
    Ptr<MobilityModel> mob2 = server->GetObject<MobilityModel>();

    mob0->SetPosition(Vector(5.0, 15.0, 0.0));
    mob1->SetPosition(Vector(10.0, 2.0, 0.0));
    mob2->SetPosition(Vector(15.0, 15.0, 0.0));


    // Position eavesdropper between client and router (man-in-the-middle position)
    MobilityHelper eavesdropperMobility;
    eavesdropperMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    eavesdropperMobility.Install(eavesdropper);
    Ptr<MobilityModel> mobEavesdropper = eavesdropper->GetObject<MobilityModel>();
    mobEavesdropper->SetPosition(Vector(7.5, 8.5, 0.0)); // Midpoint
    
    // Position attackers in a circle around the router (botnet simulation)
    if (enableDDoS)
    {
        MobilityHelper attackerMobility;
        attackerMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        attackerMobility.Install(attackers);

        double radius = 20.0;
        double angleStep = 2 * M_PI / numAttackers;

        for (uint32_t i = 0; i < numAttackers; i++)
        {
           double angle = i * angleStep;
           double x = 10.0 + radius * cos(angle); // Center at router position
           double y = 2.0 + radius * sin(angle);

           Ptr<MobilityModel> mobAttacker = attackers.Get(i)->GetObject<MobilityModel>();
           mobAttacker->SetPosition(Vector(x, y, 0.0));
        }
    }

    /*// Position them near each other
    for (uint32_t i = 0; i < 3; i++) {
       Ptr<MobilityModel> mobServer = serverCluster.Get(i)->GetObject<MobilityModel>();
       mobServer->SetPosition(Vector(15.0 + i*2, 15.0, 0.0));
    }*/

    // Install Internet stack
    InternetStackHelper stack;
    stack.Install(nodes);

    stack.Install (attackers);

    // Connect attackers to the router (simulating botnet from different locations)
    vector<NetDeviceContainer> attackerLinks;
    vector<Ipv4InterfaceContainer> attackerInterfaces;

    // Assign IP addresses
    Ipv4AddressHelper address1;
    address1.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer network1interfaces = address1.Assign(network1devices);

    Ipv4AddressHelper address2;
    address2.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer network2interfaces = address2.Assign(network2devices);

    // Install internet stack on all servers
    stack.Install(serverCluster);

    // Create links from router to each server
    NetDeviceContainer serverDevices[3];
    Ipv4InterfaceContainer serverInterfaces[3];

    /*for (uint32_t i = 0; i < 3; i++) {
        NodeContainer routerToServer(router, serverCluster.Get(i));
        serverDevices[i] = p2p.Install(routerToServer);

        // Assign SAME IP subnet to all
        Ipv4AddressHelper address;
        address.SetBase("10.1.2.0", "255.255.255.0");
        serverInterfaces[i] = address.Assign(serverDevices[i]);
     }*/

    for (uint32_t i = 0; i < 3; i++) {
       NodeContainer routerToServer(router, serverCluster.Get(i));
       serverDevices[i] = p2p.Install(routerToServer);

       // Each server gets unique subnet: 10.1.20.0, 10.1.21.0, 10.1.22.0
       Ipv4AddressHelper address;
       string subnet = "10.1." + std::to_string(20 + i) + ".0";
       address.SetBase(subnet.c_str(), "255.255.255.0");
       serverInterfaces[i] = address.Assign(serverDevices[i]);
    }

    // NOW install mobility on server cluster
    MobilityHelper serverMobility;
    serverMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    serverMobility.Install(serverCluster);

    // NOW position them
    for (uint32_t i = 0; i < 3; i++) {
       Ptr<MobilityModel> mobServer = serverCluster.Get(i)->GetObject<MobilityModel>();
       mobServer->SetPosition(Vector(15.0 + i*2, 15.0, 0.0));
    }


    if (enableDDoS)
    {
       PointToPointHelper attackerP2p;
       attackerP2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
       attackerP2p.SetChannelAttribute("Delay", StringValue("10ms"));

       for (uint32_t i = 0; i < numAttackers; i++)
        {
	   
           // Create link between attacker and router
           NodeContainer attackerRouterLink(attackers.Get(i), router);
           NetDeviceContainer devices = attackerP2p.Install(attackerRouterLink);
           attackerLinks.push_back(devices);

           // Assign IP addresses
           Ipv4AddressHelper attackerAddress;
           string baseAddress = "10.1." + std::to_string(10 + i) + ".0";
           attackerAddress.SetBase(baseAddress.c_str(), "255.255.255.0");

           Ipv4InterfaceContainer interfaces = attackerAddress.Assign(devices);
           attackerInterfaces.push_back(interfaces);

           cout << "   Attacker-" << (i+1) << ": " << interfaces.GetAddress(0)
                     << " -> Router: " << interfaces.GetAddress(1) << "\n";
       }
    }


    // Enable IP forwarding on router (VPN Gateway)
    Ptr<Ipv4> ipv4Router = router->GetObject<Ipv4>();
    ipv4Router->SetAttribute("IpForward", BooleanValue(true));

    // Configure static routing
    Ipv4StaticRoutingHelper staticRoutingHelper;

    Ptr<Ipv4StaticRouting> staticroutingclient =
        staticRoutingHelper.GetStaticRouting(client->GetObject<Ipv4>());
    staticroutingclient->AddNetworkRouteTo(Ipv4Address("10.1.2.0"),
                                       Ipv4Mask("255.255.255.0"),
                                       Ipv4Address("10.1.1.2"),
                                       1);

    Ptr<Ipv4StaticRouting> staticroutingserver =
        staticRoutingHelper.GetStaticRouting(server->GetObject<Ipv4>());
    staticroutingserver->AddNetworkRouteTo(Ipv4Address("10.1.1.0"),
                                       Ipv4Mask("255.255.255.0"),
                                       Ipv4Address("10.1.2.1"),
    				       1);

    /*// Add multiple routes to same destination with equal cost
    Ptr<Ipv4StaticRouting> routerRouting =
       staticRoutingHelper.GetStaticRouting(router->GetObject<Ipv4>());

    for (uint32_t i = 0; i < 3; i++) {
       routerRouting->AddNetworkRouteTo(
           Ipv4Address("10.1.2.0"),
           Ipv4Mask("255.255.255.0"),
           i + 2  // Different interface IDs for each server
       );
    }*/

    // Configure routing for server cluster - each server on its own subnet
    for (uint32_t i = 0; i < 3; i++)
    {
       Ptr<Ipv4StaticRouting> serverRouting =
           staticRoutingHelper.GetStaticRouting(serverCluster.Get(i)->GetObject<Ipv4>());

       // Route back to client network
       serverRouting->AddNetworkRouteTo(Ipv4Address("10.1.1.0"),
                                        Ipv4Mask("255.255.255.0"),
                                        serverInterfaces[i].GetAddress(0),
                                        1);
    }



    // Initialize and configure firewall
    if (enableACL)
    {
       g_firewall = new SimpleFirewall();
       g_firewall->Enable();

       cout << "\n[FIREWALL] Access Control List ENABLED\n";

       // Block attacker IP addresses
       if (enableDDoS && blockAttackerIPs)
       {
           cout << "[FIREWALL] Blocking attacker IP addresses...\n";
           for (uint32_t i = 0; i < numAttackers; i++)
           {
              g_firewall->BlockIPAddress(attackerInterfaces[i].GetAddress(0));
           }

           // Alternative: Block entire attacker subnets
           // for (uint32_t i = 0; i < numAttackers; i++)
           // {
           //     std::string subnet = "10.1." + std::to_string(10 + i) + ".0";
           //     g_firewall->BlockIPSubnet(Ipv4Address(subnet.c_str()), Ipv4Mask("255.255.255.0"));
           // }
       }

       // Enable rate limiting
       if (enableRateLimit)
       {
           cout << "[FIREWALL] Rate limiting enabled: " << rateLimitPPS << " packets/sec per IP\n";
           g_firewall->SetRateLimit(rateLimitPPS);
       }

       // Optional: Block specific ports
       // g_firewall->BlockPort(9); // Block UDP echo port

       cout << endl;
   }


    // Configure routing for attackers to reach the server
    if (enableDDoS)
    {
       for (uint32_t i = 0; i < numAttackers; i++)
       {
           Ptr<Ipv4StaticRouting> attackerRouting =
               staticRoutingHelper.GetStaticRouting(attackers.Get(i)->GetObject<Ipv4>());

           // Route to server network via the router interface on this attacker's link
           attackerRouting->AddNetworkRouteTo(Ipv4Address("10.1.2.0"),
                                               Ipv4Mask("255.255.255.0"),
                                               attackerInterfaces[i].GetAddress(1), // Router's IP on this link
                                               1);
       }
    }

    // Print configuration
    cout << "\n════════════════════════════════════════════════════════════\n";
    cout << "         IPSec VPN SIMULATION CONFIGURATION                 \n";
    cout << "════════════════════════════════════════════════════════════\n";
    cout << " VPN Status: " << (enableVpn ? "ENABLED " : "DISABLED") << "                                       \n";
    cout << "════════════════════════════════════════════════════════════\n";
    cout << " Network Topology:                                          \n";
    cout << "   Client :      " << network1interfaces.GetAddress(0) << "                       \n";
    cout << "   router (VPN Gateway) : " << network1interfaces.GetAddress(1) 
              << " | " << network2interfaces.GetAddress(0) << "          \n";
    cout << "   Server :      " << network2interfaces.GetAddress(1) << "                       \n";
    cout << "════════════════════════════════════════════════════════════\n";
    
    if (enableVpn)
    {
        cout << " IPSec Parameters (ESP Tunnel Mode):                       \n";
        cout << "   Encryption:       AES-256-CBC                            \n";
        cout << "   Authentication:   HMAC-SHA256                            \n";
        cout << "   Overhead:         " << IPSecNetDevice::GetOverhead() 
                  << " bytes per packet                      \n";
        cout << "   Effective MTU:    " << (1500 - IPSecNetDevice::GetOverhead()) 
                  << " bytes                              \n";
        cout << "   Encryption Delay: " << encryptionDelayUs << " μs                             \n";
        cout << "   Total Link Delay: " << totalDelay << "                                  \n";
        cout << "   Effective BW:     " << effectiveDataRate << "                              \n";
    }
    cout << "════════════════════════════════════════════════════════════\n\n";

    // Create UDP Echo Server
    uint16_t port = 9;
    UdpEchoServerHelper echoserver(port);
    ApplicationContainer serverapps = echoserver.Install(server);
    serverapps.Start(Seconds(1.0));
    serverapps.Stop(Seconds(10.0));

    ApplicationContainer serverApps;
    for (uint32_t i = 0; i < 3; i++) {
       UdpEchoServerHelper echoServer(9);
       ApplicationContainer App = echoServer.Install(serverCluster.Get(i));
       App.Start(Seconds(1.0));
       App.Stop(Seconds(10.0));
       serverApps.Add(App);
    }

    // Create UDP Echo Client
    //UdpEchoClientHelper echoclient(network2interfaces.GetAddress(1), port);
    // Target first server in cluster (10.1.20.2)
    UdpEchoClientHelper echoclient(serverInterfaces[0].GetAddress(1), port);

    echoclient.SetAttribute("MaxPackets", UintegerValue(5));
    echoclient.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    
    // Adjust packet size for VPN overhead
    uint32_t packetSize = enableVpn ? 1024 - IPSecNetDevice::GetOverhead() : 1024;
    echoclient.SetAttribute("PacketSize", UintegerValue(packetSize));

    
    ApplicationContainer clientapps = echoclient.Install(client);
    clientapps.Start(Seconds(2.0));
    clientapps.Stop(Seconds(10.0));

    // Install eavesdropper on network1 (client-router link)
    Ptr<EavesdropperApp> eavesdropperApp = CreateObject<EavesdropperApp>();
    eavesdropper->AddApplication(eavesdropperApp);

    // Enable promiscuous sniffing on the WAN link
    eavesdropperApp->SetPromiscuousCallback(network1devices.Get(0));
    eavesdropperApp->SetStartTime(Seconds(1.5));
    eavesdropperApp->SetStopTime(Seconds(10.5));

    // Install DDoS attack applications
    ApplicationContainer attackApps;
    if (enableDDoS)
    {
       //Ipv4Address targetAddress = network2interfaces.GetAddress(1); // Server address
       // Target first server in cluster
       Ipv4Address targetAddress = serverInterfaces[0].GetAddress(1);
       uint16_t targetPort = 9;

       if (attackType == "udp")
       {
           cout << "Launching UDP Flood Attack...\n";
           cout << "   Target: " << targetAddress << ":" << targetPort << "\n";
           cout << "   Attack Rate: " << attackRateMbps << " Mbps per attacker\n";
           cout << "   Total Attack Traffic: " << (attackRateMbps * numAttackers) << " Mbps\n\n";

           for (uint32_t i = 0; i < numAttackers; i++)
           {
               Ptr<DDoSAttackApp> attackApp = CreateObject<DDoSAttackApp>();
               attackApp->Setup(InetSocketAddress(targetAddress, targetPort),
                              512, // packet size
                              DataRate(std::to_string(attackRateMbps) + "Mbps"));

               attackers.Get(i)->AddApplication(attackApp);
               attackApp->SetStartTime(Seconds(3.0)); // Start after legitimate traffic
               attackApp->SetStopTime(Seconds(10.0));
               attackApps.Add(attackApp);
           }
       }
       else if (attackType == "syn")
       {
           cout << "Launching SYN Flood Attack...\n";
           cout << "   Target: " << targetAddress << ":" << targetPort << "\n";
           cout << "   SYN Rate: " << synFloodRate << " packets/sec per attacker\n";
           cout << "   Total SYN Rate: " << (synFloodRate * numAttackers) << " packets/sec\n\n";

           for (uint32_t i = 0; i < numAttackers; i++)
           {
               Ptr<SynFloodAttackApp> synAttackApp = CreateObject<SynFloodAttackApp>();
               synAttackApp->Setup(InetSocketAddress(targetAddress, targetPort), synFloodRate);

               attackers.Get(i)->AddApplication(synAttackApp);
               synAttackApp->SetStartTime(Seconds(3.0));
               synAttackApp->SetStopTime(Seconds(10.0));
               attackApps.Add(synAttackApp);
           }
       }
   }


    // Remove default queue discs first
    TrafficControlHelper tchUninstall;
    tchUninstall.Uninstall(network1devices);
    tchUninstall.Uninstall(network2devices);
    if (enableDDoS)
    {
       for (uint32_t i = 0; i < attackerLinks.size(); i++)
       {
           tchUninstall.Uninstall(attackerLinks[i]);
       }
    }

    // Now install custom queue disc with FifoQueueDisc
    TrafficControlHelper tch;
    tch.SetRootQueueDisc("ns3::FifoQueueDisc",
       "MaxSize", QueueSizeValue(QueueSize("50p"))); // Small queue to see drops during DDoS

    // Install on router interfaces
    QueueDiscContainer qdiscs1 = tch.Install(network1devices.Get(1)); // Router->Client direction
    QueueDiscContainer qdiscs2 = tch.Install(network2devices.Get(0)); // Router->Server direction

    // Install firewall packet filter on router interfaces
    if (enableACL && g_firewall)
    {
       // Install on router's interface facing network1 (where attackers connect)
       Ptr<NetDevice> routerDevice1 = network1devices.Get(1);
       routerDevice1->SetReceiveCallback(MakeCallback(&FirewallFilterCallback));

       // Optional: Also install on other router interfaces
       // Ptr<NetDevice> routerDevice2 = network2devices.Get(0);
       // routerDevice2->SetReceiveCallback(MakeCallback(&FirewallFilterCallback));
    }

    // NetAnim Configuration
    AnimationInterface anim("rouuter-static-routing3.xml");
    
    anim.UpdateNodeDescription(client, "VPN Client\n10.1.1.1");
    anim.UpdateNodeDescription(router, "VPN Gateway\n10.1.1.2|10.1.2.1");
    anim.UpdateNodeDescription(server, "VPN Server\n10.1.2.2");

    anim.UpdateNodeColor(client, 0, 255, 0);    // Green
    anim.UpdateNodeColor(router, 255, 165, 0);  // Orange
    anim.UpdateNodeColor(server, 0, 0, 255);    // Blue

    anim.UpdateNodeDescription(eavesdropper, "EAVESDROPPER\n(Attacker)");
    anim.UpdateNodeColor(eavesdropper, 255, 0, 0); // Red for attacker
    
    // Visualize attackers in NetAnim
    if (enableDDoS)
    {
       for (uint32_t i = 0; i < numAttackers; i++)
       {
           std::string label = "Attacker-" + std::to_string(i + 1);
           anim.UpdateNodeDescription(attackers.Get(i), label);
           anim.UpdateNodeColor(attackers.Get(i), 139, 0, 0); // Dark red for attackers
           anim.UpdateNodeSize(attackers.Get(i)->GetId(), 3, 3); // Smaller nodes
       }
    }

    // Enable packet capture
    p2p.EnablePcapAll("router-static-routing3");

    // Separate PCAP for eavesdropper analysis
    std::string pcapPrefix = enableVpn ? "eavesdrop-encrypted" : "eavesdrop-plaintext";
    p2p.EnablePcap(pcapPrefix, network1devices.Get(0), true); // promiscuous mode

    // Print routing tables
    Ptr<OutputStreamWrapper> routingStream =
        Create<OutputStreamWrapper>("router-static-routing3.routes", std::ios::out);
    staticRoutingHelper.PrintRoutingTableAllAt(Seconds(1.0), routingStream);

    // Track legitimate traffic for impact analysis
    clientapps.Get(0)->TraceConnectWithoutContext("Tx", MakeCallback(&LegitimatePacketSent));
    serverapps.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&LegitimatePacketReceived));

    // Run simulation
    Simulator::Stop(Seconds(11.0));
    
    cout << "Starting simulation...\n\n";
    Simulator::Run();
    Simulator::Destroy();

    cout << "\nâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n";
    cout << "           EAVESDROPPING ATTACK ANALYSIS                    \n";
    cout << "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n";

    if (!enableVpn)
    {
       cout << " VULNERABLE: Traffic is UNENCRYPTED!                    \n";
       cout << "   â€¢ Attacker can read: Usernames, passwords, credit cards  \n";
       cout << "   â€¢ All payload data is visible in plaintext              \n";
       cout << "   â€¢ IP addresses and routing info exposed                 \n";
       cout << "   â€¢ Check: " << pcapPrefix << ".pcap for captured data      \n";
    }
    else
    {
       cout << " PROTECTED: IPSec encryption active!                     \n";
       cout << "   â€¢ Payload encrypted with AES-256-CBC                     \n";
       cout << "   â€¢ Authentication prevents tampering (HMAC-SHA256)       \n";
       cout << "   â€¢ Attacker sees only encrypted gibberish                \n";
       cout << "   â€¢ Original IP headers hidden (ESP tunnel mode)          \n";
    }
    cout << "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n";

    // Performance analysis
    cout << "\n════════════════════════════════════════════════════════════\n";
    cout << "              SIMULATION COMPLETE                           \n";
    cout << "════════════════════════════════════════════════════════════\n";
    cout << " Output Files:                                              \n";
    cout << "   - router-static-routing3.xml (NetAnim)                     \n";
    cout << "   - router-static-routing3.routes (Routing tables)                      \n";
    cout << "   - router-static-routing3*.pcap (Packet captures)                     \n";
    cout << "════════════════════════════════════════════════════════════\n";
    cout << " Expected Performance Impact:                               \n";
    cout << "   • Latency increase: ~50-100 μs per packet                \n";
    cout << "   • Throughput reduction: ~3-5% (overhead + encryption)    \n";
    cout << "   • CPU overhead: ~10-15% (AES-256 encryption)             \n";
    cout << "   • MTU reduction: 58 bytes (ESP tunnel mode)              \n";
    cout << "════════════════════════════════════════════════════════════\n\n";

    // Calculate DDoS attack statistics
    double deliveryRatio = 0.0;
    double packetLossRate = 0.0;

    if (g_legitimatePacketsSent > 0)
    {
       deliveryRatio = (double)g_legitimatePacketsReceived / g_legitimatePacketsSent * 100.0;
       packetLossRate = (double)g_legitimatePacketsDropped / g_legitimatePacketsSent * 100.0;
    }

    if (enableDDoS)
    {
        cout << "\n════════════════════════════════════════════════════════════\n";
        cout << "           DDoS ATTACK IMPACT ANALYSIS                      \n";
        cout << "════════════════════════════════════════════════════════════\n";
        cout << " Attack Type: " << (attackType == "udp" ? "UDP Flood" : "SYN Flood") << "\n";
        cout << " Number of Attackers: " << numAttackers << "\n";

        if (attackType == "udp")
        {
           cout << " Total Attack Traffic: " << (attackRateMbps * numAttackers) << " Mbps\n";
        }
        else
        {
           cout << " Total SYN Rate: " << (synFloodRate * numAttackers) << " packets/sec\n";
        }

        cout << " Attack Packets Sent: " << g_attackPacketsSent << "\n";
        cout << "────────────────────────────────────────────────────────────\n";
        cout << " LEGITIMATE TRAFFIC IMPACT:\n";
        cout << "   Packets Sent:     " << g_legitimatePacketsSent << "\n";
        cout << "   Packets Received: " << g_legitimatePacketsReceived << "\n";
        cout << "   Packets Dropped:  " << g_legitimatePacketsDropped << "\n";
        cout << "   Delivery Ratio:   " << std::fixed << std::setprecision(2)
              << deliveryRatio << "%\n";
        cout << "   Packet Loss Rate: " << std::fixed << std::setprecision(2)
              << packetLossRate << "%\n";
        cout << "────────────────────────────────────────────────────────────\n";

        if (deliveryRatio < 50.0)
        {
           cout << "SEVERE IMPACT: Legitimate traffic heavily degraded!\n";
        }
        else if (deliveryRatio < 80.0)
        {
           cout << "MODERATE IMPACT: Noticeable service degradation\n";
        }
        else
        {
           cout << "MINIMAL IMPACT: Service relatively stable\n";
        }

        cout << "════════════════════════════════════════════════════════════\n";
   }

    if (enableACL && g_firewall)
    {
        cout << "\n════════════════════════════════════════════════════════════\n";
        cout << "           FIREWALL/ACL STATISTICS                          \n";
        cout << "════════════════════════════════════════════════════════════\n";
        cout << " Firewall Status: ACTIVE\n";
        cout << " Packets Blocked: " << g_firewall->GetBlockedPackets() << "\n";
        cout << " Packets Allowed: " << g_firewall->GetAllowedPackets() << "\n";

        double blockRate = 0.0;
        uint32_t totalPackets = g_firewall->GetBlockedPackets() + g_firewall->GetAllowedPackets();
        if (totalPackets > 0)
        {
           blockRate = (double)g_firewall->GetBlockedPackets() / totalPackets * 100.0;
        }

        cout << " Block Rate: " << std::fixed << std::setprecision(2) << blockRate << "%\n";
        cout << "────────────────────────────────────────────────────────────\n";

        if (g_firewall->GetBlockedPackets() > 0)
        {
            cout << "Firewall successfully blocked malicious traffic!\n";
        }
        else
        {
           cout << "No packets blocked (rules may need adjustment)\n";
        }

        cout << "════════════════════════════════════════════════════════════\n";
   }

    if (g_firewall)
    {
       delete g_firewall;
    }

    return 0;
}
