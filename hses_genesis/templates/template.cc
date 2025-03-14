#include "ns3/applications-module.h"
#include "ns3/bridge-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
 
#include <fstream>
#include <iostream>
 
NS_LOG_COMPONENT_DEFINE("GeNESIS");
using namespace ns3;


void ReceivePacket(Ptr<Socket> socket) {
    while (socket->Recv()) {
        NS_LOG_INFO("Server received a packet!");
    }
}

void SendPacket(Ptr<Socket> socket, uint32_t packetSize, Time interval) {
    Ptr<Packet> packet = Create<Packet>(packetSize);
    socket->Send(packet);  // Send packet

    // Schedule next packet transmission
    Simulator::Schedule(interval, &SendPacket, socket, packetSize, interval);
} 

int main(int argc, char* argv[])
{
 bool verbose = true;
     if (verbose)
    {
        LogComponentEnable("GeNESIS", LOG_LEVEL_INFO);
    }
 
    int simDurationSeconds = 60;
 
    std::string csmaLinkDataRate = "100Mbps";
    std::string csmaLinkDelay = "500ns";

    // ======================================================================
    // Create the nodes.
    // ----------------------------------------------------------------------
    
    NS_LOG_INFO("INFO: Create nodes.");

    // create_nodes()

    // add_names()

    // ======================================================================
    // Create CSMA links to use for connecting LAN nodes together
    // ----------------------------------------------------------------------
 
    NS_LOG_INFO("L2: Create a " << csmaLinkDataRate << " " << csmaLinkDelay << " CSMA link for csma for LANs.");

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue(csmaLinkDataRate));
    csma.SetChannelAttribute("Delay", StringValue(csmaLinkDelay));
    
    // ----------------------------------------------------------------------
    // Connect the top LAN nodes together with csma links.
    // ----------------------------------------------------------------------
    
    NS_LOG_INFO("L2: Connect nodes together with half-duplex CSMA links.");
    
    // create_links()

    // ======================================================================
    // Create the list of NetDevices for each switch
    // ----------------------------------------------------------------------

    // create_bridges()
 
    // ======================================================================
    // Install bridging code on each switch
    // ----------------------------------------------------------------------

    BridgeHelper bridge;
    
    // install_bridges()
    
    // ======================================================================
    // Install the L3 internet stack (TCP/IP)
    // ----------------------------------------------------------------------
    InternetStackHelper ns3IpStack;
    
    // ======================================================================
    // Install the L3 internet stack on UDP endpoints
    // ----------------------------------------------------------------------
    
    NS_LOG_INFO("L3: Install the ns3 IP stack on udp client and server nodes.");
    
    // install_end_device_ip_stack()
    
    // ======================================================================
    // Install the L3 internet stack on routers
    // ----------------------------------------------------------------------
    NS_LOG_INFO("L3: Install the ns3 IP stack on routers.");

    // install_router_ip_stack()

    // ======================================================================
    // Assign LAN IP addresses
    // ----------------------------------------------------------------------
    NS_LOG_INFO("L3: Assign top LAN IP Addresses.");

    // assign_router_ips()

    // assign_device_ips()

    // ======================================================================
    // Calculate and populate routing tables
    // ----------------------------------------------------------------------
    NS_LOG_INFO("L3: Populate routing tables.");
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();
    int udpEchoPort = 60;

    UdpServerHelper server(udpEchoPort);
    Time interPacketInterval = Seconds(0.005);
    uint32_t packetSize = 1000;
    uint32_t maxPacketCount = (simDurationSeconds - 2.0) / 0.005;

    //install_udp()

    //install_tcp()

    Simulator::Stop(simDurationSeconds);
    Simulator::Run();
    Simulator::Destroy();

    return 0; 
}