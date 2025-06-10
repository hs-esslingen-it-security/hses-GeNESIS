package inet.examples.genesis;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.visualizer.canvas.integrated.IntegratedCanvasVisualizer;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.ethernet.EthernetSwitch;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import ned.DatarateChannel;
import inet.node.tsn.TsnSwitch;
import inet.node.tsn.TsnDevice;
import inet.networks.base.TsnNetworkBase;

network GeNESISExport extends TsnNetworkBase
{
    types:
        channel fiberline extends DatarateChannel
        {
            delay = 1us;
            datarate = 512Mbps;
        }
        channel ethline extends DatarateChannel
        {
            delay = 50ns;
            datarate = 100Mbps;
        }
    submodules:
    connections:
}