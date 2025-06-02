from ipaddress import ip_address, ip_network
from json import dumps
from typing import Optional
from warnings import warn
from matplotlib.pyplot import close, savefig
from networkx import Graph, draw, write_graphml, spring_layout
from os.path import join

from hses_genesis.utils.constants import ACL_RULE_COUNT, NS3_FOLDER, OMNET_FOLDER, ZIMPL_FOLDER
from hses_genesis.utils.enum_objects import EDeviceRole, EParameterKey
from hses_genesis.utils.functions import load_resource

def prepare_topology(G):
        g_copy = G.copy()
        for n, data in g_copy.nodes(data = True):
            if 'services' in data.keys():
                g_copy.nodes[n]['services'] = ','.join([service.name for service in data['services']])

            for key, joiner in [['subnet', ','], ['ip', ','], ['ruleset', '\n'], ['default_action', None], ['role', None]]:
                data = g_copy.nodes[n]
                if key in data.keys():
                    value = data[key]
                    if not isinstance(value, str):
                        if joiner != None:
                            g_copy.nodes[n][key] = joiner.join([str(v) for v in data[key]])
                        else:
                            g_copy.nodes[n][key] = data[key].name
        return g_copy

def to_ietf(G : Graph, location, generated_packets : Optional[dict] = None):
    def prepare_packets(G : Graph, packets : Optional[dict] = None):
        if not packets:
            return []
        
        output = []
        for _, packet in packets.items():
            output.append(
                {
                    EParameterKey.SRC.value : G.nodes(packet[EParameterKey.SRC.value])['ip'],
                    EParameterKey.DST.value : G.nodes(packet[EParameterKey.DST.value])['ip'],
                    EParameterKey.PROTOCOL.value : packet[EParameterKey.PROTOCOL.value],
                    EParameterKey.SRC_PORT.value : packet[EParameterKey.SRC_PORT.value],
                    EParameterKey.DST_PORT.value : packet[EParameterKey.DST_PORT.value],
                    'packet_size' : packet['packet_size'],
                    'packets_per_second' : packet['packets_per_second']
                }
            )
        return output
    
    ietf_nodes = []
    for dev in G.nodes:
        if EDeviceRole.from_device_id(dev) == EDeviceRole.PORT:
            continue

        node_data = G.nodes[dev]

        service_values = [{'name' : service.name, 'protocols' : service.value.protocols, 'ports' : service.value.protocols} for service in node_data['services']]

        ietf_node = {
            'node_id' : dev.lower(),
            'services' : service_values
        }

        for key in ['role', 'ip', 'subnet', 'branch', 'layer']:
            if key == 'services':
                continue
            ietf_node[key] = node_data[key]

        for enum_key in ['default_action', 'role']:
            ietf_node[enum_key] = node_data[enum_key].name if enum_key in node_data else '' 
        
        ietf_node['ruleset'] = node_data['ruleset'] if 'ruleset' in node_data else []
        ietf_node['packets'] = list() if (generated_packets == None) else prepare_packets(generated_packets.get(dev, None))
        if EDeviceRole.from_device_id(dev) not in [EDeviceRole.ROUTER, EDeviceRole.SWITCH]:
            ietf_node['termination_point'] = [f'{dev.lower()}#0']
        else:
            ietf_node['termination_point'] = [f'{dev.lower()}#{i}' for i in range(len(list(G.neighbors(dev))))]

        ietf_nodes.append(ietf_node)

    ietf_links = []
    for s, d in G.edges:
        ietf_link = {
            'source': {
                'source-node' : s.split('#')[0].lower(),
                'source-tp' : s.lower() if EDeviceRole.from_device_id(s) == EDeviceRole.PORT else f'{s.lower()}#0'
            },
            'destination' : {
                'destination-node' : d.split('#')[0].lower(),
                'source-tp' : d.lower() if EDeviceRole.from_device_id(d) == EDeviceRole.PORT else f'{d.lower()}#0'
            }
        }
        ietf_links.append(ietf_link)

    ietf_topology = {
        'ietf-network:networks' : {
        'network': [
                {
                    'network-types': {},
                    'network-id': 'ietf-topology',
                    'node': ietf_nodes,
                    'ietf-network-topology:link': ietf_links
                }
            ]
        }
    }
        
    with open(join(location, 'ietf-topology.yang.json'), 'w') as file:
        file.write(dumps(ietf_topology, indent=4))

def to_zimpl_parsable(G, location):
    zimpl_location = join(location, ZIMPL_FOLDER)
    with open(join(zimpl_location, 'vertices.txt'), 'w') as file:
        file.write('# <id,ip,container_capacity>\n')
        for node, data in G.nodes(data = True):
            if data['role'] == EDeviceRole.ROUTER:
                for ip in data["ip"]:
                    file.write(f'{node},{int(ip_address(ip))},{-1}\n')
            else:
                file.write(f'{node},{int(ip_address(data["ip"]))},{ACL_RULE_COUNT if data["role"] == EDeviceRole.SWITCH else 0}\n')
    
    with open(join(zimpl_location, 'edges.txt'), 'w') as edges_file, open(join(zimpl_location, 'ip_edges.txt'), 'w') as ip_edges_file:
        edges_file.write('# <src_id,dst_id>weight\n')
        ip_edges_file.write('# <src_ip,dst_ip>weight\n')
        for (src, dst) in G.edges:
            edges_file.write(f'{src},{dst},1\n')
            src_ips, dst_ips = G.nodes[src]["ip"], G.nodes[dst]["ip"]
            src_ips = [src_ips] if not isinstance(src_ips, list) else src_ips
            dst_ips = [dst_ips] if not isinstance(dst_ips, list) else dst_ips
            for src_ip in src_ips:
                for dst_ip in dst_ips:
                    ip_edges_file.write(f'{int(ip_address(src_ip))},{int(ip_address(dst_ip))},1\n')

def to_omnet_ned(G : Graph, location):
    submodules = ['\tconfigurator: Ipv4NetworkConfigurator { }\n', '\tvisualizer: IntegratedCanvasVisualizer { }\n']
    interfaces = []
    for node, data in G.nodes(data=True):
        extension = '{ }'
        if data['role'] == EDeviceRole.ROUTER:
            role = 'Router'
        elif data['role'] == EDeviceRole.SWITCH:
            role = 'EthernetSwitch'
        else:
            role = 'StandardHost'
            extension = '{' + f'@display("i=device/pc");' + '}'

        submodules.append(f'\t\t{node}: {role} {extension}\n')

        ips = [(data['ip'], data['subnet'])] if isinstance(data['ip'], str) else [(ip, data['subnet'][i]) for i, ip in enumerate(data['ip'])]

        for ip, subnet in ips:
            interface = {
                'hosts' : node,
                'address' : ip,
                'netmask' : str(ip_network(subnet, False).netmask)
            }

            if data['role'] == EDeviceRole.ROUTER:
                target_hosts = [n for n, d in G.nodes(data=True) if n != node and d['subnet'] == subnet and d['role'] in EDeviceRole.hosts()]
                if len(target_hosts) == 0:
                    warn(f'Invalid Configuration Exception: Cannot determine interface target for {node} in interface {subnet} ({[n for n, d in G.nodes(data=True) if d["subnet"] == subnet]}). You probably defined a layer without any end devices.')
                    continue

                interface['towards'] = target_hosts[0]

            interfaces.append(interface)
            

    connections = []
    for (src, dst) in G.edges:
        connections.append(f'\t\t{src}.ethg++ <--> ethline <--> {dst}.ethg++;\n')

    lines = []
    with open(load_resource('templates', 'template.ned'), 'r') as f:
        for line in f.readlines():
            lines.append(line)
            if 'submodules:' in line:
                lines.extend(submodules)
            elif 'connections:' in line:
                lines.extend(connections)

    with open(join(location, OMNET_FOLDER, 'graph.ned'), 'w') as f:
        f.writelines(lines)

    with open(join(location, OMNET_FOLDER, 'interfaces.xml'), 'w') as f:
        f.write('<config>\n')
        for interface in interfaces:
            values = ['\t<interface']
            for key, value in interface.items():
                values.append(f'{key}="{value}"')
            f.write(' '.join(values) + '/>\n')
        f.write('</config>')

def to_graphml(G, location, file_name = 'graph.graphml'):
    write_graphml(prepare_topology(G), join(location, file_name))

def to_ns3_cc(G : Graph, location, generated_packets : Optional[dict]):

    def create_nodes(G : Graph):
        return [f'Ptr<Node> {node} = CreateObject<Node>();' for node in G.nodes]
    
    def add_names(G : Graph):
        return [f'Names::Add("{node}", {node});' for node in G.nodes]
    
    def create_links(G : Graph):
        lines = []
        for src, dst in G.edges():
            link = f'link_{src}_{dst}'
            lines.append(f'NetDeviceContainer {link} = csma.Install(NodeContainer({src}, {dst}));')
        return lines

    def create_bridges(G : Graph):
        lines = []
        links = {}

        for src, dst in G.edges():
            if G.nodes[src]['role'] != EDeviceRole.SWITCH:
                continue
            if src not in links.keys():
                links[src] = []
            links[src].append(f'link_{src}_{dst}')

        for switch, links in links.items():
            lines.append('')
            lines.append(f'NetDeviceContainer {switch}nd;')
            for link in links:
                lines.append(f'{switch}nd.Add({link}.Get(0));')
        return lines

    def install_bridges(G : Graph):
        return [f'bridge.Install({node}, {node}nd);' for node, data in G.nodes(data=True) if data['role'] == EDeviceRole.SWITCH]

    def install_end_device_ip_stack(G : Graph):
        end_points = ', '.join([node for node, data in G.nodes(data = True) if data['role'] in EDeviceRole.hosts()])
        return [f'NodeContainer endpointNodes({end_points});', 'ns3IpStack.Install(endpointNodes);']
    
    def install_router_ip_stack(G : Graph):
        routers = ', '.join([node for node, data in G.nodes(data = True) if data['role'] == EDeviceRole.ROUTER])
        return [f'NodeContainer routerNodes({routers});', 'ns3IpStack.Install(routerNodes);']
    
    def assign_router_ips(G : Graph):
        lines = []
        introduced_routers = []
        net_devices = []
        for edge in G.edges:
            routers = [(router, G.nodes[router]) for router in edge if G.nodes[router]['role'] == EDeviceRole.ROUTER]
            if len(routers) != 1:
                continue

            router, data = routers[0]
            lines.append('')

            router_occurence = int(router in introduced_routers)
            net_device_name = f'{router}_{router_occurence}'
            ipv4_name = f'ipv4proto{router}'
            interface_name = f'{router}_{router_occurence}interface'
            net_devices.append((interface_name, ipv4_name))
            
            lines.append(f'Ptr<NetDevice> {net_device_name}nd = link_{edge[0]}_{edge[1]}.Get({list(edge).index(router)});')
            
            if router not in introduced_routers:
                introduced_routers.append(router)
                lines.append(f'Ptr<Ipv4> {ipv4_name} = {router}->GetObject<Ipv4>();')

            lines.append(f'uint32_t {interface_name} = {ipv4_name}->GetInterfaceForDevice({net_device_name}nd);')
            lines.append(f'if ({interface_name} == -1)' + '{' f'{interface_name} = {ipv4_name}->AddInterface({net_device_name}nd);' + '}')
            
            subnet = G.nodes[[other for other in edge if other != router][0]]['subnet']
            ip = data['ip'][list(data['subnet']).index(subnet)]

            ipv4Mask = str(subnet).split('/')[-1]
            ip4Addr_name = f'ipv4Addr{edge[0]}{edge[1]}'
            lines.append(f'Ipv4InterfaceAddress {ip4Addr_name} = Ipv4InterfaceAddress(Ipv4Address("{ip}"), Ipv4Mask("/{ipv4Mask}"));')
            lines.append(f'{ipv4_name}->AddAddress({interface_name}, {ip4Addr_name});')

        lines.append('')

        for interface, ipv4_name in set(net_devices):
            lines.append(f'{ipv4_name}->SetUp({interface});')
        return lines

    def assign_device_ips(G : Graph):
        lines = []
        for node, data in G.nodes(data=True):
            if data['role'] not in EDeviceRole.hosts():
                continue
            lines.append('')
            lines.append(f'Ptr<NetDevice> {node}NetDevice= {node}->GetDevice(0);')
            lines.append(f'Ptr<Ipv4> ipv4proto{node} = {node}->GetObject<Ipv4>();')
            lines.append(f'uint32_t {node}interface = ipv4proto{node}->AddInterface({node}NetDevice);')
            ip, ipv4Mask = data['ip'], str(data['subnet']).split('/')[-1]
            lines.append(f'Ipv4InterfaceAddress ipv4Addr{node} = Ipv4InterfaceAddress(Ipv4Address("{ip}"), Ipv4Mask("/{ipv4Mask}"));')
            lines.append(f'ipv4proto{node}->AddAddress({node}interface, ipv4Addr{node});')
            lines.append(f'ipv4proto{node}->SetUp({node}interface);')
        return lines
    
    def install_udp(G : Graph, packet_map : dict):
        def add_servers(udp_nodes):
            lines = ['']
            lines.append(f'NodeContainer udpNodes({", ".join(udp_nodes)});')
            lines.append(f'ApplicationContainer serverApp = server.Install(udpNodes);')
            lines.append(f'serverApp.Start(Seconds(0.5));')
            lines.append(f'serverApp.Stop(Seconds(simDurationSeconds));')
            lines.append(f'serverApp.Stop(Seconds(simDurationSeconds));')
            return lines

        def add_sink(node, server_ip, server_index):
            lines = []
            lines.append('')
            prefix = f'{node}_{server_index}'
            lines.append(f'UdpClientHelper client{prefix}(Ipv4Address("{server_ip}"), udpEchoPort);')
            for key, value in [('MaxPackets', 'UintegerValue()'), ('Interval', 'TimeValue(interPacketInterval)'), ('PacketSize', 'UintegerValue(packetSize)')]:
                lines.append(f'client{prefix}.SetAttribute("{key}", {value});')
            lines.append(f'ApplicationContainer {prefix}ClientApp = client{prefix}.Install({node});')
            lines.append(f'{prefix}ClientApp.Start(Seconds(0.5));')
            lines.append(f'{prefix}ClientApp.Stop(Seconds(simDurationSeconds));')
            return lines

        udp_packets = [packet for _, packets in packet_map.items() for packet in packets if packet['Protocol'] == 'udp']
        servers = set([packet['DestinationName'] for packet in udp_packets])
        lines = add_servers(servers)
        for i, server in enumerate(servers):
            related_sinks = set([(packet['SourceName'], packet[f'DestinationIp']) for packet in udp_packets if packet['DestinationName'] == server])
            for node, server_ip in related_sinks:
                lines += add_sink(node, server_ip, i)
        
        return lines

    def install_tcp(G : Graph, packet_map : dict):
        def add_server(node, ip, port, prefix):
            lines = ['']
            lines.append(f'Ptr<Socket> {prefix}ServerSocket = Socket::CreateSocket({node}, TcpSocketFactory::GetTypeId());')
            lines.append(f'InetSocketAddress {prefix}ServerAddress = InetSocketAddress(Ipv4Address("{ip}"), {port});')
            lines.append(f'{prefix}ServerSocket->Bind({prefix}ServerAddress);')
            lines.append(f'{prefix}ServerSocket->Listen();')
            lines.append(f'{prefix}ServerSocket->SetRecvCallback(MakeCallback(&ReceivePacket));')
            return lines

        def add_socket(node_id, server, prefix, message_length = 1024, send_interval = 0.5):
            lines = ['']
            lines.append(f'Ptr<Socket> {prefix}ClientSocket = Socket::CreateSocket({node_id}, TcpSocketFactory::GetTypeId());')
            lines.append(f'{prefix}ClientSocket->Connect({server}ServerAddress);')
            lines.append(f'Simulator::Schedule(Seconds(2.0), &SendPacket, {prefix}ClientSocket, {message_length}, Seconds({send_interval}));')
            return lines
        
        tcp_packets = [packet for _, packets in packet_map.items() for packet in packets if packet['Protocol'] == 'tcp']

        servers = set([(packet['DestinationName'], packet['DestinationName']) for packet in tcp_packets])
        lines = []
        for i, (server, port) in enumerate(servers):
            server_prefix = f'{server}_{port}'
            lines += add_server(server, G.nodes[server]['ip'], port, server_prefix)

            packets = [packet for packet in tcp_packets if packet['DestinationName'] == server]
            for j, packet in enumerate(packets):
                node = packet['SourceName']
                prefix = f'{node}_{i}_{j}'
                send_interval = round(1/ packet['PacketsPerSecond'], 3)
                message_length = packet['PacketSize']
                lines += add_socket(node, server_prefix, prefix, message_length, send_interval)

        return lines

    with open(load_resource('templates', 'template.cc'), 'r') as resource_file, open(join(location, NS3_FOLDER, 'genesis.cc'), 'w') as output_file:
        for line in resource_file.readlines():
            output_file.write(line)
            for func in [create_nodes, add_names, create_links, create_bridges, install_bridges, install_end_device_ip_stack, install_router_ip_stack, assign_router_ips, assign_device_ips]:
                if func.__name__ in line:
                    output_file.writelines(map(lambda x: f'\t{x}\n', func(G)))

            if generated_packets:
                for func in [install_udp, install_tcp]:
                    if func.__name__ in line:
                        output_file.writelines(map(lambda x: f'\t{x}\n', func(G, generated_packets)))

def to_image(G, location, seed=None):
    g_copy = G.copy()
    color_map, size_map, border_map, shape_map = [], [], [], []
    for n in g_copy.nodes:
        role = EDeviceRole.from_device_id(n)

        if role == EDeviceRole.PORT:
            color_map.append('lightgray')
            size_map.append(50)
        elif role == EDeviceRole.ROUTER:
            color_map.append('black')
            border_map.append('black')
            size_map.append(200)
        elif role == EDeviceRole.SWITCH:
            color_map.append('white')
            border_map.append('black')
            size_map.append(150)
        elif role == EDeviceRole.CONTROLLER:
            color_map.append('#F8CECC')
            border_map.append('#B85450')
            shape_map.append('d')
            size_map.append(100)
        elif role == EDeviceRole.SERVER:
            color_map.append('#DAE8FC')
            border_map.append('#6C8EBF')
            shape_map.append('o')
            size_map.append(100)
        else:
            border_map.append('#D6B656')
            color_map.append('#FFF2CC')
            shape_map.append('o')
            size_map.append(100)

    draw(g_copy, node_color=color_map, node_size=size_map, edgecolors=border_map, with_labels=False, pos=spring_layout(g_copy, seed=seed))
    savefig(join(location, f'graph_unlabeled.png'), dpi=300)
    draw(g_copy, node_color=color_map, node_size=size_map, edgecolors=border_map, with_labels=True, pos=spring_layout(g_copy, seed=seed))
    savefig(join(location, f'graph_labeled.png'), dpi=300)
    close()
