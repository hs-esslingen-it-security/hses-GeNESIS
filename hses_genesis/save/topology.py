from ipaddress import ip_address, ip_network
from json import dumps
from matplotlib.pyplot import close, savefig
from networkx import Graph, draw, write_graphml, spring_layout
from os.path import join

from hses_genesis.utils.constants import GRAPH_FOLDER
from hses_genesis.utils.enum_objects import EDeviceRole, EParameterKey
    
def to_ietf(G : Graph, location, generated_packets = None):
    def prepare_packets(G : Graph, packets = None):
        if not packets:
            return []
        
        output = []
        for packet in packets:
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

        ietf_node = {
            'node_id' : dev.lower(),
            'services' : [service.to_dict() for service, _ in G.nodes[dev]['services']]
        }
        for key in ['role', 'ip', 'subnet', 'branch', 'layer']:
            if key == 'services':
                continue
            ietf_node[key] = G.nodes[dev][key]

        for enum_key in ['default_action', 'role']:
            ietf_node[enum_key] = G.nodes[dev][enum_key].name if enum_key in G.nodes[dev] else '' 
        
        ietf_node['ruleset'] = G.nodes[dev]['ruleset'] if 'ruleset' in G.nodes[dev] else []
        ietf_node['packets'] = [] if generated_packets == None or dev not in generated_packets else prepare_packets(generated_packets[dev])
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
        
    with open(join(location, GRAPH_FOLDER, 'ietf-topology.yang.json'), 'w') as file:
        file.write(dumps(ietf_topology, indent=4))

def to_graphml(G, location, file_name = 'graph.graphml'):
    g_copy = G.copy()
    for n, data in g_copy.nodes(data = True):
        if 'services' in data.keys():
            g_copy.nodes[n]['services'] = ','.join([service.name for service, _ in data['services']])

        if data['role'] == EDeviceRole.ROUTER:
            g_copy.nodes[n]['subnet'] = ','.join(g_copy.nodes[n]['subnet'])
            g_copy.nodes[n]['ip'] = ','.join(g_copy.nodes[n]['ip'])
        
        for key, joiner in [['ruleset', '\n'], ['default_action', None], ['role', None]]:
            if key in g_copy.nodes[n].keys():
                if joiner != None:
                    g_copy.nodes[n][key] = joiner.join([str(v) for v in g_copy.nodes[n][key]])
                else:
                    g_copy.nodes[n][key] = g_copy.nodes[n][key].name

    write_graphml(g_copy, join(location, file_name))

def to_image(G, location):
    g_copy = G.copy()
    color_map, size_map = [], []
    for n in g_copy.nodes:
        role = EDeviceRole.from_device_id(n)

        if role == EDeviceRole.PORT:
            color_map.append('lightgray')
            size_map.append(50)
        elif role == EDeviceRole.ROUTER:
            color_map.append('blue')
            size_map.append(200)
        elif role == EDeviceRole.SWITCH:
            color_map.append('green')
            size_map.append(150)
        else:
            color_map.append('yellow')
            size_map.append(100)

    draw(g_copy, node_color=color_map, node_size=size_map, with_labels=False, pos=spring_layout(g_copy))
    savefig(join(location, f'graph.png'))
    savefig(join(location, f'graph.jpg'))
    close()