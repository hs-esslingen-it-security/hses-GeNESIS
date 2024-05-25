from json import dumps
from math import ceil, sqrt
from random import Random
from matplotlib.pyplot import savefig
from networkx import Graph, compose, connected_components, cycle_graph, draw, grid_2d_graph, path_graph, relabel_nodes, star_graph, write_graphml
from enum_objects import EDeviceRole, ENetworkLayer, EPacketDecision, EService, ESubnetTopologyType
from config_parser import LayerDefinitionConfig, LayerDeviceCountConfig
from os.path import join

class TopologyGenerator():
    def __init__(self, seed : int, range_resolution_seed) -> None:
        self.existing_devices = []
        self.existing_subnets = []
        self.random = Random(seed)
        self.range_resolution_seed = range_resolution_seed

    def print_graph_info(self, G : Graph):
        print('--- GRAPH INFORMATION ---')
        print(f'Number of nodes:\t \t{len(G.nodes)}')
        print(f'\tof which ports:\t \t{len([n for n in G.nodes if "#" in n])}')
        print(f'\tof which routers:\t{len([n for n in G.nodes if "#" not in n and EDeviceRole.from_device_id(n) == EDeviceRole.ROUTER])}')
        print(f'\tof which switches:\t{len([n for n in G.nodes if "#" not in n and EDeviceRole.from_device_id(n) == EDeviceRole.SWITCH])}')
        print(f'\tof which end devices:\t{len([n for n in G.nodes if "#" not in n and EDeviceRole.from_device_id(n) not in [EDeviceRole.SWITCH, EDeviceRole.ROUTER]])}')
        print(f'Number of edges:\t \t{len(G.edges)}')
        print(f'Number of subnets:\t \t{len(list(set([G.nodes[n]["subnet"] for n in G.nodes if "#" not in n])))}')
        print(f'Number of subgraphs:\t \t{len(list(connected_components(G)))} (should always be 1)')
        print('-------------------------')

    def generate_device(self, device_role : EDeviceRole, initial_index = 0):
        index = initial_index
        while f'{device_role.value}{index}' in self.existing_devices:
            index += 1
        self.existing_devices.append(f'{device_role.value}{index}')
        return f'{device_role.value}{index}'
    
    def add_ports(self, G : Graph, devices_per):
        devices = [n for n in G.nodes if EDeviceRole.from_device_id(n) in [EDeviceRole.SWITCH, EDeviceRole.ROUTER]]
        for device in devices:
            neighbours = list(G.neighbors(device))
            G.remove_node(device)
            ports = [f'{device}#{i}' for i in range(devices_per + len(neighbours))]
            extended_device = star_graph([device] + ports)
            G = compose(G, extended_device)
            [G.add_edge(n, ports[i]) for i, n in enumerate(neighbours)]
        return G

    def assign_node_informations(self, G : Graph, layer : ENetworkLayer, branch_id : str):
        if len(G.nodes) > 255:
            raise Exception('Too many devices in a single subnet! Only 254 devices are supported.')

        net = 0
        while f'192.168.{net}.0/24' in self.existing_subnets:
            net+=1

        if net > 255:
            raise Exception('IP overflow!')
        self.existing_subnets.append(f'192.168.{net}.0/24')
        
        for i, device in enumerate(G.nodes):
            device_role = EDeviceRole.from_device_id(device)
            G.nodes[device]['layer'] = layer.name
            G.nodes[device]['branch'] = branch_id
            G.nodes[device]['subnet'] = f'192.168.{net}.0/24'
            G.nodes[device]['ip'] = f'192.168.{net}.{i + 1}'
            G.nodes[device]['role'] = device_role.name
            G.nodes[device]['services'] =  EService.from_role(device_role, self.random)
            if device_role == EDeviceRole.ROUTER:
                G.nodes[device]['default_action'] = EPacketDecision.DROP
                G.nodes[device]['ruleset'] = []
        return G

    def generate_subnet(self, layer_type_config : LayerDeviceCountConfig, layer_definition : LayerDefinitionConfig, additional_switches : int, branch_id : str) -> Graph:
        values = [e for e in ESubnetTopologyType]
        value_percentages = list(map(lambda x: float(layer_definition.TOPOLOGY_DISTRIBUTION[x]), values))
        if all([v == 0 for v in value_percentages]):
            value_percentages = list(map(lambda _: 1, value_percentages))
        subnet_type = self.random.choices(values, weights=value_percentages, k = 1)[0]
        devices = [self.generate_device(EDeviceRole.SWITCH, index) for index in range(layer_definition.SWITCH_COUNT.resolve(self.range_resolution_seed) + additional_switches)]
        if branch_id != '0':
            redundancy_types = [ESubnetTopologyType.RING, ESubnetTopologyType.MESH]
            if subnet_type in redundancy_types:
                devices.extend([self.generate_device(EDeviceRole.ROUTER) for _ in range(2)])
            else:
                devices.extend([self.generate_device(EDeviceRole.ROUTER)])

        center_node = None
        if subnet_type == ESubnetTopologyType.RING:
            G = cycle_graph(devices)
        elif subnet_type == ESubnetTopologyType.LINE:
            G = path_graph(devices)
        elif subnet_type == ESubnetTopologyType.STAR:
            center_node = devices[0]
            G= star_graph(devices)
        else:
            n = ceil(sqrt(len(devices)))
            G = grid_2d_graph(n, n)
            mapping = {}
            marked_to_delete = []
            for i, node in enumerate(G.nodes):
                if i + 1 > len(devices):
                    marked_to_delete.append(node)
                else:
                    mapping[node] = devices[i]
            G.remove_nodes_from(marked_to_delete)
            G = relabel_nodes(G, mapping)

        possible_device_owners = [s for s in G.nodes if EDeviceRole.from_device_id(s) == EDeviceRole.SWITCH and (s != center_node if center_node else True)]
        if len(possible_device_owners) == 0:
            raise Exception('InvalidConfigurationException: Layer instance without switches generated. Most likely your configuration file does not specify a switch_count in the last layer_definition.')

        min_device_requirements = layer_type_config.LAYER_DEFINITIONS[layer_definition.LAYER_CLASS]
        
        controller_owner, server_owner = [], []
        for key, collection in [(EDeviceRole.CONTROLLER, controller_owner), (EDeviceRole.SERVER, server_owner)]:
            resolved_value = min_device_requirements[key].resolve(self.range_resolution_seed)
            if resolved_value > 0:
                sample_size = len(possible_device_owners)
                if (sample_size - resolved_value) > 0:
                    collection.extend(self.random.sample(possible_device_owners, k = resolved_value))
                else:
                    collection.extend(possible_device_owners)

        device_count = layer_definition.DEVICE_PER_SWITCH.resolve(self.range_resolution_seed)
        for i, switch in enumerate(possible_device_owners):
            tmp_device_count = device_count
            if switch in controller_owner:
                device = self.generate_device(EDeviceRole.CONTROLLER)
                G.add_node(device)
                G.add_edge(device, switch)
                tmp_device_count -= 1
            
            if switch in server_owner:
                device = self.generate_device(EDeviceRole.SERVER)
                G.add_node(device)
                G.add_edge(device, switch)
                tmp_device_count -= 1

            if tmp_device_count <= 0:
                continue

            for j in range(tmp_device_count):
                device_choices = [t for t in [EDeviceRole.IT_END_DEVICE, EDeviceRole.OT_END_DEVICE] if min_device_requirements[t].resolve(self.range_resolution_seed) > 0]
                if len(device_choices) == 0:
                    continue
                device = self.generate_device(self.random.choice(device_choices), i + j)
                G.add_node(device)
                G.add_edge(device, switch)

        G = self.add_ports(G, device_count)
        return self.assign_node_informations(G, subnet_type, branch_id)

    def generate_network(self, layer_device_count_configuration : LayerDeviceCountConfig, layer_definitions : list[LayerDefinitionConfig], i = 0, branch = '0'):
        """
        The amount of switches per subnet/layer is dependant on its specified dimension as well as 2 * the number of child/lower layers.
        The additional switches are necessary, since every router has to have a connectable switch in an upper layer.
        """
        layer_definition = layer_definitions[i]
        next_layer = layer_definitions[i + 1] if i < len(layer_definitions) - 1 else None
        next_layer_dimension = next_layer.COUNT.resolve(self.range_resolution_seed)  if next_layer else 0
        upper_layer = self.generate_subnet(layer_device_count_configuration, layer_definition, additional_switches = 2 * next_layer_dimension, branch_id=branch)

        upper_switches = [n for n in upper_layer if EDeviceRole.from_device_id(n) == EDeviceRole.SWITCH]
        self.random.shuffle(upper_switches)

        if next_layer:
            for j in range(next_layer_dimension):
                next_branch = f'{branch}.{j}'
                lower_layer = self.generate_network(layer_device_count_configuration, layer_definitions, i + 1, next_branch)
                lower_routers = [r for r in lower_layer.nodes if EDeviceRole.from_device_id(r) == EDeviceRole.ROUTER and lower_layer.nodes[r]['branch'] == next_branch]
                upper_layer : Graph = compose(upper_layer, lower_layer)
                [upper_layer.add_edge(r, upper_switches[(2 * j) + r_i]) for r_i, r in enumerate(lower_routers)]

        return upper_layer

    def to_ietf(self, G : Graph, location, generated_packets = None):
        ietf_nodes = []
        for dev in G.nodes:
            if EDeviceRole.from_device_id(dev) == EDeviceRole.PORT:
                continue

            ietf_node = {
                'node_id' : dev.lower(),
                'services' : [s.to_dict() for s in G.nodes[dev]['services']]
            }
            for key in ['role', 'ip', 'subnet', 'branch', 'layer']:
                if key == 'services':
                    continue
                ietf_node[key] = G.nodes[dev][key]

            ietf_node['default_action'] = G.nodes[dev]['default_action'].name if 'default_action' in G.nodes[dev] else ''
            ietf_node['ruleset'] = G.nodes[dev]['ruleset'] if 'ruleset' in G.nodes[dev] else []

            ietf_node['packets'] = [] if generated_packets == None or dev not in generated_packets else generated_packets[dev]
            if EDeviceRole.from_device_id(dev) not in [EDeviceRole.ROUTER, EDeviceRole.SWITCH]:
                ietf_node['termination_point'] = [f'{dev.lower()}#0']
            else:
                ietf_node['termination_point'] = [tp for tp in G.neighbors(dev) if EDeviceRole.from_device_id(tp) == EDeviceRole.PORT and tp.split('#')[0] == dev]

            ietf_nodes.append(ietf_node)

        ietf_links = []
        for s, d in G.edges:
            if (s in d) or (d in s) or (EDeviceRole.PORT not in [EDeviceRole.from_device_id(s), EDeviceRole.from_device_id(d)]):
                continue

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

    def save_graph(self, G, location, generated_packets = None):
        g_copy = G.copy()
        color_map = []
        for n in g_copy.nodes:
            for key, joiner in [['ruleset', '\n'], ['services', ','], ['default_action', None]]:
                if key in g_copy.nodes[n].keys():
                    if joiner != None:
                        g_copy.nodes[n][key] = joiner.join([str(v) for v in g_copy.nodes[n][key]])
                    else:
                        g_copy.nodes[n][key] = str(g_copy.nodes[n][key])
            if '#' in n:
                color_map.append('lightgray')
                continue
            
            role = g_copy.nodes[n]['role']
            if role == str(EDeviceRole.ROUTER):
                color_map.append('blue')
            elif role == str(EDeviceRole.SWITCH):
                color_map.append('green')
            else:
                color_map.append('yellow')

        for n in g_copy.nodes:
            for key in g_copy.nodes[n].keys():
                if isinstance(g_copy.nodes[n][key], list):
                    print(key)

        write_graphml(g_copy, join(location, f'graph.graphml'))
        self.to_ietf(G, location, generated_packets)
        draw(g_copy, node_color=color_map, with_labels=False)
        savefig(join(location, f'graph.png'))
        savefig(join(location, f'graph.jpg'))