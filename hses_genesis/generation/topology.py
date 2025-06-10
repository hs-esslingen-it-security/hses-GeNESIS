from abc import abstractmethod
from math import ceil, floor, log2
from random import Random
from typing import DefaultDict, Iterator, Optional
from networkx import Graph, compose, connected_components, cycle_graph, path_graph, neighbors, star_graph, random_regular_graph, relabel_nodes
from hses_genesis.utils.enum_objects import EDeviceRole, EPacketDecision, ESubnetTopologyStructure
from hses_genesis.parsing.configuration import IterativeParameterValue, LayerDefinition
from ipaddress import ip_network, IPv4Network
from itertools import count

def get_metadata(G : Graph):
    return {
        "number_of_nodes" : len(G.nodes),
        "number_of_routers" : len([n for n, d in G.nodes(data=True) if d['role'] == EDeviceRole.ROUTER]),
        "number_of_switches" : len([n for n, d in G.nodes(data=True) if d['role'] == EDeviceRole.SWITCH]),
        "number_of_hosts" : len([n for n, d in G.nodes(data=True) if d['role'] in EDeviceRole.hosts()]),
        "number_of_ot_devices" : len([n for n, d in G.nodes(data=True) if d['role'] == EDeviceRole.OT_END_DEVICE]),
        "number_of_it_devices" : len([n for n, d in G.nodes(data=True) if d['role'] == EDeviceRole.IT_END_DEVICE]),
        "number_of_servers" : len([n for n, d in G.nodes(data=True) if d['role'] == EDeviceRole.SERVER]),
        "number_of_controllers" : len([n for n, d in G.nodes(data=True) if d['role'] == EDeviceRole.CONTROLLER]),
        "number_of_edges" : len(G.edges),
        "number_of_subnets" : len([subnet for _, d in G.nodes(data=True) for subnet in d['subnet']])
    }

def get_graph_information(G : Graph):
    return {
        'number of nodes' : len(G.nodes),
        '- of which ports' : len([n for n in G.nodes if "#" in n]),
        '- of which routers' : len([n for n in G.nodes if "#" not in n and EDeviceRole.from_device_id(n) == EDeviceRole.ROUTER]),
        '- of which switches' : len([n for n in G.nodes if "#" not in n and EDeviceRole.from_device_id(n) == EDeviceRole.SWITCH]),
        '- of which end devices' : len([n for n in G.nodes if "#" not in n and EDeviceRole.from_device_id(n) not in [EDeviceRole.SWITCH, EDeviceRole.ROUTER]]),
        'number of edges' : len(G.edges),
        '- of which cables' : len([(s, d) for (s, d) in G.edges if s not in d and d not in s]),
        'number of subnets' : len(list(set([data["subnet"][0] for _, data in G.nodes(data=True) if data['role'] != EDeviceRole.ROUTER]))),
        'number of subgraphs' : f'{len(list(connected_components(G)))} (should always be 1)'
    }

def calculate_subnets(layer_definitions : list[LayerDefinition], subnet_connectivity = 2):
    required_number_of_ips = []
    for i, layer_definition in enumerate(layer_definitions):
        switch_count = layer_definition.switch_count.current
        if switch_count < 0 and i < len(layer_definitions) - 1:
            switch_count = (2 * layer_definition.subnet_descendants.current) + (1 if layer_definition.structure_distribution.get(ESubnetTopologyStructure.STAR, 0) > 0 else 0)
        ip_count = switch_count + (switch_count * layer_definition.max_hosts_per_switch.current) + (2 * subnet_connectivity)
        
        if i < len(layer_definitions) - 1:
            child_count = layer_definition.subnet_descendants.current if i < len(layer_definitions) - 1 else 0
            ip_count += 2 * child_count
        required_number_of_ips.append(ip_count)
    worst_case_subnet_size = max(required_number_of_ips) + 2 # +2 due to diff between total number of hosts and usable number of hosts
    netmask_size = max(16, min(32 - ceil(log2(worst_case_subnet_size)), 32))
    base_network = ip_network(f'192.0.0.0/16')
    return list(base_network.subnets(new_prefix=netmask_size))

class TopologyGenerator():
    def __init__(self, seed : int) -> None:
        self.seed = seed
        self.device_related_counters = DefaultDict(count)
        self.ip_iterators : dict[str, Iterator] = {}
        self.random = Random(seed)

    def get_topology_type(self, topology_distribution : dict[ESubnetTopologyStructure, int]):
        tmp_distribution : dict[ESubnetTopologyStructure, int] = topology_distribution.copy()
        if all(percentage == 0 for percentage in tmp_distribution.values()):
            tmp_distribution = {key : 1 for key, _ in tmp_distribution.items()}

        return self.random.choices(list(tmp_distribution.keys()), tmp_distribution.values(), k = 1)[0]

    def generate_device(self, device_role : EDeviceRole, subnets : list[str], layer_id : int = 0, branch_id : str = '0'):
        device_name = f'{device_role.value}{next(self.device_related_counters[device_role.value])}'
        mac_index = next(self.device_related_counters['mac'])
        mac_address = "02:00:00:%02x:%02x:%02x" % ((mac_index >> 16) & 0xFF, (mac_index >> 8) & 0xFF, mac_index & 0xFF)
        possible_services = device_role.possible_services()

        data = {
            'mac' : mac_address,
            'layer' : layer_id,
            'branch' : branch_id,
            'role' : device_role,
            'services' : self.random.sample(possible_services, k=self.random.randint(1,len(possible_services))),
            'subnet' : [subnet for subnet in subnets],
            'ip' : [str(next(self.ip_iterators[subnet])) for subnet in subnets]
        }

        if device_role == EDeviceRole.ROUTER:
            data['default_action'] = EPacketDecision.DROP
            data['ruleset'] = list()

        return device_name, data

    def generate_abstracted_graph(self, layer_definitions : list[LayerDefinition], subnets : Iterator[IPv4Network]):
        G = Graph()
        for i, layer_definition in enumerate(layer_definitions):
            switch_count = layer_definition.switch_count.current
            if switch_count < 0:
                subnet_descendants = layer_definition.subnet_descendants.current
                switch_count = 1 + subnet_descendants

            if i == 0:
                subnet = str(next(subnets))
                G.add_node(subnet)
                G.nodes[subnet]['layer'] = i
                G.nodes[subnet]['switch_count'] = switch_count
                G.nodes[subnet]['host_count'] = layer_definition.max_hosts_per_switch.current
                G.nodes[subnet]['host_types'] = layer_definition.host_types
                G.nodes[subnet]['structure'] = self.get_topology_type(layer_definition.structure_distribution)
                G.nodes[subnet]['branch'] = '0'
            else:
                earlier_layer_subnets = [subnet for subnet, data in G.nodes(data=True) if (data['layer'] == i - 1)]
                for parent in earlier_layer_subnets:
                    for j in range(layer_definitions[i - 1].subnet_descendants.current):
                        subnet = str(next(subnets))
                        G.add_node(subnet)
                        G.nodes[subnet]['layer'] = i
                        G.nodes[subnet]['switch_count'] = switch_count
                        G.nodes[subnet]['host_count'] = layer_definition.max_hosts_per_switch.current
                        G.nodes[subnet]['host_types'] = layer_definition.host_types
                        G.nodes[subnet]['structure'] = self.get_topology_type(layer_definition.structure_distribution)
                        G.nodes[subnet]['branch'] = G.nodes[parent]['branch'] + f'.{j}'
                        G.add_edge(parent, subnet)
        return G
    
    @abstractmethod
    def __is_center_node__(G : Graph, node):
        return sum([1 for n in neighbors(G, node) if EDeviceRole.from_device_id(n) == EDeviceRole.SWITCH]) > 2
    
    def add_hosts(self, G : Graph, subnet : IPv4Network, layer_id : int, branch_id : str, host_count : int, host_types : dict[EDeviceRole, IterativeParameterValue], host_connectivity : int, subnet_structure : ESubnetTopologyStructure):
        def sliding_window_wrap(owners : list):
            for i in range(len(owners)):
                window = [owners[(i + j) % len(owners)] for j in range(host_connectivity)]
                yield window

        def has_remaining_capacity(G : Graph, node : str):
            host_neighbors = [n for n in neighbors(G, node) if EDeviceRole.from_device_id(n) in EDeviceRole.hosts()]
            return len(host_neighbors) < host_count

        no_devices_configured = sum([max(0, v.current) for v in host_types.values()]) == 0 and sum([min(0, v.current) for v in host_types.values()]) == 0
        if no_devices_configured:
            return G

        device_owners = [node for node, data in G.nodes(data=True) if data.get('role', None) == EDeviceRole.SWITCH and str(subnet) in data.get('subnet', list()) and not (subnet_structure == ESubnetTopologyStructure.STAR and TopologyGenerator.__is_center_node__(G, node))]
        possible_device_owners = [node for node in device_owners if has_remaining_capacity(G, node)]
        
        if len(possible_device_owners) == 0:
            raise Exception('InvalidConfigurationException: Layer instance without switches generated. Most likely your configuration file does not specify a switch_count in the last layer_definition.')
        
        if (len(possible_device_owners) * host_count) / host_connectivity < sum([max(value.current, 0) for value in host_types.values()]):
            raise Exception(f'InvalidConfigurationException: Your configuration of fixed devices exceeds the available space ({len(possible_device_owners)} * {host_count}) / {host_connectivity} < {sum([max(value.current, 0) for value in host_types.values()])}.')
        
        fixed_devices = [device for device_type, device_count in host_types.items() if device_count.current > 0 for device in [self.generate_device(device_role=device_type, subnets=[str(subnet)], layer_id=layer_id, branch_id=branch_id) for _ in range(device_count.current)]]

        for device, data in fixed_devices:
            G.add_node(device, **data)
            possible_device_owners = [node for node in device_owners if has_remaining_capacity(G, node)]
            owner_windows = list(sliding_window_wrap(possible_device_owners))
            chosen_owners = self.random.choice(owner_windows)
            G.add_edges_from([(owner, device) for owner in chosen_owners])

        filling_hosts = {host_type : abs(count.current) for host_type, count in host_types.items() if count.current < 0}
        
        if not filling_hosts:
            return G

        possible_device_owners = [node for node in device_owners if has_remaining_capacity(G, node)]
        while len(possible_device_owners) >= host_connectivity:
            owner_windows = list(list(sliding_window_wrap(possible_device_owners)))
            chosen_owners = self.random.choice(owner_windows)

            device_type = self.random.choices(list(filling_hosts.keys()), weights=list(filling_hosts.values()), k=1)[0]
            device, data = self.generate_device(device_type, subnets=[str(subnet)], layer_id=layer_id, branch_id=branch_id)
            
            G.add_node(device, **data)
            G.add_edges_from([(owner, device) for owner in chosen_owners])

            possible_device_owners = [node for node in device_owners if has_remaining_capacity(G, node)]

        return G

    def replace_network_nodes_by_switches(self, subnet : IPv4Network, switch_count : int, subnet_structure : ESubnetTopologyStructure, routers : Optional[list[tuple[str, dict]]] = None, layer_id = 0, branch_id = '0', meshing_degree = 3):
        forwarding_devices = [self.generate_device(device_role=EDeviceRole.SWITCH, subnets=[str(subnet)], layer_id=layer_id, branch_id=branch_id) for _ in range(switch_count)]
        
        switch_names = [name for name, _ in forwarding_devices]
        center_node : Optional[str] = None

        if subnet_structure == ESubnetTopologyStructure.LINE:
            G : Graph = path_graph(switch_names)
        elif subnet_structure == ESubnetTopologyStructure.STAR:
            G : Graph = star_graph(switch_names)
            center_node = [n for n in G.nodes if TopologyGenerator.__is_center_node__(G, n)][0]
        elif subnet_structure == ESubnetTopologyStructure.RING:
            G : Graph = cycle_graph(switch_names)

        else:
            if meshing_degree < 2:
                edges = [(s, e) for s in switch_names for e in switch_names if s != e]
                G : Graph = Graph(edges)
            elif meshing_degree == 2:
                G : Graph = cycle_graph(switch_names)
            else:
                while (len(switch_names) * meshing_degree) % 2 != 0:
                    additional_switch, additional_switch_data = self.generate_device(device_role=EDeviceRole.SWITCH, subnets=[str(subnet)], layer_id=layer_id, branch_id=branch_id)
                    forwarding_devices.append((additional_switch, additional_switch_data))
                    switch_names.append(additional_switch)

                G : Graph = relabel_nodes(random_regular_graph(meshing_degree, len(switch_names), self.seed), dict(zip(range(len(switch_names)), switch_names)))

        if routers:
            connection_nodes = switch_names
            if center_node:
                connection_nodes = [s for s in connection_nodes if s != center_node]
            
            if len(routers) <= len(connection_nodes):
                sampled_connection_nodes = self.random.sample(connection_nodes, k = len(routers))
            
            else:
                sampled_connection_nodes = connection_nodes.copy()

                if len(routers) > len(connection_nodes):
                    iterations = floor(len(routers) / len(connection_nodes))
                    if iterations > 1:
                        for i in range(1, iterations):
                            sampled_connection_nodes += connection_nodes.copy()

                    sampled_connection_nodes += self.random.sample(connection_nodes, k = len(routers) % len(connection_nodes))
                            
            for i, (router, router_data) in enumerate(routers):
                forwarding_devices.append((router, router_data))
                G.add_node(router, **router_data)
                G.add_edge(router, sampled_connection_nodes[i])

        for name, data in forwarding_devices:
            for key, value in data.items():
                G.nodes[name][key] = value

        return G

    def insert_routers_at_network_borders(self, G : Graph, subnet_connectivity = 1):
        subnet_borders = list(G.edges)
        redundant_types = ESubnetTopologyStructure.redundant_types()
        for (src_net, dst_net) in subnet_borders:
            G.remove_edge(src_net, dst_net)
            src_data, dst_data = G.nodes[src_net], G.nodes[dst_net]
            if (src_data['structure'] in redundant_types) or (dst_data['structure'] in redundant_types):
                routers = [self.generate_device(EDeviceRole.ROUTER, [src_net, dst_net], layer_id=src_data['layer'], branch_id=src_data['branch']) for _ in range(subnet_connectivity)]
            else:
                routers = [self.generate_device(EDeviceRole.ROUTER, [src_net, dst_net], layer_id=src_data['layer'], branch_id=src_data['branch'])]
            for router, data in routers:
                G.add_node(router, **data)
                G.add_edges_from([(src_net, router),(router, dst_net)])
        return G

    def generate_network_topology_graph(self, layer_definitions : list[LayerDefinition], subnets : list[IPv4Network], default_meshing = 3, deault_subnet_connectivity = 1, default_host_connectivity = 1, return_subnet_graph = False):
        for subnet in subnets:
            self.ip_iterators[str(subnet)] = subnet.hosts()

        subnet_graph : Graph = self.generate_abstracted_graph(layer_definitions=layer_definitions, subnets = iter(subnets))
        subnets = list(subnet_graph.nodes(data=True))
        G : Graph = self.insert_routers_at_network_borders(subnet_graph.copy(), subnet_connectivity=deault_subnet_connectivity)

        for subnet, data in subnets:
            G.remove_node(subnet)
            routers = [(router, data) for router, data in G.nodes(data=True) if str(subnet) in data.get('subnet', list())]
            subgraph = self.replace_network_nodes_by_switches(subnet=subnet, switch_count=data['switch_count'], subnet_structure=data['structure'], routers=routers, layer_id=data['layer'], branch_id=data['branch'], meshing_degree=default_meshing)
            subgraph = self.add_hosts(G=subgraph, subnet=subnet, host_connectivity=default_host_connectivity, layer_id=data['layer'], branch_id=data['branch'], host_count=data['host_count'], host_types=data['host_types'], subnet_structure=data['structure'])
            G : Graph = compose(G, subgraph)

        if return_subnet_graph:
            return G, subnet_graph
        return G