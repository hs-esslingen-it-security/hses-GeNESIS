from math import ceil, log2
from random import Random
from networkx import Graph, compose, connected_components, cycle_graph, path_graph, neighbors, star_graph
from hses_genesis.utils.enum_objects import EDeviceRole, ENetworkLayer, EPacketDecision, EService, ESubnetTopologyStructure
from hses_genesis.parsing.configuration import LayerDefinition
from ipaddress import ip_network, IPv4Network

def get_graph_information(G : Graph):
    return {
        'number of nodes' : len(G.nodes),
        '- of which ports' : len([n for n in G.nodes if "#" in n]),
        '- of which routers' : len([n for n in G.nodes if "#" not in n and EDeviceRole.from_device_id(n) == EDeviceRole.ROUTER]),
        '- of which switches' : len([n for n in G.nodes if "#" not in n and EDeviceRole.from_device_id(n) == EDeviceRole.SWITCH]),
        '- of which end devices' : len([n for n in G.nodes if "#" not in n and EDeviceRole.from_device_id(n) not in [EDeviceRole.SWITCH, EDeviceRole.ROUTER]]),
        'number of edges' : len(G.edges),
        '- of which cables' : len([(s, d) for (s, d) in G.edges if s not in d and d not in s]),
        'number of subnets' : len(list(set([data["subnet"] for _, data in G.nodes(data=True) if data['role'] != EDeviceRole.ROUTER]))),
        'number of subgraphs' : f'{len(list(connected_components(G)))} (should always be 1)'
    }

def calculate_subnets(layer_definitions : list[LayerDefinition]):
    required_number_of_ips = []
    for i, layer_definition in enumerate(layer_definitions):
        max_router_count = 2
        switch_count = layer_definition.switch_count.CURRENT
        ip_count = max_router_count + switch_count + (switch_count * layer_definition.max_hosts_per_switch.CURRENT)
        if i < len(layer_definitions) - 1: # due to children
            ip_count += 2* (2 * layer_definitions[i + 1].per_upper_layer.CURRENT) # additional switches in subnet + required ips for routers in children
        required_number_of_ips.append(ip_count)

    worst_case_subnet_size = max(required_number_of_ips) + 2 # +2 due do diff between total number of hosts and usable number of hosts
    netmask_size = max(16, min(32 - ceil(log2(worst_case_subnet_size)), 32))
    base_network = ip_network(f'192.0.0.0/16')
    return list(base_network.subnets(new_prefix=netmask_size))

class TopologyGenerator():
    def __init__(self, seed : int) -> None:
        self.existing_devices = []
        self.existing_subnets = []
        self.random = Random(seed)

    def generate_device(self, device_role : EDeviceRole, initial_index = 0):
        index = initial_index
        while f'{device_role.value}{index}' in self.existing_devices:
            index += 1
        self.existing_devices.append(f'{device_role.value}{index}')
        return f'{device_role.value}{index}'

    def assign_node_informations(self, G : Graph, layer : ENetworkLayer, branch_id : str, subnet_ip : IPv4Network):
        if len([n for n in G.nodes if EDeviceRole.from_device_id(n) not in [EDeviceRole.PORT]]) > 253:
            raise Exception('Too many devices in a single subnet! Only 253 devices are supported.')

        self.existing_subnets.append(subnet_ip)
        ips = list(subnet_ip.hosts())
        
        for device in G.nodes:
            device_role = EDeviceRole.from_device_id(device)
            G.nodes[device]['layer'] = layer.name
            G.nodes[device]['branch'] = branch_id
            G.nodes[device]['role'] = device_role
            G.nodes[device]['services'] =  EService.from_role(device_role, self.random)
            ip = str(ips.pop(0))
            if device_role == EDeviceRole.ROUTER:
                G.nodes[device]['subnet'] = [str(subnet_ip)]
                G.nodes[device]['ip'] = [str(ip)]
                G.nodes[device]['default_action'] = EPacketDecision.DROP
                G.nodes[device]['ruleset'] = []
            else:
                G.nodes[device]['subnet'] = str(subnet_ip)
                G.nodes[device]['ip'] = str(ip)
        return G, ips
    
    def get_topology_type(self, topology_distribution : dict[ESubnetTopologyStructure, int]):
        tmp_distribution : dict[ESubnetTopologyStructure, int] = topology_distribution.copy()
        if all(percentage == 0 for percentage in tmp_distribution.values()):
            tmp_distribution = {key : 1 for key, _ in tmp_distribution.items()}

        return self.random.choices(list(tmp_distribution.keys()), tmp_distribution.values(), k = 1)[0]

    def get_barebone_subnet(self,
                            number_of_switches : int,
                            subnet_structure : ESubnetTopologyStructure,
                            has_parent = False):

        switches = [self.generate_device(EDeviceRole.SWITCH, index) for index in range(number_of_switches)]
        routers = []
        if has_parent:
            routers = [self.generate_device(EDeviceRole.ROUTER) for _ in range(2 if subnet_structure in ESubnetTopologyStructure.redundant_types() else 1)]

        forwarding_devices = switches + routers

        if subnet_structure == ESubnetTopologyStructure.LINE:
            G = path_graph(forwarding_devices)
        elif subnet_structure == ESubnetTopologyStructure.RING:
            G = cycle_graph(forwarding_devices)
        elif subnet_structure == ESubnetTopologyStructure.STAR:
            G = star_graph(forwarding_devices)
        else:
            G = Graph([(s, e) for s in forwarding_devices for e in forwarding_devices if s != e])
        return G

    def add_devices(self, G : Graph, max_hosts_per_owner : int, host_types : dict[EDeviceRole, int]):
        def is_center_node(G, node):
            return sum([1 for n in neighbors(G, node) if EDeviceRole.from_device_id(n) == EDeviceRole.SWITCH]) > 2
        
        device_owners = [node for node in G.nodes() if EDeviceRole.from_device_id(node) == EDeviceRole.SWITCH and not is_center_node(G, node)]
        if len(device_owners) == 0:
            raise Exception('InvalidConfigurationException: Layer instance without switches generated. Most likely your configuration file does not specify a switch_count in the last layer_definition.')
        
        if len(device_owners) * max_hosts_per_owner < sum([value for value in host_types.values() if value > 0]):
            raise Exception('InvalidConfigurationException: Your configuration of fixed devices exceeds the available space.')
        

        for device_type, device_count in host_types.items():
            if device_count <= 0:
                continue

            if len(device_owners) - device_count <= 0:
                chosen_owners = device_owners.copy()
            else:
                chosen_owners = self.random.sample(device_owners, k = device_count)

            for chosen_owner in chosen_owners:
                device = self.generate_device(device_type)
                G.add_node(device)
                G.add_edge(chosen_owner, device)

        remaining_device_choices = [host_type for host_type, count in host_types.items() if count < 0]
        
        if len(remaining_device_choices) == 0:
            return G

        for switch in device_owners:
            existing_devices = sum([1 for n in neighbors(G, switch) if EDeviceRole.from_device_id(n) in EDeviceRole.configurables()])
            remaining_space = max_hosts_per_owner - existing_devices

            if remaining_space <= 0:
                continue

            for _ in range(remaining_space):
                device = self.generate_device(self.random.choice(remaining_device_choices))
                G.add_node(device)
                G.add_edge(switch, device)
        return G
        
    def generate_subnet(self,
                        subnet_structure : ESubnetTopologyStructure,
                        switch_count : int,
                        hosts_per_owner : int,
                        host_types : list[EDeviceRole],
                        has_parent = False) -> Graph:
        
        G = self.get_barebone_subnet(switch_count, subnet_structure, has_parent)

        G = self.add_devices(G, max_hosts_per_owner=hosts_per_owner,
                             host_types=host_types)

        return G


    def generate_network(self, layer_definitions : list[LayerDefinition], available_subnet_ips : list, layer_index = 0, branch_id = '0'):
        """
        The amount of switches per subnet/layer is dependant on its specified dimension as well as 2 * the number of child/lower layers.
        The additional switches are necessary, since every router has to have a connectable switch in an upper layer.
        """
        layer_definition = layer_definitions[layer_index]

        switch_count = layer_definition.switch_count.CURRENT

        if layer_index < len(layer_definitions) - 1:
            next_layer = layer_definitions[layer_index + 1]
            number_of_children = next_layer.per_upper_layer.CURRENT
            if number_of_children > 0:
                child_redundancy = any(value > 0 for key, value in next_layer.structure_distribution.items() if key in ESubnetTopologyStructure.redundant_types())
                switch_count += ((2 if child_redundancy else 1) * number_of_children)

        network = self.generate_subnet(
            subnet_structure=self.get_topology_type(layer_definition.structure_distribution),
            switch_count=switch_count,
            hosts_per_owner=layer_definition.max_hosts_per_switch.CURRENT,
            host_types=layer_definition.host_types,
            has_parent=layer_definitions.index(layer_definition) > 0
        )

        subnet_ip = available_subnet_ips.pop(0)
        network, open_subnet_ips = self.assign_node_informations(network, layer_definition.layer_classification, branch_id=branch_id, subnet_ip=subnet_ip)

        if layer_index >= len(layer_definitions) - 1:
            return network
        
        switches = [node for node, data in network.nodes(data=True) if data['role'] == EDeviceRole.SWITCH]
        self.random.shuffle(switches)

        children = [self.generate_network(layer_definitions, available_subnet_ips, layer_index=layer_index+1, branch_id=f'{branch_id}.{i}') for i in range(layer_definitions[layer_index + 1].per_upper_layer.CURRENT)]

        for child_index, child_network in enumerate(children):
            network : Graph = compose(network, child_network)

            child_branch = f'{branch_id}.{child_index}'
            child_routers = [node for node, data in child_network.nodes(data=True) if data['role'] == EDeviceRole.ROUTER and data['branch'] == child_branch]
            child_subnet = set(data['subnet'] for _, data in child_network.nodes(data=True) if data['role'] != EDeviceRole.ROUTER and data['branch'] == child_branch)
            child_subnet = list(child_subnet)[0]
            for router_index, router in enumerate(child_routers):
                network.nodes[router]['ip'].append(str(open_subnet_ips.pop(0)))
                network.nodes[router]['subnet'].append(str(subnet_ip))

                switch_index = ((len(child_routers) * child_index) + router_index) % len(switches)
                network.add_edge(router, switches[switch_index])

        return network