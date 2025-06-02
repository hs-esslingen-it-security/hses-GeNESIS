from random import Random
from networkx import Graph
from hses_genesis.utils.enum_objects import EDeviceRole, EService, EState, ETrafficProfile, ENetworkLayer
from hses_genesis.utils.functions import print_information
from os.path import pardir

def get_metadata(total_connections, forbidden_connections, intrasubnet_connections, intersubnet_connections, sampled_connections):
    return {
        'number_of_possible_communication_pairs' : len(total_connections),
        'number_of_forbidden_communication_pairs' : len(forbidden_connections),
        'number_of_allowed_intrasubnet_communication_pairs' : len(intrasubnet_connections),
        'number_of_allowed_intersubnet_communication_pairs' : len(intersubnet_connections),
        'sampled_intersubnet_communication_paits' : len(sampled_connections)
    }

def print_connection_info(total_connections, forbidden_connections, intrasubnet_connections, intersubnet_connections, sampled_connections, traffic_profile = ETrafficProfile.STRICT_ISOLATION):
    print_information('CONNECTION INFORMATION', {
        'number of possible device connections' : len(total_connections),
        '- of which forbidden': f'{len(forbidden_connections)}, i.e., violates {traffic_profile.name.lower().replace("_", " ")} profile',
        '- of which intrasubnet' : len(intrasubnet_connections),
        '- of which intersubnet' : len(intersubnet_connections),
        '-- of which sampled' : len(sampled_connections)
    })

class CommunicationGenerator():

    def __init__(self, seed) -> None:
        self.random = Random(seed)

    def get_intrasubnet_connections(self, G : Graph):
        connections = []
        for (src_node, src_data) in G.nodes(data=True):
            if src_data['role'] not in EDeviceRole.hosts():
                continue

            initiating_services = [(service_name, service_states) for (service_name, service_states) in src_data['services'] if EState.NEW in service_states] 
            if not initiating_services:
                continue

            for (dst_node, dst_data) in G.nodes(data=True):
                if (src_node == dst_node) or (src_data['subnet'] != dst_data['subnet']) or (dst_data['role'] not in EDeviceRole.hosts()):
                    continue

                overlapping_services = [src_service for (src_service, _) in src_data['services'] if src_service in [dst_service for (dst_service, dst_service_states) in dst_data['services'] if (EState.ESTABLISHED in dst_service_states or EState.RELATED in dst_service_states)]]
                
                if not overlapping_services:
                    continue

                connections.extend([(src_node, dst_node, service) for service in overlapping_services])
        return connections
                
    def get_connections(self, G : Graph, traffic_profile = ETrafficProfile.DISTRIBUTED_CONTROL, upper_connection_bound = -1):
        def of_same_branch(a_branch, b_branch):
            return a_branch == b_branch or a_branch.startswith(b_branch) or b_branch.startswith(a_branch)
        
        def is_central_server(data):
            return data['role'] == EDeviceRole.SERVER and data['layer'] == ENetworkLayer.CONNECTIVITY.name
        
        def is_allowed_in_strict_isolation(src_data, dst_data):
            """
            Returns True if source and target are controllers within the same branch.
            """
            return of_same_branch(src_data['branch'], dst_data['branch']) and all(role == EDeviceRole.CONTROLLER for role in [src_data['role'], dst_data['role']])
        
        def is_allowed_in_converged_networks(src_data, dst_data):
            """
            Returns True if source or target is a server located in enterprise layer and the other communication partner is a controller anywhere in the network.
            """
            return EDeviceRole.CONTROLLER in [src_data['role'], dst_data['role']] and any(is_central_server(data) for data in [src_data, dst_data])
        
        def is_allowed_in_distributed_control(src_data, dst_data):
            """
            Returns True if both source and target are controllers or server to any device
            """
            return all(role == EDeviceRole.CONTROLLER for role in [src_data['role'], dst_data['role']]) or any(is_central_server(data) for data in [src_data, dst_data])

        total_connections = []
        forbidden_connections = []
        intrasubnet_connections = []
        intersubnet_connections = []

        for (src_node, src_data) in G.nodes(data=True):
            if src_data['role'] not in EDeviceRole.hosts():
                continue
            
            initiating_services = [service for service in src_data['services'] if EState.NEW in src_data['role'].possible_service_states(service)] 
            if not initiating_services:
                continue

            for (dst_node, dst_data) in G.nodes(data=True):
                if (src_node == dst_node) or (dst_data['role'] not in EDeviceRole.hosts()):
                    continue

                overlapping_services = [src_service for src_service in src_data['services'] if src_service in dst_data['services']]
                if not overlapping_services:
                    continue

                connections = [(src_node, dst_node, service) for service in overlapping_services]
                total_connections.extend(connections)

                is_intrasubnet = src_data['subnet'] == dst_data['subnet']
                if is_intrasubnet:
                    intrasubnet_connections.extend(connections)
                    continue

                if is_allowed_in_strict_isolation(src_data, dst_data):
                    intersubnet_connections.extend(connections)
                    continue
                elif traffic_profile == ETrafficProfile.STRICT_ISOLATION:
                    forbidden_connections.extend(connections)
                    continue

                if is_allowed_in_converged_networks(src_data, dst_data):
                    intersubnet_connections.extend(connections)
                    continue
                elif traffic_profile == ETrafficProfile.CONVERGED_NETWORKS:
                    forbidden_connections.extend(connections)
                    continue

                if is_allowed_in_distributed_control(src_data, dst_data):
                    intersubnet_connections.extend(connections)
                    continue

                forbidden_connections.extend(connections)

        if upper_connection_bound < 0 or len(intersubnet_connections) < upper_connection_bound:
            sampled_connections = intersubnet_connections
        else:
            sampled_connections = self.random.sample(intersubnet_connections, k=upper_connection_bound)

        return total_connections, forbidden_connections, intrasubnet_connections, intersubnet_connections, sampled_connections
    
    def generate_packet(self, service : EService, src_node : str, src_data : dict, dst_node : str, dst_data : dict, protocol : str, port : int, is_high_sender = False):
        return {
            'SourceName' : src_node,
            'DestinationName' : dst_node,
            
            # Ethernet
            'SourceMac' : src_data['mac'],
            'DestinationMac' : dst_data['mac'],
            'EtherType' : 'IPv4',

            # 802.1Q
            'PriorityCodePoint' : service.value.priority,
            'DropEligibleIndicator' : service.value.dei,
            'VlanIndicator' : 1,
            
            # IP
            'Protocol' : protocol,
            'SourceIp' : src_data['ip'],
            'DestinationIp' : dst_data['ip'],

            # TCP/UDP
            'SourcePort' : port,
            'DestinationPort' : port,

            # General
            'PacketSize' : self.random.randint(service.value.packet_size_range[0], service.value.packet_size_range[1]),
            'PacketsPerSecond' : self.random.randint(10, 100) * (2 if is_high_sender else 1)
        }