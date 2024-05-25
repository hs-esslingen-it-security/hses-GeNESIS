from itertools import product
from random import Random
from networkx import Graph, all_shortest_paths, has_path
from enum_objects import EDeviceRole, ETrafficProfile, ENetworkLayer


class CommunicationGenerator():

    def __init__(self, seed) -> None:
        self.random = Random(seed)

    @staticmethod
    def __of_same_branch(a : str, b : str):
        return a == b or a.startswith(b) or b.startswith(a)
    
    @staticmethod
    def is_allowed_in_strict_isolation(G : Graph, source, target):
        """
        Returns True if source and target are controllers within the same branch OR source and target are in the same layer instance.
        """

        if EDeviceRole.from_device_id(source) in [EDeviceRole.SWITCH, EDeviceRole.ROUTER] or EDeviceRole.from_device_id(target) in [EDeviceRole.SWITCH, EDeviceRole.ROUTER]:
            return False
        
        if G.nodes[source]['subnet'] == G.nodes[target]['subnet']:
            return True

        if not (EDeviceRole.from_device_id(source) == EDeviceRole.CONTROLLER or EDeviceRole.from_device_id(target) == EDeviceRole.CONTROLLER):
            return False
        
        if G.nodes[source]['subnet'] == G.nodes[target]['subnet']:
            return True
        
        elif EDeviceRole.from_device_id(source) == EDeviceRole.CONTROLLER and EDeviceRole.from_device_id(target) == EDeviceRole.CONTROLLER and CommunicationGenerator.__of_same_branch(G.nodes[source]['branch'], G.nodes[target]['branch']):
            return True
        
        return False
    
    @staticmethod
    def is_allowed_in_converged_networks(G, source, target):
        """
        Returns True if source or target is a server located in enterprise layer.
        """
        
        if (EDeviceRole.from_device_id(source) == EDeviceRole.SERVER and G.nodes[source]['layer'] == ENetworkLayer.CONNECTIVITY.name) or (EDeviceRole.from_device_id(target) == EDeviceRole.SERVER and G.nodes[target]['layer'] == ENetworkLayer.CONNECTIVITY.name):
            return True

        return False
    
    @staticmethod
    def is_allowed_in_distributed_control(G, source, target):
        """
        Returns True if both source and target are controllers or both source and target are OT/IT devices within the same branch.
        """
        src_role, dst_role = EDeviceRole.from_device_id(source), EDeviceRole.from_device_id(target)
        if src_role == EDeviceRole.CONTROLLER and dst_role == EDeviceRole.CONTROLLER:
            return True
        
        branch_allowed_roles = [EDeviceRole.OT_END_DEVICE, EDeviceRole.IT_END_DEVICE]
        if src_role in branch_allowed_roles and dst_role in branch_allowed_roles and CommunicationGenerator.__of_same_branch(source, target):
            return True
        
        return False
    
    def get_connections(self, G : Graph, traffic_profile : ETrafficProfile, connection_count = 100, print_info = True):
        allowed_connections = []
        invalid_connections = []
        forbidden_connections = []

        devices = [n for n in G.nodes if EDeviceRole.from_device_id(n) not in [EDeviceRole.PORT]]
        connections = [(s, t) for s, t in product(devices, devices) if s != t]

        for source, target in connections:
            if not any(s in G.nodes[target]['services'] for s in G.nodes[source]['services']):
                invalid_connections.append((source, target))
                continue

            if (source == target) or (not has_path(G, source, target)):
                invalid_connections.append((source, target))
                continue

            # if not any(any(EDeviceRole.from_device_id(device) == EDeviceRole.ROUTER for device in path) for path in all_shortest_paths(G, source, target)):
            #     invalid_connections.append((source, target))
            #     continue

            if CommunicationGenerator.is_allowed_in_strict_isolation(G, source, target):
                allowed_connections.append((source, target))
                continue
            elif traffic_profile == ETrafficProfile.STRIC_ISOLATION:
                forbidden_connections.append((source, target))
                continue
            
            if CommunicationGenerator.is_allowed_in_converged_networks(G, source, target):
                allowed_connections.append((source, target))
                continue
            elif traffic_profile == ETrafficProfile.CONVERGED_NETWORKS:
                forbidden_connections.append((source, target))
                continue
                
            if CommunicationGenerator.is_allowed_in_distributed_control(G, source, target):
                allowed_connections.append((source, target))
                continue

            forbidden_connections.append((source, target))

        if len(allowed_connections) <= connection_count:
            sampled_connections = allowed_connections
        else:
            sampled_connections = self.random.sample(allowed_connections, k=connection_count)

        if print_info:
            print('--- CONNECTION INFOFORMATION ---')
            print(f'Number of device connections: {len(connections)}')
            print(f'\tof which allowed: {len(allowed_connections)}')
            print(f'\t \tof which sampled: {len(sampled_connections)}')
            print(f'\tof which forbidden: {len(forbidden_connections)}, i.e., violates {traffic_profile.name.lower().replace("_", " ")} profile')
            print(f'\tof which invalid: {len(invalid_connections)}, i.e., no matching services') # or without a filter device between src and dst
            print('--------------------------------')

        return sampled_connections
    
    def get_affected_connections(self, G : Graph, router : str, allowed_connections):
        output = []
        for source, target, p, sport, dport in allowed_connections:
            if any(router in path for path in all_shortest_paths(G, source, target)):
                output.append((G.nodes[source]['ip'], G.nodes[target]['ip'], p, sport, dport))
        return output