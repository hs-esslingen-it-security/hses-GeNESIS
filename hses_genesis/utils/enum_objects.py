from enum import Enum
from types import SimpleNamespace
from networkx import Graph, simple_cycles

class EGenerationSteps(Enum):
    TOPOLOGY = 0
    COMMUNICATION_RELATIONS = 1
    NETWORK_CONFIGURATIONS = 2

class ENetworkLayer(Enum):
    CONNECTIVITY = 0
    AGGREGATED_CONTROL = 1
    PROCESS = 2

    @staticmethod
    def from_str(input : str):
        for v in ENetworkLayer:
            if v.name.lower().startswith(input.lower()):
                return v
            
        raise Exception(f'No matching network layer found for {input}')
    
    def from_value(input : int):
        for v in ENetworkLayer:
            if v.value == input:
                return v
            
        raise Exception(f'No matching network layer found for {input}')

class EPacketDecision(Enum):
    DROP = 0
    ACCEPT = 1
    
    def negate(self):
        if self == EPacketDecision.ACCEPT:
            return EPacketDecision.DROP
        return EPacketDecision.ACCEPT
    
    @staticmethod
    def from_str(value):
        for v in EPacketDecision:
            if str(v) == value or v.name == value:
                return v
        raise Exception(f'Invalid packet decision: {value}')

class ESubnetTopologyStructure(Enum):
    STAR = 0
    RING = 1
    LINE = 2
    MESH = 3
    
    @staticmethod
    def from_str(value : str):
        for v in ESubnetTopologyStructure:
            if v.name.lower() == value.lower() or v.name.lower().startswith(value.lower()):
                return v
        raise Exception(f'Invalid Subnet Type: {value}. Use one of {list(ESubnetTopologyStructure.__members__.values())}.')
    
    @staticmethod
    def redundant_types():
        return [ESubnetTopologyStructure.RING, ESubnetTopologyStructure.MESH]
        
    @staticmethod
    def from_topology(G : Graph):
        try:
            cycles = list(simple_cycles(G))
        except Exception as e:
            print(e)
            cycles = None
        
        if cycles and any(all(node in cycle for node, data in G.nodes(data=True) if data['role'] in [EDeviceRole.SWITCH, EDeviceRole.ROUTER]) for cycle in cycles):
            return ESubnetTopologyStructure.RING

        else:
            switch_graph = G.subgraph([node for node, data in G.nodes(data=True) if data['role'] == EDeviceRole.SWITCH])
            if len(list(simple_cycles(switch_graph))) > 0:
                return ESubnetTopologyStructure.MESH
            elif any(switch_graph.degree(switch) > 2 for switch in switch_graph.nodes):
                return ESubnetTopologyStructure.STAR
        
        return ESubnetTopologyStructure.LINE


class EState(Enum):
    NONE = 0
    NEW = 1
    ESTABLISHED = 2
    RELATED = 3
    INVALID = 4
    UNTRACKED = 5

    @staticmethod
    def from_value(input : int):
        for v in EState:
            if v.value == input:
                return v
            
        raise Exception(f'NO VALID STATE ({input}). Use one of {list(EState.__members__.values())}')
    

class EService(Enum):
    # bei high: tolerated_packet_loss - 1
    SSH = SimpleNamespace(**{'protocols' : ['tcp'], 'ports' : [22], 'packet_size_range' : [512,1500], 'priority' : 1, 'dei' : 0})
    HTTP = SimpleNamespace(**{'protocols' : ['tcp'], 'ports' : [80], 'packet_size_range' : [64,1500], 'priority' : 1, 'dei' : 0})
    HTTPS = SimpleNamespace(**{'protocols' : ['tcp'], 'ports' : [443], 'packet_size_range' : [64,1500], 'priority' : 1, 'dei' : 0})
    NETCONF = SimpleNamespace(**{'protocols' : ['tcp'], 'ports' : [830], 'packet_size_range' : [64,800], 'priority' : 1, 'dei' : 0})
    IP_Camera = SimpleNamespace(**{'protocols' : ['tcp'], 'ports' : [554], 'packet_size_range' : [1000,1500], 'priority' : 1, 'dei' : 0}) # rstp uses mostly tcp --> no signature protocol number in ip header
    
    # bei high: semaless_paths +1
    OPC_UA = SimpleNamespace(**{'protocols' : ['tcp'], 'ports' : [4840], 'packet_size_range' : [64,800], 'priority' : 1, 'dei' : 0})
    ModbusTCP = SimpleNamespace(**{'protocols' : ['tcp'], 'ports' : [502], 'packet_size_range' : [64,800], 'priority' : 1, 'dei' : 0})
    EthernetIP = SimpleNamespace(**{'protocols' : ['tcp', 'udp'], 'ports' : [44818, 2222], 'packet_size_range' : [64,100], 'priority' : 1, 'dei' : 0})
    EtherCAT = SimpleNamespace(**{'protocols' : ['udp'], 'ports' : [34980], 'packet_size_range' : [64,100], 'priority' : 1, 'dei' : 0})
    ProfiNet = SimpleNamespace(**{'protocols' : ['udp'], 'ports' : [34962,34963,34964,53247], 'packet_size_range' : [64,100], 'priority' : 1, 'dei' : 0})

    # CB braucht fixe Pfade! --> d.h. es müssen 2 disjunkte Pfade berechent werden

    # TODO: implementierung von PRIORITY_PROFILES: None, Realistic, High; Manipulieren seamless_paths und tolerated_packet_loss; Für seamless paths: Ausgeben der benltigten parallelen pfade; für tolerated_packet_loss entweder CB oder RSTP.

    def __str__(self) -> str:
        return self.name
    
    @staticmethod
    def from_str(value):
        for v in EService:
            if v.name == value:
                return v
            
        raise Exception(f'Unknown Service passed: {value}.')
    
    @staticmethod
    def control_traffic():
        return [
            EService.OPC_UA,
            EService.ModbusTCP,
            EService.EthernetIP,
            EService.EtherCAT,
            EService.ProfiNet
        ]

    @staticmethod
    def best_effort():
        return [
            EService.SSH,
            EService.HTTP,
            EService.HTTPS,
            EService.NETCONF,
            EService.IP_Camera
        ]


class EDeviceRole(Enum):
    SERVER = 'SV'
    ROUTER = 'R'
    SWITCH = 'SW'
    IT_END_DEVICE = 'I'
    CONTROLLER = 'C'
    OT_END_DEVICE = 'O'
    PORT = '#'
    
    @staticmethod
    def from_name(input : str):
        for v in EDeviceRole:
            if v.name.lower() == input.lower():
                return v
        raise Exception(f'No device role with name {input} supported.')
        
    @staticmethod
    def from_device_id(input : str):
        matches = [e for e in EDeviceRole if input.startswith(str(e.value))]
        if len(matches) != 1:
            raise Exception(f'Invalid Device ID: {input}')
        return matches[0]
    
    @staticmethod
    def hosts():
        return [EDeviceRole.SERVER, EDeviceRole.IT_END_DEVICE, EDeviceRole.OT_END_DEVICE, EDeviceRole.CONTROLLER]
    
    @staticmethod
    def from_configurables_id(value : str):
        for v in EDeviceRole.hosts():
            if value.startswith(v.name[0]):
                return v
        raise Exception(f'No configurable with name {value} supported.')
    
    def __str__(self) -> str:
        return self.name
    
    def possible_services(self) -> list[EService]:
        services = [EService.HTTP, EService.HTTPS]
        if self != EDeviceRole.OT_END_DEVICE:
            services.append(EService.SSH)

        if self != EDeviceRole.IT_END_DEVICE:
            services.append(EService.OPC_UA)

        if self not in [EDeviceRole.IT_END_DEVICE, EDeviceRole.OT_END_DEVICE]:
            services.append(EService.NETCONF)

        if self in [EDeviceRole.SERVER, EDeviceRole.IT_END_DEVICE]:
            services.append(EService.IP_Camera)

        if self in [EDeviceRole.SERVER, EDeviceRole.CONTROLLER, EDeviceRole.OT_END_DEVICE]:
            services.append(EService.ModbusTCP)
            services.append(EService.EthernetIP)
            services.append(EService.EtherCAT)
            services.append(EService.ProfiNet)

        return services

    def possible_service_states(self, service : EService):
        if self == EDeviceRole.SERVER:
            return [EState.NEW, EState.ESTABLISHED, EState.RELATED]
        
        if self in [EDeviceRole.ROUTER, EDeviceRole.SWITCH]:
            if service in [EService.HTTP, EService.HTTPS, EService.OPC_UA, EService.NETCONF]:
                return [EState.ESTABLISHED, EState.RELATED]
            return []
            
        if self == EDeviceRole.CONTROLLER:
            if service in [EService.HTTP, EService.HTTPS]:
                return [EState.ESTABLISHED, EState.RELATED]
            elif service != EService.IP_Camera:
                return [EState.NEW, EState.ESTABLISHED, EState.RELATED]
            
            return []
            
        if self == EDeviceRole.IT_END_DEVICE:
            if service in [EService.HTTP, EService.HTTPS, EService.SSH, EService.IP_Camera]:
                return [EState.NEW, EState.ESTABLISHED, EState.RELATED]
            return []

        if self == EDeviceRole.OT_END_DEVICE:
            if service in [EService.ModbusTCP, EService.EthernetIP, EService.EtherCAT, EService.ProfiNet]:
                return [EState.NEW, EState.ESTABLISHED, EState.RELATED]
            elif service in [EService.HTTP, EService.HTTPS, EService.OPC_UA]:
                return [EState.ESTABLISHED, EState.RELATED]

        return []
    
    @staticmethod
    def high_senders():
        return [EDeviceRole.IT_END_DEVICE, EDeviceRole.OT_END_DEVICE]
    
class ETrafficProfile(Enum):
    STRICT_ISOLATION = 0
    CONVERGED_NETWORKS = 1
    DISTRIBUTED_CONTROL = 2

    @staticmethod
    def from_str(input : str):
        input_value = input.upper().replace(' ', '_')
        for v in ETrafficProfile:
            if v.name == input_value:
                return v
        
        raise Exception(f'NO VALID TRAFFIC PROFILE ({input}). Use one of {list(ETrafficProfile.__members__.keys())}.')
    
    @staticmethod
    def from_value(input : int):
        for v in ETrafficProfile:
            if v.value == input:
                return v
        raise Exception(f'NO VALID TRAFFIC PROFILE ({input}). Use one of {list(ETrafficProfile.__members__.values())}.')
    
class EParameterKey(Enum):
    SRC = 's'
    DST = 'd'
    PROTOCOL = 'p'
    SRC_PORT = '-sport'
    DST_PORT = '-dport'

    @staticmethod
    def from_str(input : str):
        for v in EParameterKey:
            if v.name == input or v.value == input:
                return v
        raise Exception(f'No parameter key supported matching {input}. Use one of {list(EParameterKey.__members__.values())}.')

class EParameterType(Enum):
    IP = 0
    NUMBER = 1
    PROTOCOL = 2

    @staticmethod
    def from_parameter_key(parameter_key : EParameterKey):
        if parameter_key in [EParameterKey.SRC, EParameterKey.DST]:
            return EParameterType.IP
        elif parameter_key in [EParameterKey.PROTOCOL]:
            return EParameterType.PROTOCOL
        else:
            return EParameterType.NUMBER