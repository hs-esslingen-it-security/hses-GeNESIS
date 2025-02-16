from enum import Enum
from random import Random

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
        if EDeviceRole.PORT.value in input:
            return EDeviceRole.PORT
        matches = [e for e in EDeviceRole if input.startswith(str(e.value))]
        if len(matches) != 1:
            raise Exception(f'Invalid Device ID: {input}')
        return matches[0]
    
    @staticmethod
    def configurables():
        return [EDeviceRole.SERVER, EDeviceRole.IT_END_DEVICE, EDeviceRole.OT_END_DEVICE, EDeviceRole.CONTROLLER]
    
    @staticmethod
    def from_configurables_id(value : str):
        for v in EDeviceRole.configurables():
            if value.startswith(v.name[0]):
                return v
        raise Exception(f'No configurable with name {value} supported.')
    
    def __str__(self) -> str:
        return self.name
    
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
    SSH = (['TCP'], [22], (512,1500), (10,100))
    Webserver = (['TCP'], [80,443], (64,1500), (10,100))
    IP_Camera = (['TCP'], [554], (1000,1500), (10,100)) # rtsp uses mostly tcp --> no signature protocol number in ip header
    NETCONF = (['TCP'], [830], (64,800), (10,100))
    OPC_UA = (['TCP'], [4840], (64,800), (10,100))
    Profinet = (['UDP'], [34962,34963,34964,53247], (64,100), (10,100))
    EtherCAT = (['UDP'], [34980], (64,100), (10,100))

    def __str__(self) -> str:
        return self.name
    
    def to_dict(self):
        protocols, ports, _, _ = self.value
        return {
            "service": self.name, 
            "protocols": protocols, 
            "ports": ports
        }
    
    @staticmethod
    def from_str(value):
        for v in EService:
            if v.name == value:
                return v
            
        raise Exception(f'Unknown Service passed: {value}.')

    @staticmethod
    def from_role(role : EDeviceRole, random : Random):
        if role == EDeviceRole.PORT:
            return []
        
        if role == EDeviceRole.CONTROLLER:
            choices = [
                (EService.SSH, [EState.NEW, EState.RELATED, EState.ESTABLISHED]),
                (EService.Webserver, [EState.ESTABLISHED, EState.RELATED]),
                (EService.Profinet, [EState.NEW, EState.ESTABLISHED, EState.RELATED]),
                (EService.EtherCAT, [EState.NEW, EState.ESTABLISHED, EState.RELATED]),
                (EService.OPC_UA, [EState.NEW, EState.ESTABLISHED, EState.RELATED])
            ]
        elif role == EDeviceRole.IT_END_DEVICE:
            choices = [
                (EService.SSH, [EState.ESTABLISHED, EState.RELATED]),
                (EService.Webserver, [EState.ESTABLISHED, EState.RELATED]),
                (EService.IP_Camera, [EState.NEW, EState.ESTABLISHED, EState.RELATED])
            ]
        elif role == EDeviceRole.OT_END_DEVICE:
            choices = [
                (EService.Profinet, [EState.NEW, EState.ESTABLISHED, EState.RELATED]),
                (EService.EtherCAT, [EState.NEW, EState.ESTABLISHED, EState.RELATED]),
                (EService.Webserver, [EState.ESTABLISHED, EState.RELATED])
            ]
        elif role == EDeviceRole.SERVER:
            choices = [
                (EService.SSH, [EState.NEW, EState.ESTABLISHED, EState.RELATED]),
                (EService.NETCONF, [EState.NEW, EState.ESTABLISHED, EState.RELATED]),
                (EService.OPC_UA, [EState.NEW, EState.ESTABLISHED, EState.RELATED]),
                (EService.IP_Camera, [EState.ESTABLISHED, EState.RELATED])
            ]
        elif role == EDeviceRole.SWITCH:
            choices = [
                (EService.SSH, [EState.ESTABLISHED, EState.RELATED]),
                (EService.NETCONF, [EState.ESTABLISHED, EState.RELATED]),
                (EService.Webserver, [EState.ESTABLISHED, EState.RELATED])
            ]
        else:
            choices = [
                (EService.SSH, [EState.ESTABLISHED, EState.RELATED]),
                (EService.NETCONF, [EState.ESTABLISHED, EState.RELATED]),
                (EService.Webserver, [EState.ESTABLISHED, EState.RELATED])
            ]
        return random.sample(choices, k=random.randint(1,len(choices)))
    
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