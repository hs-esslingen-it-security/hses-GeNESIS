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
    ACCEPT = 0
    DROP = 1
    
    def negate(self):
        if self == EPacketDecision.ACCEPT:
            return EPacketDecision.DROP
        return EPacketDecision.ACCEPT

class ESubnetTopologyType(Enum):
    STAR = 0
    RING = 1
    LINE = 2
    MESH = 3

    @staticmethod
    def from_str(input : str):
        value = input.upper()
        matches = [e for e in ESubnetTopologyType if value == str(e.name) or str(e.name).lower().startswith(value.lower())]
        if len(matches) != 1:
            raise Exception(f'Invalid topology type: {input}')
        
        return matches[0]
        
class EDeviceRole(Enum):
    SERVER = 'SV'
    ROUTER = 'R'
    SWITCH = 'SW'
    IT_END_DEVICE = 'IT'
    CONTROLLER = 'CNTRL'
    OT_END_DEVICE = 'OT'
    PORT = '#'
    
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
    
    def __str__(self) -> str:
        return self.name
    
class ETrafficProfile(Enum):
    STRIC_ISOLATION = 0
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
    

class ECommunicationRelationParameter(Enum): 
    SOURCE = 'src'
    DESTINATION = 'dst'

    def negate(self):
        if self == ECommunicationRelationParameter.SOURCE:
            return ECommunicationRelationParameter.DESTINATION
        else:
            return ECommunicationRelationParameter.SOURCE
        
    @staticmethod
    def from_str(input : str):
        for v in ECommunicationRelationParameter:
            if input == v.value:
                return v
        raise Exception(f'No valid communication relation parameter found for {input}. Choose one of {list(ETrafficProfile.__members__.values())}')
    

class EService(Enum):
    SSH = (['TCP'], [22], (512,1500), (10,100))
    Webserver = (['TCP'], [80,443], (64,1500), (10,100))
    IP_Camera = (['TCP', 'RTSP'], [554], (1000,1500), (10,100))
    NETCONF = (['TCP'], [830], (64,800), (10,100))
    OPC_UA = (['TCP'], [4840], (64,800), (10,100))
    Profinet = (['UDP'], [34962,34963,34964,53247], (64,100), (10,100))
    EtherCAT = (['UDP'], [0], (64,100), (10,100))

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
    def from_role(role : EDeviceRole, random : Random):
        if role == EDeviceRole.PORT:
            return []
        
        if role == EDeviceRole.CONTROLLER:
            choices = [
                EService.SSH,
                EService.Webserver,
                EService.Profinet,
                EService.EtherCAT,
                EService.OPC_UA
            ]
        elif role == EDeviceRole.IT_END_DEVICE:
            choices = [
                EService.SSH,
                EService.Webserver,
                EService.IP_Camera
            ]
        elif role == EDeviceRole.OT_END_DEVICE:
            choices = [
                EService.Profinet,
                EService.EtherCAT,
                EService.Webserver
            ]
        elif role == EDeviceRole.SERVER:
            choices = [
                EService.SSH,
                EService.NETCONF,
                EService.OPC_UA,
                EService.IP_Camera
            ]
        elif role == EDeviceRole.SWITCH:
            choices = [
                EService.SSH,
                EService.NETCONF,
                EService.Webserver
            ]
        else:
            choices = [
                EService.SSH,
                EService.NETCONF,
                EService.Webserver
            ]
        return random.sample(choices, k=random.randint(1,len(choices)))