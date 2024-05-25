from abc import ABC, abstractmethod
from copy import deepcopy
from random import Random
from enum_objects import EDeviceRole, EGenerationSteps, ENetworkLayer, ESubnetTopologyType, ETrafficProfile
from json import load
from importlib.metadata import version

BIG_SEPARATOR = '::'
INTERMEDIATE_SEPARATOR = ':'
SMALL_SEPARATOR = '·'
TAG_ENCAPSULATOR = '#'
RANGE_SEPARATOR = ','

class AParameterValue(ABC):
    @abstractmethod
    def resolve(self, seed) -> int:
        pass

    @abstractmethod
    def to_dict_value(self, seed) -> any:
        pass
    
    @abstractmethod
    def from_str(self, seed):
        pass
    
    @abstractmethod
    def from_dict(self, seed):
        pass

class RangedParameterValue(AParameterValue):
    
    def __init__(self, start : int, end = None) -> None:
        self.START, self.END = start, end if end else start

    def __str__(self) -> str:
        if self.START == self.END:
            return str(self.START)
        return RANGE_SEPARATOR.join([str(self.START), str(self.END)])
    
    def to_dict_value(self):
        if self.START == self.END:
            return self.START
        else:
            return [self.START, self.END]
        
    def resolve(self, seed):
        if self.START == self.END:
            return self.START
        
        return Random(seed).randint(self.START, self.END)

    
    @staticmethod
    def from_str(value : str, special_separator = None):
        separator = special_separator if special_separator else RANGE_SEPARATOR
        
        if value.isdigit():
            return RangedParameterValue(int(value))
        
        if separator in value:
            splits = value.split(separator)
            if len(splits) > 2:
                raise Exception('InvalidInputException: More than two endpoints provided.')
            elif not all(s.isdigit() for s in splits):
                raise Exception('InvalidInputException: Tried parsing a non-digit while digit was expected.')
            else:
                return RangedParameterValue(int(splits[0]), int(splits[1]))
        
        raise Exception('InvalidInputException: Tried parsing a non-digit while digit was expected.')
        
        

    @staticmethod
    def from_dict(input):
        if isinstance(input, list):
            if len(input) > 2:
                raise Exception('InvalidInputException: More than two endpoints provided.')
            return RangedParameterValue(input[0], input[1])
        else:
            return RangedParameterValue(input)

    @staticmethod
    def random(random : Random, min, max = None):
        if not max or min == max or random.choice([True, False]):
            return RangedParameterValue(random.randint(min,max))

        values = [random.randint(min,max), random.randint(min,max)]
        values.sort()
        return RangedParameterValue(values[0], values[1])
    
    def __add__(self, other):
        if isinstance(other, int):
            self.START += other
            self.END += other

class TruthParameterValue(AParameterValue):
    def __init__(self, value : bool) -> None:
        self.VALUE = value

    def resolve(self, _):
        return int(self.VALUE)

    @staticmethod
    def random(random : Random):
        return TruthParameterValue(random.choice([True, False]))

    @staticmethod
    def from_str(input : str):
        if str(True).lower() == input.lower() or str(int(True)) == input:
            return TruthParameterValue(True)
        
        if str(False).lower() == input.lower() or str(int(False)) == input:
            return TruthParameterValue(False)
        
        raise Exception('InvalidInputException: Tried parsing a truth value and failed.')
    
    @staticmethod
    def from_dict(input):
        if isinstance(input, bool):
            return TruthParameterValue(input)
        
        if isinstance(input, int):
            if input in [0,1]:
                return TruthParameterValue(bool(input))
        
        if isinstance(input, str):
            return TruthParameterValue.from_str(input)
        
        raise Exception('InvalidInputException: Tried parsing a truth value and failed.')

        
    def __str__(self) -> str:
        return str(int(self.VALUE))
    
    def to_dict_value(self):
        return self.VALUE

class StepConfig():
    def __init__(self, steps : dict[EGenerationSteps, dict[str, int]]) -> None:
        self.STEPS = steps
        
    @staticmethod
    def from_str(input : str):
        try:
            steps = {}
            splits = input.split(INTERMEDIATE_SEPARATOR)
            for i, step in enumerate(EGenerationSteps):
                iterations, seed = splits[i].split(SMALL_SEPARATOR)
                steps[step] = {
                    'iterations' : int(iterations),
                    'seed' : int(seed)
                }
            
            return StepConfig(steps)
        except:
            raise Exception(f'InvalidGenesisTag: Unable to parse rerun seeds from {input}.')
        
    
    @staticmethod
    def from_json(random : Random, input : dict):
        steps = input.copy()
        for step in EGenerationSteps:
            if step.name in input.keys():
                steps[step] = steps.pop(step.name)
                if 'seed' not in steps[step].keys():
                    steps[step]['seed'] = random.randint(0,1000)
            else:
                steps[step] = {
                    'iterations' : 1,
                    'seed' : random.randint(0,1000)
                }
        return StepConfig(steps)
    
    @staticmethod
    def random(random : Random):
        steps = {}
        for step in EGenerationSteps:
            steps[step] = {
                'iterations' : 1,
                'seed' : random.randint(0,1000)
            }
        return StepConfig(steps)
    
    def iterate(self, seed = None):
        if seed == None:
            for step in EGenerationSteps:
                self.STEPS[step]['seed'] += 1
        else:
            self.STEPS[seed]['seed'] += 1
        return self

    def __str__(self) -> str:
        return INTERMEDIATE_SEPARATOR.join([SMALL_SEPARATOR.join([str(self.STEPS[s]['iterations']), str(self.STEPS[s]['seed'])]) for s in EGenerationSteps])
    
    def current_iteration(self):
        return INTERMEDIATE_SEPARATOR.join(['1' + SMALL_SEPARATOR + str(self.STEPS[s]['seed']) for s in EGenerationSteps])

    
    def to_dict(self):
        output = deepcopy(self.STEPS)
        for step in EGenerationSteps:
            output[step.name] = output.pop(step)
        return output
    
class CommunicationConfig():
    def __init__(self, traffic_profile : ETrafficProfile, connection_count : RangedParameterValue, anomaly_count : RangedParameterValue) -> None:
        self.TRAFFIC_PROFILE = traffic_profile
        self.CONNECTION_COUNT = connection_count
        self.ANOMALY_COUNT = anomaly_count

    @staticmethod
    def from_str(input: str):
        traffic_profile, conneciton_count, anomaly_count = input.split(SMALL_SEPARATOR)
        return CommunicationConfig(ETrafficProfile.from_value(int(traffic_profile)), RangedParameterValue.from_str(conneciton_count), RangedParameterValue.from_str(anomaly_count))

    @staticmethod
    def random(random : Random):
        return CommunicationConfig(random.choice([ETrafficProfile.STRIC_ISOLATION, ETrafficProfile.CONVERGED_NETWORKS, ETrafficProfile.DISTRIBUTED_CONTROL]), RangedParameterValue.random(random, 10,100),RangedParameterValue.random(random, 10,100))

    @staticmethod
    def from_dict(json : dict):
        return CommunicationConfig(ETrafficProfile.from_str(json['traffic_profile']), RangedParameterValue.from_dict(json['connection_count']), RangedParameterValue.from_dict(json['anomaly_count']))

    def to_dict(self):
        return {
            'traffic_profile' : self.TRAFFIC_PROFILE.name,
            'connection_count' : self.CONNECTION_COUNT.to_dict_value(),
            'anomaly_count' : self.ANOMALY_COUNT.to_dict_value()
        }
    
    def __str__(self) -> str:
        return SMALL_SEPARATOR.join([str(self.TRAFFIC_PROFILE.value), str(self.CONNECTION_COUNT), str(self.ANOMALY_COUNT)])
    

class LayerDeviceCountConfig():
    def __init__(self, definitions : dict[ENetworkLayer, dict[EDeviceRole, AParameterValue]]) -> None:
        self.LAYER_DEFINITIONS = definitions
        pass

    def from_str(input : str):
        topology_splits = input.split(INTERMEDIATE_SEPARATOR)
        definitions : dict[ENetworkLayer, dict[EDeviceRole, int]] = {}
        for i, topolog_type in enumerate(ENetworkLayer):
            device_splits = topology_splits[i].split(SMALL_SEPARATOR)
            minimal_device_distribution = {}
            for j, device_type in enumerate(EDeviceRole.configurables()):
                value = device_splits[j]
                if device_type in [EDeviceRole.IT_END_DEVICE, EDeviceRole.OT_END_DEVICE]:
                    minimal_device_distribution[device_type] = TruthParameterValue.from_str(value)
                else:
                    minimal_device_distribution[device_type] = RangedParameterValue.from_str(value)
            
            definitions[topolog_type] = minimal_device_distribution

        return LayerDeviceCountConfig(definitions)
    
    def from_dict(input : dict):
        json = input.copy()
        for layer in ENetworkLayer:
            json[layer] = json.pop(layer.name)
            for device_type in EDeviceRole.configurables():
                if device_type in [EDeviceRole.IT_END_DEVICE, EDeviceRole.OT_END_DEVICE]:
                    json[layer][device_type] = TruthParameterValue.from_dict(json[layer].pop(device_type.name))
                else:
                    json[layer][device_type] = RangedParameterValue.from_dict(json[layer].pop(device_type.name))

        return LayerDeviceCountConfig(json)

    def __str__(self) -> str:
        output = []
        for ld in self.LAYER_DEFINITIONS.values():
            tmp = []
            for key in EDeviceRole.configurables():
                tmp.append(str(ld[key]))
            output.append(SMALL_SEPARATOR.join(tmp))
                                
        return INTERMEDIATE_SEPARATOR.join(output)
    
    def to_dict(self):
        output = deepcopy(self.LAYER_DEFINITIONS)
        for layer in ENetworkLayer:
            output[layer.name] = output.pop(layer)
            for device_type in EDeviceRole.configurables():
                output[layer.name][device_type.name] = output[layer.name].pop(device_type).to_dict_value()
        return output
    
    @staticmethod
    def random(random : Random):
        definitions = {}
        for layer in ENetworkLayer:
            definitions[layer] = {}
            for device_type in EDeviceRole.configurables():
                if device_type == EDeviceRole.SERVER:
                    if layer == ENetworkLayer.CONNECTIVITY:
                        definitions[layer][device_type] = RangedParameterValue(random.randint(1,2))
                    else:
                        definitions[layer][device_type] = RangedParameterValue(0)

                elif device_type == EDeviceRole.CONTROLLER:
                    definitions[layer][device_type] = RangedParameterValue.random(random, 1, random.randint(2, 4))

                elif device_type in [EDeviceRole.OT_END_DEVICE, EDeviceRole.IT_END_DEVICE]:
                    if device_type == EDeviceRole.OT_END_DEVICE and layer == ENetworkLayer.CONNECTIVITY:
                        definitions[layer][device_type] = TruthParameterValue(False)
                    else:
                        definitions[layer][device_type] = TruthParameterValue.random(random)
                else:
                    definitions[layer][device_type] = RangedParameterValue.random(random, 2)

        return LayerDeviceCountConfig(definitions)
            
class LayerDefinitionConfig():
    def __init__(self, layer_class : ENetworkLayer, topology_distribution : dict[ESubnetTopologyType, int], switch_count : RangedParameterValue, devices_per_switch : RangedParameterValue, count : RangedParameterValue) -> None:
        self.LAYER_CLASS = layer_class
        self.TOPOLOGY_DISTRIBUTION = topology_distribution
        self.SWITCH_COUNT = switch_count
        self.DEVICE_PER_SWITCH = devices_per_switch
        self.COUNT = count

    @staticmethod
    def from_str(input : str):
        try:
            preamble, structure = input.split(INTERMEDIATE_SEPARATOR)
            layer_type, per_upper_layer, switch_count, devices_per_switch = preamble.split(SMALL_SEPARATOR)
            
            structure_splits = structure.split(SMALL_SEPARATOR)
            topology_distribution = {}
            for i, topology_type in enumerate(ESubnetTopologyType):
                topology_distribution[topology_type] = int(structure_splits[i])

            return LayerDefinitionConfig(ENetworkLayer.from_value(int(layer_type)), topology_distribution, RangedParameterValue.from_str(switch_count), RangedParameterValue.from_str(devices_per_switch), RangedParameterValue.from_str(per_upper_layer))
        except:
            raise Exception(f'InvalidGenesisTag: Unable to parse genesis tag layer configuration from {input}.')
        
    @staticmethod
    def from_dict(input : dict):
        topology_distribution : dict = input['structure'].copy()
        for topology_type in ESubnetTopologyType:
            topology_distribution[topology_type] = topology_distribution.pop(topology_type.name)

        return LayerDefinitionConfig(ENetworkLayer.from_str(input['layer_type']), topology_distribution, RangedParameterValue.from_dict(input['switch_count']), RangedParameterValue.from_dict(input['devices_per_switch']), RangedParameterValue.from_dict(input['per_upper_layer']))
        
    def __str__(self) -> str:
        output = [str(self.LAYER_CLASS.value), str(self.COUNT), str(self.SWITCH_COUNT), str(self.DEVICE_PER_SWITCH)]
        output = [SMALL_SEPARATOR.join(output)]
        tmp = []
        for topology in ESubnetTopologyType:
            tmp.append(str(self.TOPOLOGY_DISTRIBUTION[topology]))
        output.append(SMALL_SEPARATOR.join(tmp))
        return INTERMEDIATE_SEPARATOR.join(output)
    
    def to_dict(self) -> dict:
        output = {
            "layer_type" : self.LAYER_CLASS.name,
            "per_upper_layer" : self.COUNT.to_dict_value(),
            "switch_count" : self.SWITCH_COUNT.to_dict_value(),
            "devices_per_switch" : self.DEVICE_PER_SWITCH.to_dict_value(),
            "structure" : {}
        }

        for topology_type in ESubnetTopologyType:
            output['structure'][topology_type.name] = int(self.TOPOLOGY_DISTRIBUTION[topology_type])
        return output
    
    @staticmethod
    def random(random : Random, tree_height : int):
        layer_class = ENetworkLayer.CONNECTIVITY if tree_height == 0 else random.choice([ENetworkLayer.AGGREGATED_CONTROL, ENetworkLayer.PROCESS])
        subnet_distribution = {}
        for topology_type in ESubnetTopologyType:
            subnet_distribution[topology_type] = random.randint(0,10)

        return LayerDefinitionConfig(layer_class, subnet_distribution, RangedParameterValue(random.randint(2,4)), RangedParameterValue(random.randint(2,4)), RangedParameterValue(random.randint(2,4)))
    
class GenerationConfig():
    def __init__(self, range_resolution_seed : int, step_config : StepConfig, communication_config : CommunicationConfig, layer_config : LayerDeviceCountConfig, layer_definition_configs : list[LayerDefinitionConfig]) -> None:
        self.RANGE_RESOLUTION_SEED = range_resolution_seed
        self.STEP_CONFIG = step_config
        self.COMMUNICATION = communication_config
        self.LAYER_TYPE_CONFIG = layer_config
        self.LAYER_DEFINITIONS = layer_definition_configs

    def __str__(self):
        output = [str(self.RANGE_RESOLUTION_SEED), str(self.STEP_CONFIG), str(self.COMMUNICATION), str(self.LAYER_TYPE_CONFIG)] + [str(lg) for lg in self.LAYER_DEFINITIONS]
        return f"genesis:v{version('HSES-GeNESIS')}" + TAG_ENCAPSULATOR + BIG_SEPARATOR.join(output) + TAG_ENCAPSULATOR
    
    def current_iteration_tag(self) -> str:
        output = [str(self.RANGE_RESOLUTION_SEED), self.STEP_CONFIG.current_iteration(), str(self.COMMUNICATION), str(self.LAYER_TYPE_CONFIG)] + [str(lg) for lg in self.LAYER_DEFINITIONS]
        return f"genesis:v{version('HSES-GeNESIS')}" + TAG_ENCAPSULATOR + BIG_SEPARATOR.join(output) + TAG_ENCAPSULATOR


    def to_dict(self) -> dict:
        return {
            'range_resolution_seed' : self.RANGE_RESOLUTION_SEED,
            'steps' : self.STEP_CONFIG.to_dict(),
            'communication' : self.COMMUNICATION.to_dict(),
            'layer_device_count_configuration' : self.LAYER_TYPE_CONFIG.to_dict(),
            'layer_definitions' : [d.to_dict() for d in self.LAYER_DEFINITIONS]
        }

    @staticmethod
    def from_dict(random : Random, input):
        if 'range_resolution_seed' not in input:
            range_resolution_seed = random.randint(0,1000)
        else:
            range_resolution_seed = input['range_resolution_seed']

        steps = StepConfig.from_json(random, input['steps'])

        communication_config = CommunicationConfig.from_dict(input['communication'])

        layer_type_config = LayerDeviceCountConfig.from_dict(input['layer_device_count_configuration'])

        layer_definitions = [LayerDefinitionConfig.from_dict(layer_json) for layer_json in input['layer_definitions']]

        return GenerationConfig(range_resolution_seed, steps, communication_config, layer_type_config, layer_definitions)

    @staticmethod
    def from_file(random, input):
        return GenerationConfig.from_dict(random, load(input))

    @staticmethod
    def from_str(input : str):
        try:
            if not input.endswith(TAG_ENCAPSULATOR):
                raise Exception(f'InvalidGenesisTag: Incomplete genesis tag detected: {input}.')
            
            versioning, tag_infos = input.split(TAG_ENCAPSULATOR)[:2]
            version_number = versioning.split(INTERMEDIATE_SEPARATOR)[1][1:]
            if version_number != version('HSES-GeNESIS'):
                raise Exception(f'InvalidGenesisTag: Incompatible GeNESIS version detected {version_number}.')

            configs = tag_infos.split(BIG_SEPARATOR)
            range_resolution_seed, seed_info, communication_info, layer_device_distribution = configs[:4]
            seed_config = StepConfig.from_str(seed_info)
            communication_config = CommunicationConfig.from_str(communication_info)
            layer_config = LayerDeviceCountConfig.from_str(layer_device_distribution)
            
            layer_generation_configs = [LayerDefinitionConfig.from_str(lgc) for lgc in configs[4:]]
            return GenerationConfig(range_resolution_seed, seed_config, communication_config, layer_config, layer_generation_configs)
        except Exception as e:
            print(e)
            raise Exception(f'InvalidGenesisTag: Unable to parse genesis tag {input}.')
    
    @staticmethod
    def random(random):
        seeds = {}
        for step in EGenerationSteps:
            seeds[step] = random.randint(0, 1000)
        
        depth = random.randint(2,4)
        layer_configs = []
        while len(layer_configs) < depth:
            layer_config = LayerDefinitionConfig.random(random, len(layer_configs))
            layer_configs.append(layer_config)
            if layer_config.LAYER_CLASS == ENetworkLayer.PROCESS:
                break
        return GenerationConfig(random.randint(0,1000), StepConfig.random(random), CommunicationConfig.random(random), LayerDeviceCountConfig.random(random), layer_configs)