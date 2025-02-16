from abc import ABC, abstractmethod
from json import dump, load
from random import randint
from hses_genesis.utils.constants import BIG_SEPARATOR, COMMUNICATION_KEY, GENESIS_PACKAGE_NAME, HOST_TYPES_KEY, ITERATION_SEPARATOR, ITERATIONS_KEY, LAYER_DESCRIPTIONS_KEY, MAX_HOSTS_PER_SWITCH_KEY, MEDIUM_SEPARATOR, PER_UPPER_LAYER_KEY, REPETITIONS_KEY, RULESET_ANOMALY_COUNT_KEY, SECURITY_KEY, SMALL_SEPARATOR, STATEFUL_RULE_PERCENTAGE_KEY, STRUCTURE_DISTRIBUTION_KEY, SWITCH_COUNT_KEY, TAG_ENCAPSULATOR, TOPOLOGY_KEY, TRAFFIC_PROFILE_KEY, UNSET_INDICATOR, UPPER_CONNECTION_BOUND_KEY
from hses_genesis.utils.enum_objects import EDeviceRole, ESubnetTopologyStructure, ETrafficProfile, ENetworkLayer
from importlib.metadata import version
from re import search

class AGenesisTaggable(ABC):
    def __init__(self):
        super().__init__()
        self.COMPLETED = False

    @abstractmethod
    def from_str(value):
        pass
    
    @abstractmethod
    def from_dict(value):
        pass

    @abstractmethod
    def to_run_str(self) -> str:
        pass

    def __str__(self):
        return self.to_run_str()

    @abstractmethod
    def to_run_dict_value(self):
        pass

    def to_total_str(self) -> str:
        return self.to_run_str()

    def to_total_dict_value(self):
        return self.to_run_dict_value()
    
    def iterate(self) -> bool:
        if self.COMPLETED:
            return False
        
        iteration_success = self.__apply_iteration_logic__()
        if not iteration_success:
            self.COMPLETED = True
        return iteration_success
    
    def __apply_iteration_logic__(self) -> bool:
        return False
    
    def reset(self):
        self.COMPLETED = False

class IterativeParameterValue(AGenesisTaggable):
    def __init__(self, start : int, end : int = None, step_size : int = 1):
        super().__init__()
        self.CURRENT, self.START = start, start
        self.END = end if end else start
        self.STEP_SIZE = step_size

    def to_run_str(self, default_value = None):
        if default_value == self.CURRENT:
            return UNSET_INDICATOR
        return str(self.CURRENT)
    
    def to_total_str(self, default_value = None):
        if self.START == self.END and default_value == self.START:
            return UNSET_INDICATOR
        if self.START == self.END:
            return str(self.CURRENT)
        return f'{self.START}{ITERATION_SEPARATOR}{self.END}{ITERATION_SEPARATOR}{self.STEP_SIZE}'
    
    def to_run_dict_value(self):
        return self.CURRENT

    def __int__(self):
        return self.CURRENT
    
    def __list__(self):
        if self.START == self.END:
            return [self.CURRENT]
        return list(range(self.CURRENT, self.END, self.STEP_SIZE))

    def to_total_dict_value(self):
        if self.START != self.END:
            return [self.START, self.END, self.STEP_SIZE]
        return self.CURRENT

    @staticmethod
    def from_dict(value, minimum = None, maximum = None):
        output = [int(x) for x in value] if isinstance(value, list) else [int(value)]
        if minimum:
            output = [max(minimum, x) for x in output]
        if maximum:
            output = [min(maximum, x) for x in output]

        if len(output) > 1:
            start, end, step_size = output
            return IterativeParameterValue(start, end, step_size)
        return IterativeParameterValue(output[0])
    
    @staticmethod
    def from_str(value : str, minimum = None, maximum = None):
        values = [int(x) for x in value.split(ITERATION_SEPARATOR)]
        return IterativeParameterValue.from_dict(values, minimum, maximum)
    
    def __apply_iteration_logic__(self):
        if self.CURRENT < self.END:
            self.CURRENT = min(self.END, self.CURRENT + self.STEP_SIZE)
            return True
        
        self.CURRENT = self.START
        return False
    
    def reset(self):
        self.CURRENT = self.START
        return super().reset()

class LayerDefinition(AGenesisTaggable):
    def __init__(self, per_upper_layer : IterativeParameterValue, switch_count : IterativeParameterValue, max_hosts_per_switch : IterativeParameterValue, repetitions : IterativeParameterValue, host_types : dict, structure_distribution : dict, layer_classification = ENetworkLayer.AGGREGATED_CONTROL):
        super().__init__()
        self.per_upper_layer = per_upper_layer
        self.switch_count = switch_count
        self.max_hosts_per_switch = max_hosts_per_switch
        self.host_types = host_types
        self.structure_distribution = structure_distribution
        self.layer_classification = layer_classification
        self.repetitions = repetitions

    @staticmethod
    def from_dict(value : dict, layer_type = ENetworkLayer.AGGREGATED_CONTROL):
        per_upper_layer = IterativeParameterValue.from_dict(value.get(PER_UPPER_LAYER_KEY, 1), minimum=1)
        switch_count = IterativeParameterValue.from_dict(value.get(SWITCH_COUNT_KEY, 0), minimum=1)
        max_hosts_per_switch = IterativeParameterValue.from_dict(value.get(MAX_HOSTS_PER_SWITCH_KEY, 0), minimum=1)
        repetitions = IterativeParameterValue.from_dict(value.get(REPETITIONS_KEY, 1), minimum=1)
        host_types : dict = value.get(HOST_TYPES_KEY, {})
        host_types = {role : int(host_types.get(role.name, 0)) for role in EDeviceRole.configurables()}
        structure_distribution = value.get(STRUCTURE_DISTRIBUTION_KEY, {})
        structure_distribution = {key : structure_distribution.get(key.name, 0) for key in ESubnetTopologyStructure}
        if sum(structure_distribution.values()) == 0:
            structure_distribution[ESubnetTopologyStructure.LINE] = 1
        return LayerDefinition(
            per_upper_layer=per_upper_layer,
            switch_count=switch_count,
            max_hosts_per_switch=max_hosts_per_switch,
            host_types=host_types,
            structure_distribution=structure_distribution,
            layer_classification=layer_type,
            repetitions=repetitions)
    
    @staticmethod
    def from_str(value : str, layer_type = ENetworkLayer.AGGREGATED_CONTROL):
        preamble, raw_host_types, raw_structures = value.split(MEDIUM_SEPARATOR)
        per_upper_layer, switch_counts, hosts_per_switch, repetitions = tuple(map(lambda x: IterativeParameterValue.from_str(x, minimum=1), preamble.split(SMALL_SEPARATOR)))
        if raw_host_types == UNSET_INDICATOR:
            host_types = {key : 0 for key in EDeviceRole.configurables()}
        else:
            host_snippets = raw_host_types.split(SMALL_SEPARATOR)
            host_types = {}
            for snippet in host_snippets:
                role = EDeviceRole.from_configurables_id(snippet)
                match = search(r'(\d+)', snippet)
                host_types[role] = int(match.group()) if match else -1
            host_types = {key : host_types.get(key, 0) for key in EDeviceRole.configurables()}

        if raw_structures == UNSET_INDICATOR:
            structures = {key : 0 if key != ESubnetTopologyStructure.LINE else 1 for key in ESubnetTopologyStructure}
        else:
            structure_snippets = raw_structures.split(SMALL_SEPARATOR)
            structures = {}
            for snippet in structure_snippets:
                subnet_type = ESubnetTopologyStructure.from_str(snippet[0])
                match = search(r'(\d+)', snippet)
                structures[subnet_type] = int(match.group()) if match else 1
            structures = { key : structures.get(key, 0) for key in ESubnetTopologyStructure}
        
        return LayerDefinition(
            per_upper_layer=per_upper_layer,
            switch_count=switch_counts,
            max_hosts_per_switch=hosts_per_switch,
            host_types=host_types,
            structure_distribution=structures,
            layer_classification=layer_type,
            repetitions=repetitions
        )

    def __get_static_str_suffix__(self):
        host_types = []
        for key, value in self.host_types.items():
            if value != 0:
                if value < 0:
                    host_types.append(key.value[0])
                else:
                    host_types.append(f'{key.value[0]}{value}')
        host_types = SMALL_SEPARATOR.join(host_types) if len(host_types) > 0 else UNSET_INDICATOR
        structures = [f'{key.name[0]}{value if value > 1 else ""}' for key, value in self.structure_distribution.items() if value > 0]
        structures = SMALL_SEPARATOR.join(structures) if len(structures) > 0 else UNSET_INDICATOR
        return MEDIUM_SEPARATOR.join([host_types, structures])
    
    def to_run_str(self):
        preamble = SMALL_SEPARATOR.join(map(lambda x: x.to_run_str(default_value=1), [self.per_upper_layer, self.switch_count, self.max_hosts_per_switch, self.repetitions]))
        return MEDIUM_SEPARATOR.join([preamble, self.__get_static_str_suffix__()])

    def to_total_str(self):
        preamble = SMALL_SEPARATOR.join(map(lambda x: x.to_total_str(default_value=1), [self.per_upper_layer, self.switch_count, self.max_hosts_per_switch, self.repetitions]))
        return MEDIUM_SEPARATOR.join([preamble, self.__get_static_str_suffix__()])

    def to_run_dict_value(self):
        return {
            PER_UPPER_LAYER_KEY : self.per_upper_layer.to_run_dict_value(),
            SWITCH_COUNT_KEY : self.switch_count.to_run_dict_value(),
            MAX_HOSTS_PER_SWITCH_KEY : self.max_hosts_per_switch.to_run_dict_value(),
            HOST_TYPES_KEY : {key.name : value for key, value in self.host_types.items()},
            STRUCTURE_DISTRIBUTION_KEY : {key.name : value for key, value in self.structure_distribution.items()},
            REPETITIONS_KEY : self.repetitions.to_run_dict_value()
        }
    
    def to_total_dict_value(self):
        return {
            PER_UPPER_LAYER_KEY : self.per_upper_layer.to_total_dict_value(),
            SWITCH_COUNT_KEY : self.switch_count.to_total_dict_value(),
            MAX_HOSTS_PER_SWITCH_KEY : self.max_hosts_per_switch.to_total_dict_value(),
            HOST_TYPES_KEY : {key.name : value for key, value in self.host_types.items()},
            STRUCTURE_DISTRIBUTION_KEY : {key.name : value for key, value in self.structure_distribution.items()},
            REPETITIONS_KEY : self.repetitions.to_total_dict_value()
        }
    
    def __apply_iteration_logic__(self):
        for iterable_value in [self.per_upper_layer, self.switch_count, self.max_hosts_per_switch, self.repetitions]:
            if iterable_value.iterate():
                return True

        return False
    
    def reset(self):
        for iterable_value in [self.per_upper_layer, self.switch_count, self.max_hosts_per_switch, self.repetitions]:
            iterable_value.reset()

        return super().reset()

class TopologyGenerationConfig(AGenesisTaggable):
    DEFAULT_MAPPING = 1

    def __init__(self, iterations : int, layer_definitions : list[LayerDefinition]):
        super().__init__()
        self.iterations = iterations
        self.layer_definitions = layer_definitions

    @staticmethod
    def from_dict(value : dict):
        iterations = value.get(ITERATIONS_KEY, 1)
        layer_definitions = [LayerDefinition.from_dict(layer_definition) for layer_definition in value.get(LAYER_DESCRIPTIONS_KEY, [])]
        if len(layer_definitions) > 0:
            layer_definitions[0].layer_classification = ENetworkLayer.CONNECTIVITY
            layer_definitions[-1].layer_classification = ENetworkLayer.PROCESS

        return TopologyGenerationConfig(iterations=iterations,
                                        layer_definitions=layer_definitions)
    
    @staticmethod
    def from_str(value : list[str]):
        iterations = int(value[0]) if value[0] != UNSET_INDICATOR else TopologyGenerationConfig.DEFAULT_MAPPING[0]
        layer_definitions = [LayerDefinition.from_str(layer_definition) for layer_definition in value[1:]] if len(value) > 1 else []
        if len(layer_definitions) > 0:
            layer_definitions[0].layer_classification = ENetworkLayer.CONNECTIVITY
            layer_definitions[-1].layer_classification = ENetworkLayer.PROCESS
        return TopologyGenerationConfig(iterations=iterations, layer_definitions=layer_definitions)

    def to_run_str(self):
        return BIG_SEPARATOR.join([UNSET_INDICATOR] + [x.to_run_str() for x in self.layer_definitions])
    
    def to_total_str(self):
        iteration_str = str(self.iterations) if self.iterations != TopologyGenerationConfig.DEFAULT_MAPPING else UNSET_INDICATOR
        return BIG_SEPARATOR.join([iteration_str] + [x.to_total_str() for x in self.layer_definitions])
    
    def to_run_dict_value(self):
        return {
            ITERATIONS_KEY : 1,
            LAYER_DESCRIPTIONS_KEY : [layer_definition.to_run_dict_value() for layer_definition in self.layer_definitions]
        }
    
    def to_total_dict_value(self):
        return {
            ITERATIONS_KEY : self.iterations,
            LAYER_DESCRIPTIONS_KEY : [layer_definition.to_total_dict_value() for layer_definition in self.layer_definitions]
        }
    
    def __apply_iteration_logic__(self):
        for layer_definition in self.layer_definitions:
            if layer_definition.iterate():
                return True
        return False
    
    def reset(self):
        for layer_definition in self.layer_definitions:
            layer_definition.reset()
        return super().reset()
    
class CommunicationGenerationConfig(AGenesisTaggable):
    DEFAULT_MAPPING = [1,0,-1]

    def __init__(self, iterations : int = DEFAULT_MAPPING[0], traffic_profile : ETrafficProfile = ETrafficProfile.from_value(DEFAULT_MAPPING[1]), connection_bound : IterativeParameterValue = IterativeParameterValue(DEFAULT_MAPPING[2])):
        super().__init__()
        self.iterations = iterations
        self.traffic_profile = traffic_profile
        self.connection_bound = connection_bound

    @staticmethod
    def from_str(value : str):
        if value == UNSET_INDICATOR:
            iterations, traffic_profile_id, connection_bound = CommunicationGenerationConfig.DEFAULT_MAPPING.copy()
        else:
            iterations, traffic_profile_id, connection_bound = [(CommunicationGenerationConfig.DEFAULT_MAPPING[i] if x == UNSET_INDICATOR else int(x)) for (i, x) in enumerate(value.split(SMALL_SEPARATOR))]
        
        return CommunicationGenerationConfig(iterations=(1 if iterations == UNSET_INDICATOR else int(iterations)),
                                             traffic_profile=ETrafficProfile.from_value(int(traffic_profile_id)),
                                             connection_bound=IterativeParameterValue(connection_bound))

    @staticmethod
    def from_dict(value : dict):
        iterations = value.get(ITERATIONS_KEY, 1)
        traffic_profile = ETrafficProfile.from_str(value.get(TRAFFIC_PROFILE_KEY, ETrafficProfile.STRICT_ISOLATION.name))
        connection_bound = IterativeParameterValue.from_dict(value.get(UPPER_CONNECTION_BOUND_KEY, -1))
        return CommunicationGenerationConfig(iterations=iterations,
                                             traffic_profile=traffic_profile,
                                             connection_bound=connection_bound)
    
    def to_run_str(self):
        if all(int(x) == CommunicationGenerationConfig.DEFAULT_MAPPING[i] for (i,x) in enumerate([1, self.traffic_profile.value, self.connection_bound.CURRENT])):
            return UNSET_INDICATOR
        
        traffic_profile = str(self.traffic_profile.value) if self.traffic_profile != CommunicationGenerationConfig.DEFAULT_MAPPING[1] else UNSET_INDICATOR
        connection_bound = self.connection_bound.to_run_str(default_value=CommunicationGenerationConfig.DEFAULT_MAPPING[2])
        return SMALL_SEPARATOR.join([UNSET_INDICATOR, traffic_profile, connection_bound])
    
    def to_total_str(self):
        if all(x == CommunicationGenerationConfig.DEFAULT_MAPPING[i] for (i,x) in enumerate([self.iterations, self.traffic_profile.value, self.connection_bound.to_total_dict_value()])):
            return UNSET_INDICATOR
        
        iterations = str(self.iterations) if self.iterations != CommunicationGenerationConfig.DEFAULT_MAPPING[0] else UNSET_INDICATOR
        traffic_profile = str(self.traffic_profile.value) if self.traffic_profile != CommunicationGenerationConfig.DEFAULT_MAPPING[1] else UNSET_INDICATOR
        connection_bound = self.connection_bound.to_total_str(CommunicationGenerationConfig.DEFAULT_MAPPING[2])
        return SMALL_SEPARATOR.join([iterations, traffic_profile, connection_bound])

    def to_run_dict_value(self):
        return {
            ITERATIONS_KEY : 1,
            TRAFFIC_PROFILE_KEY : self.traffic_profile.name,
            UPPER_CONNECTION_BOUND_KEY : self.connection_bound.to_run_dict_value()
        }
    
    def to_total_dict_value(self):
        return {
            ITERATIONS_KEY : self.iterations,
            TRAFFIC_PROFILE_KEY : self.traffic_profile.name,
            UPPER_CONNECTION_BOUND_KEY : self.connection_bound.to_total_dict_value()
        }
    
    def __apply_iteration_logic__(self):
        if self.connection_bound.iterate():
            return True
        return False
    
    def reset(self):
        self.connection_bound.reset()
        return super().reset()
    
class SecurityGenerationConfig(AGenesisTaggable):
    DEFAULT_MAPPING = [1,0,0]

    def __init__(self, iterations : int = DEFAULT_MAPPING[0], ruleset_anomaly_count = IterativeParameterValue(DEFAULT_MAPPING[1]), stateful_rule_percentage = IterativeParameterValue(DEFAULT_MAPPING[2])):
        super().__init__()
        self.iterations = iterations
        self.ruleset_anomaly_count = ruleset_anomaly_count
        self.stateful_percentage = stateful_rule_percentage

    @staticmethod
    def from_dict(value : dict):
        iterations = value.get(ITERATIONS_KEY, 1)
        ruleset_anomaly_count = IterativeParameterValue.from_dict(value.get(RULESET_ANOMALY_COUNT_KEY, 0))
        stateful_rule_percentage = IterativeParameterValue.from_dict(value.get(STATEFUL_RULE_PERCENTAGE_KEY, 0), minimum=0, maximum=100)
        return SecurityGenerationConfig(iterations=iterations,
                                        ruleset_anomaly_count=ruleset_anomaly_count,
                                        stateful_rule_percentage=stateful_rule_percentage)
    
    @staticmethod
    def from_str(value : str):
        if value == UNSET_INDICATOR:
            iterations, ruleset_anomaly_count, stateful_rule_percentage = SecurityGenerationConfig.DEFAULT_MAPPING.copy()
        else:
            iterations, ruleset_anomaly_count, stateful_rule_percentage = [SecurityGenerationConfig.DEFAULT_MAPPING[i] if x == UNSET_INDICATOR else x for (i,x) in enumerate(value.split(SMALL_SEPARATOR))]
        ruleset_anomaly_count = IterativeParameterValue.from_str(ruleset_anomaly_count, minimum=0)
        stateful_rule_percentage = IterativeParameterValue.from_str(stateful_rule_percentage, minimum=0, maximum=100)
        return SecurityGenerationConfig(iterations=int(iterations),
                                        ruleset_anomaly_count=ruleset_anomaly_count,
                                        stateful_rule_percentage=stateful_rule_percentage)

    def to_run_str(self):
        if all((x == SecurityGenerationConfig.DEFAULT_MAPPING[i]) for (i, x) in enumerate([1, self.ruleset_anomaly_count, self.stateful_percentage.CURRENT])):
            return UNSET_INDICATOR
        
        ruleset_anomaly_count = self.ruleset_anomaly_count.to_run_str(SecurityGenerationConfig.DEFAULT_MAPPING[1])
        stateful_rule_percentage = self.stateful_percentage.to_run_str(SecurityGenerationConfig.DEFAULT_MAPPING[2])
        return SMALL_SEPARATOR.join([UNSET_INDICATOR, ruleset_anomaly_count, stateful_rule_percentage])
    
    def to_total_str(self):
        if all((x == SecurityGenerationConfig.DEFAULT_MAPPING[i]) for (i, x) in enumerate([self.iterations, self.ruleset_anomaly_count.to_total_dict_value(), self.stateful_percentage.to_total_dict_value()])):
            return UNSET_INDICATOR
        
        iterations = self.iterations if self.iterations != SecurityGenerationConfig.DEFAULT_MAPPING[0] else UNSET_INDICATOR
        ruleset_anomaly_count = self.ruleset_anomaly_count.to_total_str(SecurityGenerationConfig.DEFAULT_MAPPING[1])
        stateful_rule_percentage = self.stateful_percentage.to_total_str(SecurityGenerationConfig.DEFAULT_MAPPING[2])
        return SMALL_SEPARATOR.join([iterations, ruleset_anomaly_count, stateful_rule_percentage])

    def to_run_dict_value(self):
        return {
            ITERATIONS_KEY : 1,
            RULESET_ANOMALY_COUNT_KEY : self.ruleset_anomaly_count.to_run_dict_value(),
            STATEFUL_RULE_PERCENTAGE_KEY : self.stateful_percentage.to_run_dict_value()
        }
    
    def to_total_dict_value(self):
        return {
            ITERATIONS_KEY : self.iterations,
            RULESET_ANOMALY_COUNT_KEY : self.ruleset_anomaly_count.to_total_dict_value(),
            STATEFUL_RULE_PERCENTAGE_KEY : self.stateful_percentage.to_total_dict_value()
        }
    
    def __apply_iteration_logic__(self):
        for iterable_value in [self.ruleset_anomaly_count, self.stateful_percentage]:
            if iterable_value.iterate():
                return True

        return False
    
    def reset(self):
        for iterable_value in [self.ruleset_anomaly_count, self.stateful_percentage]:
            iterable_value.reset()
        return super().reset()
        
class SeedConfig(AGenesisTaggable):
    def __init__(self, topology_seed : IterativeParameterValue, communication_seed : IterativeParameterValue, security_seed : IterativeParameterValue):
        super().__init__()
        self.topology_seed = topology_seed
        self.communication_seed = communication_seed
        self.security_seed = security_seed

    @staticmethod
    def from_str(value : str, iterations = None):
        topology_seed, communication_seed, security_seed = [IterativeParameterValue(int(x), (int(x) + iterations[i] - 1) if iterations else None) for i, x in enumerate(value.split(SMALL_SEPARATOR))]
        return SeedConfig(topology_seed=topology_seed,
                          communication_seed=communication_seed,
                          security_seed=security_seed)
    
    @staticmethod
    def from_dict(value : dict, iterations = None):
        raw_seeds = [value.get(key, randint(1,1000)) for key in [TOPOLOGY_KEY, COMMUNICATION_KEY, SECURITY_KEY]]
        topology_seed, communication_seed, security_seed = [IterativeParameterValue(seed, (seed + iterations[i] - 1) if iterations else None) for i, seed in enumerate(raw_seeds)]

        return SeedConfig(topology_seed=topology_seed,
                          communication_seed=communication_seed,
                          security_seed=security_seed)
    
    @staticmethod
    def random(iterations = None):
        raw_seeds = [randint(1,1000) for _ in range(3)]
        topology_seed, communication_seed, security_seed = [IterativeParameterValue(seed, (seed + iterations[i] - 1) if iterations else None) for i, seed in enumerate(raw_seeds)]
    
        return SeedConfig(topology_seed=topology_seed,
                          communication_seed=communication_seed,
                          security_seed=security_seed)

    def __apply_iteration_logic__(self):
        for iterative_value in [self.topology_seed, self.communication_seed, self.security_seed]:
            if iterative_value.iterate():
                return True
        return False
    
    def reset(self):
        for iterative_value in [self.topology_seed, self.communication_seed, self.security_seed]:
            iterative_value.reset()
        return super().reset()

    def to_run_str(self):
        return SMALL_SEPARATOR.join([str(x.CURRENT) for x in [self.topology_seed, self.communication_seed, self.security_seed]])
    
    def to_total_str(self):
        return SMALL_SEPARATOR.join([str(x.START) for x in [self.topology_seed, self.communication_seed, self.security_seed]])
    
    def to_run_dict_value(self):
        return {key : value.CURRENT for key, value in [(TOPOLOGY_KEY, self.topology_seed), (COMMUNICATION_KEY, self.communication_seed), (SECURITY_KEY, self.security_seed)]}
    
    def to_total_dict_value(self):
        return {key : value.START for key, value in [(TOPOLOGY_KEY, self.topology_seed), (COMMUNICATION_KEY, self.communication_seed), (SECURITY_KEY, self.security_seed)]}
    
class GenerationConfig(AGenesisTaggable):
    def __init__(self, seed_config : SeedConfig, topology_config : TopologyGenerationConfig, communication_config : CommunicationGenerationConfig, security_config : SecurityGenerationConfig):
        super().__init__()
        self.seed_config = seed_config
        self.topology_config = topology_config
        self.communication_config = communication_config
        self.security_config = security_config

    @staticmethod
    def from_str(genesis_tag : str):
        versioning, information, _ = genesis_tag.split(TAG_ENCAPSULATOR)
        version_number = versioning.split(MEDIUM_SEPARATOR)[-1][1:]
        if version(GENESIS_PACKAGE_NAME) != version_number:
            raise Exception(f'InvalidGenesisTag: Incompatible GeNESIS version detected: {version(GENESIS_PACKAGE_NAME)} != {version_number}.')
        sequences = information.split(BIG_SEPARATOR)
        communication_config = CommunicationGenerationConfig.from_str(sequences[1])
        security_config = SecurityGenerationConfig.from_str(sequences[2])
        topology_config = TopologyGenerationConfig.from_str(sequences[3:])
        seed_config = SeedConfig.from_str(sequences[0], [topology_config.iterations, communication_config.iterations, security_config.iterations])
        return GenerationConfig(seed_config=seed_config,
                                topology_config=topology_config,
                                communication_config=communication_config,
                                security_config=security_config)

    @staticmethod
    def from_dict(value):
        topology_config = TopologyGenerationConfig.from_dict(value[TOPOLOGY_KEY])

        raw_communication_config = value[COMMUNICATION_KEY]
        if raw_communication_config:
            communication_config = CommunicationGenerationConfig.from_dict(raw_communication_config)
        else:
            communication_config = CommunicationGenerationConfig()
        
        raw_security_config = value[SECURITY_KEY]
        if raw_security_config:
            security_config = SecurityGenerationConfig.from_dict(raw_security_config)
        else:
            security_config = SecurityGenerationConfig()
            
        return GenerationConfig(seed_config=SeedConfig.random([topology_config.iterations, communication_config.iterations, security_config.iterations]),
                                topology_config=topology_config,
                                communication_config=communication_config,
                                security_config=security_config)

    @staticmethod
    def from_file(dir : str):
        with open(dir, 'r') as file:
            json_config : dict = load(file)
            return GenerationConfig.from_dict(json_config)

    
    def to_run_str(self):
        return f'genesis:v{version(GENESIS_PACKAGE_NAME)}{TAG_ENCAPSULATOR}{BIG_SEPARATOR.join(map(lambda x: x.to_run_str(), [self.seed_config, self.communication_config, self.security_config, self.topology_config]))}{TAG_ENCAPSULATOR}'
    
    def to_total_str(self):
        return f'genesis:v{version(GENESIS_PACKAGE_NAME)}{TAG_ENCAPSULATOR}{BIG_SEPARATOR.join(map(lambda x: x.to_total_str(), [self.seed_config, self.communication_config, self.security_config, self.topology_config]))}{TAG_ENCAPSULATOR}'

    def to_run_dict_value(self):
        return {key : value.to_run_dict_value() for key, value in [(TOPOLOGY_KEY, self.topology_config), (COMMUNICATION_KEY, self.communication_config), (SECURITY_KEY, self.security_config)]}
    
    def to_total_dict_value(self):
        return {key : value.to_total_dict_value() for (key, value) in [(TOPOLOGY_KEY, self.topology_config), (COMMUNICATION_KEY, self.communication_config), (SECURITY_KEY, self.security_config)]}

    def to_run_file(self, location):
        with open(location, 'x') as file:
            dump(self.to_run_dict_value(), file, indent=4)
        print('Configuration saved at: ', location)

    def to_total_file(self, location):
        with open(location, 'x') as file:
            dump(self.to_total_dict_value(), file, indent=4)
        print('Configuration saved at: ', location)

    def __apply_iteration_logic__(self):
        for subconfig in [self.topology_config, self.communication_config, self.security_config]:
            if subconfig.iterate():
                return True
        return False
    
    def reset(self):
        for subconfig in [self.topology_config, self.communication_config, self.security_config]:
            subconfig.reset()
        return super().reset()