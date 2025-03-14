from abc import ABC, abstractmethod
from json import dump, load
from random import randint
from hses_genesis.utils.constants import BIG_SEPARATOR, COMMUNICATION_KEY, GENESIS_PACKAGE_NAME, HOST_TYPES_KEY, ITERATION_SEPARATOR, ITERATIONS_KEY, LAYER_DEFINITIONS_KEY, MAX_HOSTS_PER_SWITCH_KEY, MEDIUM_SEPARATOR, SUBNET_DESCENDANTS_KEY, REPETITIONS_KEY, ANOMALY_COUNT_KEY, SECURITY_KEY, SMALL_SEPARATOR, STATEFUL_PERCENTAGE_KEY, STRUCTURE_KEY, SWITCH_COUNT_KEY, TAG_ENCAPSULATOR, TOPOLOGY_KEY, TRAFFIC_PROFILE_KEY, UNSET_INDICATOR, UPPER_CONNECTION_BOUND_KEY
from hses_genesis.utils.enum_objects import EDeviceRole, ESubnetTopologyStructure, ETrafficProfile, ENetworkLayer
from importlib.metadata import version
from re import match, search

def get_single_value_by_multiple_keys(value : dict, keys : list[str], default_value):
    for key in keys:
        if key in value.keys():
            return value.get(key)
        if key.lower() in value.keys():
            return value.get(key.lower())
    return default_value

class AGenesisTaggable(ABC):
    def __init__(self, use_latex_tag = False):
        super().__init__()
        self.COMPLETED = False
        self.use_latex_tag = use_latex_tag

    @abstractmethod
    def from_str(value, use_latex_tag = False):
        pass
    
    @abstractmethod
    def from_dict(value, use_latex_tag = False):
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
    def __init__(self, start : int, end : int = None, step_size : int = 1, use_latex_tag = False):
        super().__init__(use_latex_tag)
        self.CURRENT, self.START = start, start
        self.END = end if end else start
        self.STEP_SIZE = step_size

    def to_run_str(self, default_value = None):
        if (not self.use_latex_tag) and default_value == self.CURRENT:
            return UNSET_INDICATOR
        return str(self.CURRENT)
    
    def to_total_str(self, default_value = None):
        if (not self.use_latex_tag) and self.START == self.END and default_value == self.START:
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
    def from_dict(value, use_latex_tag = False, minimum = None, maximum = None):
        output = [int(x) for x in value] if isinstance(value, list) else [int(value)]
        if minimum:
            output = [max(minimum, x) for x in output]
        if maximum:
            output = [min(maximum, x) for x in output]

        if len(output) > 1:
            start, end, step_size = output
            return IterativeParameterValue(start, end, step_size, use_latex_tag=use_latex_tag)
        return IterativeParameterValue(output[0], use_latex_tag=use_latex_tag)
    
    @staticmethod
    def from_str(value : str, use_latex_tag = False, minimum = None, maximum = None):
        values = [int(x) for x in value.split(ITERATION_SEPARATOR)]
        return IterativeParameterValue.from_dict(values, use_latex_tag, minimum, maximum)
    
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
    def __init__(self, subnet_descendants : IterativeParameterValue, switch_count : IterativeParameterValue, max_hosts_per_switch : IterativeParameterValue, repetitions : IterativeParameterValue, host_types : dict, structure_distribution : dict, layer_classification = ENetworkLayer.AGGREGATED_CONTROL, use_latex_tag = False):
        super().__init__(use_latex_tag)
        self.subnet_descendants = subnet_descendants
        self.switch_count = switch_count
        self.max_hosts_per_switch = max_hosts_per_switch
        self.host_types = host_types
        self.structure_distribution = structure_distribution
        self.layer_classification = layer_classification
        self.repetitions = repetitions

    @staticmethod
    def from_dict(value : dict, use_latex_tag = False, layer_type = ENetworkLayer.AGGREGATED_CONTROL):
        subnet_descendants = IterativeParameterValue.from_dict(value.get(SUBNET_DESCENDANTS_KEY, 1), minimum=1, use_latex_tag=use_latex_tag)
        switch_count = IterativeParameterValue.from_dict(value.get(SWITCH_COUNT_KEY, 1), minimum=-1, use_latex_tag=use_latex_tag)
        max_hosts_per_switch = IterativeParameterValue.from_dict(value.get(MAX_HOSTS_PER_SWITCH_KEY, 1), minimum=1, use_latex_tag=use_latex_tag)
        repetitions = IterativeParameterValue.from_dict(value.get(REPETITIONS_KEY, 1), minimum=1, use_latex_tag=use_latex_tag)
        host_types : dict = value.get(HOST_TYPES_KEY, dict())
        host_types = {role : int(get_single_value_by_multiple_keys(host_types, [role.name, role.name[:2], role.value], 0)) for role in EDeviceRole.configurables()}
        structure_distribution = value.get(STRUCTURE_KEY, dict())
        structure_distribution = {key : get_single_value_by_multiple_keys(structure_distribution, [key.name, key.name[0]], 0) for key in ESubnetTopologyStructure}
        if sum(structure_distribution.values()) == 0:
            structure_distribution[ESubnetTopologyStructure.LINE] = 1
        return LayerDefinition(
            subnet_descendants=subnet_descendants,
            switch_count=switch_count,
            max_hosts_per_switch=max_hosts_per_switch,
            host_types=host_types,
            structure_distribution=structure_distribution,
            layer_classification=layer_type,
            repetitions=repetitions,
            use_latex_tag=use_latex_tag)
    
    @staticmethod
    def from_str(value : str, use_latex_tag = False, layer_type = ENetworkLayer.AGGREGATED_CONTROL):
        def parse_host_types(raw_host_types : str):
            if raw_host_types == UNSET_INDICATOR:
                return {key : 0 for key in EDeviceRole.configurables()}
            
            host_types = {}
            for i, snippet in enumerate(raw_host_types.split(SMALL_SEPARATOR)):
                if match(r'(^-?\d+)', snippet):
                    host_types[EDeviceRole.configurables()[i]] = int(snippet)
                else:
                    role = EDeviceRole.from_configurables_id(snippet)
                    host_types[role] = -1

                    found = search(r'(-?\d+)', snippet)
                    if found:
                        host_types[role] = int(found.group())
            return {key : host_types.get(key, 0) for key in EDeviceRole.configurables()}
            
        def parse_structures(raw_structures : str):
            if raw_structures == UNSET_INDICATOR:
                return {key : 0 if key != ESubnetTopologyStructure.LINE else 1 for key in ESubnetTopologyStructure}
            structures = {}
            for i, snippet in enumerate(raw_structures.split(SMALL_SEPARATOR)):
                if match(r'(^-?\d+)', snippet):
                    structures[list(ESubnetTopologyStructure)[i]] = int(snippet)
                else:
                    subnet_type = ESubnetTopologyStructure.from_str(snippet[0])
                    structures[subnet_type] = 1

                    found = search(r'(^\d+)', snippet)
                    if found:
                        structures[subnet_type] = int(found.group())

            return {key : structures.get(key, 0) for key in ESubnetTopologyStructure}

        preamble, raw_host_types, raw_structures = value.split(MEDIUM_SEPARATOR)
        subnet_descendants, switch_counts, max_hosts_per_switch, repetitions = [IterativeParameterValue(1, use_latex_tag=use_latex_tag) if x == UNSET_INDICATOR else IterativeParameterValue.from_str(x, use_latex_tag=use_latex_tag) for x in preamble.split(SMALL_SEPARATOR)]

        return LayerDefinition(
            subnet_descendants=subnet_descendants,
            switch_count=switch_counts,
            max_hosts_per_switch=max_hosts_per_switch,
            host_types=parse_host_types(raw_host_types),
            structure_distribution=parse_structures(raw_structures),
            layer_classification=layer_type,
            repetitions=repetitions,
            use_latex_tag=use_latex_tag
        )

    def __get_static_str_suffix__(self):
        if self.use_latex_tag:
            host_types = SMALL_SEPARATOR.join([str(self.host_types.get(x, 0)) for x in EDeviceRole.configurables()])
            structures = SMALL_SEPARATOR.join([str(self.structure_distribution.get(x, 0)) for x in ESubnetTopologyStructure])
            return MEDIUM_SEPARATOR.join([host_types, structures])


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
        values = [x.to_run_str(default_value=1) for x in [self.subnet_descendants, self.switch_count, self.max_hosts_per_switch, self.repetitions]]
        if (not self.use_latex_tag) and all(x == UNSET_INDICATOR for x in values):
            preamble = UNSET_INDICATOR
        else:
            preamble = SMALL_SEPARATOR.join(values)
        return MEDIUM_SEPARATOR.join([preamble, self.__get_static_str_suffix__()])

    def to_total_str(self):
        preamble = SMALL_SEPARATOR.join(map(lambda x: x.to_total_str(default_value=1), [self.subnet_descendants, self.switch_count, self.max_hosts_per_switch, self.repetitions]))
        return MEDIUM_SEPARATOR.join([preamble, self.__get_static_str_suffix__()])

    def to_run_dict_value(self):
        return {
            SUBNET_DESCENDANTS_KEY : self.subnet_descendants.to_run_dict_value(),
            SWITCH_COUNT_KEY : self.switch_count.to_run_dict_value(),
            MAX_HOSTS_PER_SWITCH_KEY : self.max_hosts_per_switch.to_run_dict_value(),
            HOST_TYPES_KEY : {key.name : value for key, value in self.host_types.items()},
            STRUCTURE_KEY : {key.name : value for key, value in self.structure_distribution.items()},
            REPETITIONS_KEY : self.repetitions.to_run_dict_value()
        }
    
    def to_total_dict_value(self):
        return {
            SUBNET_DESCENDANTS_KEY : self.subnet_descendants.to_total_dict_value(),
            SWITCH_COUNT_KEY : self.switch_count.to_total_dict_value(),
            MAX_HOSTS_PER_SWITCH_KEY : self.max_hosts_per_switch.to_total_dict_value(),
            HOST_TYPES_KEY : {key.name : value for key, value in self.host_types.items()},
            STRUCTURE_KEY : {key.name : value for key, value in self.structure_distribution.items()},
            REPETITIONS_KEY : self.repetitions.to_total_dict_value()
        }
    
    def __apply_iteration_logic__(self):
        for iterable_value in [self.subnet_descendants, self.switch_count, self.max_hosts_per_switch, self.repetitions]:
            if iterable_value.iterate():
                return True

        return False
    
    def reset(self):
        for iterable_value in [self.subnet_descendants, self.switch_count, self.max_hosts_per_switch, self.repetitions]:
            iterable_value.reset()

        return super().reset()

class TopologyGenerationConfig(AGenesisTaggable):

    def __init__(self, iterations : int, layer_definitions : list[LayerDefinition], use_latex_tag = False):
        super().__init__(use_latex_tag)
        self.iterations = iterations
        self.layer_definitions = layer_definitions

    @staticmethod
    def from_dict(value : dict, use_latex_tag = False):
        iterations = value.get(ITERATIONS_KEY, 1)
        layer_definitions = [LayerDefinition.from_dict(layer_definition, use_latex_tag=use_latex_tag) for layer_definition in value.get(LAYER_DEFINITIONS_KEY, [])]
        if len(layer_definitions) > 0:
            layer_definitions[0].layer_classification = ENetworkLayer.CONNECTIVITY
            layer_definitions[-1].layer_classification = ENetworkLayer.PROCESS

        return TopologyGenerationConfig(iterations=iterations,
                                        layer_definitions=layer_definitions,
                                        use_latex_tag=use_latex_tag)
    
    @staticmethod
    def from_str(value : list[str], use_latex_tag = False):
        iterations = int(value[0]) if value[0] != UNSET_INDICATOR else 1
        layer_definitions = [LayerDefinition.from_str(layer_definition, use_latex_tag=use_latex_tag) for layer_definition in value[1:]] if len(value) > 1 else []
        if len(layer_definitions) > 0:
            layer_definitions[0].layer_classification = ENetworkLayer.CONNECTIVITY
            layer_definitions[-1].layer_classification = ENetworkLayer.PROCESS
        return TopologyGenerationConfig(iterations=iterations,
                                        layer_definitions=layer_definitions,
                                        use_latex_tag=use_latex_tag)

    def to_run_str(self):
        iterations = str(1)
        if not self.use_latex_tag:
            iterations = UNSET_INDICATOR
        return BIG_SEPARATOR.join([iterations] + [x.to_run_str() for x in self.layer_definitions])
    
    def to_total_str(self):
        iterations = str(self.iterations)
        if (not self.use_latex_tag) and self.iterations == 1:
            iterations = UNSET_INDICATOR
        return BIG_SEPARATOR.join([iterations] + [x.to_total_str() for x in self.layer_definitions])
    
    def to_run_dict_value(self):
        return {
            ITERATIONS_KEY : 1,
            LAYER_DEFINITIONS_KEY : [layer_definition.to_run_dict_value() for layer_definition in self.layer_definitions]
        }
    
    def to_total_dict_value(self):
        return {
            ITERATIONS_KEY : self.iterations,
            LAYER_DEFINITIONS_KEY : [layer_definition.to_total_dict_value() for layer_definition in self.layer_definitions]
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

    def __init__(self, iterations : int = DEFAULT_MAPPING[0], traffic_profile : ETrafficProfile = ETrafficProfile.from_value(DEFAULT_MAPPING[1]), connection_bound : IterativeParameterValue = None, use_latex_tag = False):
        super().__init__(use_latex_tag)
        self.iterations = iterations
        self.traffic_profile = traffic_profile
        if connection_bound:
            self.connection_bound = connection_bound
        else:
            self.connection_bound = IterativeParameterValue(CommunicationGenerationConfig.DEFAULT_MAPPING[2], use_latex_tag=use_latex_tag)

    @staticmethod
    def from_str(value : str, use_latex_tag = False):
        if value == UNSET_INDICATOR:
            iterations, traffic_profile_id, connection_bound = CommunicationGenerationConfig.DEFAULT_MAPPING.copy()
        else:
            iterations, traffic_profile_id, connection_bound = [(CommunicationGenerationConfig.DEFAULT_MAPPING[i] if x == UNSET_INDICATOR else int(x)) for (i, x) in enumerate(value.split(SMALL_SEPARATOR))]
        
        return CommunicationGenerationConfig(iterations=(1 if iterations == UNSET_INDICATOR else int(iterations)),
                                             traffic_profile=ETrafficProfile.from_value(int(traffic_profile_id)),
                                             connection_bound=IterativeParameterValue(connection_bound, use_latex_tag=use_latex_tag),
                                             use_latex_tag=use_latex_tag)

    @staticmethod
    def from_dict(value : dict, use_latex_tag = False):
        iterations = value.get(ITERATIONS_KEY, 1)
        traffic_profile = ETrafficProfile.from_str(value.get(TRAFFIC_PROFILE_KEY, ETrafficProfile.STRICT_ISOLATION.name))
        connection_bound = IterativeParameterValue.from_dict(value.get(UPPER_CONNECTION_BOUND_KEY, -1), use_latex_tag=use_latex_tag)
        return CommunicationGenerationConfig(iterations=iterations,
                                             traffic_profile=traffic_profile,
                                             connection_bound=connection_bound,
                                             use_latex_tag=use_latex_tag)
    
    def to_run_str(self):
        if (not self.use_latex_tag) and all(int(x) == CommunicationGenerationConfig.DEFAULT_MAPPING[i] for (i,x) in enumerate([1, self.traffic_profile.value, self.connection_bound.CURRENT])):
            return UNSET_INDICATOR
        
        traffic_profile = str(self.traffic_profile.value)
        if (not self.use_latex_tag) and self.traffic_profile.value == CommunicationGenerationConfig.DEFAULT_MAPPING[1]:
            traffic_profile = UNSET_INDICATOR

        connection_bound = self.connection_bound.to_run_str(default_value=CommunicationGenerationConfig.DEFAULT_MAPPING[2])
        iterations = str(self.iterations) if self.use_latex_tag else UNSET_INDICATOR
        return SMALL_SEPARATOR.join([iterations, traffic_profile, connection_bound])
    
    def to_total_str(self):
        if (not self.use_latex_tag) and all(x == CommunicationGenerationConfig.DEFAULT_MAPPING[i] for (i,x) in enumerate([self.iterations, self.traffic_profile.value, self.connection_bound.to_total_dict_value()])):
            return UNSET_INDICATOR
        
        iterations = str(self.iterations)
        if (not self.use_latex_tag) and self.iterations == CommunicationGenerationConfig.DEFAULT_MAPPING[0]:
            iterations = UNSET_INDICATOR

        traffic_profile = str(self.traffic_profile.value)
        if (not self.use_latex_tag) and self.traffic_profile.value == CommunicationGenerationConfig.DEFAULT_MAPPING[1]:
            traffic_profile = UNSET_INDICATOR
            
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

    def __init__(self, iterations : int = DEFAULT_MAPPING[0], ruleset_anomaly_count = None, stateful_rule_percentage = None, use_latex_tag = False):
        super().__init__(use_latex_tag)
        self.iterations = iterations
        if ruleset_anomaly_count:
            self.ruleset_anomaly_count = ruleset_anomaly_count
        else:
            self.ruleset_anomaly_count = IterativeParameterValue(SecurityGenerationConfig.DEFAULT_MAPPING[1], use_latex_tag=use_latex_tag)

        if stateful_rule_percentage:
            self.stateful_percentage = stateful_rule_percentage
        else:
            self.stateful_percentage = IterativeParameterValue(SecurityGenerationConfig.DEFAULT_MAPPING[2], use_latex_tag=use_latex_tag)

    @staticmethod
    def from_dict(value : dict, use_latex_tag = False):
        iterations = value.get(ITERATIONS_KEY, 1)
        ruleset_anomaly_count = IterativeParameterValue.from_dict(value.get(ANOMALY_COUNT_KEY, 0), use_latex_tag=use_latex_tag)
        stateful_rule_percentage = IterativeParameterValue.from_dict(value.get(STATEFUL_PERCENTAGE_KEY, 0), minimum=0, maximum=100, use_latex_tag=use_latex_tag)
        return SecurityGenerationConfig(iterations=iterations,
                                        ruleset_anomaly_count=ruleset_anomaly_count,
                                        stateful_rule_percentage=stateful_rule_percentage,
                                        use_latex_tag=use_latex_tag)
    
    @staticmethod
    def from_str(value : str, use_latex_tag = False):
        if value == UNSET_INDICATOR:
            iterations, ruleset_anomaly_count, stateful_rule_percentage = [str(x) for x in SecurityGenerationConfig.DEFAULT_MAPPING]
        else:
            iterations, ruleset_anomaly_count, stateful_rule_percentage = [str(SecurityGenerationConfig.DEFAULT_MAPPING[i]) if x == UNSET_INDICATOR else x for (i,x) in enumerate(value.split(SMALL_SEPARATOR))]
        ruleset_anomaly_count = IterativeParameterValue.from_str(ruleset_anomaly_count, minimum=0, use_latex_tag=use_latex_tag)
        stateful_rule_percentage = IterativeParameterValue.from_str(stateful_rule_percentage, minimum=0, maximum=100, use_latex_tag=use_latex_tag)
        return SecurityGenerationConfig(iterations=int(iterations),
                                        ruleset_anomaly_count=ruleset_anomaly_count,
                                        stateful_rule_percentage=stateful_rule_percentage,
                                        use_latex_tag=use_latex_tag)

    def to_run_str(self):
        if (not self.use_latex_tag) and all((x.to_run_dict_value() == SecurityGenerationConfig.DEFAULT_MAPPING[i + 1]) for (i, x) in enumerate([self.ruleset_anomaly_count, self.stateful_percentage])):
            return UNSET_INDICATOR
        
        iterations = str(1)
        if not self.use_latex_tag:
            iterations = UNSET_INDICATOR

        ruleset_anomaly_count = self.ruleset_anomaly_count.to_run_str(SecurityGenerationConfig.DEFAULT_MAPPING[1])
        stateful_rule_percentage = self.stateful_percentage.to_run_str(SecurityGenerationConfig.DEFAULT_MAPPING[2])
        return SMALL_SEPARATOR.join([iterations, ruleset_anomaly_count, stateful_rule_percentage])
    
    def to_total_str(self):
        if (not self.use_latex_tag) and all((x == SecurityGenerationConfig.DEFAULT_MAPPING[i]) for (i, x) in enumerate([self.iterations, self.ruleset_anomaly_count.to_total_dict_value(), self.stateful_percentage.to_total_dict_value()])):
            return UNSET_INDICATOR
        
        iterations = str(self.iterations)
        if (not self.use_latex_tag) and self.iterations == SecurityGenerationConfig.DEFAULT_MAPPING[0]:
            iterations = UNSET_INDICATOR
        ruleset_anomaly_count = self.ruleset_anomaly_count.to_total_str(SecurityGenerationConfig.DEFAULT_MAPPING[1])
        stateful_rule_percentage = self.stateful_percentage.to_total_str(SecurityGenerationConfig.DEFAULT_MAPPING[2])
        return SMALL_SEPARATOR.join([iterations, ruleset_anomaly_count, stateful_rule_percentage])

    def to_run_dict_value(self):
        return {
            ITERATIONS_KEY : 1,
            ANOMALY_COUNT_KEY : self.ruleset_anomaly_count.to_run_dict_value(),
            STATEFUL_PERCENTAGE_KEY : self.stateful_percentage.to_run_dict_value()
        }
    
    def to_total_dict_value(self):
        return {
            ITERATIONS_KEY : self.iterations,
            ANOMALY_COUNT_KEY : self.ruleset_anomaly_count.to_total_dict_value(),
            STATEFUL_PERCENTAGE_KEY : self.stateful_percentage.to_total_dict_value()
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
    def __init__(self, topology_seed : IterativeParameterValue, communication_seed : IterativeParameterValue, security_seed : IterativeParameterValue, use_latex_tag = False):
        super().__init__(use_latex_tag)
        self.topology_seed = topology_seed
        self.communication_seed = communication_seed
        self.security_seed = security_seed

    @staticmethod
    def from_str(value : str, iterations = None, use_latex_tag = False):
        topology_seed, communication_seed, security_seed = [IterativeParameterValue(start=int(x), end=(int(x) + iterations[i] - 1) if iterations else None, use_latex_tag=use_latex_tag) for i, x in enumerate(value.split(SMALL_SEPARATOR))]
        return SeedConfig(topology_seed=topology_seed,
                          communication_seed=communication_seed,
                          security_seed=security_seed)
    
    @staticmethod
    def from_dict(value : dict, iterations = None, use_latex_tag = False):
        raw_seeds = [value.get(key, randint(1,1000)) for key in [TOPOLOGY_KEY, COMMUNICATION_KEY, SECURITY_KEY]]
        topology_seed, communication_seed, security_seed = [IterativeParameterValue(start=seed, end=(seed + iterations[i] - 1) if iterations else None, use_latex_tag=use_latex_tag) for i, seed in enumerate(raw_seeds)]

        return SeedConfig(topology_seed=topology_seed,
                          communication_seed=communication_seed,
                          security_seed=security_seed)
    
    @staticmethod
    def random(iterations = None, use_latex_tag = False):
        raw_seeds = [randint(1,1000) for _ in range(3)]
        topology_seed, communication_seed, security_seed = [IterativeParameterValue(start=seed, end=(seed + iterations[i] - 1) if iterations else None, use_latex_tag=use_latex_tag) for i, seed in enumerate(raw_seeds)]
    
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
    def __init__(self, seed_config : SeedConfig, topology_config : TopologyGenerationConfig, communication_config : CommunicationGenerationConfig, security_config : SecurityGenerationConfig, use_latex_tag = False):
        super().__init__(use_latex_tag)
        self.seed_config = seed_config
        self.topology_config = topology_config
        self.communication_config = communication_config
        self.security_config = security_config

    @staticmethod
    def from_str(genesis_tag : str, use_latex_tag = False):
        versioning, information, _ = genesis_tag.split(TAG_ENCAPSULATOR)
        version_number = versioning.split(MEDIUM_SEPARATOR)[-1][1:]
        if version(GENESIS_PACKAGE_NAME) != version_number:
            raise Exception(f'InvalidGenesisTag: Incompatible GeNESIS version detected: {version(GENESIS_PACKAGE_NAME)} != {version_number}. You can checkout the GeNESIS version matching your tag with "git checkout tags/{version_number}" *if it exists*.')
        sequences = information.split(BIG_SEPARATOR)
        communication_config = CommunicationGenerationConfig.from_str(sequences[1], use_latex_tag=use_latex_tag)
        security_config = SecurityGenerationConfig.from_str(sequences[2], use_latex_tag=use_latex_tag)
        topology_config = TopologyGenerationConfig.from_str(sequences[3:], use_latex_tag=use_latex_tag)
        seed_config = SeedConfig.from_str(sequences[0], [topology_config.iterations, communication_config.iterations, security_config.iterations], use_latex_tag=use_latex_tag)
        return GenerationConfig(seed_config=seed_config,
                                topology_config=topology_config,
                                communication_config=communication_config,
                                security_config=security_config,
                                use_latex_tag=use_latex_tag)

    @staticmethod
    def from_dict(value : dict, use_latex_tag = False):
        topology_config = TopologyGenerationConfig.from_dict(value.get(TOPOLOGY_KEY, dict()), use_latex_tag=use_latex_tag)

        raw_communication_config = value.get(COMMUNICATION_KEY, dict())
        if raw_communication_config:
            communication_config = CommunicationGenerationConfig.from_dict(raw_communication_config, use_latex_tag=use_latex_tag)
        else:
            communication_config = CommunicationGenerationConfig(use_latex_tag=use_latex_tag)
        
        raw_security_config = value.get(SECURITY_KEY, dict())
        if raw_security_config:
            security_config = SecurityGenerationConfig.from_dict(raw_security_config, use_latex_tag=use_latex_tag)
        else:
            security_config = SecurityGenerationConfig(use_latex_tag=use_latex_tag)
            
        return GenerationConfig(seed_config=SeedConfig.random([topology_config.iterations, communication_config.iterations, security_config.iterations], use_latex_tag=use_latex_tag),
                                topology_config=topology_config,
                                communication_config=communication_config,
                                security_config=security_config,
                                use_latex_tag=use_latex_tag)

    @staticmethod
    def from_file(dir : str, use_latex_tag = False):
        with open(dir, 'r') as file:
            json_config : dict = load(file)
            return GenerationConfig.from_dict(json_config, use_latex_tag)

    
    def to_run_str(self):
        content = BIG_SEPARATOR.join(map(lambda x: x.to_run_str(), [self.seed_config, self.communication_config, self.security_config, self.topology_config]))
        if self.use_latex_tag:
            return f'genesis:v{version(GENESIS_PACKAGE_NAME)}\\{TAG_ENCAPSULATOR}{content}\\{TAG_ENCAPSULATOR}'
        return f'genesis:v{version(GENESIS_PACKAGE_NAME)}{TAG_ENCAPSULATOR}{content}{TAG_ENCAPSULATOR}'
    
    def to_total_str(self):
        content = BIG_SEPARATOR.join(map(lambda x: x.to_total_str(), [self.seed_config, self.communication_config, self.security_config, self.topology_config]))
        if self.use_latex_tag:
            return f'genesis:v{version(GENESIS_PACKAGE_NAME)}\\{TAG_ENCAPSULATOR}{content}\\{TAG_ENCAPSULATOR}'
        return f'genesis:v{version(GENESIS_PACKAGE_NAME)}{TAG_ENCAPSULATOR}{content}{TAG_ENCAPSULATOR}'

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