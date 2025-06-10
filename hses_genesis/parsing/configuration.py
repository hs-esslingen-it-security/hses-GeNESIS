from abc import ABC, abstractmethod
from itertools import groupby
from json import dump, load
from random import randint
from statistics import median
from typing import DefaultDict, Optional
from networkx import Graph, neighbors, periphery
from re import match
from hses_genesis.parsing.topology import get_subnet_graph

from hses_genesis.utils.constants import BEST_EFFORT_TRAFFIC_REQUIREMENT_KEY, BIG_SEPARATOR, COMMUNICATION_KEY, CONTROL_TRAFFIC_REQUIREMENT_KEY, GENESIS_PACKAGE_NAME, HOST_CONNECTIVITY_KEY, HOST_TYPES_KEY, ITERATION_SEPARATOR, ITERATIONS_KEY, LAYER_DEFINITIONS_KEY, MAX_HOSTS_PER_SWITCH_KEY, MEDIUM_SEPARATOR, SUBNET_CONNECTIVITY_KEY, SUBNET_DESCENDANTS_KEY, REPETITIONS_KEY, ANOMALY_COUNT_KEY, SECURITY_KEY, SMALL_SEPARATOR, STATEFUL_PERCENTAGE_KEY, STRUCTURE_KEY, SWITCH_COUNT_KEY, TAG_ENCAPSULATOR, TOPOLOGY_KEY, TRAFFIC_PROFILE_KEY, UNSET_INDICATOR, UPPER_CONNECTION_BOUND_KEY, MESHING_KEY
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
    def __init__(self):
        super().__init__()

    @abstractmethod
    def from_str(value):
        pass
    
    @abstractmethod
    def from_dict(value):
        pass

    @abstractmethod
    def to_tag(self, run_specific = False, short_tag = False) -> str:
        pass

    def __str__(self):
        return self.to_tag()

    @abstractmethod
    def to_dict_value(self, run_specific = False):
        pass

    def iterate(self, synced = False) -> bool:
        if synced:
            iteration_success = self.__apply_synced_iteration_logic__()
        else:
            iteration_success = self.__apply_unsynced_iteration_logic__()

        return iteration_success
    
    def __apply_synced_iteration_logic__(self) -> bool:
        return False
    
    def __apply_unsynced_iteration_logic__(self) -> bool:
        return False
    
    @abstractmethod
    def reset(self):
        pass


class IterativeParameterValue(AGenesisTaggable):
    def __init__(self, values : list[int], synced = False):
        super().__init__()
        self.synced = synced
        if synced:
            self.start = values[0]
            self.fixed_values = values
            self.gen = iter(values)
        elif len(values) == 1:
            self.start = values[0]
            self.end = values[0]
            self.gen = iter(values)
        else:
            self.start, self.end, self.step_size = values
            self.gen = iter(range(self.start, self.end + 1, self.step_size))
        
        self.current = next(self.gen, None)

    def __int__(self):
        return self.current

    def __list__(self):
        if self.synced:
            return self.fixed_values.copy()
        if self.start == self.end:
            return [self.start]
        
        return list(range(self.start, self.end + 1, self.step_size))

    def to_tag(self, run_specific = False):
        if run_specific:
            return str(self.current)

        if self.synced:
            if len(self.fixed_values) > 1:
                if len(self.fixed_values):
                    compressed_groups = list()
                    for key, group in groupby(self.fixed_values):
                        group_size = sum(1 for _ in group)
                        if group_size > 2:
                            compressed_groups.append(str(key) + '{' + str(group_size) +'}')
                        else:
                            compressed_groups.append(ITERATION_SEPARATOR.join(([str(key)] * group_size)))
                            
                    return f"[{ITERATION_SEPARATOR.join(compressed_groups)}]"
                return f"[{ITERATION_SEPARATOR.join(map(str, self.fixed_values))}]"
            else:
                return str(self.start)

        if self.start == self.end:
            return str(self.start)

        return ITERATION_SEPARATOR.join(map(str, [self.start, self.end, self.step_size]))

    def to_dict_value(self, run_specific = False):
        if run_specific:
            return self.current
        
        if self.synced:
            if len(self.fixed_values) == 1:
                return self.fixed_values[0]
            
            return {
                'values' : self.fixed_values,
                'synced' : True
            }
        else:
            if self.start == self.end:
                return self.start
            
            return {
                'start' : self.start,
                'end' : self.end,
                'step_size' : self.step_size
            }

    @staticmethod
    def from_dict(value):
        if isinstance(value, int):
            return IterativeParameterValue([value])
        
        if value.get('synced', False):
            return IterativeParameterValue(values=value.get('values', list()), synced=True)

        return IterativeParameterValue([value.get('start', 0), value.get('end', 1), value.get('step_size', 1)])

    @staticmethod
    def from_str(value : str):
        is_synched = match(r'\[(\d+(\{\d+\})?\.?)+\]', value)
        if is_synched:
            values = []
            for v in value[1:-1].split(ITERATION_SEPARATOR):
                value_dict = match(r'(?:(?P<value>\d+)(?:\{(?P<multiplier>\d+)\})?)', v).groupdict()
                multiplier = value_dict.get('multiplier', None)
                values += [int(value_dict['value'])] * (1 if not multiplier else int(multiplier))
            return IterativeParameterValue(values=values, synced=True)
        
        return IterativeParameterValue(values=list(map(int, value.split(ITERATION_SEPARATOR))))
    
    def __apply_iteration_logic__(self):
        next_element = next(self.gen, None)
        if next_element != None:
            self.current = next_element
            return True
        
        if not self.synced:
            self.current = self.start
        return False

    def __apply_synced_iteration_logic__(self):
        if not self.synced:
            return False
        return self.__apply_iteration_logic__()
    
    def __apply_unsynced_iteration_logic__(self):
        if self.synced:
            return False
        return self.__apply_iteration_logic__()


    def reset(self, synced = False):
        if self.synced != synced:
            return
        
        if self.synced:
            self.gen = iter(self.fixed_values)
        else:
            if self.start == self.end:
                self.gen = iter([self.start])
            else:
                self.gen = iter(range(self.start, self.end + 1, self.step_size))
        self.current = next(self.gen, None)

class LayerDefinition(AGenesisTaggable):
    def __init__(self, subnet_descendants : IterativeParameterValue, switch_count : IterativeParameterValue, max_hosts_per_switch : IterativeParameterValue, meshing_degree : Optional[IterativeParameterValue], repetitions : IterativeParameterValue, host_types : dict[EDeviceRole, IterativeParameterValue], structure_distribution : dict, layer_classification = ENetworkLayer.AGGREGATED_CONTROL):
        super().__init__()
        self.subnet_descendants = subnet_descendants
        self.switch_count = switch_count
        self.max_hosts_per_switch = max_hosts_per_switch
        self.host_types = host_types
        self.structure_distribution = structure_distribution
        self.layer_classification = layer_classification
        self.meshing_degree = meshing_degree
        self.repetitions = repetitions

    @staticmethod
    def from_topology(G : Graph, layer_subnets : list[str], subnet_descendants = 1, layer_classification = ENetworkLayer.AGGREGATED_CONTROL):
        switch_count = []
        hosts_per_switch = []
        meshing_degrees = []
        host_types = DefaultDict(list)
        structure_distribution = DefaultDict(int)

        for subnet in layer_subnets:
            subnet_graph : Graph = G.subgraph([node for node, data in G.nodes(data=True) if subnet in data['subnet']])
            structure = ESubnetTopologyStructure.from_topology(subnet_graph)
            structure_distribution[structure] += 1
            switches = [node for node, data in subnet_graph.nodes(data=True) if data['role'] == EDeviceRole.SWITCH]
            switch_count.append(len(switches))
            meshing_degree = 1
            if structure == ESubnetTopologyStructure.MESH:
                meshing_degree = max([sum(1 for n in G.neighbors(s) if subnet_graph.nodes[n]['role'] == EDeviceRole.SWITCH) for s in switches])
            meshing_degrees.append(meshing_degree)
            hosts_per_switch.append(max([len([neighbor for neighbor in neighbors(subnet_graph, switch) if subnet_graph.nodes[neighbor]['role'] in EDeviceRole.hosts()]) for switch in switches]))
            for key in EDeviceRole.hosts():
                host_types[key].append(len([node for node, data in subnet_graph.nodes(data=True) if data['role'] == key]))

        host_types = {key : int(median(value)) for key, value in host_types.items()}

        if len(structure_distribution) == 1:
            structure_distribution = {key : min(structure_distribution.get(key, 0), 1) for key in ESubnetTopologyStructure}
        else:
            structure_distribution = {key : structure_distribution.get(key, 0) for key in ESubnetTopologyStructure}

        return LayerDefinition(subnet_descendants=IterativeParameterValue([subnet_descendants]),
                               switch_count=IterativeParameterValue([max(switch_count)]),
                               max_hosts_per_switch=IterativeParameterValue([max(hosts_per_switch)]),
                               repetitions=IterativeParameterValue([1]),
                               meshing_degree=IterativeParameterValue([max(meshing_degrees)]),
                               host_types=host_types,
                               structure_distribution=structure_distribution,
                               layer_classification=layer_classification)

    @staticmethod
    def from_dict(value : dict, layer_type = ENetworkLayer.AGGREGATED_CONTROL):
        subnet_descendants = IterativeParameterValue.from_dict(value.get(SUBNET_DESCENDANTS_KEY, 1))
        switch_count = IterativeParameterValue.from_dict(value.get(SWITCH_COUNT_KEY, 1))
        max_hosts_per_switch = IterativeParameterValue.from_dict(value.get(MAX_HOSTS_PER_SWITCH_KEY, 1))
        repetitions = IterativeParameterValue.from_dict(value.get(REPETITIONS_KEY, 1))
        meshing_degree = value.get(MESHING_KEY, None)
        if meshing_degree:
            meshing_degree = IterativeParameterValue.from_dict(meshing_degree)
        host_types : dict = value.get(HOST_TYPES_KEY, dict())
        host_types = {role : IterativeParameterValue.from_dict(get_single_value_by_multiple_keys(host_types, [role.name, role.name[:2], role.value], 0)) for role in EDeviceRole.hosts()}
        structure_distribution = value.get(STRUCTURE_KEY, dict())
        structure_distribution = {key : get_single_value_by_multiple_keys(structure_distribution, [key.name, key.name[0]], 0) for key in ESubnetTopologyStructure}
        if sum(structure_distribution.values()) == 0:
            structure_distribution[ESubnetTopologyStructure.LINE] = 1
        return LayerDefinition(
            subnet_descendants=subnet_descendants,
            switch_count=switch_count,
            max_hosts_per_switch=max_hosts_per_switch,
            meshing_degree=meshing_degree,
            repetitions=repetitions,
            host_types=host_types,
            structure_distribution=structure_distribution,
            layer_classification=layer_type
            )
    
    @staticmethod
    def from_str(value : str, layer_type = ENetworkLayer.AGGREGATED_CONTROL):
        def parse_host_types(raw_host_types : str):
            if raw_host_types == UNSET_INDICATOR:
                return {key : IterativeParameterValue([0]) for key in EDeviceRole.hosts()}
            
            host_types = {}
            host_type_snippets = raw_host_types.split(SMALL_SEPARATOR)
            for i, snippet in enumerate(host_type_snippets):
                if len(host_type_snippets) == len(EDeviceRole.hosts()) and match(r'(^-?\d+$)', snippet):
                    host_types[EDeviceRole.hosts()[i]] = IterativeParameterValue.from_str(snippet)
                else:
                    role = EDeviceRole.from_configurables_id(snippet)
                    host_types[role] = IterativeParameterValue([-1])

                    found = search(r'(-?\d+)', snippet)
                    if found:
                        host_types[role] = IterativeParameterValue([int(found.group())])
            return {key : host_types.get(key, IterativeParameterValue([0])) for key in EDeviceRole.hosts()}
            
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
        preamble_snippets = preamble.split(SMALL_SEPARATOR)
        subnet_descendants, switch_counts, max_hosts_per_switch, repetitions = [IterativeParameterValue([1]) if x == UNSET_INDICATOR else IterativeParameterValue.from_str(x) for x in preamble_snippets[:4]]
        meshing = IterativeParameterValue.from_str(preamble_snippets[4]) if len(preamble_snippets) > 4 else None

        return LayerDefinition(
            subnet_descendants=subnet_descendants,
            switch_count=switch_counts,
            max_hosts_per_switch=max_hosts_per_switch,
            host_types=parse_host_types(raw_host_types),
            structure_distribution=parse_structures(raw_structures),
            layer_classification=layer_type,
            repetitions=repetitions,
            meshing_degree=meshing
        )

    def to_tag(self, run_specific = False, short_tag = False):
        def get_postamble(short_tag = False):
            if not short_tag:
                host_types = SMALL_SEPARATOR.join([self.host_types.get(x, IterativeParameterValue([0])).to_tag(run_specific) for x in EDeviceRole.hosts()])
                structures = SMALL_SEPARATOR.join([str(self.structure_distribution.get(x, 0)) for x in ESubnetTopologyStructure])
                return MEDIUM_SEPARATOR.join([host_types, structures])
            
            host_types = [str(key.value)[0] if value.end < 0 else f'{str(key.value)[0]}{value.to_tag(run_specific)}' for key, value in self.host_types.items() if value != 0]
            host_types_str = SMALL_SEPARATOR.join(host_types) if len(host_types) > 0 else UNSET_INDICATOR
            structures = [f'{key.name[0]}{value if value > 1 else ""}' for key, value in self.structure_distribution.items() if value > 0]
            structures_str = SMALL_SEPARATOR.join(structures) if len(structures) > 0 else UNSET_INDICATOR
            return MEDIUM_SEPARATOR.join([host_types_str, structures_str])

        values = [x.to_tag(run_specific=run_specific) for x in [self.subnet_descendants, self.switch_count, self.max_hosts_per_switch, self.repetitions]]
        if self.meshing_degree:
            values.append(self.meshing_degree.to_tag(run_specific=run_specific))
        preamble = UNSET_INDICATOR if all(x == UNSET_INDICATOR for x in values) else SMALL_SEPARATOR.join(values)
        return MEDIUM_SEPARATOR.join([preamble, get_postamble(short_tag)])

    def to_dict_value(self, run_specific = False):
        if self.meshing_degree:
            return {
                SUBNET_DESCENDANTS_KEY : self.subnet_descendants.to_dict_value(run_specific=run_specific),
                SWITCH_COUNT_KEY : self.switch_count.to_dict_value(run_specific=run_specific),
                MAX_HOSTS_PER_SWITCH_KEY : self.max_hosts_per_switch.to_dict_value(run_specific=run_specific),
                HOST_TYPES_KEY : {key.name : value.to_dict_value(run_specific) for key, value in self.host_types.items()},
                STRUCTURE_KEY : {key.name : value for key, value in self.structure_distribution.items()},
                REPETITIONS_KEY : self.repetitions.to_dict_value(run_specific=run_specific),
                MESHING_KEY : self.meshing_degree.to_dict_value(run_specific=run_specific)
            }
        else:
            return {
                SUBNET_DESCENDANTS_KEY : self.subnet_descendants.to_dict_value(run_specific=run_specific),
                SWITCH_COUNT_KEY : self.switch_count.to_dict_value(run_specific=run_specific),
                MAX_HOSTS_PER_SWITCH_KEY : self.max_hosts_per_switch.to_dict_value(run_specific=run_specific),
                HOST_TYPES_KEY : {key.name : value.to_dict_value(run_specific) for key, value in self.host_types.items()},
                STRUCTURE_KEY : {key.name : value for key, value in self.structure_distribution.items()},
                REPETITIONS_KEY : self.repetitions.to_dict_value(run_specific=run_specific)
            }
    
    def __apply_synced_iteration_logic__(self):
        iterable_values : list[IterativeParameterValue | None] = [self.subnet_descendants, self.switch_count, self.max_hosts_per_switch, self.meshing_degree, self.repetitions] 
        synced_values = [iterable_value for iterable_value in iterable_values if iterable_value != None and iterable_value.synced]
        iteration_success = any([iterable_value.iterate(synced=True) for iterable_value in synced_values])
        
        return iteration_success

    def __apply_unsynced_iteration_logic__(self):
        iterable_values : list[IterativeParameterValue | None] = [self.subnet_descendants, self.switch_count, self.max_hosts_per_switch, self.meshing_degree, self.repetitions] 
        unsynced_values = [iterable_value for iterable_value in iterable_values if iterable_value and not iterable_value.synced]
        for iterable_value in unsynced_values:
            if iterable_value and iterable_value.iterate():
                return True
        return False
    
    def reset(self, synced = False):
        for iterable_value in [self.subnet_descendants, self.switch_count, self.max_hosts_per_switch, self.meshing_degree, self.repetitions]:
            if iterable_value != None:
                iterable_value.reset(synced)

        return super().reset()

class TopologyGenerationConfig(AGenesisTaggable):

    def __init__(self, iterations : int, meshing_degree : IterativeParameterValue, subnet_connectivity : IterativeParameterValue, host_connectivity : IterativeParameterValue, layer_definitions : list[LayerDefinition]):
        super().__init__()
        self.iterations = iterations
        self.meshing_degree = meshing_degree
        self.subnet_connectivity = subnet_connectivity
        self.host_connectivity = host_connectivity
        self.layer_definitions = layer_definitions

    @staticmethod
    def from_topology(G : Graph, iterations = 1):
        layer_definitions, previous_layer_width, compressed_graph = list(), 1, get_subnet_graph(G)
        while len(compressed_graph.nodes) > 0:
            longest_distance_subnets = periphery(compressed_graph)
            layer_width = len(longest_distance_subnets)
            layer_definitions.insert(0, LayerDefinition.from_topology(G, layer_subnets=longest_distance_subnets, subnet_descendants=max(1, int(previous_layer_width / layer_width))))
            marked_to_delete = []
            remaining_subnets = {node for node, data in compressed_graph.nodes(data=True) if data['role'] != EDeviceRole.ROUTER}.difference(longest_distance_subnets)
            
            for node, data in compressed_graph.nodes(data=True):
                is_in_subnet = any(subnet in longest_distance_subnets for subnet in data['subnet'])
                if not is_in_subnet:
                    continue
                
                is_in_remaining_subnet = any(subnet in remaining_subnets for subnet in data['subnet'])
                if is_in_remaining_subnet:
                    continue

                marked_to_delete.append(node)

            compressed_graph.remove_nodes_from(marked_to_delete)
            previous_layer_width = layer_width

        layer_definitions[0].layer_classification = ENetworkLayer.AGGREGATED_CONTROL
        if len(layer_definitions) > 1:
            layer_definitions[-1].layer_classification = ENetworkLayer.PROCESS
            
        return TopologyGenerationConfig(iterations=iterations, layer_definitions=layer_definitions)

    @staticmethod
    def from_dict(value : dict):
        iterations = value.get(ITERATIONS_KEY, 1)
        meshing_degree = IterativeParameterValue.from_dict(value.get(MESHING_KEY, -1))
        subnet_connectivity = IterativeParameterValue.from_dict(value.get(SUBNET_CONNECTIVITY_KEY, 2))
        host_connectivity = IterativeParameterValue.from_dict(value.get(HOST_CONNECTIVITY_KEY, 1))
        layer_definitions = [LayerDefinition.from_dict(layer_definition) for layer_definition in value.get(LAYER_DEFINITIONS_KEY, [])]
        if len(layer_definitions) > 0:
            layer_definitions[0].layer_classification = ENetworkLayer.CONNECTIVITY
            layer_definitions[-1].layer_classification = ENetworkLayer.PROCESS

        return TopologyGenerationConfig(iterations=iterations,
                                        layer_definitions=layer_definitions,
                                        meshing_degree=meshing_degree,
                                        subnet_connectivity=subnet_connectivity,
                                        host_connectivity=host_connectivity)
    
    @staticmethod
    def from_str(value : list[str]):
        if value[0] == UNSET_INDICATOR:
            iterations, meshing, subnet_connectivity, host_connectivity = 1, IterativeParameterValue([-1]), IterativeParameterValue([2]), IterativeParameterValue([1])
        else:
            iterations, meshing, subnet_connectivity, host_connectivity = value[0].split(SMALL_SEPARATOR)
            iterations = int(iterations) if iterations != UNSET_INDICATOR else 1
            meshing = IterativeParameterValue.from_str(meshing)
            subnet_connectivity = IterativeParameterValue.from_str(subnet_connectivity)
            host_connectivity = IterativeParameterValue.from_str(host_connectivity)
            
        layer_definitions = [LayerDefinition.from_str(layer_definition) for layer_definition in value[1:]] if len(value) > 1 else []
        if len(layer_definitions) > 0:
            layer_definitions[0].layer_classification = ENetworkLayer.CONNECTIVITY
            layer_definitions[-1].layer_classification = ENetworkLayer.PROCESS
        return TopologyGenerationConfig(iterations=iterations,
                                        meshing_degree=meshing,
                                        layer_definitions=layer_definitions,
                                        subnet_connectivity=subnet_connectivity,
                                        host_connectivity=host_connectivity)

    def to_tag(self, run_specific = False, short_tag = False):
        iterations = '1' if run_specific else str(self.iterations)
        if short_tag and (run_specific or self.iterations == 1):
            iterations = UNSET_INDICATOR
        meshing = self.meshing_degree.to_tag(run_specific=run_specific)
        subnet_connectivity = self.subnet_connectivity.to_tag(run_specific=run_specific)
        host_connectivity = self.host_connectivity.to_tag(run_specific=run_specific)
        prefix = UNSET_INDICATOR if short_tag and all(value == UNSET_INDICATOR for value in [iterations, meshing, subnet_connectivity, host_connectivity]) else SMALL_SEPARATOR.join([iterations, meshing, subnet_connectivity, host_connectivity])
        return BIG_SEPARATOR.join([prefix] + [x.to_tag(run_specific=run_specific) for x in self.layer_definitions])
    
    def to_dict_value(self, run_specific = False):
        return {
            ITERATIONS_KEY : 1 if run_specific else self.iterations,
            MESHING_KEY : self.meshing_degree.to_dict_value(run_specific=run_specific),
            SUBNET_CONNECTIVITY_KEY : self.subnet_connectivity.to_dict_value(run_specific=run_specific),
            HOST_CONNECTIVITY_KEY : self.host_connectivity.to_dict_value(run_specific=run_specific),
            LAYER_DEFINITIONS_KEY : [layer_definition.to_dict_value(run_specific=run_specific) for layer_definition in self.layer_definitions]
        }
    
    def __apply_synced_iteration_logic__(self):
        return any([self.meshing_degree.iterate(True), self.subnet_connectivity.iterate(True), self.host_connectivity.iterate(True)] + [layer_definition.iterate(True) for layer_definition in self.layer_definitions])

    def __apply_unsynced_iteration_logic__(self):
        for v in [self.meshing_degree, self.subnet_connectivity, self.host_connectivity]:
            if v.iterate():
                return True

        for layer_definition in self.layer_definitions:
            if layer_definition.iterate():
                return True

        return False
        
    def reset(self, synced = False):
        for v in [self.meshing_degree, self.subnet_connectivity, self.host_connectivity]:
            v.reset(synced)
        for layer_definition in self.layer_definitions:
            layer_definition.reset(synced)
        return super().reset()
    
class CommunicationGenerationConfig(AGenesisTaggable):
    DEFAULT_ITERATIONS = 1
    DEFAULT_TRAFFIC_PROFILE = ETrafficProfile.CONVERGED_NETWORKS
    DEFAULT_CONNECTION_BOUND = -1
    DEFAULT_EFFORT_PATHS = 1
    DEFAULT_CONTROL_PATHS = 1

    def __init__(self, iterations : Optional[int] = None, traffic_profile : Optional[ETrafficProfile] = None, connection_bound : Optional[IterativeParameterValue] = None, control_traffic_path_requirement : Optional[IterativeParameterValue] = None, best_effort_path_requirement : Optional[IterativeParameterValue] = None):
        super().__init__()
        self.iterations = iterations if iterations else CommunicationGenerationConfig.DEFAULT_ITERATIONS
        self.traffic_profile = traffic_profile if traffic_profile else CommunicationGenerationConfig.DEFAULT_TRAFFIC_PROFILE
        self.connection_bound = connection_bound if connection_bound else IterativeParameterValue([CommunicationGenerationConfig.DEFAULT_CONNECTION_BOUND])
        self.control_traffic_path_requirement = control_traffic_path_requirement if control_traffic_path_requirement else IterativeParameterValue([CommunicationGenerationConfig.DEFAULT_CONTROL_PATHS])
        self.best_effort_path_requirement = best_effort_path_requirement if best_effort_path_requirement else IterativeParameterValue([CommunicationGenerationConfig.DEFAULT_EFFORT_PATHS])

    @staticmethod
    def from_str(value : str):
        if value == UNSET_INDICATOR:
            return CommunicationGenerationConfig()
        else:
            values = value.split(SMALL_SEPARATOR)
            if len(values) == 3:
                iterations, traffic_profile, connection_bound = values
                control_traffic_path_requirement, best_effort_path_requirement = UNSET_INDICATOR, UNSET_INDICATOR
            else:
                iterations, traffic_profile, connection_bound, control_traffic_path_requirement, best_effort_path_requirement = values
            
            iterations = CommunicationGenerationConfig.DEFAULT_ITERATIONS if iterations == UNSET_INDICATOR else int(iterations)
            traffic_profile = CommunicationGenerationConfig.DEFAULT_TRAFFIC_PROFILE if traffic_profile == UNSET_INDICATOR else ETrafficProfile.from_value(int(traffic_profile))
            connection_bound = IterativeParameterValue.from_str(connection_bound) if connection_bound != UNSET_INDICATOR else None
            control_traffic_path_requirement = IterativeParameterValue.from_str(control_traffic_path_requirement) if control_traffic_path_requirement != UNSET_INDICATOR else None
            best_effort_path_requirement = IterativeParameterValue.from_str(best_effort_path_requirement) if best_effort_path_requirement != UNSET_INDICATOR else None

        return CommunicationGenerationConfig(iterations=iterations,
                                             traffic_profile=traffic_profile,
                                             connection_bound=connection_bound,
                                             control_traffic_path_requirement=control_traffic_path_requirement,
                                             best_effort_path_requirement=best_effort_path_requirement)

    @staticmethod
    def from_dict(value : dict):
        iterations = value.get(ITERATIONS_KEY, 1)
        
        traffic_profile = value.get(TRAFFIC_PROFILE_KEY, None)
        traffic_profile = ETrafficProfile.from_str(traffic_profile) if traffic_profile else CommunicationGenerationConfig.DEFAULT_TRAFFIC_PROFILE
        
        connection_bound = value.get(UPPER_CONNECTION_BOUND_KEY, None)
        if connection_bound != None:
            connection_bound = IterativeParameterValue.from_dict(connection_bound)
        
        control_traffic_path_requirement = value.get(CONTROL_TRAFFIC_REQUIREMENT_KEY, None)
        if control_traffic_path_requirement != None:
            control_traffic_path_requirement = IterativeParameterValue.from_dict(control_traffic_path_requirement)
        
        best_effort_path_requirement = value.get(BEST_EFFORT_TRAFFIC_REQUIREMENT_KEY, None)
        if best_effort_path_requirement != None:
            best_effort_path_requirement = IterativeParameterValue.from_dict(best_effort_path_requirement)

        return CommunicationGenerationConfig(iterations=iterations,
                                             traffic_profile=traffic_profile,
                                             connection_bound=connection_bound,
                                             control_traffic_path_requirement=control_traffic_path_requirement,
                                             best_effort_path_requirement=best_effort_path_requirement)
    
    def to_tag(self, run_specific = False, short_tag = False):
        iterations = str(1 if run_specific else self.iterations)
        traffic_profile = str(self.traffic_profile.value)
        connection_bound = self.connection_bound.to_tag(run_specific=run_specific)
        control_traffic_path_requirement = self.control_traffic_path_requirement.to_tag(run_specific=run_specific)
        best_effort_path_requirement = self.best_effort_path_requirement.to_tag(run_specific=run_specific)

        if short_tag:
            if run_specific or self.iterations == CommunicationGenerationConfig.DEFAULT_ITERATIONS:
                iterations = UNSET_INDICATOR
            if self.traffic_profile == CommunicationGenerationConfig.DEFAULT_TRAFFIC_PROFILE:
                traffic_profile = UNSET_INDICATOR

            if all(x == UNSET_INDICATOR for x in [iterations, traffic_profile, connection_bound, control_traffic_path_requirement, best_effort_path_requirement]):
                return UNSET_INDICATOR

        return SMALL_SEPARATOR.join([iterations, traffic_profile, connection_bound, control_traffic_path_requirement, best_effort_path_requirement])

    def to_dict_value(self, run_specific = False):
        return {
            ITERATIONS_KEY : 1 if run_specific else self.iterations,
            TRAFFIC_PROFILE_KEY : self.traffic_profile.name,
            UPPER_CONNECTION_BOUND_KEY : self.connection_bound.to_dict_value(run_specific=run_specific),
            CONTROL_TRAFFIC_REQUIREMENT_KEY : self.control_traffic_path_requirement.to_dict_value(run_specific=run_specific),
            BEST_EFFORT_TRAFFIC_REQUIREMENT_KEY : self.best_effort_path_requirement.to_dict_value(run_specific=run_specific)
        }
    
    def __apply_synced_iteration_logic__(self):
        iterable_values = [self.connection_bound, self.control_traffic_path_requirement, self.best_effort_path_requirement]
        return any([iterable_value.iterate(synced=True) for iterable_value in iterable_values])
        
    def __apply_unsynced_iteration_logic__(self):
        iterable_values = [self.connection_bound, self.control_traffic_path_requirement, self.best_effort_path_requirement]
        unsynced_values = [iterable_value for iterable_value in iterable_values if iterable_value != None and not iterable_value.synced]
        for x in unsynced_values:
            if x.iterate():
                return True
            
        return False
    
    def reset(self, synced = False):
        for iterable_value in [self.connection_bound, self.control_traffic_path_requirement, self.best_effort_path_requirement]:
            iterable_value.reset(synced)
        return super().reset()
    
class SecurityGenerationConfig(AGenesisTaggable):
    DEFAULT_MAPPING = [1,0,0]

    def __init__(self, iterations : int = DEFAULT_MAPPING[0], ruleset_anomaly_count : Optional[IterativeParameterValue] = None, stateful_rule_percentage : Optional[IterativeParameterValue] = None):
        super().__init__()
        self.iterations = iterations
        if ruleset_anomaly_count:
            self.ruleset_anomaly_count = ruleset_anomaly_count
        else:
            self.ruleset_anomaly_count = IterativeParameterValue([SecurityGenerationConfig.DEFAULT_MAPPING[1]])

        if stateful_rule_percentage:
            self.stateful_percentage = stateful_rule_percentage
        else:
            self.stateful_percentage = IterativeParameterValue([SecurityGenerationConfig.DEFAULT_MAPPING[2]])

    @staticmethod
    def from_dict(value : dict):
        iterations = value.get(ITERATIONS_KEY, 1)
        ruleset_anomaly_count = IterativeParameterValue.from_dict(value.get(ANOMALY_COUNT_KEY, 0))
        stateful_rule_percentage = IterativeParameterValue.from_dict(value.get(STATEFUL_PERCENTAGE_KEY, 0))
        return SecurityGenerationConfig(iterations=iterations,
                                        ruleset_anomaly_count=ruleset_anomaly_count,
                                        stateful_rule_percentage=stateful_rule_percentage
                                        )
    
    @staticmethod
    def from_str(value : str):
        if value == UNSET_INDICATOR:
            iterations, ruleset_anomaly_count, stateful_rule_percentage = [str(x) for x in SecurityGenerationConfig.DEFAULT_MAPPING]
        else:
            iterations, ruleset_anomaly_count, stateful_rule_percentage = [str(SecurityGenerationConfig.DEFAULT_MAPPING[i]) if x == UNSET_INDICATOR else x for (i,x) in enumerate(value.split(SMALL_SEPARATOR))]
        ruleset_anomaly_count = IterativeParameterValue.from_str(ruleset_anomaly_count)
        stateful_rule_percentage = IterativeParameterValue.from_str(stateful_rule_percentage)
        return SecurityGenerationConfig(iterations=int(iterations),
                                        ruleset_anomaly_count=ruleset_anomaly_count,
                                        stateful_rule_percentage=stateful_rule_percentage)

    def to_tag(self, run_specific = False, short_tag = False):
        default_iterations = SecurityGenerationConfig.DEFAULT_MAPPING[0]
        iterations = UNSET_INDICATOR if (short_tag and (run_specific or self.iterations == default_iterations)) else (str(default_iterations) if run_specific else str(self.iterations))

        ruleset_anomaly_count = self.ruleset_anomaly_count.to_tag(run_specific=run_specific)

        stateful_rule_percentage = self.stateful_percentage.to_tag(run_specific=run_specific)

        if short_tag and all(x == UNSET_INDICATOR for x in [iterations, ruleset_anomaly_count, stateful_rule_percentage]):
            return UNSET_INDICATOR
        
        return SMALL_SEPARATOR.join([iterations, ruleset_anomaly_count, stateful_rule_percentage])
    
    def to_dict_value(self, run_specific = False):
        return {
            ITERATIONS_KEY : 1 if run_specific else self.iterations,
            ANOMALY_COUNT_KEY : self.ruleset_anomaly_count.to_dict_value(run_specific=run_specific),
            STATEFUL_PERCENTAGE_KEY : self.stateful_percentage.to_dict_value(run_specific=run_specific)
        }
    
    def __apply_synced_iteration_logic__(self):
        iterable_values = [self.ruleset_anomaly_count, self.stateful_percentage]
        return any([iterable_value.iterate(synced=True) for iterable_value in iterable_values])
    
    def __apply_unsynced_iteration_logic__(self):
        iterable_values = [self.ruleset_anomaly_count, self.stateful_percentage]
        unsynced_values = [iterable_value for iterable_value in iterable_values if iterable_value != None and not iterable_value.synced]
        for x in unsynced_values:
            if x.iterate():
                return True
        return False


    def reset(self, synced = False):
        for iterable_value in [self.ruleset_anomaly_count, self.stateful_percentage]:
            iterable_value.reset(synced)
        return super().reset()
        
class SeedConfig(AGenesisTaggable):
    def __init__(self, topology_seed : IterativeParameterValue, communication_seed : IterativeParameterValue, security_seed : IterativeParameterValue):
        super().__init__()
        self.topology_seed = topology_seed
        self.communication_seed = communication_seed
        self.security_seed = security_seed

    @staticmethod
    def from_str(value : str, iterations = None):
        topology_seed, communication_seed, security_seed = [IterativeParameterValue(values=[seed] if not iterations else [seed, seed + iterations[i] - 1, 1]) for i, seed in enumerate(map(int, value.split(SMALL_SEPARATOR)))]
        return SeedConfig(topology_seed=topology_seed,
                          communication_seed=communication_seed,
                          security_seed=security_seed)
    
    @staticmethod
    def from_dict(value : dict, iterations = None):
        raw_seeds = [value.get(key, randint(1,1000)) for key in [TOPOLOGY_KEY, COMMUNICATION_KEY, SECURITY_KEY]]
        topology_seed, communication_seed, security_seed = [IterativeParameterValue(values=[seed] if not iterations else [seed, seed + iterations[i] - 1, 1]) for i, seed in enumerate(raw_seeds)]

        return SeedConfig(topology_seed=topology_seed,
                          communication_seed=communication_seed,
                          security_seed=security_seed)
    
    @staticmethod
    def random(iterations = None):
        raw_seeds = [randint(1,1000) for _ in range(3)]
        topology_seed, communication_seed, security_seed = [IterativeParameterValue(values=[seed] if not iterations else [seed, seed + iterations[i] - 1, 1]) for i, seed in enumerate(raw_seeds)]
    
        return SeedConfig(topology_seed=topology_seed,
                          communication_seed=communication_seed,
                          security_seed=security_seed)

    def __apply_synced_iteration_logic__(self):
        iterable_values = [self.topology_seed, self.communication_seed, self.security_seed]
        synced_values = [iterable_value for iterable_value in iterable_values if iterable_value != None and iterable_value.synced]
        return any([iterable_value.iterate(synced=True) for iterable_value in synced_values])

    def __apply_unsynced_iteration_logic__(self):
        iterable_values = [self.topology_seed, self.communication_seed, self.security_seed]
        unsynced_values = [iterable_value for iterable_value in iterable_values if iterable_value != None and not iterable_value.synced]
        for x in unsynced_values:
            if x.iterate():
                return True
        return False
            
    
    def reset(self, synced = False):
        for iterative_value in [self.topology_seed, self.communication_seed, self.security_seed]:
            iterative_value.reset(synced)
        return super().reset()

    def to_tag(self, run_specific = False, short_tag = False):
        return SMALL_SEPARATOR.join([str(x.current if run_specific else x.start) for x in [self.topology_seed, self.communication_seed, self.security_seed]])
    
    def to_dict_value(self, run_specific = False):
        return {key : value.current if run_specific else value.start for key, value in [(TOPOLOGY_KEY, self.topology_seed), (COMMUNICATION_KEY, self.communication_seed), (SECURITY_KEY, self.security_seed)]}
    
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
            raise Exception(f'InvalidGenesisTag: Incompatible GeNESIS version detected: {version(GENESIS_PACKAGE_NAME)} != {version_number}. You can checkout the GeNESIS version matching your tag with "git checkout tags/{version_number}" *if it exists*.')
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
    def from_dict(value : dict):
        topology_config = TopologyGenerationConfig.from_dict(value.get(TOPOLOGY_KEY, dict()))

        raw_communication_config = value.get(COMMUNICATION_KEY, dict())
        if raw_communication_config:
            communication_config = CommunicationGenerationConfig.from_dict(raw_communication_config)
        else:
            communication_config = CommunicationGenerationConfig()
        
        raw_security_config = value.get(SECURITY_KEY, dict())
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

    def to_tag(self, run_specific = False, short_tag = False):
        content = BIG_SEPARATOR.join(map(lambda x: x.to_tag(run_specific=run_specific, short_tag=short_tag), [self.seed_config, self.communication_config, self.security_config, self.topology_config]))
        encapsulator = TAG_ENCAPSULATOR if short_tag else f'\\{TAG_ENCAPSULATOR}'
        return f'genesis:v{version(GENESIS_PACKAGE_NAME)}{encapsulator}{content}{encapsulator}'
    
    def to_dict_value(self, run_specific = False):
        return {key : value.to_dict_value(run_specific=run_specific) for key, value in [(TOPOLOGY_KEY, self.topology_config), (COMMUNICATION_KEY, self.communication_config), (SECURITY_KEY, self.security_config)]}
    
    def to_file(self, location, run_specific = False):
        with open(location, 'x') as file:
            dump(self.to_dict_value(run_specific=run_specific), file, indent=4)
        print('Configuration saved at: ', location)

    def __apply_synced_iteration_logic__(self):
        subconfigs = [self.topology_config, self.communication_config, self.security_config]
        iteration_success = any([subconfig.iterate(synced=True) for subconfig in subconfigs])
        return iteration_success
    
    def __apply_unsynced_iteration_logic__(self):
        subconfigs = [self.topology_config, self.communication_config, self.security_config]
        for subconfig in subconfigs:
            if subconfig.iterate():
                return True
        return False
    
    def reset(self, synced = False):
        for subconfig in [self.topology_config, self.communication_config, self.security_config]:
            subconfig.reset(synced)
        return super().reset()