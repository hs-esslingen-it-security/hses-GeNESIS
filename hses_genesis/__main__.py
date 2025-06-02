from copy import copy
from json import dumps
from math import ceil
from typing import DefaultDict, Literal, Optional

from hses_genesis.generation.communication import CommunicationGenerator, print_connection_info, get_metadata as communication_metadata
from hses_genesis.generation.dynamic_configuration import ConfigurationGenerator
from hses_genesis.generation.network_configuration import NetworkConfigurationGenerator
from hses_genesis.generation.topology import TopologyGenerator, calculate_subnets, get_graph_information, get_metadata as topology_metadata
from hses_genesis.parsing.configuration import GenerationConfig
from hses_genesis.setup.output_location import setup_base_location, setup_run_location
from hses_genesis.utils.constants import GRAPH_FOLDER, TERMINAL_WIDTH
from hses_genesis.utils.enum_objects import EDeviceRole
from hses_genesis.save import topology as topology
from hses_genesis.save import packets as packets
from hses_genesis.save import rulesets as rulesets
from hses_genesis.save import resilience as resilience
from argparse import ArgumentParser
from os.path import abspath, dirname, join, basename, exists
from networkx import Graph, shortest_simple_paths
from hses_genesis.utils.functions import load_resource, print_information


def user_choice(prompt, choices, default = None):
    while True:
        value = input(prompt + ' (' + ', '.join(choices + ([f'default {default}'] if default else [])) + '): ')
        if not value and default:
            return default
        if value in choices:
            return value
        
        print('No valid option chosen. Please try again.')

parser = ArgumentParser()
parser.add_argument('-j', '--json', help='pass the name or absolute path of the configuration file to use.', default=None)
parser.add_argument('-g', '--genesis_tag', help='pass the GeNESIS-TAG of a previous run.', default=None)
parser.add_argument('-n', '--new_configuration', help='start the Interactive GeNESIS Configuration Generator to create a new configuration.', action='store_true')
parser.add_argument('-o', '--output_location', help='set the output location for generated files.', default=join(dirname(abspath(__file__)), 'output'))
parser.add_argument('-img', '--export_graph_images', help='export a .png and a .jpg of the network topology.', action='store_true')
parser.add_argument('-zimpl', '--export_zimpl_parsables', help='export the topology and rules as zimpl parsable txt files.', action='store_true')
parser.add_argument('-omnet', '--export_omnet_files', help='export the topology and packet configuration files for omnet++.', action='store_true')
parser.add_argument('-ns3', '--export_ns3_files', help='export the topology and packet configuration files for ns3.', action='store_true')
parser.add_argument('-yang', '--export_yang_files', help='export the all outputs in a single json file.', action='store_true')
parser.add_argument('-ipt', '--export_iptables_files', help='export the security configurations as iptables save files.', action='store_true')
parser.add_argument('-ri', '--export_resilience_info', help='export the resilience information of communication pairs as csv.', action='store_true')
parser.add_argument('-b', '--early_break', help='Breaks the generation process after the specified generation step.', choices=['topology', 'communication'])
parser.add_argument('-l', '--label', help='defines the name of the created output folder, where GeNESIS saves all output files.')

args = parser.parse_args()

def perform_generation_cycle(base_location : str, config : GenerationConfig):

    def save_metadata(run_location, G, total_connections, forbidden_connections, intrasubnet_connections, intersubnet_connections, sampled_connections):
        metadata = topology_metadata(G) | communication_metadata(total_connections, forbidden_connections, intrasubnet_connections, intersubnet_connections, sampled_connections)
        with open(join(run_location, 'metadata.json'), 'w') as file:
            file.write(dumps(metadata, indent=4))
    
    def save_generated(run_location : str, run_label : str, generated_graph : Graph, generated_packets : Optional[dict] = None, router_ruleset_map : Optional[dict] = None, sampled_connections : Optional[list] = None):
        topology.to_graphml(generated_graph, join(run_location, GRAPH_FOLDER))

        if args.export_graph_images:
            topology.to_image(generated_graph, join(run_location, GRAPH_FOLDER), seed=config.seed_config.topology_seed.current)
        if args.export_yang_files:
            topology.to_ietf(generated_graph, join(run_location, GRAPH_FOLDER), generated_packets)
        if args.export_omnet_files:
            topology.to_omnet_ned(generated_graph, run_location)
        if args.export_ns3_files:
            topology.to_ns3_cc(generated_graph, run_location, generated_packets)
        if args.export_zimpl_parsables:
            topology.to_zimpl_parsable(G, run_location)
    
        if generated_packets:
            packets.to_csv(run_location, generated_packets)
            if args.export_omnet_files:
                packets.to_omnet_ini(run_location, generated_packets)

        if sampled_connections and args.export_resilience_info:
            communication_pairs = set([(s, d) for (s, d, _) in sampled_connections])
            resilience.save_path_diversity(dir = dirname(run_location), run_label=run_label, G=generated_graph, communication_pairs=communication_pairs, control_traffic_path_requirement=config.communication_config.control_traffic_path_requirement.current, best_effort_path_requirement=config.communication_config.best_effort_path_requirement.current)
            resilience.save_minimal_cuts(dir = dirname(run_location), run_label=run_label, G=generated_graph, communication_pairs=communication_pairs)

        if router_ruleset_map:
            if args.export_iptables_files:
                rulesets.to_save_files(run_location, router_ruleset_map)
            if args.export_zimpl_parsables:
                rulesets.to_zimpl_parsable(run_location, router_ruleset_map)

        print_information('GENERAL INFORMATION', {
            'seeds used for this iteration' : '',
            '- topology' : str(config.seed_config.topology_seed.current),
            '- communication' : str(config.seed_config.communication_seed.current),
            '- security' : str(config.seed_config.security_seed.current),
            'output data location for this iteration' : run_location,
            'genesis tag for this iteration (long)' : config.to_tag(run_specific=True),
            'genesis tag for this iteration (short)' : config.to_tag(run_specific=True, short_tag=True)
        })

    print(f'Start Generation Step "topology"')
    topology_generator = TopologyGenerator(config.seed_config.topology_seed.current)
    layer_definitions = [clone for layer_definition in config.topology_config.layer_definitions for clone in [copy(layer_definition) for _ in range(layer_definition.repetitions.current)]]
    available_subnets = calculate_subnets(layer_definitions)
    G = topology_generator.generate_network_topology_graph(layer_definitions=layer_definitions,
                                                           subnets=available_subnets,
                                                           default_meshing=config.topology_config.meshing_degree.current,
                                                           default_host_connectivity=config.topology_config.host_connectivity.current,
                                                           deault_subnet_connectivity=config.topology_config.subnet_connectivity.current)
    print_information('GRAPH INFORMATION', get_graph_information(G))

    run_label = '-'.join(map(lambda x: str(x), [config.seed_config.topology_seed.current, config.seed_config.communication_seed.current, config.seed_config.security_seed.current]))
    run_location = setup_run_location(config=config,
                                      base_location=base_location,
                                      run_label=run_label,
                                      export_iptables_files = args.export_iptables_files,
                                      export_omnet_files = args.export_omnet_files,
                                      export_ns3_files = args.export_ns3_files,
                                      export_zimpl_parsables = args.export_zimpl_parsables)
    run_label = basename(run_location)

    if args.early_break == 'topology':
        save_generated(run_location=run_location, run_label=run_label, generated_graph=G)
        return

    print(f'Start Generation Step "communication"')
    communication_generator = CommunicationGenerator(config.seed_config.communication_seed.current)
    total_connections, forbidden_connections, intrasubnet_connections, intersubnet_connections, sampled_connections = communication_generator.get_connections(G, config.communication_config.traffic_profile, config.communication_config.connection_bound.current)
    print_connection_info(total_connections=total_connections, forbidden_connections=forbidden_connections, intrasubnet_connections=intrasubnet_connections, intersubnet_connections=intersubnet_connections, sampled_connections=sampled_connections, traffic_profile=config.communication_config.traffic_profile)

    ruleset_connections = []
    generated_packets = DefaultDict(list)

    for (source_id, destination_id, service) in sampled_connections:
        protocol = communication_generator.random.choice(service.value.protocols)
        port = communication_generator.random.choice(service.value.ports)
        ruleset_connections.append(((source_id, destination_id, protocol, port, port)))

        src_data, dst_data = [G.nodes[node] for node in [source_id, destination_id]]

        src_packet = communication_generator.generate_packet(service=service,
                                                src_node=source_id,
                                                dst_node=destination_id,
                                                src_data=src_data,
                                                dst_data=dst_data,
                                                protocol=protocol,
                                                port=port,
                                                is_high_sender=src_data['role'] in EDeviceRole.high_senders())
        
        generated_packets[source_id].append(src_packet)

        dst_packet = communication_generator.generate_packet(service=service,
                                                src_node=destination_id,
                                                dst_node=source_id,
                                                src_data=dst_data,
                                                dst_data=src_data,
                                                protocol=protocol,
                                                port=port,
                                                is_high_sender=dst_data['role'] in EDeviceRole.high_senders())
        
        generated_packets[destination_id].append(dst_packet)

    save_metadata(run_location, G, total_connections, forbidden_connections, intrasubnet_connections, intersubnet_connections, sampled_connections)

    if args.early_break == 'communication':
        save_generated(run_location=run_location, run_label=run_label, generated_graph=G, generated_packets=generated_packets, sampled_connections=sampled_connections)
        return

    print(f'Start Generation Step "security"')

    routers = [router for router, data in G.nodes(data=True) if data['role'] == EDeviceRole.ROUTER]

    router_connections = DefaultDict(list)
    for source, target, p, sport, dport in ruleset_connections:
        affected_routers = [router for router in routers if any(router in path for path in shortest_simple_paths(G, source, target))]
        for router in affected_routers:
            router_connections[router].append((G.nodes[source]['ip'], G.nodes[target]['ip'], p, sport, dport))

    router_ruleset_map = {}
    network_configuration_generator = NetworkConfigurationGenerator(config.seed_config.security_seed.current)
    for router in router_connections.keys():
        raw_ruleset = network_configuration_generator.generate_ruleset(router_connections[router], config.security_config.ruleset_anomaly_count.current, config.security_config.stateful_percentage.current)
        G.nodes[router]['ruleset'] = [NetworkConfigurationGenerator.rule_to_str(rule) for rule in raw_ruleset]
        router_ruleset_map[router] = [{'int' : NetworkConfigurationGenerator.to_numerical_representation(rule), 'str' : NetworkConfigurationGenerator.rule_to_str(rule)} for rule in raw_ruleset]
    
    save_generated(run_location=run_location, run_label=run_label, generated_graph=G, generated_packets=generated_packets, router_ruleset_map=router_ruleset_map, sampled_connections=sampled_connections)

print('-' * ceil((TERMINAL_WIDTH - 12) / 2), 'Welcome to', '-' * ceil((TERMINAL_WIDTH - 12) / 2))
print('  ___     _  _ ___ ___ ___ ___     _   ___ ')
print(' / __|___| \| | __/ __|_ _/ __|_ _/ | |_  )')
print('| (_ / -_)  ` | _|\__ \| |\__ \ V / |_ / /')
print(' \___\___|_|\_|___|___/___|___/\_/|_(_)___|')
print()
print('-' * TERMINAL_WIDTH)

configuration_choices = [t for (t, v) in [('g', args.genesis_tag), ('j', args.json), ('n', args.new_configuration)] if v]
if len (configuration_choices) > 1:
    choice = user_choice('Multiple configuration origins were provided. Please choose the one you want to use', configuration_choices)
elif len(configuration_choices) == 1:
    choice = configuration_choices[0]
else:
    choice = 'r'

config : dict = {}

if choice == 'n':
    config = GenerationConfig.from_dict(ConfigurationGenerator().edit_config())
    config_name = 'custom_config'
elif choice == 'j':
    config_file = args.json
    if not str(config_file).endswith('.json'):
        config_file += '.json'
    if not exists(args.json):
        config_file = load_resource('configurations', config_file)
    config_name = basename(str(args.json)).removesuffix('.json')
    config : GenerationConfig = GenerationConfig.from_file(config_file)
elif choice == 'g':
    config_name = 'tag_rerun_config'
    config : GenerationConfig = GenerationConfig.from_str(args.genesis_tag)
else:
    config_name = 'example_config'
    config_file = load_resource('configurations', f'{config_name}.json')
    config : GenerationConfig = GenerationConfig.from_file(config_file)

print('-' * TERMINAL_WIDTH)
print(f'GeNESIS started with GeNESIS-TAG:')
print(f'(long tag version)\t{config.to_tag()}')
print(f'(short tag version)\t{config.to_tag(short_tag=True)}')
print('-' * TERMINAL_WIDTH)
base_location = setup_base_location(config, args.output_location, config_name if not args.label else args.label)


while True:
    config.reset(synced=True)
    while True:
        config.reset()
        while True:
            perform_generation_cycle(base_location, config)
            if not config.iterate():
                break
        if not config.iterate(synced=True):
            break
    if not config.seed_config.iterate():
        break