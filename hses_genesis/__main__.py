from copy import copy
from math import ceil

from hses_genesis.generation.communication import CommunicationGenerator
from hses_genesis.generation.dynamic_configuration import ConfigurationGenerator
from hses_genesis.generation.network_configuration import NetworkConfigurationGenerator
from hses_genesis.generation.topology import TopologyGenerator, calculate_subnets, get_graph_information
from hses_genesis.parsing.configuration import GenerationConfig
from hses_genesis.setup.output_location import setup_base_location, setup_run_location
from hses_genesis.utils.constants import GRAPH_FOLDER, RULESET_FOLDER, TERMINAL_WIDTH
from hses_genesis.utils.enum_objects import EDeviceRole
from hses_genesis.save import topology as topology
from hses_genesis.save import packets as packets
from hses_genesis.save import rulesets as rulesets
from argparse import ArgumentParser
from os.path import abspath, dirname, join, basename, exists
from networkx import shortest_simple_paths
from hses_genesis.utils.functions import load_resource, print_information

def user_choice(prompt, choices, default = None):
    while True:
        value = input(prompt + ' (' + ', '.join(choices + ([f'default {default}'] if default else [])) + '): ')
        if not value and default:
            return default
        if value in choices:
            return value
        
        print('No valid option chosen. Please try again.')

def perform_generation_cycle(base_location : str, config : GenerationConfig, export_yang_files = False, export_iptables_files = False, export_graph_images = False, export_omnet_files = False, export_ns3_files = False, export_zimpl_parsables = False):
    print(f'Start Generation Step "topology"')
    topology_generator = TopologyGenerator(config.seed_config.topology_seed.CURRENT)
    layer_definitions = [clone for layer_definition in config.topology_config.layer_definitions for clone in [copy(layer_definition) for _ in range(layer_definition.repetitions.CURRENT)]]
    available_subnets = calculate_subnets(layer_definitions)
    G = topology_generator.generate_network(layer_definitions, available_subnets)
    print_information('GRAPH INFORMATION', get_graph_information(G))

    print(f'Start Generation Step "communication"')
    communication_generator = CommunicationGenerator(config.seed_config.communication_seed.CURRENT)
    _, sampled_connections = communication_generator.get_connections(G, config.communication_config.traffic_profile, config.communication_config.connection_bound.CURRENT)
    
    ruleset_connections = []
    generated_packets = {}

    for (source_id, destination_id, service) in sampled_connections:
        protocol = communication_generator.random.choice(service.value.protocols)
        port = communication_generator.random.choice(service.value.ports)
        ruleset_connections.append(((source_id, destination_id, protocol, port, port), list(shortest_simple_paths(G, source_id, destination_id))))

        if source_id not in generated_packets:
            generated_packets[source_id] = []

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

        if destination_id not in generated_packets:
            generated_packets[destination_id] = []
            
        dst_packet = communication_generator.generate_packet(service=service,
                                                src_node=destination_id,
                                                dst_node=source_id,
                                                src_data=dst_data,
                                                dst_data=src_data,
                                                protocol=protocol,
                                                port=port,
                                                is_high_sender=dst_data['role'] in EDeviceRole.high_senders())
        
        generated_packets[destination_id].append(dst_packet)

    run_location = setup_run_location(config=config,
                                      base_location=base_location,
                                      run_label='-'.join(map(lambda x: str(x), [config.seed_config.topology_seed.CURRENT, config.seed_config.communication_seed.CURRENT, config.seed_config.security_seed.CURRENT])),
                                      export_iptables_files = export_iptables_files,
                                      export_omnet_files = export_omnet_files,
                                      export_ns3_files = export_ns3_files,
                                      export_zimpl_parsables = export_zimpl_parsables)
    
    packets.to_csv(run_location, generated_packets)
    
    print(f'Start Generation Step "security"')
    network_configuration_generator = NetworkConfigurationGenerator(config.seed_config.security_seed.CURRENT)

    routers = [router for router, data in G.nodes(data=True) if data['role'] == EDeviceRole.ROUTER]

    router_connections = {}
    for (source, target, p, sport, dport), paths in ruleset_connections:
        affected_routers = [router for router in routers if any(router in path for path in paths)]
        for router in affected_routers:
            if router not in router_connections.keys():
                router_connections[router] = []
            router_connections[router].append((G.nodes[source]['ip'], G.nodes[target]['ip'], p, sport, dport))

    router_ruleset_map = {}
    for router in router_connections.keys():
        raw_ruleset = network_configuration_generator.generate_ruleset(set(router_connections[router]), config.security_config.ruleset_anomaly_count.CURRENT, config.security_config.stateful_percentage.CURRENT)
        G.nodes[router]['ruleset'] = [NetworkConfigurationGenerator.rule_to_str(rule) for rule in raw_ruleset]
        if export_iptables_files:
            rulesets.to_save_file(join(run_location, RULESET_FOLDER), router, G.nodes[router]['ruleset'])
        router_ruleset_map[router] = [NetworkConfigurationGenerator.to_numerical_representation(rule) for rule in raw_ruleset]
    
    print_information('GENERAL INFORMATION', {
        'seeds used for this iteration' : '',
        '- topology' : str(config.seed_config.topology_seed.CURRENT),
        '- communication' : str(config.seed_config.communication_seed.CURRENT),
        '- security' : str(config.seed_config.security_seed.CURRENT),
        'output data location for this iteration' : run_location,
        'genesis tag for this iteration' : config.to_run_str()
    })

    topology.to_graphml(G, join(run_location, GRAPH_FOLDER))
    if export_yang_files:
        topology.to_ietf(G, join(run_location, GRAPH_FOLDER), generated_packets)
    if export_graph_images:
        topology.to_image(G, join(run_location, GRAPH_FOLDER), seed=config.seed_config.topology_seed.CURRENT)
    if export_omnet_files:
        topology.to_omnet_ned(G, run_location)
        packets.to_omnet_ini(run_location, generated_packets)
    if export_ns3_files:
        topology.to_ns3_cc(G, run_location, generated_packets)
    if export_zimpl_parsables:
        topology.to_zimpl_parsable(G, run_location)

parser = ArgumentParser()
parser.add_argument('-j', '--json', help='pass the name or absolute path of the configuration file to use.', default=None)
parser.add_argument('-g', '--genesis_tag', help='pass the GeNESIS-TAG of a previous run.', default=None)
parser.add_argument('-n', '--new_configuration', help='start the Interactive GeNESIS Configuration Generator to create a new configuration.', action='store_true')
parser.add_argument('-o', '--output_location', help='set the output location for generated files.', default=join(dirname(abspath(__file__)), 'output'))
parser.add_argument('-img', '--export_graph_images', help='export a .png and a .jpg of the network topology.', action='store_true')
parser.add_argument('-zpl', '--export_zimpl_parsables', help='export the topology and rules as zimpl parsable txt files.', action='store_true')
parser.add_argument('-omnet', '--export_omnet_files', help='export the topology and packet configuration files for omnet++.', action='store_true')
parser.add_argument('-ns3', '--export_ns3_files', help='export the topology and packet configuration files for ns3.', action='store_true')
parser.add_argument('-yang', '--export_yang_files', help='export the all outputs in a single json file.', action='store_true')
parser.add_argument('-ipt', '--export_iptables_files', help='export the scurity configurations as iptables save files.', action='store_true')
parser.add_argument('-latag', '--use_latex_tag', help='get the genesis tag in latex parsable form.', action='store_true')

args = parser.parse_args()

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
    config : GenerationConfig = GenerationConfig.from_file(config_file, args.use_latex_tag)
elif choice == 'g':
    config_name = 'tag_rerun_config'
    config : GenerationConfig = GenerationConfig.from_str(args.genesis_tag, args.use_latex_tag)
else:
    config_name = 'example_config'
    config_file = load_resource('configurations', f'{config_name}.json')
    config : GenerationConfig = GenerationConfig.from_file(config_file, args.use_latex_tag)

print('-' * TERMINAL_WIDTH)
print(f'GeNESIS started with GeNESIS-TAG: {config.to_total_str()}')
print('-' * TERMINAL_WIDTH)
base_location = setup_base_location(config, args.output_location, config_name)

while True:
    config.reset()
    while True:
        perform_generation_cycle(base_location,
                                 config,
                                 export_yang_files=args.export_yang_files,
                                 export_iptables_files=args.export_iptables_files,
                                 export_graph_images=args.export_graph_images,
                                 export_ns3_files=args.export_ns3_files,
                                 export_omnet_files=args.export_omnet_files,
                                 export_zimpl_parsables=args.export_zimpl_parsables)
        if not config.iterate():
            break
    if not config.seed_config.iterate():
        break