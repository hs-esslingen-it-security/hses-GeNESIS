from copy import copy
from ipaddress import ip_address
from math import ceil
from hses_genesis.generation.communication import CommunicationGenerator
from hses_genesis.generation.network_configuration import NetworkConfigurationGenerator
from hses_genesis.generation.topology import TopologyGenerator, calculate_subnets, get_graph_information
from hses_genesis.generation.genesis_configuration import get_config_from_mask
from hses_genesis.parsing.configuration import GenerationConfig
from hses_genesis.setup.output_location import setup_base_location, setup_run_location
from hses_genesis.utils.constants import GRAPH_FOLDER, PROTOCOLS, RULESET_FOLDER, TERMINAL_WIDTH
from hses_genesis.utils.enum_objects import EDeviceRole, EParameterKey
from hses_genesis.save import topology as topology
from hses_genesis.save import packets as packets
from hses_genesis.save import rulesets as rulesets
from argparse import ArgumentParser
from os.path import abspath, dirname, join, basename
from networkx import shortest_simple_paths
from hses_genesis.utils.functions import print_information

def user_choice(prompt, choices, default = None):
    while True:
        value = input(prompt + ' (' + ', '.join(choices + ([f'default {default}'] if default else [])) + '): ')
        if not value and default:
            return default
        if value in choices:
            return value
        
        print('No valid option chosen. Please try again.')

def perform_generation_cycle(base_location : str, config : GenerationConfig, export_yang_files = False, export_iptables_files = False, export_graph_images = False):
    print(f'Start Generation Step "topology"')
    topology_generator = TopologyGenerator(config.seed_config.topology_seed.CURRENT)
    layer_definitions = [clone for layer_definition in config.topology_config.layer_definitions for clone in [copy(layer_definition) for _ in range(layer_definition.repetitions.CURRENT)]]
    available_subnets = calculate_subnets(layer_definitions)
    G = topology_generator.generate_network(layer_definitions, available_subnets)
    print_information('GRAPH INFORMATION', get_graph_information(G))

    print(f'Start Generation Step "communication"')
    communication_generator = CommunicationGenerator(config.seed_config.communication_seed.CURRENT)
    intrasubnet_connections, sampled_connections = communication_generator.get_connections(G, config.communication_config.traffic_profile, config.communication_config.connection_bound.CURRENT)
    
    ruleset_connections = []
    generated_packets = {}

    for (source_id, destination_id, service) in sampled_connections:
        protocols, ports, packet_size, packets_per_second = service.value
        protocol = communication_generator.random.choice(protocols) if len(protocols) > 0 else '*'
        port = communication_generator.random.choice(ports) if len(ports) > 0 else '*'
        ruleset_connections.append(((source_id, destination_id, protocol, port, port), list(shortest_simple_paths(G, source_id, destination_id))))
        src_role, dst_role = EDeviceRole.from_device_id(source_id), EDeviceRole.from_device_id(destination_id)
        high_sender_roles = [EDeviceRole.IT_END_DEVICE, EDeviceRole.OT_END_DEVICE]
        src_communication_modifier, dst_communication_modifier = 2 if src_role in high_sender_roles else 1, 2 if dst_role in high_sender_roles else 1

        if source_id not in generated_packets:
            generated_packets[source_id] = []

        generated_packets[source_id].append({
            EParameterKey.SRC.value : source_id,
            f'{EParameterKey.SRC.name.lower()}_ip' : ip_address(G.nodes[source_id]['ip']),
            EParameterKey.DST.value : destination_id,
            f'{EParameterKey.DST.name.lower()}_ip' : ip_address(G.nodes[destination_id]['ip']),
            EParameterKey.PROTOCOL.value : protocol.lower(),
            f'{EParameterKey.PROTOCOL.name.lower()}_code' : PROTOCOLS[protocol.lower()],
            EParameterKey.SRC_PORT.value : port,
            EParameterKey.DST_PORT.value : port,
            'packet_size' : communication_generator.random.randint(packet_size[0], packet_size[1]),
            'packets_per_second' : communication_generator.random.randint(packets_per_second[0], packets_per_second[1]) * src_communication_modifier
        })

        if destination_id not in generated_packets:
            generated_packets[destination_id] = []

        generated_packets[destination_id].append({
            EParameterKey.SRC.value : destination_id,
            f'{EParameterKey.SRC.name.lower()}_ip' : ip_address(G.nodes[destination_id]['ip']),
            EParameterKey.DST.value : source_id,
            f'{EParameterKey.DST.name.lower()}_ip' : ip_address(G.nodes[source_id]['ip']),
            EParameterKey.PROTOCOL.value : protocol.lower(),
            f'{EParameterKey.PROTOCOL.name.lower()}_code' : PROTOCOLS[protocol.lower()],
            EParameterKey.SRC_PORT.value : port,
            EParameterKey.DST_PORT.value : port,
            'packet_size' : communication_generator.random.randint(packet_size[0], packet_size[1]),
            'packets_per_second' : communication_generator.random.randint(packets_per_second[0], packets_per_second[1]) * dst_communication_modifier
        })

    run_location = setup_run_location(config, base_location, '-'.join(map(lambda x: str(x), [config.seed_config.topology_seed.CURRENT, config.seed_config.communication_seed.CURRENT, config.seed_config.security_seed.CURRENT])), args.export_iptables_files)
    
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
        topology.to_ietf(G, run_location, generated_packets)
    if export_graph_images:
        topology.to_image(G, run_location)

parser = ArgumentParser()
parser.add_argument('-j', '--json', help='location of json configuration file.', default=None)
parser.add_argument('-g', '--genesis_tag', help='GeNESIS-TAG of a previous run.', default=None)
parser.add_argument('-n', '--new_configuration', help='start the Interactive GeNESIS Configuration Generator to create a new configuration.', default=False, action='store_true')
parser.add_argument('-o', '--output_location', help='set the output location for generated files.', default=join(dirname(abspath(__file__)), 'output'))
parser.add_argument('-yang', '--export_yang_files', help='use this to export all outputs in a single yang.json file in an ietf conform format.', action='store_true', default=False)
parser.add_argument('-ipt', '--export_iptables_files', help='use this to export all rulesets in iptable-save format.', action='store_true', default=False)
parser.add_argument('-img', '--export_graph_images', help='use this to export an image of the network topology on creation.', action='store_true', default=False)

args = parser.parse_args()

print('-' * ceil((TERMINAL_WIDTH - 12) / 2), 'Welcome to', '-' * ceil((TERMINAL_WIDTH - 12) / 2))
print('  ___     _  _ ___ ___ ___ ___     _   _ ')
print(' / __|___| \| | __/ __|_ _/ __|_ _/ | / |')
print('| (_ / -_) .` | _|\__ \| |\__ \ V / |_| |')
print(' \___\___|_|\_|___|___/___|___/\_/|_(_)_|')
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
    config = get_config_from_mask(join(dirname(__file__), 'resources/example_config.json'))
    config_name = 'custom_config'
elif choice == 'j':
    config_name = basename(str(args.json)).removesuffix('.json')
    config : GenerationConfig = GenerationConfig.from_file(args.json)
elif choice == 'g':
    config_name = 'tag_rerun_config'
    config : GenerationConfig = GenerationConfig.from_str(args.genesis_tag)
else:
    config_name = 'example_config'
    config : GenerationConfig = GenerationConfig.from_file(join(dirname(__file__), 'resources/example_config.json'))

print('-' * TERMINAL_WIDTH)
print(f'GeNESIS started with GeNESIS-TAG: {config.to_total_str()}')
print('-' * TERMINAL_WIDTH)
base_location = setup_base_location(config, args.output_location, config_name)

while True:
    config.reset()
    while True:
        perform_generation_cycle(base_location, config, args.export_yang_files, args.export_iptables_files, args.export_graph_images)
        if not config.iterate():
            break
    if not config.seed_config.iterate():
        break