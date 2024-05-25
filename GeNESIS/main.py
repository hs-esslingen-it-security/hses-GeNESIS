from copy import deepcopy
from config_generator import get_config_from_mask
from communication_generation import CommunicationGenerator
from config_parser import GenerationConfig
from enum_objects import EDeviceRole, EGenerationSteps
from network_configuration_generation import NetworkConfigurationGenerator
from topology_generator import TopologyGenerator
from argparse import ArgumentParser
from datetime import datetime
from os import mkdir
from os.path import abspath, dirname, join, exists
from json import dumps
from csv import DictWriter
from random import Random, randint

def setup_base_location(config):
    location = args.output_location
    if not exists(location):
        mkdir(location)
    testrun_id = datetime.now().strftime('%y-%m-%d-%H-%M-%S')
    location = join(location, str(testrun_id))
    if not exists(location):
        mkdir(location)

    with open(join(location, 'config.json'), 'x') as file:
        file.write(dumps(config.to_dict(), indent=4))

    with open(join(location, '.genesistag'), 'x') as file:
        file.write(str(config))

    return location

def setup_run_location(base_location : str, run_label):
    run_location = base_location
    if not exists(run_location):
        mkdir(run_location)

    run_location = join(run_location, run_label)
    if not exists(run_location):
        mkdir(run_location)

    ruleset_location = join(run_location, 'rulesets')
    if not exists(ruleset_location):
        mkdir(ruleset_location)

    graph_location = join(run_location, 'graphs')
    if not exists(graph_location):
        mkdir(graph_location)

    return run_location, ruleset_location, graph_location

def user_choice(prompt, choices, default = None):
    while True:
        value = input(prompt + ' (' + ', '.join(choices + ([f'default {default}'] if default else [])) + '): ')
        if not value and default:
            return default
        if value in choices:
            return value
        
        print('No valid option chosen. Please try again.')

parser = ArgumentParser()
parser.add_argument('-j', '--json', help='location of json configuration file.', default=None)
parser.add_argument('-g', '--genesis_tag', help='GeNESIS-TAG of a previous run.', default=None)
parser.add_argument('-d', '--default_run', help='start GeNESIS with the default configuration (./rssources/example_config.json).', default=False, action='store_true')
parser.add_argument('-n', '--new_configuration', help='start the Interactive GeNESIS Configuration Generator to create a new configuration.', default=False, action='store_true')
parser.add_argument('-o', '--output_location', help='set the output location for generated files.', default=join(dirname(abspath(__file__)), 'output'))

args = parser.parse_args()

configuration_choices = [t for (t, v) in [('g', args.genesis_tag), ('j', args.json), ('n', args.new_configuration), ('d', args.default_run)] if v]
if len (configuration_choices) > 1:
    choice = user_choice('Multiple configuration origins were provided. Please choose the one you want to use', configuration_choices)
elif len(configuration_choices) == 1:
    choice = configuration_choices[0]
else:
    choice = 'r'

config : dict = {}

if choice == 'n':
    config = get_config_from_mask()
elif choice == 'j':
    with open(args.json, 'r') as f:
        config : GenerationConfig = GenerationConfig.from_file(Random(randint(0,1000)), f)
elif choice == 'g':
    config : GenerationConfig = GenerationConfig.from_str(args.genesis_tag)
elif choice == 'd':
    with open(join(dirname(__file__), 'resources/example_config.json'), 'r') as f:
        config : GenerationConfig = GenerationConfig.from_file(Random(randint(0,1000)), f)
else:
    config : GenerationConfig = GenerationConfig.random(Random(randint(0,1000)))

print('--------------------------------')
print(f'GeNESIS started with GeNESIS-TAG: {str(config)}')
print('--------------------------------')
base_location = setup_base_location(config)

t_iterations = config.STEP_CONFIG.STEPS[EGenerationSteps.TOPOLOGY]['iterations']
c_iterations = config.STEP_CONFIG.STEPS[EGenerationSteps.COMMUNICATION_RELATIONS]['iterations']
n_iterations = config.STEP_CONFIG.STEPS[EGenerationSteps.NETWORK_CONFIGURATIONS]['iterations']
total_iterations = t_iterations * c_iterations * n_iterations

for t_i in range(t_iterations):
    if t_i > 0:
        config.STEP_CONFIG.iterate(EGenerationSteps.TOPOLOGY)

    for c_i in range(c_iterations):
        if c_i > 0:
            config.STEP_CONFIG.iterate(EGenerationSteps.COMMUNICATION_RELATIONS)

        for n_i in range(n_iterations):
            if n_i > 0:
                config.STEP_CONFIG.iterate(EGenerationSteps.NETWORK_CONFIGURATIONS)
            
            run_location, ruleset_location, graph_location = setup_run_location(base_location, '-'.join([str(config.STEP_CONFIG.STEPS[s]['seed']) for s in EGenerationSteps]))
            
            run_index = t_i + c_i + n_i + 1
            print(f'Start Generation Step "{EGenerationSteps.TOPOLOGY.name}" ({run_index}/{total_iterations})')
            topology_generator = TopologyGenerator(config.STEP_CONFIG.STEPS[EGenerationSteps.TOPOLOGY]['seed'], config.RANGE_RESOLUTION_SEED)
            G = topology_generator.generate_network(config.LAYER_TYPE_CONFIG, config.LAYER_DEFINITIONS)
            topology_generator.print_graph_info(G)
            
            print(f'Start Generation Step "{EGenerationSteps.COMMUNICATION_RELATIONS.name}" ({run_index}/{total_iterations})')
            communication_generator = CommunicationGenerator(config.STEP_CONFIG.STEPS[EGenerationSteps.COMMUNICATION_RELATIONS]['seed'])
            allowed_connections = communication_generator.get_connections(G, config.COMMUNICATION.TRAFFIC_PROFILE, config.COMMUNICATION.CONNECTION_COUNT.resolve(config.RANGE_RESOLUTION_SEED))
            ruleset_connections = []
            generated_packets = {}
            
            with open(join(run_location, 'packets.csv'), 'w') as file:
                writer = DictWriter(file, ['src', 'dst', 'p', 'sport', 'dport', 'packet_size', 'packets_per_second'])
                writer.writeheader()
                for src, dst in allowed_connections:
                    services = [s for s in G.nodes[src]['services'] if s in G.nodes[dst]['services']]
                    service = communication_generator.random.choice(services)
                    protocols, ports, packet_size, packets_per_second = service.value
                    protocol = communication_generator.random.choice(protocols) if len(protocols) > 0 else '*'
                    port = communication_generator.random.choice(ports) if len(ports) > 0 else '*'
                    ruleset_connections.append((src, dst, protocol, port, port))
                    src_role, dst_role = EDeviceRole.from_device_id(src), EDeviceRole.from_device_id(dst)
                    high_sender_roles = [EDeviceRole.IT_END_DEVICE, EDeviceRole.OT_END_DEVICE]
                    src_communication_modifier, dst_communication_modifier = 2 if src_role in high_sender_roles else 1, 2 if dst_role in high_sender_roles else 1

                    if src not in generated_packets:
                        generated_packets[src] = []
                    generated_packets[src].append({
                        'src' : src,
                        'dst' : dst,
                        'p' : protocol,
                        'sport' : port,
                        'dport' : port, 
                        'packet_size' : communication_generator.random.randint(packet_size[0], packet_size[1]),
                        'packets_per_second' : communication_generator.random.randint(packets_per_second[0], packets_per_second[1]) * src_communication_modifier
                    })
                    writer.writerow(generated_packets[src][-1])

                    if dst not in generated_packets:
                        generated_packets[dst] = []
                    generated_packets[dst].append({
                        'src' : dst,
                        'dst' : src,
                        'p' : protocol,
                        'sport' : port,
                        'dport' : port, 
                        'packet_size' : communication_generator.random.randint(packet_size[0], packet_size[1]),
                        'packets_per_second' : communication_generator.random.randint(packets_per_second[0], packets_per_second[1]) * dst_communication_modifier
                    })
                    writer.writerow(generated_packets[dst][-1])

            print(f'Start Generation Step "{EGenerationSteps.NETWORK_CONFIGURATIONS.name}" ({run_index}/{total_iterations})')
            network_configuration_generator = NetworkConfigurationGenerator(config.STEP_CONFIG.STEPS[EGenerationSteps.NETWORK_CONFIGURATIONS]['seed'])
            for r_i, router in enumerate([r for r in G.nodes if EDeviceRole.from_device_id(r) == EDeviceRole.ROUTER]):
                router_connections = communication_generator.get_affected_connections(G, router, ruleset_connections)
                if len(router_connections) == 0:
                    G.nodes[router]['ruleset'] = []
                    continue

                G.nodes[router]['ruleset'] = network_configuration_generator.generate_ruleset(router_connections, config.COMMUNICATION.ANOMALY_COUNT.resolve(config.RANGE_RESOLUTION_SEED))

                with open(join(ruleset_location, f'{router.lower()}-iptables-save'), 'w') as file:
                    file.write(f'# Generated by GeNESIS v1.0 on {datetime.now().strftime("%a %b %d %H:%M:%S %Y")}\n')
                    file.write('*filter\n')
                    [file.write(f':{chain} DROP [0:0]\n') for chain in ['INPUT', 'FORWARD', 'OUTPUT']]
                    for rule in G.nodes[router]['ruleset']:
                        file.write(f'-A INPUT {rule}\n')
                    file.write('COMMIT\n')
                    file.write(f'# Completed on {datetime.now().strftime("%a %b %d %H:%M:%S %Y")}')
                    
            print('--- GENERAL INFORMATION --------')
            print(f"seeds used for this iteration:")
            for step in EGenerationSteps:
                print(f'\t{step.name.lower().replace("_", " ")}: {config.STEP_CONFIG.STEPS[step]["seed"]}')
            print(f'output data location for this iteration: {run_location}')
            print(f'genesis tag for this iteration: {str(config.current_iteration_tag())}')
            print('--------------------------------')

            topology_generator.save_graph(G, graph_location, generated_packets)