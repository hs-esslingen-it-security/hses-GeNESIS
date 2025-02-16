from json import dumps
from hses_genesis.parsing.configuration import GenerationConfig, CommunicationGenerationConfig, LayerDefinition, SecurityGenerationConfig, SeedConfig, TopologyGenerationConfig
from hses_genesis.utils.constants import TERMINAL_WIDTH
from hses_genesis.utils.enum_objects import EDeviceRole, ESubnetTopologyStructure, ETrafficProfile
from os.path import dirname, join

def print_current_setup(input):
    print('-' * TERMINAL_WIDTH)
    print(dumps(input, indent=4))
    print('--------------------------------------------------')

def ask_user(question, default_action = False):
    accept, deny = 'y', 'n'
    default = accept if default_action else deny
    while True:
        response = input(f'{question} ({"/".join([accept, deny])}; default: {default})? ')
        if not response:
            return default_action
        
        if response not in [accept, deny]:
            print(f'Invalid answer was passed. Please try again.')
        
        return response == accept

def get_int_from_user(intro_text, default_value):
    while True:
        value = input(intro_text + f' (default {default_value}): ')
        if not value:
            return default_value
        elif value.isdigit():
            return int(value)
        
        print(f'Non-digit value "{value}" was passed. Please try again.')

def get_enum_choice_from_user(intro_text, enum_values, default_value):
    default = default_value.name[0].lower()
    possible_values = [e.name[0].lower() for e in enum_values]
    while True:
        description = ', '.join([f'{e.name[0].lower()} - {e.name.lower().replace("_", " ")}' for e in enum_values])

        value = input(intro_text + f' ({description}; default {default}): ')
        if not value:
            return default_value
        elif value in possible_values:
            for v in enum_values:
                if v.name.lower().startswith(value):
                    return v
                
        print('Invalid answer was passed. Please try again.')

def create_communication():
    print('-- You are now defining the configurations necessary for *COMMUNICATION* generation --')
    iterations = get_int_from_user('Please provide the number of communication generation iterations', 1)
    traffic_profile = get_enum_choice_from_user('Please provide the traffic profile you want to use', ETrafficProfile, ETrafficProfile.STRICT_ISOLATION)
    connection_count = get_int_from_user('Please provide the upper bound for the number of allowed communication connections in your network; A negative answer will result in no bounds', -1)
    return CommunicationGenerationConfig(iterations=iterations, traffic_profile=traffic_profile, connection_bound=connection_count)

def create_security():
    print('-- You are now defining the configurations necessary for *SECURITY* generation --')
    iterations = get_int_from_user('Please provide the number of security generation iterations', 1)
    ruleset_anomaly_count = get_int_from_user('Please provide the number of anomalies, i.e., intersections of rules, in each ruleset', 0)
    stateful_rule_percentage = get_int_from_user('Please provide the percentage of stateful rules in each ruleset [%]', 0)

    return SecurityGenerationConfig(iterations=iterations, ruleset_anomaly_count=ruleset_anomaly_count, stateful_rule_percentage=stateful_rule_percentage)

def create_topology():
    print('-- You are now defining the configurations necessary for *TOPOLOGY* generation --')
    iterations = get_int_from_user('Please provide the number of topology generation iterations', 1)
    layer_definitions = create_layer_definitions()
    return TopologyGenerationConfig(iterations=iterations, layer_definitions=layer_definitions)

def create_fixed_hosts():
    if ask_user('Do you want specific device types to occur in every layer instance', True):
        return {key : get_int_from_user(f'Please provide the number of {key.name.lower()}s in each layer instance', 2) for key in EDeviceRole.configurables()}
    
    return {key : 0 for key in EDeviceRole.configurables()}

def create_filling_host_distribution(hosts_per_switch = 0):
    if hosts_per_switch == 0:
        return []
    
    if ask_user(f'You set the max number of devices per switch to *{hosts_per_switch}*. Do you want to fill remaining connections with specific host types', True):
        return [key for key in [EDeviceRole.IT_END_DEVICE, EDeviceRole.OT_END_DEVICE] if ask_user(f'Do you want to add {key.name.lower().replace("_", " ")}s to filling devices', True)]
    return []

def create_structure_distribution(per_upper_layer):
    if per_upper_layer <= 1 or ask_user('Do you want all layer instances to be of the same structure', True):
        chosen_structure = get_enum_choice_from_user('Please provide the wanted layer instance structure', ESubnetTopologyStructure, ESubnetTopologyStructure.RING)
        return {key : 1 if key == chosen_structure else 0 for key in ESubnetTopologyStructure}
    else:
        return {key : get_int_from_user(f'Please provide the distribution value for a {key.name.lower()} structure', 1) for key in ESubnetTopologyStructure}

def create_layer_definition(is_root_layer = False):
    if not is_root_layer:
        per_upper_layer = get_int_from_user('please provide the number of layer instances per upper layer instance', 2)
    else:
        per_upper_layer = 1
    switch_count = get_int_from_user('Please provide the number of fixed switches per layer instance', 0)
    hosts_per_switch = get_int_from_user('Please provide the number of hosts connected to each switch', 2)
    host_types = create_filling_host_distribution(hosts_per_switch)
    fixed_hosts = create_fixed_hosts()

    structure_distribution = create_structure_distribution(per_upper_layer)

    return LayerDefinition(
        per_upper_layer=per_upper_layer,
        switch_count=switch_count,
        fixed_hosts=fixed_hosts,
        max_hosts_per_switch=hosts_per_switch,
        host_types=host_types,
        structure_distribution=structure_distribution
    )

def create_layer_definitions():
    layer_definitions : list[LayerDefinition] = []
    while True:
        if len(layer_definitions) >= 2:
            print('-' * TERMINAL_WIDTH)
            if not ask_user('Do you want to create another layer', True):
                return layer_definitions
                
        print(f'-- You are now defining the *{len(layer_definitions) + 1}. LAYER* --')
        layer_definition = create_layer_definition(len(layer_definitions) == 0)
        if not layer_definition:
            break
        layer_definitions.append(layer_definition)

    return layer_definitions

def create_configuration_from_menu():
    seed_config = SeedConfig.random()
    communication_config = create_communication()
    security_config = create_security()
    topology_config = create_topology()
    config = GenerationConfig(seed_config=seed_config,
                              topology_config=topology_config,
                              communication_config=communication_config,
                              security_config=security_config)
    return config

def get_config_from_mask(default_config : str):
    print('Welcome to the Interactive GeNESIS Configuration Generator')
    if ask_user('Do you want to create a new Configuration File', True):
        return create_configuration_from_menu()
    
    if ask_user('Do you want to run GeNESIS with an existing Configuration File', True):
        with open(input('Please provide the link to the Configuration File: '), 'r') as f:
            return GenerationConfig.from_file(SeedConfig.random(), f)
    
    if ask_user('Do you want to run GeNESIS with a GeNESIS-TAG of a previous run', True):
        return GenerationConfig.from_str(input('Please provide the GeNESIS-TAG: '))
    
    print('GeNESIS will be started with a random configuration.')
    return GenerationConfig.from_file(SeedConfig.random(), default_config)