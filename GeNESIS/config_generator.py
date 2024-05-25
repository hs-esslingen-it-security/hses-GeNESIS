from json import dumps
from config_parser import CommunicationConfig, GenerationConfig, LayerDefinitionConfig, LayerDeviceCountConfig, RangedParameterValue, StepConfig, TruthParameterValue
from enum_objects import EDeviceRole, EGenerationSteps, ENetworkLayer, ESubnetTopologyType, ETrafficProfile
from random import randint

def print_current_setup(input):
    print('--------------------------------------------------')
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

def get_ranged_int_from_user(intro_text, default_value):
    while True:
        value = input(intro_text + f'; You can also provide ranges by passing the endpoints by a comma, e.g., "1,2" (default {default_value}): ')
        try:
            return RangedParameterValue.from_str(value if value else str(default_value), ',')
        except Exception as e:
            print(f'Invalid value {value} was passed. Please try again.')

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


def create_seeds():
    print('-- now defining generation steps --')
    steps = {}
    for step in EGenerationSteps:
        steps[step] = {}

    range_resolution_seed = randint(0,1000)
    define_seeds = ask_user('Do you want to use specific seeds', False)
    if define_seeds:
        range_resolution_seed = get_int_from_user('Please provide the range resolution seed', range_resolution_seed)
    
    for step in EGenerationSteps:
        steps[step]['seed'] = get_int_from_user(f'Please provide the seed for the {step.name.lower().replace("_", " ")} generation step', 1) if define_seeds else randint(0,1000)
    
    configure_iterations = ask_user('Do you want to run multiple iterations of a specific step', False)
    for step in EGenerationSteps:
        if configure_iterations:
            steps[step]['iterations'] = get_int_from_user(f'Please provide the number of iterations for the {step.name.lower().replace("_", " ")} generation step', 1)
        else:
            steps[step]['iterations'] = 1

    return range_resolution_seed, StepConfig(steps)

def create_communication():
    print('-- now defining communication configurations --')
    traffic_profile = get_enum_choice_from_user('Please provide the traffic profile you want to use', ETrafficProfile, ETrafficProfile.STRIC_ISOLATION)
    connection_count = get_ranged_int_from_user('Please provide the number of allowed communication relations in your network', 100)
    anomaly_count = get_ranged_int_from_user('Please provide the max number of anomalies created in each rulesets', 0)
    return CommunicationConfig(traffic_profile, connection_count, anomaly_count)

def create_layer_count_configuration():
    layer_device_count_configuration = {}
    for layer in ENetworkLayer:
        print(f'-- now defining device occurences in {layer.name.lower().replace("_", " ")} layer instances --')
        layer_config = {}
        layer_config[EDeviceRole.SERVER] = get_ranged_int_from_user(f'Please provide the number of {EDeviceRole.SERVER.name.lower()}s in {layer.name.lower().replace("_", " ")} layer instances', 0 if layer != ENetworkLayer.CONNECTIVITY else 2)
        layer_config[EDeviceRole.IT_END_DEVICE] = TruthParameterValue(ask_user(f"Do you want {EDeviceRole.IT_END_DEVICE.name.lower().replace('_', ' ')}s to occur in {layer.name.lower().replace('_', ' ')} layer instances", True if layer != ENetworkLayer.CONNECTIVITY else False))
        layer_config[EDeviceRole.OT_END_DEVICE] = TruthParameterValue(ask_user(f"Do you want {EDeviceRole.OT_END_DEVICE.name.lower().replace('_', ' ')}s to occur in {layer.name.lower().replace('_', ' ')} layer instances", True if layer != ENetworkLayer.CONNECTIVITY else False))
        layer_config[EDeviceRole.CONTROLLER] = get_ranged_int_from_user(f'Please provide the range of {EDeviceRole.CONTROLLER.name.lower()}s in {layer.name.lower().replace("_", " ")} layer instances as comma separated integers', 2)
        layer_device_count_configuration[layer] = layer_config
    return LayerDeviceCountConfig(layer_device_count_configuration)

def create_layer_definition(is_root_layer = False):
    layer_type = ENetworkLayer.CONNECTIVITY if is_root_layer else get_enum_choice_from_user('Please provide the layer type you want', [ENetworkLayer.AGGREGATED_CONTROL, ENetworkLayer.PROCESS], ENetworkLayer.AGGREGATED_CONTROL)
    per_upper_layer = RangedParameterValue(1) if is_root_layer else get_ranged_int_from_user('Please provide the number of layer instances per upper layer instance', 2)
    switch_count = get_ranged_int_from_user('Please provide the number of additional switches per layer instance', 1 if layer_type != ENetworkLayer.PROCESS else 3)
    devices_per_switch = get_ranged_int_from_user('Please provide the number of end devices connected to each switch', 2)

    distribution = {}
    if ask_user('Do you want all layer instances to be of the same structure', False):
        chosen_structure = get_enum_choice_from_user('Please provide the wanted structure', ESubnetTopologyType, ESubnetTopologyType.RING)
        for subnet_type in ESubnetTopologyType:
            distribution[subnet_type] = 0 if subnet_type != chosen_structure else 1
    else:
        for subnet_type in ESubnetTopologyType:
            distribution[subnet_type] = get_int_from_user(f'Please provide the distribution value for a {subnet_type.name.lower()} structure', 1)

    return LayerDefinitionConfig(layer_type, distribution, switch_count, devices_per_switch, per_upper_layer)

def create_layer_definitions():
    layer_definitions : list[LayerDefinitionConfig] = []
    while len(layer_definitions) == 0 or layer_definitions[-1].LAYER_CLASS != ENetworkLayer.PROCESS:
        if len(layer_definitions) > 1:
            if not ask_user('Do you want to create another layer', True):
                if len(layer_definitions) < 3:
                    if ask_user("Creating less than three layers is not recommended. Are you shure you don't want to define another layer", False):
                        break
                else:
                    break
        
        print(f'-- now defining the {len(layer_definitions) + 1}. layer --')
        layer_definition = create_layer_definition(len(layer_definitions) == 0)
        if not layer_definition:
            break
        layer_definitions.append(layer_definition)
    return layer_definitions

def create_configuration_from_menu():
    range_resolution_seed, step_config = create_seeds()
    communication = create_communication()
    layer_device_count_configuration = create_layer_count_configuration()
    layer_definitions = create_layer_definitions()

    config = GenerationConfig(range_resolution_seed, step_config, communication, layer_device_count_configuration, layer_definitions)
    print_current_setup(config.to_dict())
    return config

def get_config_from_mask():
    print('Welcome to the Interactive GeNESIS Configuration Generator')
    if ask_user('Do you want to create a new Configuration File', True):
        return create_configuration_from_menu()
    
    if ask_user('Do you want to run GeNESIS with an existing Configuration File', True):
        with open(input('Please provide the link to the Configuration File: '), 'r') as f:
            return GenerationConfig.from_file(f)
    
    if ask_user('Do you want to run GeNESIS with a GeNESIS-TAG of a previous run', True):
        return GenerationConfig.from_str(input('Please provide the GeNESIS-TAG: '))
    
    print('GeNESIS will be started with a random configuration.')
    return GenerationConfig.random()