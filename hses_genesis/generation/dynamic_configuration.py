from enum import Enum
from json import dumps, load
from typing import Type

from hses_genesis.utils.constants import MAX_HOSTS_PER_SWITCH_KEY, TERMINAL_WIDTH, LAYER_DEFINITIONS_KEY, STRUCTURE_KEY, SECURITY_KEY, COMMUNICATION_KEY, TOPOLOGY_KEY, ITERATIONS_KEY, SUBNET_DESCENDANTS_KEY, SWITCH_COUNT_KEY, HOST_TYPES_KEY, ANOMALY_COUNT_KEY, STATEFUL_PERCENTAGE_KEY, TRAFFIC_PROFILE_KEY, UPPER_CONNECTION_BOUND_KEY
from hses_genesis.utils.enum_objects import EDeviceRole, ESubnetTopologyStructure
from hses_genesis.utils.functions import load_resource

class EResponse(Enum):
    ANSWER = 0
    HELP = 1
    INTERRUPT = 2
    INVALID = 3
    NONE = 4
    SKIP = 5
    BACK = 6

class ConfigurationGenerator():
    def __init__(self):
        self.config = {
            SECURITY_KEY : dict(),
            COMMUNICATION_KEY : dict(),
            TOPOLOGY_KEY : {
                LAYER_DEFINITIONS_KEY : []
            }
        }

        hint_location = load_resource('configurations', 'configuration_hints.json')
        with open(hint_location, 'r') as f:
            self.parameter_info = dict(load(f))

    def sloppy_answer(self, question : str, possible_values : list[str]):
        while True:
            answer = input(question)
            matches = [x for x in possible_values if x.lower().startswith(answer.lower())]
            if len(matches) != 1:
                print('Your input did not match any of the allowed options. Please try again.')
                continue
            
            return matches[0]

    def interpret_answer(self, answer, answer_type : Type, possible_values = None):
        if not answer:
            return EResponse.NONE, None
        
        if answer == 'h' or answer == 'help':
            return EResponse.HELP, None
        
        if answer == 'b':
            return EResponse.BACK, None
        
        if answer == 's':
            return EResponse.SKIP, None
        
        if answer == 'x' or answer == 'cancel' or answer == 'exit':
            return EResponse.INTERRUPT, None
        
        if (possible_values and answer not in possible_values):
            return EResponse.INVALID, f'Your response did not match any of the allowed options ({str(possible_values)}).'
        
        try:
            return EResponse.ANSWER, answer_type(answer)
        except:
            return EResponse.INVALID, f'Your response is not of type {answer_type}.'
        
    def parameter_question(self, parameter, answer_type : Type, default_value = None, possible_values = None, allow_back = False, allow_skip = False, help_key = None):
        if default_value == None:
            default_value = dict(self.parameter_info.get(parameter, dict())).get('default_value', None)

        if possible_values == None:
            possible_values = dict(self.parameter_info.get(parameter, dict())).get('valid_options', None)
        
        question = f'Please provide your {parameter} value'
        if possible_values != None:
            question += f' {possible_values}'
        if allow_skip:
            question += ', skip it (s)'
        if allow_back:
            question += ', go back (b)'
        question += f', ask for help (h) or exit (x)' + (f' (default value: {default_value}): ' if default_value != None else ': ')
        
        while True:
            answer = input(question)
            response_type, value = self.interpret_answer(answer, answer_type, possible_values)
            if response_type == EResponse.NONE:
                if default_value != None:
                    return EResponse.ANSWER, answer_type(default_value)
                else:
                    response_type = EResponse.INVALID

            if response_type == EResponse.BACK:
                if not allow_back:
                    response_type = EResponse.INVALID
                else:
                    return EResponse.BACK, None
                
            if response_type == EResponse.SKIP:
                if not allow_skip:
                    response_type = EResponse.INVALID
                else:
                    return EResponse.SKIP, answer_type(default_value)
            
            if response_type in [EResponse.ANSWER, EResponse.INTERRUPT]:
                return response_type, value
            
            if response_type == EResponse.HELP:
                help_parameter = parameter if help_key == None else help_key
                print(f'"{help_parameter}"', self.parameter_info.get(help_parameter, {'info' : f'Sorry, could not find infos for parameter "{parameter}".'})['info'])

            if response_type == EResponse.INVALID:
                print(value, 'Please try again.')
                continue

    def print_config_info(self, key : str = None, to_print : dict = None, no_header = False):
        if not no_header:
            print('-' * TERMINAL_WIDTH)
            if not key:
                print(f'Your current configuration:')
            else:
                print(f'Your current {key.lower()} configuration:')
            print('-' * TERMINAL_WIDTH)
        if to_print == None:
            to_print = self.config
        print(dumps(to_print, indent=4))
        print('-' * TERMINAL_WIDTH)

    def edit_config(self):
        while True:
            self.print_config_info()

            value = self.ask_user('What do you want to do? Configure (t) topology, (c) communication, (s) security, or (x) save your current configuration and start generation: ', possible_answers=['t', 'c', 's', 'x'])
            if value == 't':
                self.edit_topology()
            if value == 'c':
                self.edit_communication()
            if value == 's':
                self.edit_security()
            if  value == 'x':
                if len(self.config[TOPOLOGY_KEY][LAYER_DEFINITIONS_KEY]) == 0:
                    print('=' * TERMINAL_WIDTH)
                    print('WARNING: Your configuration is invalid! At least one layer definition is required! Please configure at least one layer definition:')
                    print('=' * TERMINAL_WIDTH)
                    self.edit_topology('a')
                else:
                    break
        return self.config

    def setup_segment(self, contained_keys : dict[str, dict], allow_pagination = True, help_key = None):
        segment = {
            key : value['default_value'] for key, value in contained_keys.items() if 'default_value' in value.keys() 
        }
        items = list(contained_keys.items())
        i = 0
        while i <= len(contained_keys) - 1:
            key, infos = items[i]
            allow_back = allow_pagination and i > 0
            while True:
                response_type, value = self.parameter_question(key, infos['typing'], default_value = segment.get(key, None), allow_skip=allow_pagination, allow_back=allow_back, help_key=help_key)
                if response_type == EResponse.SKIP and allow_pagination:
                    break

                if response_type == EResponse.BACK and allow_back:
                    i -= 2
                    break

                if response_type == EResponse.INTERRUPT:
                    return response_type, None

                if response_type == EResponse.ANSWER:
                    segment[key] = value
                    break
            i += 1
        return response_type, segment

    def edit_security(self):
        self.print_config_info(SECURITY_KEY, self.config[SECURITY_KEY])

        response, segment = self.setup_segment({
            x: {
                'typing' : int,
                'default_value' : None
            } for x in [ITERATIONS_KEY, ANOMALY_COUNT_KEY, STATEFUL_PERCENTAGE_KEY]
        })
        if response == EResponse.ANSWER:
            self.config[SECURITY_KEY] = segment        

    def edit_communication(self):
        self.print_config_info(COMMUNICATION_KEY, self.config[COMMUNICATION_KEY])

        response, segment = self.setup_segment({
            ITERATIONS_KEY: {
                'typing' : int,
                'default_value' : None
            },
            TRAFFIC_PROFILE_KEY: {
                'typing' : str,
                'default_value' : None
            },
            UPPER_CONNECTION_BOUND_KEY: {
                'typing' : int,
                'default_value' : None
            },
        })
        if response == EResponse.ANSWER:
            self.config[COMMUNICATION_KEY] = segment        

    def ask_user(self, question, possible_answers = None, answer_type : Type = str):
        while True:
            answer = input(question).lower()
            if possible_answers and answer not in possible_answers:
                print('You did not provide a valid option. Please try again.')
                continue
            
            try:
                return answer_type(answer)
            except:
                print(f'Your answer is not of type {answer_type}. Please try again.')        

    def get_host_types(self, switch_count : int, hosts_per_switch : int, default_values : dict = None):
        def fixed_host_count(values : dict[str, int]):
            return sum(v for v in values.values() if v > 0)

        def validity_check(values : dict[str, int]):
            max_host_count = switch_count * hosts_per_switch
            remaining_hosts = max_host_count - fixed_host_count(values)
            return remaining_hosts >= 0

        if default_values == None:
            default_values = {key.name : 0 for key in EDeviceRole.hosts()}

        self.print_config_info(HOST_TYPES_KEY, default_values)

        while True:
            
            value_info = {key.name : {
                'typing' : int,
                'default_value' : default_values.get(key.name, 0)
            } for key in EDeviceRole.hosts()}

            response, default_values = self.setup_segment(contained_keys=value_info, help_key=HOST_TYPES_KEY)
            if response == EResponse.INTERRUPT:
                break

            if validity_check(default_values):
                return response, default_values
            else:
                print('=' * TERMINAL_WIDTH)
                print(f'WARNING: Your host_types configuration is invalid! You defined too many fixed devices (hosts_per_switch ({hosts_per_switch}) * switch_count ({switch_count}) < {fixed_host_count(default_values)}). Please adjust your configuration.')
                print('=' * TERMINAL_WIDTH)
                self.print_config_info(HOST_TYPES_KEY, default_values, no_header=True)
        
    def get_structure_distribution(self, default_values = None):
        if default_values == None:
            default_values = {key.name : 0 for key in ESubnetTopologyStructure}
        
        self.print_config_info(STRUCTURE_KEY, default_values)

        default_values = {
            key.name : {
            'typing' : int,
            'default_value' : default_values.get(key.name, 0)
            } for key in ESubnetTopologyStructure
        }

        return self.setup_segment(default_values, help_key=STRUCTURE_KEY)

    def edit_layer_definition(self, layer_index = -1):
        if layer_index < 0:
            print(f'-- Adding a new layer --')
            input_definition = dict()
        else:
            print(f'-- Editing layer {layer_index} --')
            input_definition = self.config[TOPOLOGY_KEY][LAYER_DEFINITIONS_KEY][int(layer_index)]
        
        response_type, layer_definition = self.setup_segment({
            x: {
                'typing' : int,
                'default_value' : input_definition.get(x, None)
            } for x in [SUBNET_DESCENDANTS_KEY, SWITCH_COUNT_KEY, MAX_HOSTS_PER_SWITCH_KEY]
        })

        if response_type == EResponse.INTERRUPT:
            return
        
        response_type, host_types = self.get_host_types(layer_definition.get(SWITCH_COUNT_KEY), layer_definition.get(MAX_HOSTS_PER_SWITCH_KEY), input_definition.get(HOST_TYPES_KEY, None))
        
        if response_type == EResponse.INTERRUPT:
            return
        
        layer_definition[HOST_TYPES_KEY] = host_types

        response_type, structure = self.get_structure_distribution(input_definition.get(STRUCTURE_KEY, None))
        
        if response_type == EResponse.INTERRUPT:
            return
        
        layer_definition[STRUCTURE_KEY] = structure

        if layer_index < 0:
            self.config[TOPOLOGY_KEY][LAYER_DEFINITIONS_KEY].append(layer_definition)
        else:
            self.config[TOPOLOGY_KEY][LAYER_DEFINITIONS_KEY][layer_index] = layer_definition

        
    def edit_topology(self, intro_step = None):
        def handle_response(answer : str):
            if answer in ['', 'a']:
                self.edit_layer_definition()
            
            if answer == 'e':
                layer_index = 0
                if len(layer_definitions) > 1:
                    layer_index = self.ask_user(f'Which layer do you want to edit? Please provide its index [0..{len(layer_definitions) - 1}]: ', answer_type=int, possible_answers=map(lambda x: str(x), range(0, len(layer_definitions))))
                self.edit_layer_definition(layer_index)
            
            if answer == 'r':
                layer_index = self.ask_user(f'Which layer do you want to remove? Please provide its index [0..{len(layer_definitions) - 1}]: ', answer_type=int, possible_answers=map(lambda x: str(x), range(0, len(layer_definitions))))
                print(f'You aim to remove layer {layer_index}:')
                print('-' * TERMINAL_WIDTH)
                print(dumps(layer_definitions[layer_index]))
                print('-' * TERMINAL_WIDTH)
                answer = self.ask_user('Are you shure you want to remove this layer (y - yes/n - no)?', ['y', 'n'])
                if answer == 'y':
                    self.config[TOPOLOGY_KEY][LAYER_DEFINITIONS_KEY].pop(layer_index)

        if intro_step:
            handle_response(intro_step)

        while True:
            self.print_config_info(TOPOLOGY_KEY, self.config[TOPOLOGY_KEY])
            
            layer_definitions = self.config[TOPOLOGY_KEY][LAYER_DEFINITIONS_KEY]
            question = 'What do you want to do? (a - add layer,'
            possible_answers = ['', 'a', 'x']
            if len(layer_definitions) > 0:
                question += ' r - remove layer, e - edit layer,'
                possible_answers += ['r', 'e']
            question += ' x - exit (default value a): '
            answer = self.ask_user(question, possible_answers=possible_answers)

            if answer == 'x':
                return
            
            handle_response(answer)
