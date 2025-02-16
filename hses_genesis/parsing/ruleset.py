from ipaddress import ip_address, ip_network
from itertools import product
from re import match, search
from hses_genesis.utils.constants import ACTION_PATTERN, CHAIN_PATTERN, FULL_RANGES, PROTOCOLS, RULE_CONTAINER_PATTERN, SUBNET_INDICATOR, TABLE_PATTERN, RULE_VALUE_SEPARATOR, WILDCARD, MEDIUM_SEPARATOR
from hses_genesis.utils.enum_objects import EParameterKey, EParameterType, EPacketDecision

def __unify_value(value : str, parameter_key : EParameterKey):
    parameter_type = EParameterType.from_parameter_key(parameter_key)
    
    if value == WILDCARD:
        return FULL_RANGES[parameter_type]
    
    if parameter_type == EParameterType.IP:
        return int(ip_address(value))
    
    if parameter_key == EParameterKey.PROTOCOL:
        for acronym, protocol_number in PROTOCOLS.items():
            if value == protocol_number or str(value).lower() == acronym:
                return PROTOCOLS[value.lower()]
    return int(value)

def __get_unified_ranges(value : str, parameter_key : EParameterKey):
    if RULE_VALUE_SEPARATOR in value:
        return [(__unify_value(v, parameter_key), __unify_value(v, parameter_key)) for v in value.split(RULE_VALUE_SEPARATOR)]
    elif MEDIUM_SEPARATOR in value:
        start, end = value.split(MEDIUM_SEPARATOR)
        return [(__unify_value(start, parameter_key), __unify_value(end, parameter_key))]
    elif SUBNET_INDICATOR in value:
        network_address = ip_network(value, strict=False)
        start, end = network_address[0], network_address[-1]
        return [(__unify_value(start, parameter_key), __unify_value(end, parameter_key))]
    
    start = __unify_value(value, parameter_key)
    if isinstance(start, tuple):
        return [start]
    return [(start, start)]

def negate_value_ranges(value_ranges : list[tuple[int, int]], parameter_type : EParameterType):
    start, end = FULL_RANGES[parameter_type]
    ranges = [(start, start)] + value_ranges + [(end, end)]
    negated = []
    for i in range(len(ranges) - 1):
        (_, front_end), (r_s, _) = ranges[i], ranges[i+1]
        new_range = (front_end + (1 if i > 0 else 0), r_s - (1 if i < len(ranges) - 2 else 0))
        if new_range not in negated:
            negated.append(new_range)
    return negated

def parse_parameters(value : str):
    parameter_values = []
    for parameter_key in EParameterKey:
        parameter_match = search(f'(?P<negated>!\s)?-{parameter_key.value}\s(?P<value>[^\s]+)', value)
        if parameter_match:
            groups = parameter_match.groupdict()
            parameter_value : str = groups['value']
            ranges = __get_unified_ranges(parameter_value, parameter_key)
            if 'negated' in groups.keys() and groups['negated'] != None:
                ranges = negate_value_ranges(ranges, EParameterType.from_parameter_key(parameter_key))
            parameter_values.append(ranges)
        else:
            parameter_type = EParameterType.from_parameter_key(parameter_key)
            parameter_values.append([FULL_RANGES[parameter_type]])
    return parameter_values


def parse_rule(value : str, from_node = False):
    rule_pattern = (RULE_CONTAINER_PATTERN + '.+' + ACTION_PATTERN) if not from_node else ('^.+' + ACTION_PATTERN)
    general_match = match(rule_pattern, value)
    if not general_match:
        return None

    chain = general_match.group('chain') if 'chain' in general_match.groupdict().keys() else 'INPUT'
    action = EPacketDecision.from_str(general_match.group('action'))
    
    rules = [(chain, parameters, action) for parameters in product(*parse_parameters(value))]
    return rules

def parse_tables(lines : list[str], from_node = False, debug = False):
    tables = []
    if from_node:
        tables.append((
            'filter',
            [('INPUT', 'DROP'), ('FORWARD', 'DROP'), ('OUTPUT', 'DROP')],
            []
        ))
    for line in lines:
        line_value = line.strip()
        hit = match(TABLE_PATTERN, line_value)
        if hit:
            tables.append((hit.group('table'), [], []))
            continue

        hit = match(CHAIN_PATTERN, line_value)
        if hit:
            tables[-1][1].append((hit.group('chain'), EPacketDecision.from_str(hit.group('default_action'))))
            continue
        
        rule = parse_rule(line_value, from_node)
        if rule:
            tables[-1][2].extend(rule)
            continue
        
        if debug:
            print(f'Skipped parsing of line: {line_value}')
    return tables