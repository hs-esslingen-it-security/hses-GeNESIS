from hses_genesis.utils.enum_objects import EParameterKey, EParameterType

TOPOLOGY_KEY = 'topology'
COMMUNICATION_KEY = 'communication'
SECURITY_KEY = 'security'

ITERATIONS_KEY = 'iterations'

LAYER_DEFINITIONS_KEY = 'layer_definitions'

SWITCH_COUNT_KEY = 'switch_count'
MAX_HOSTS_PER_SWITCH_KEY = 'max_hosts_per_switch'
STRUCTURE_KEY = "structure"
HOST_TYPES_KEY = "host_types"
REPETITIONS_KEY = 'repetitions'
SUBNET_DESCENDANTS_KEY = 'subnet_descendants'

TRAFFIC_PROFILE_KEY = "traffic_profile"
UPPER_CONNECTION_BOUND_KEY = "upper_connection_bound"

ANOMALY_COUNT_KEY = "anomaly_count"
STATEFUL_PERCENTAGE_KEY = "stateful_percentage"

SMALL_SEPARATOR = '·'

MEDIUM_SEPARATOR = ':'

BIG_SEPARATOR = '::'

UNSET_INDICATOR = '-'

ITERATION_SEPARATOR = '.'

TAG_ENCAPSULATOR = '#'

GENESIS_PACKAGE_NAME = 'hses_genesis'

RULE_CONTAINER_PATTERN = '^-A\s(?P<chain>[^\s]+)'

ACTION_PATTERN = '-j\s(?P<action>[^\s]+)'

TABLE_PATTERN = '^\*(?P<table>[^\s]+)$'

CHAIN_PATTERN = '^\:(?P<chain>[^\s]+)\s(?P<default_action>[^\s]+)'

RULE_VALUE_SEPARATOR = ','

WILDCARD = '*'

SUBNET_INDICATOR = '/'

GRAPH_FOLDER = 'graphs'

RULESET_FOLDER = 'rulesets'

OMNET_FOLDER = 'omnetpp'

NS3_FOLDER = 'ns3'

ZIMPL_FOLDER = 'zimpl'

PACKET_FOLDER = 'packets'

TERMINAL_WIDTH = 44

PROTOCOLS = {
    'ip' : 0,
    'tcp' : 6,
    'udp' : 17
}

def update_protocols(protocols : dict[str: int]):
    global PROTOCOLS
    PROTOCOLS = protocols

FULL_RANGES : dict[EParameterType, tuple[int, int]] = {
    EParameterType.IP: (1, 4294967295),
    EParameterType.NUMBER: (0, 65535),
    EParameterType.PROTOCOL: (0,255)
}

DEFAULT_TUPLE = [
    EParameterKey.SRC,
    EParameterKey.DST,
    EParameterKey.PROTOCOL,
    EParameterKey.SRC_PORT,
    EParameterKey.DST_PORT
]

PACKET_HEADERS = ['SourceName', 'DestinationName', 'SourceMac', 'DestinationMac', 'EtherType', 'PriorityCodePoint', 'DropEligibleIndicator', 'VlanIndicator', 'Protocol', 'SourceIp', 'DestinationIp', 'SourcePort', 'DestinationPort', 'PacketSize', 'PacketsPerSecond']