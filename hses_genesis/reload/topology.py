from networkx import Graph, read_graphml
from hses_genesis.parsing.ruleset import parse_tables
from hses_genesis.utils.enum_objects import EPacketDecision, EService, EDeviceRole

def from_file(file_dir, debug = False):
    G : Graph = read_graphml(file_dir)
    for n in G.nodes():
        node_info = G.nodes[n]
        if 'role' in node_info.keys():
            G.nodes[n]['role'] = EDeviceRole.from_name(G.nodes[n]['role'])
        if 'ruleset' in node_info.keys():
            tables = parse_tables(node_info['ruleset'].split('\n'), True, debug)
            G.nodes[n]['ruleset'] = [(chain, conditions, action) for (_, _, ruleset) in tables for (chain, conditions, action) in ruleset]
        if 'services' in node_info.keys():
            G.nodes[n]['services'] = list(map(lambda x: EService.from_str(x), node_info['services'].split(','))) if ',' in G.nodes[n]['services'] else []
        if 'default_action' in node_info.keys():
            G.nodes[n]['default_action'] = EPacketDecision.from_str(node_info['default_action'])
        
        G.nodes[n]['ip'] = node_info['ip'].split(',')
        G.nodes[n]['subnet'] = node_info['subnet'].split(',')
    return G