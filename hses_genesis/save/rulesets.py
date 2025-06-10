from collections import defaultdict
from datetime import datetime
from itertools import product
from os.path import join
from hses_genesis.utils.constants import RULESET_FOLDER, ZIMPL_FOLDER
from hses_genesis.utils.enum_objects import EPacketDecision

def to_save_file(location, node, ruleset, default_action = EPacketDecision.DROP):
    with open(join(location, f'{node.lower()}-iptables-save'), 'w') as file:
        file.write(f'# Generated on {datetime.now().strftime("%a %b %d %H:%M:%S %Y")}\n')
        file.write('*filter\n')
        [file.write(f':{chain} {default_action.name} [0:0]\n') for chain in ['INPUT', 'FORWARD', 'OUTPUT']]
        for rule in ruleset:
            file.write(f'-A INPUT {rule}\n')
        file.write('COMMIT\n')
        file.write(f'# Completed on {datetime.now().strftime("%a %b %d %H:%M:%S %Y")}')

def to_save_files(location, router_ruleset_map : dict[str, list], default_action = EPacketDecision.DROP):
    rulesets_location = join(location, RULESET_FOLDER)
    for router, ruleset in router_ruleset_map.items():
        with open(join(rulesets_location, f'{router.lower()}-iptables-save'), 'w') as file:
            file.write(f'# Generated on {datetime.now().strftime("%a %b %d %H:%M:%S %Y")}\n')
            file.write('*filter\n')
            [file.write(f':{chain} {default_action.name} [0:0]\n') for chain in ['INPUT', 'FORWARD', 'OUTPUT']]
            for rule in ruleset:
                if 'str' in rule.keys():
                    rule_str = rule['str']
                    file.write(f'-A INPUT {rule_str}\n')
            file.write('COMMIT\n')
            file.write(f'# Completed on {datetime.now().strftime("%a %b %d %H:%M:%S %Y")}')


def to_zimpl_parsable(location : str, router_ruleset_map : dict[str, list]):
    zimpl_location = join(location, ZIMPL_FOLDER)
    with open(join(zimpl_location, 'ruleset.txt'), 'w') as file:
        header_fields = [f'{prefix}_{suffix}' for prefix, suffix in product(['src', 'dst', 'prot', 'src_port', 'dst_port', 'state'], ['start', 'end'])] + ['action']
        for i, header in enumerate(header_fields):
            file.write(f'# <routers,x,{i}>{header}\n')

        duplication_map = defaultdict(set)
        for router, ruleset in router_ruleset_map.items():
            for rule in ruleset:
                if 'int' in rule.keys():
                    duplication_map[tuple(rule['int'])].add(router)
        
        for i, (rule, routers) in enumerate(duplication_map.items()):
            for j, v in enumerate(rule):
                file.write(','.join(list(map(lambda x : str(x), [('{' + '-'.join(sorted(routers)) + '}'), i, j, v]))) + '\n')