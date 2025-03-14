from datetime import datetime
from itertools import product
from os.path import join
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

def to_zimpl_parsable(location, rulesets):
    with open(join(location, 'ruleset.txt'), 'w') as file:
        header_fields = [f'{prefix}_{suffix}' for prefix, suffix in product(['src', 'dst', 'prot', 'src_port', 'dst_port', 'state'], ['start', 'end'])] + ['action']
        for i, header in enumerate(header_fields):
            file.write(f'# <router,x,{i}>{header}\n')

        for router, ruleset in rulesets:
            for i, rule in enumerate(ruleset):
                for j, v in enumerate(rule):
                    file.write(f'{router},{i},{j},{v}\n')