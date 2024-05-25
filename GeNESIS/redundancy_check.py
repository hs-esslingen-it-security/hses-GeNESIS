from argparse import ArgumentParser
from os.path import join, basename, dirname
from os import listdir
from re import match

RUN_DIR_PATTERN = '^\d+-\d+-\d+$'

parser = ArgumentParser()
parser.add_argument('-a', '--input_location_a')
parser.add_argument('-b', '--input_location_b')

args = parser.parse_args()

def check_by_line(a_location, b_location):
    with open(a_location) as a_file, open(b_location) as b_file:
        for i, (a_line, b_line) in enumerate(zip(a_file.readlines(), b_file.readlines()), start=1):
            if 'rulesets' in a_location and a_line.startswith('#') and b_line.startswith('#'):
                continue
            if a_line != b_line:
                raise Exception('\n\t'.join([s.replace('\n', '') for s in [f'Difference found in line {i}:', f'"{a_line}" vs "{b_line}" of files', f'"{a_location}" and', f'"{b_location}"']]))

def perform_run_check(a_location, b_location, run):
    check_by_line(join(a_location, run, 'packets.csv'), join(b_location, run, 'packets.csv'))

    check_by_line(join(a_location, run, 'graphs', 'graph.graphml'), join(b_location, run, 'graphs', 'graph.graphml'))
    check_by_line(join(a_location, run, 'graphs', 'ietf-topology.yang.json'), join(b_location, run, 'graphs', 'ietf-topology.yang.json'))

    for ruleset in listdir(join(a_location, run, 'rulesets')):
        check_by_line(join(a_location, run, 'rulesets', ruleset), join(b_location, run, 'rulesets', ruleset))

a, b = args.input_location_a, args.input_location_b

if not (a != None and b != None):
    raise Exception('missing locations')

base_a, base_b = basename(a), basename(b)
if match(RUN_DIR_PATTERN, base_a):
    if base_a == base_b:
        perform_run_check(dirname(a), dirname(b), base_a)
    else:
        raise Exception(f'mismatching run seeds detected ({base_a} vs {base_b})!')
else:
    with open(join(a, '.genesistag'), 'r') as a_code:
        with open(join(b, '.genesistag'), 'r') as b_code:
            if a_code.readline() != b_code.readline():
                raise Exception('genesis tag mismatch detected!')
            
    for run_dir in listdir(a):
        if match(RUN_DIR_PATTERN, run_dir):
            perform_run_check(a, b, run_dir)


print('All exported files match line by line. Redundancy provided.')