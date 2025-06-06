from datetime import datetime
from hses_genesis.parsing.configuration import GenerationConfig
from os.path import join, exists
from os import makedirs

from hses_genesis.utils.constants import GRAPH_FOLDER, NS3_FOLDER, OMNET_FOLDER, PACKET_FOLDER, RULESET_FOLDER, ZIMPL_FOLDER

def setup_base_location(config : GenerationConfig, output_location, config_name = 'config'):
    testrun_id = datetime.now().strftime('%y-%m-%d-%H-%M-%S')
    location = join(output_location, config_name, testrun_id)
    makedirs(location, exist_ok = True)

    config.to_file(join(location, 'config.json'))

    with open(join(location, '.genesistag'), 'x') as file:
        file.write(config.to_tag(short_tag=True) + '\n')
        file.write(config.to_tag())

    return location

def setup_run_location(config : GenerationConfig, base_location : str, run_label, export_iptables_files = False, export_omnet_files = False, export_ns3_files = False, export_zimpl_parsables = False):
    i = 0
    while True:
        run_location = join(base_location, f'{run_label}-{i}')
        if not exists(run_location):
            break
        i += 1
    makedirs(run_location, exist_ok=True)

    config.to_file(join(run_location, 'config.json'), run_specific=True)
    with open(join(run_location, '.genesistag'), 'x') as file:
        file.write(config.to_tag(run_specific=True, short_tag=True) + '\n')
        file.write(config.to_tag(run_specific=True))

    for subfolder in [GRAPH_FOLDER, PACKET_FOLDER] + ([RULESET_FOLDER] if export_iptables_files else []):
        sublocation = join(run_location, subfolder)
        makedirs(sublocation, exist_ok=True)

    if export_omnet_files:
        makedirs(join(run_location, OMNET_FOLDER), exist_ok=True)

    if export_ns3_files:
        makedirs(join(run_location, NS3_FOLDER), exist_ok=True)

    if export_zimpl_parsables:
        makedirs(join(run_location, ZIMPL_FOLDER), exist_ok=True)

    return run_location