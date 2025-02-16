from datetime import datetime
from hses_genesis.parsing.configuration import GenerationConfig
from os.path import join, exists
from os import makedirs

from hses_genesis.utils.constants import GRAPH_FOLDER, PACKET_FOLDER, RULESET_FOLDER

def setup_base_location(config : GenerationConfig, output_location, config_name = 'config'):
    testrun_id = datetime.now().strftime('%y-%m-%d-%H-%M-%S')
    location = join(output_location, config_name, testrun_id)
    makedirs(location, exist_ok = True)

    config.to_total_file(join(location, 'config.json'))

    with open(join(location, '.genesistag'), 'x') as file:
        file.write(config.to_total_str())

    return location

def setup_run_location(config : GenerationConfig, base_location : str, run_label, save_iptables_files = False):
    i = 0
    while True:
        run_location = join(base_location, f'{run_label}-{i}')
        if not exists(run_location):
            break
        i += 1
    makedirs(run_location, exist_ok=True)

    config.to_run_file(join(run_location, 'config.json'))
    with open(join(run_location, '.genesistag'), 'x') as file:
        file.write(config.to_run_str())

    for subfolder in [GRAPH_FOLDER, PACKET_FOLDER] + ([RULESET_FOLDER] if save_iptables_files else []):
        sublocation = join(run_location, subfolder)
        makedirs(sublocation, exist_ok=True)

    return run_location