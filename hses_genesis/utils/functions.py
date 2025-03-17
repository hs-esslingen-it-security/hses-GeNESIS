from math import floor
from hses_genesis.utils.constants import TERMINAL_WIDTH
from os.path import join, dirname, exists


def print_information(title : str, key_values : dict):
    prefix_len = int(floor(TERMINAL_WIDTH - len(title) - 2) / 2)
    print('-' * prefix_len, title, '-' * (TERMINAL_WIDTH - (prefix_len + len(title) + 2)))
    padding = max([len(key) for key in key_values.keys()]) + 2
    for key, value in key_values.items():
        print(str(key) + ':' + (padding - len(key)) * ' ' + str(value))
    print('-' * TERMINAL_WIDTH)

def load_resource(folder, file):
    file_location = join(dirname(dirname(__file__)), 'resources', folder, file)
    if exists(file_location):
        return file_location
    else:
        raise Exception(f'Resource does not exist: {file_location}')