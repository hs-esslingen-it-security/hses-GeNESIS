from math import floor
from hses_genesis.utils.constants import TERMINAL_WIDTH


def print_information(title : str, key_values : dict):
    prefix_len = int(floor(TERMINAL_WIDTH - len(title) - 2) / 2)
    print('-' * prefix_len, title, '-' * (TERMINAL_WIDTH - (prefix_len + len(title) + 2)))
    padding = max([len(key) for key in key_values.keys()]) + 2
    for key, value in key_values.items():
        print(str(key) + ':' + (padding - len(key)) * ' ' + str(value))
    print('-' * TERMINAL_WIDTH)