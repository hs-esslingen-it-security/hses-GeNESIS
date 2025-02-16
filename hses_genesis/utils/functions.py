from hses_genesis.utils.constants import TERMINAL_WIDTH


def print_information(title : str, key_values : dict):
    print('---' + f' {title} ' + '-' * (27 - len(title)))
    padding = max([len(key) for key in key_values.keys()]) + 2
    for key, value in key_values.items():
        print(str(key) + ':' + (padding - len(key)) * ' ' + str(value))
    print('-' * TERMINAL_WIDTH)