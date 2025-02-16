from hses_genesis.parsing.ruleset import parse_tables

def from_file(file_dir, debug = False):
    with open(file_dir, 'r') as file:
        return parse_tables(list(map(lambda x: x.strip(), file.readlines())), False, debug)