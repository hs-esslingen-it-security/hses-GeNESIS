from csv import DictReader
from hses_genesis.utils.constants import PACKET_HEADERS


def from_csv(file_path):
    with open(file_path, 'r') as file:
        return list(DictReader(file, PACKET_HEADERS))[1:]