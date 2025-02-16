from csv import DictWriter
from os.path import join

from hses_genesis.utils.constants import PACKET_FOLDER, PACKET_HEADERS

def to_csv(dst_location, packets):
    with open(join(dst_location, PACKET_FOLDER, 'packets.csv'), 'w') as file:
        writer = DictWriter(file, PACKET_HEADERS)
        writer.writeheader()
        [writer.writerow(packet) for packet_list in packets.values() for packet in packet_list]