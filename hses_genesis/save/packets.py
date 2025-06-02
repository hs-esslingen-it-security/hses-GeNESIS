from csv import DictWriter
from os.path import join
from hses_genesis.utils.constants import OMNET_FOLDER, PACKET_FOLDER, PACKET_HEADERS, ZIMPL_FOLDER
from hses_genesis.utils.enum_objects import EParameterKey
from hses_genesis.utils.functions import load_resource

def to_csv(dst_location, packets):
    with open(join(dst_location, PACKET_FOLDER, 'packets.csv'), 'w') as file:
        writer = DictWriter(file, PACKET_HEADERS)
        writer.writeheader()
        [writer.writerow(packet) for packet_list in packets.values() for packet in packet_list]

def to_zimpl_parsable(location, packets):
    with open(join(location, ZIMPL_FOLDER, f'zimpl_packets.txt'), 'w') as file:
        for i, parameter_key in enumerate(list(EParameterKey.__members__.values())):
            file.write(f'# <x,{i}>{parameter_key.name.lower()}\n')
        for i, packet in enumerate([packet for packet_list in packets.values() for packet in packet_list]):
            for j, key in enumerate([f'{EParameterKey.SRC.name.lower()}_ip', f'{EParameterKey.DST.name.lower()}_ip', f'{EParameterKey.PROTOCOL.name.lower()}_code', EParameterKey.SRC_PORT.value, EParameterKey.DST_PORT.value]):
                file.write(f'{i},{j},{int(packet[key])}\n')

def to_omnet_ini(location, app_map):
    packet_map = {}
    for packets in app_map.values():
        for packet in packets:
            src, dst = packet['SourceName'], packet['DestinationName']
            if src not in packet_map.keys():
                packet_map[src] = []

            if dst not in packet_map.keys():
                packet_map[dst] = []

            if packet['Protocol'] == 'udp':
                packet_map[src].append((packet, 'UdpBasicApp'))
                if not any(packet['DestinationName'] == p['DestinationName'] and packet['DestinationPort'] == p['DestinationPort'] and a == 'UdpSink' for (p, a) in packet_map[dst]):
                    packet_map[dst].append((packet, 'UdpSink'))
            else:
                packet_map[src].append((packet, 'TcpClientApp'))
                if not any(packet['DestinationName'] == p['DestinationName'] and packet['DestinationPort'] == p['DestinationPort'] and a == 'TcpSinkApp' for (p, a) in packet_map[dst]):
                    packet_map[dst].append((packet, 'TcpSinkApp'))

    with open(load_resource('templates', 'omnetpp.ini'), 'r') as template, open(join(location, OMNET_FOLDER, f'omnetpp.ini'), 'w') as file:
        file.writelines(template.readlines())
        file.write('\n')

        for src, apps in packet_map.items():
            if len(apps) == 0:
                continue
            file.write(f'**.{src}.numApps = {len(apps)}\n')
            for i, (packet, app_type) in enumerate(apps):
                file.write(f'**.{src}.app[{i}].typename = "{app_type}"\n')
                mappings = []

                if 'udp' in app_type.lower():

                    if app_type == 'UdpBasicApp':
                        file.write(f'**.{src}.app[{i}].stopTime = 25s\n')
                        mappings.extend([
                            ('localPort', 'SourcePort', lambda _: -1),
                            ('sendInterval', 'PacketsPerSecond', lambda x: f'{round(1 / x, 3)}s'),
                            ('messageLength', 'PacketSize', lambda x: f'{x}B'),
                            ('destAddresses', 'DestinationName', lambda x: f'"{x}"'),
                            ('destPort', 'DestinationPort', lambda x: x),
                        ])
                    else:
                        mappings.append(
                            ('localPort', 'SourcePort', lambda x: x)
                        )
                else:
                    if app_type == 'TcpClientApp':
                        file.write(f'**.{src}.app[{i}].source.packetData = intuniform(0,1)\n')
                        mappings.extend([
                            ('io.localPort', 'SourcePort', lambda _: -1),
                            ('io.connectAddress', 'DestinationName', lambda x: f'"{x}"'),
                            ('io.connectPort', 'DestinationPort', lambda x: x),
                            ('source.productionInterval', 'PacketsPerSecond', lambda x: f'{round(1 / x, 3)}s'),
                            ('source.packetLength', 'PacketSize', lambda x: f'{x}B'),
                        ])
                    else:
                        mappings.append(('localPort', 'DestinationPort', lambda x: x))

                for param, packet_key, mapping_func in mappings:
                    file.write(f'**.{src}.app[{i}].{param} = {mapping_func(packet[packet_key])}\n')

                file.write('\n')