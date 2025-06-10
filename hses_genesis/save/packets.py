from csv import DictWriter
from os.path import join
from hses_genesis.utils.constants import OMNET_FOLDER, PACKET_FOLDER, PACKET_HEADERS, ZIMPL_FOLDER
from hses_genesis.utils.enum_objects import EParameterKey, EResilienceProtocol
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

def to_omnet_ini(location, streams, stream_paths, protocol : EResilienceProtocol):
    packet_map = {}
    for stream in streams:
        src, dst = stream['SourceName'], stream['DestinationName']
        if src not in packet_map.keys():
            packet_map[src] = []

        if dst not in packet_map.keys():
            packet_map[dst] = []

        if stream['Protocol'] == 'udp':
            packet_map[src].append((stream, 'UdpBasicApp'))
            if not any(stream['DestinationName'] == p['DestinationName'] and stream['DestinationPort'] == p['DestinationPort'] and a == 'UdpSink' for (p, a) in packet_map[dst]):
                packet_map[dst].append((stream, 'UdpSink'))
        else:
            packet_map[src].append((stream, 'TcpClientApp'))
            if not any(stream['DestinationName'] == p['DestinationName'] and stream['DestinationPort'] == p['DestinationPort'] and a == 'TcpSinkApp' for (p, a) in packet_map[dst]):
                packet_map[dst].append((stream, 'TcpSinkApp'))
        
    with open(load_resource('templates', 'omnetpp.ini'), 'r') as template, open(join(location, OMNET_FOLDER, f'omnetpp.ini'), 'w') as file:
        file.writelines(template.readlines())
        file.write('\n')

        for src, apps in packet_map.items():
            if len(apps) == 0:
                continue
            file.write(f'**.{src}.numApps = {len(apps)}\n')
            for i, (stream, app_type) in enumerate(apps):
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
                    file.write(f'**.{src}.app[{i}].{param} = {mapping_func(stream[packet_key])}\n')

                file.write('\n')


        tmp = []
        if protocol == EResilienceProtocol.FRER:
            for stream in streams:
                destination_name = stream['DestinationName']
                destination_mac = stream['DestinationMac']
                tmp.append(f'*.{destination_name}.eth[*].address = "{destination_mac}"\n')
        
        [file.write(s) for s in set(tmp)]

        file.write('\n')
        file.write('*.*.bridging.streamRelay.typename = "StreamRelayLayer"\n')
        file.write('*.*.bridging.streamCoder.typename = "StreamCoderLayer"\n')
        file.write('*.streamRedundancyConfigurator.typename = "StreamRedundancyConfigurator"\n')
        file.write('\n')

        stream_descriptions = list()
        for i, ((source_name, destination_name), paths) in enumerate(stream_paths.items()):
            map_path = lambda n: f'"{n}"'
            map_paths = lambda path: f'[[{",".join(map(map_path, path))}]]'
            paths = ',\n\t\t'.join(map(map_paths, paths))
            stream_desc = '{ "name" : ' + f'"S{i}", "packet Filter" : "*", "source" : "{source_name}", "destination" : "{destination_name}",\n' + f'\t"trees" : [{paths}]' + '\n\t}'
            stream_descriptions.append(stream_desc)
        
        joined_descriptions = ",\n\t".join(stream_descriptions)
        file.write(f'*.streamRedundancyConfigurator.configuration = [{joined_descriptions}]\n')
        
        file.write('\n')