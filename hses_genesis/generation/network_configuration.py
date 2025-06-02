from collections import OrderedDict
from ipaddress import ip_address
from random import Random
from hses_genesis.utils.constants import FULL_RANGES, PROTOCOLS, WILDCARD
from hses_genesis.utils.enum_objects import EPacketDecision, EParameterType, EState

class NetworkConfigurationGenerator():
    def __init__(self, seed) -> None:
        self.seed = seed

    @staticmethod
    def rule_to_str(raw_rule):
        src, dst, (prot_start, prot_end), sport, dport, (state_start, state_end), action = raw_rule
        rule = []
        for (start, end) in [src, dst]:
            start, end = start[0], end[0]
            if start == end:
                rule.append(str(ip_address(start)))
                continue

            start_ip, end_ip = ip_address(start), ip_address(end)
            if FULL_RANGES[EParameterType.PROTOCOL] == (int(start_ip), int(end_ip)):
                rule.append(WILDCARD)
                continue

            rule.append(f'{start_ip}:{end_ip}')

        if prot_start != prot_end:
            raise Exception('Multi protocol rules not implemented yet...')
        
        if isinstance(prot_start, int):
            rule.append({v: k for (k, v) in PROTOCOLS.items()}[prot_start])
        else:
            rule.append(prot_start.lower())

        for (start, end) in [sport, dport]:
            if start == end:
                rule.append(str(start))
                continue
            if FULL_RANGES[EParameterType.NUMBER] == (start, end):
                rule.append(WILDCARD)
                continue
            rule.append(f'{start}:{end}')

        if state_start != EState.NONE:
            rule.append(','.join([EState.from_value(i).name for i in range(state_start.value, state_end.value + 1)]))
        else:
            rule.append('')

        src, dst, prot, sport, dport, states = rule
        return f'-s {src} -d {dst} -p {prot} --sport {sport if sport != 0 else WILDCARD} --dport {dport if dport != 0 else WILDCARD}' + (f' -m state --state {states}' if states else '') + f' -j {action.name}'

    @staticmethod
    def to_numerical_representation(raw_rule):
        ip_addresses = [int(ip_address(value[0])) for value_range in raw_rule[0:2] for value in list(value_range)]
        protocols = [PROTOCOLS[value.lower()] if isinstance(value, str) else value for value in raw_rule[2]]
        ports = [int(value) for value_range in raw_rule[3:5] for value in list(value_range)]
        states = [state.value for state in list(raw_rule[5])]
        action = [raw_rule[6].value]
        return ip_addresses + protocols + ports + states + action

    def generate_ruleset(self, communication_relations, anomaly_count : int, stateful_percentage : int):
        ruleset = []
        truth_weight = stateful_percentage / 100 if stateful_percentage != 0 else 0
        for i, (src, dst, prot, sport, dport) in enumerate(communication_relations):
            is_stateful_rule = Random(self.seed + i).choices([True, False], weights = [truth_weight, 1 - truth_weight], k = 1)[0]
            if is_stateful_rule:
                rule = (src,src), (dst,dst), (prot,prot), FULL_RANGES[EParameterType.NUMBER], (dport,dport), (EState.NEW, EState.RELATED), EPacketDecision.ACCEPT
                mirror = (dst,dst), (src,src), (prot,prot), (sport,sport), FULL_RANGES[EParameterType.NUMBER], (EState.ESTABLISHED, EState.RELATED), EPacketDecision.ACCEPT
            else:
                rule = (src,src), (dst,dst), (prot,prot), FULL_RANGES[EParameterType.NUMBER], (dport,dport), (EState.NONE, EState.NONE), EPacketDecision.ACCEPT
                mirror = (dst,dst), (src,src), (prot,prot), (sport,sport), FULL_RANGES[EParameterType.NUMBER], (EState.NONE, EState.NONE), EPacketDecision.ACCEPT
            ruleset.extend([rule, mirror])

        if anomaly_count == 0:
            return ruleset

        src_matching_rule_groups : dict[str, list] = {}
        dst_matching_rule_groups : dict[str, list] = {}
        for i, ((src, _), (dst, _), _, _, _, _, _) in enumerate(ruleset):
            for tag_value, container in [src, src_matching_rule_groups], [dst, dst_matching_rule_groups]:
                if tag_value not in container:
                    container[tag_value] = [ruleset[i]]
                else:
                    container[tag_value].append(ruleset[i])

        counter = 0
        for ranged_value_index, container in [[1, src_matching_rule_groups], [0, dst_matching_rule_groups]]:
            if counter >= anomaly_count:
                break

            for key in container.keys():
                if counter >= anomaly_count:
                    break

                if len(container[key]) > 1:
                    rules = container[key]
                    sorted(rules, key=lambda x: x[ranged_value_index])
                    
                    remaining_anomalies = anomaly_count - counter
                    if len(rules) > remaining_anomalies:
                        rules = rules[:remaining_anomalies]
                    counter += len(rules)

                    src, dst, prot, sport, dport = [(f'{rules[0][i]}:{rules[-1][i]}' if (rules[0][i] != rules[-1][i]) else rules[0][i]) if i < 2 else WILDCARD for i, _ in enumerate(['s', 'd', 'p', 'sport', 'dport'])]

                    ruleset.insert(ruleset.index(rules[-1]) + 1, ((src, src), (dst, dst), (prot, prot), (sport, sport), (dport, dport), (EState.NONE, EState.NONE), EPacketDecision.DROP))

        if counter < anomaly_count:
            for ranged_value_index, container in [[1, src_matching_rule_groups], [0, dst_matching_rule_groups]]:
                if counter >= anomaly_count:
                    break

                for key in container.keys():
                    if counter >= anomaly_count:
                        break

                    if len(container[key]) == 1:
                        src, dst, prot, sport, dport = [container[key][0][i] if ((i < 2) and (i != ranged_value_index)) else WILDCARD for i, _ in enumerate(['s', 'd', 'p', 'sport', 'dport'])]
                        ruleset.insert(ruleset.index(container[key][0]) + 1, (src, dst, prot, sport, dport, [], EPacketDecision.DROP))
                        counter += 1

        return list(OrderedDict.fromkeys([f'-s {src} -d {dst} -p {prot} --sport {sport if sport != 0 else WILDCARD} --dport {dport if dport != 0 else WILDCARD}' + f' -m state --state {",".join(list([s.name for s in states]))}' if len(states) > 0 else '' + f' -j {action.name}' for src, dst, prot, sport, dport, states, action in ruleset])), ruleset