from collections import OrderedDict
from enum_objects import EPacketDecision

class Rule():
    def __init__(self, source : str, target : str, action : EPacketDecision = EPacketDecision.DROP) -> None:
        self.source = source
        self.target = target
        self.action = action

    def __str__(self) -> str:
        return f'-s {self.source} -d {self.target} -j {self.action.name}'

class NetworkConfigurationGenerator():
    def __init__(self, seed) -> None:
        self.seed = seed


    def generate_ruleset(self, communication_relations, anomaly_count : int):
        ruleset = [(src, dst, prot, sport, dport, EPacketDecision.ACCEPT) for src, dst, prot, sport, dport in communication_relations]
        ruleset.extend([(dst, src, prot, sport, dport, EPacketDecision.ACCEPT) for src, dst, prot, sport, dport in communication_relations])
        
        if anomaly_count == 0:
            return [f'-s {src} -d {dst} -p {prot} --sport {sport} --dport {dport} -j {action.name}' for src, dst, prot, sport, dport, action in ruleset]
        
        src_matching_rule_groups : dict[str, list] = {}
        dst_matching_rule_groups : dict[str, list] = {}
        for i, (src, dst, _, _, _, _) in enumerate(ruleset):
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

                    # src, dst, prot, sport, dport = [f'{rules[0][i]}:{rules[-1][i]}' if ((i == ranged_value_index) and (rules[0][i] != rules[-1][i])) else ','.join(list(set(sorted([str(r[i]) for r in rules])))) for i, _ in enumerate(['s', 'd', 'p', 'sport', 'dport'])]
                    src, dst, prot, sport, dport = [(f'{rules[0][i]}:{rules[-1][i]}' if (rules[0][i] != rules[-1][i]) else rules[0][i]) if i < 2 else '*' for i, _ in enumerate(['s', 'd', 'p', 'sport', 'dport'])]

                    ruleset.insert(ruleset.index(rules[-1]) + 1, (src, dst, prot, sport, dport, EPacketDecision.DROP))

        if counter < anomaly_count:
            for ranged_value_index, container in [[1, src_matching_rule_groups], [0, dst_matching_rule_groups]]:
                if counter >= anomaly_count:
                    break

                for key in container.keys():
                    if counter >= anomaly_count:
                        break

                    if len(container[key]) == 1:
                        src, dst, prot, sport, dport = [container[key][0][i] if ((i < 2) and (i != ranged_value_index)) else '*' for i, _ in enumerate(['s', 'd', 'p', 'sport', 'dport'])]
                        ruleset.insert(ruleset.index(container[key][0]) + 1, (src, dst, prot, sport, dport, EPacketDecision.DROP))
                        counter += 1

        return list(OrderedDict.fromkeys([f'-s {src} -d {dst} -p {prot} --sport {sport} --dport {dport} -j {action.name}' for src, dst, prot, sport, dport, action in ruleset]))