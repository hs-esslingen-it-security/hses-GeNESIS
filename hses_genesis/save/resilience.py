from typing import DefaultDict
from networkx import Graph, minimum_edge_cut, minimum_node_cut, shortest_simple_paths, node_disjoint_paths, edge_disjoint_paths, all_simple_paths
from pandas import DataFrame
from os.path import join, exists
from math import e
from hses_genesis.utils.enum_objects import EService,  EDeviceRole

def save_path_diversity(dir : str, run_label : str, G : Graph, communication_pairs : set, k_max = 30, sig : float = 1, control_traffic_path_requirement = 2, best_effort_path_requirement = 1):
    data = [[run_label, (s, d)] + get_effective_path_diversity(G, k_max, s, d, sig) for s, d in communication_pairs]
    df = DataFrame(data, columns=['run_label', 'communication_pair'] + [f'EPD(k={k})' for k in range(1, k_max + 1)])
    df = df.set_index('communication_pair')

    df.loc['total'] = df.mean(numeric_only=True, axis=0)
    df.loc['total', 'run_label'] = run_label
    file_name = join(dir, 'k_shortest_path_diversities.csv')
    df.to_csv(file_name, mode='a+', header=not exists(file_name))

    data = get_disjoint_diversity(run_label, G, communication_pairs, control_traffic_path_requirement, best_effort_path_requirement)
    df = DataFrame(data, columns=['run_label', 'communication_pair', 'node_disjoint_paths', 'edge_disjoint_paths', 'node_len', 'edge_len', 'path_requirement', 'meets_requirement'])
    df = df.set_index('communication_pair')

    df.loc['total'] = df.mean(numeric_only=True, axis=0)
    df.loc['total', 'run_label'] = run_label
    file_name = join(dir, 'redundant_paths.csv')
    df.to_csv(file_name, mode='a+', header=not exists(file_name))

def get_disjoint_diversity(run_label, G : Graph, connections, control_traffic_path_requirement = 2, best_effort_path_requirement = 1):
    control_traffic_services = EService.control_traffic()
    mapped_connections = {(s, t) : any(service in control_traffic_services for service in EService if service in G.nodes[s]['services'] and service in G.nodes[t]['services']) for s, t in connections}
    data = list()

    for (s, t), is_control_traffic in mapped_connections.items():
        subgraph = G.subgraph([n for n, d in G.nodes(data=True) if n in [s, t] or d['role'] in [EDeviceRole.SWITCH, EDeviceRole.ROUTER]])
        try:
            ndp, edp = list(node_disjoint_paths(subgraph, s, t)), list(edge_disjoint_paths(subgraph, s, t))
        except Exception:
            ndp, edp = list(), list()
        path_requirement = control_traffic_path_requirement if is_control_traffic else best_effort_path_requirement
        meets_requirements = all(len(paths) >= path_requirement for paths in [ndp, edp])

        if not meets_requirements:
            print(f'WARNING: Not enough disjoint paths between {s} and {t} to meet resilience requirements!')
        
        data.append([run_label, (s,t), ndp, edp, len(ndp), len(edp), path_requirement, meets_requirements])
    
    return data

def get_path_diversity(P_b : set, P_a : set):
    """
    Calculate path diversity of two arbitraty paths @P_a and @P_b.

    $D(P_b, P_a) = 1 - \\frac{| P_b \\cap P_a |}{| P_a |}$

    $D(P_b, P_a) == 0$ if completely disjoint, $D(P_b, P_a) == 1$ if identical
    """
    return 1 - ( len(P_b.intersection(P_a)) / len(P_a) )

def get_min_path_diversity(P_b : set, paths : list[set]):
    return min(get_path_diversity(P_b, P_a) for P_a in paths) if paths else 0.0

def get_effective_path_diversity(G : Graph, k : int, s : str, t : str, sig : float = 1.0):
    """
    Calculate effective path diversity of a node pair (@s, @d)

    $EPD = 1- e^-\sig k_{sd}$, where $k_{sd}=\sum_{i=1}^k D_{min}(P_i)$

    @k is the number of maximal diverse paths to select.

    @sig is an experimentally determined constant scaling the impact of k_{sd}.
    sig >= 1 indicates lower marginal utility for additional paths.
    sig < 1 indicates higher marginal utility for additional paths.
    """
    k_sd : list[float] = [0.0]
    subgraph = G.subgraph([n for n, data in G.nodes(data=True) if n in [s, t] or data['role'] in [EDeviceRole.SWITCH, EDeviceRole.ROUTER]])
    generator = shortest_simple_paths(subgraph, source=s, target=t)
    # generator = all_simple_paths(subgraph, source=s, target=t)

    try:
        P_b = next(generator, None)
    except Exception:
        P_b = None
    paths = []
    while P_b != None and len(paths) < k:
        P_b = set(P_b) | {(P_b[i], P_b[i+1]) for i in range(len(P_b) - 1)}

        if len(paths) == 0:
            paths.append(P_b)
        else:
            min_diversity = get_min_path_diversity(P_b, paths)
            if min_diversity > 0:
                k_sd.append(k_sd[-1] + min_diversity)
                paths.append(P_b)

        P_b = next(generator, None)

    k_sd = [(1.0 - e ** (-sig * v)) for v in k_sd]
    if len(k_sd) < k:
        k_sd.extend([k_sd[-1]] * (k - len(k_sd)))

    return k_sd

def get_minimal_cuts(G : Graph, s : str, t : str):
    subgraph = G.subgraph([n for n, data in G.nodes(data=True) if n in [s, t] or data['role'] in [EDeviceRole.SWITCH, EDeviceRole.ROUTER]])
    edge_cuts = minimum_edge_cut(subgraph, s, t)
    node_cuts = minimum_node_cut(subgraph, s, t)
    return edge_cuts, node_cuts

def save_minimal_cuts(dir : str, run_label : str, G : Graph, communication_pairs : set[tuple[str, str]]):
    data = list()
    for s, t in communication_pairs:
        edge_cuts, node_cuts = get_minimal_cuts(G, s, t)
        data.append((run_label, (s, t), edge_cuts, node_cuts, min(len(edge_cuts), len(node_cuts))))
    
    df = DataFrame(data, columns=['run_label', 'communication_pairs', 'edge_cuts', 'node_cuts', 'min_cut_value'])
    df['is_bottleneck'] = df['min_cut_value'].apply(lambda x: x <= 1)
    df = df.set_index('communication_pairs')
    minimal_cut_value = df['min_cut_value'].min()
    df.loc['total'] = df.mean(numeric_only=True, axis=0)
    df.loc['total', 'min_cut_value'] = minimal_cut_value
    df.loc['total', 'run_label'] = run_label
    file_name = join(dir, 'minimal_cuts.csv')
    df.to_csv(file_name, mode='a+', header=not exists(file_name))