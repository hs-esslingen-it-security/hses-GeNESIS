from itertools import product
from networkx import Graph, contracted_nodes, neighbors, relabel_nodes
from pandas import DataFrame

from hses_genesis.utils.enum_objects import EDeviceRole

def get_subnet_graph(G : Graph, inplace = False):
    def remove_routers(G : Graph, inplace = False):
        g_copy = G if inplace else G.copy()
        routers = [router for router, data in g_copy.nodes(data=True) if data['role'] == EDeviceRole.ROUTER]
        for router in routers:
            router_neighbors = list(neighbors(g_copy, router))
            g_copy.remove_node(router)

            for src, dst in product(router_neighbors, router_neighbors):
                if src == dst:
                    continue
                g_copy.add_edge(src, dst)
        return g_copy

    def contract_nodes(G : Graph, grouped_data_df, relabel_to_subnet = False, inplace = False):
        g_copy = G if inplace else G.copy()
        for subnet, values in grouped_data_df:
            node_informations = values.to_dict(orient='records')
            if len(node_informations) == 0:
                continue

            node_to_keep = node_informations[0]['node_name']
            for node in node_informations[1:]:
                g_copy = contracted_nodes(g_copy, node_to_keep, node['node_name'], self_loops=False)

            if relabel_to_subnet:
                g_copy = relabel_nodes(g_copy, {node_to_keep : subnet})
        return g_copy

    subnet_compressed_topology = G if inplace else G.copy()
    node_data = subnet_compressed_topology.nodes(data=True)

    non_router_data_df = DataFrame([{'node_name' : node} | data for node, data in node_data if data['role'] != EDeviceRole.ROUTER]).explode('subnet')
    grouped_non_router_data_df = non_router_data_df.groupby('subnet')

    subnet_compressed_topology = contract_nodes(subnet_compressed_topology, grouped_non_router_data_df, True)

    router_data_df = DataFrame([{'node_name' : node} | data for node, data in node_data if data['role'] == EDeviceRole.ROUTER])
    router_data_df['subnet'] = router_data_df['subnet'].apply(sorted).apply(tuple)
    grouped_router_data_df = router_data_df.groupby('subnet')

    return remove_routers(contract_nodes(subnet_compressed_topology, grouped_router_data_df))