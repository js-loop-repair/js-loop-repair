import networkx as nx
import sys
import csv
import sty
import io
import logging
import json
from typing import List, Callable
import time
from src.core.jsx_constant import JSX_Edges, JSX_Nodes, JSX_Labels, JSX_Label_Key
from src.core.code_slice import PendingCodeSlice
from .utils import BranchTag, BranchTagContainer, DictCounter
from .utils import wildcard, _SpecialValue
from .logger import *
import uuid
from itertools import chain
from collections import defaultdict, deque
from typing import Dict, List, Any
import pprint
from pathlib import Path


class Graph:

    def __init__(self):
        self.graph = nx.MultiDiGraph()
        self.cur_objs = []
        self.cur_scope = None
        self.cur_jsx_component = None
        self.cur_func = None
        self.cur_id = 0
        self.entry_file_path = None
        self.cur_file_path = None  # deprecated, use G.get_cur_file_path()
        self.file_contents = {}
        # self.logger = create_logger("graph_logger", output_type="file")
        self.logger = loggers.main_logger
        self.registered_funcs = {}
        self.op_cnt = {"add_node": 0, "add_edge": 0, "get_node_attr": 0, "get_edge": 0, "get_edge_attr": 0}
        self.nearest_upper_CPG_cache = {}
        self.detection_res = {}
        self.num_removed = 0
        self.dont_quit = None
        self.last_stmts = []
        self.package_name = None
        self.no_file_based = False
        self.ipt_use = set()
        self.timestamp = 0

        # for control flow
        self.cfg_stmt = None

        # for block opt
        self.register = {}
        self.num_function_call = {}
        self.opt_func = True

        # for evaluation
        self.covered_num_stat = 0
        self.total_num_stat = 0
        self.covered_stat = {}  # set()
        self.all_stat = set()
        self.all_func = set()
        self.covered_func = set()
        self.start_time = time.time()
        self.last_time = 0

        # exit immediately when vulnerability is found
        self.finished = False
        self.exit_when_found = False
        self.time_limit_reached = False

        # mark the type of the node, built-in or application
        self.export_node = True

        self.reverse_names = defaultdict(set)

        # JS internal values
        self.function_prototype = None
        self.object_prototype = None
        self.array_prototype = None
        self.number_prototype = None
        self.string_prototype = None
        self.boolean_prototype = None
        self.regexp_prototype = None
        self.promise_prototype = None

        self.builtin_constructors = []
        self.builtin_prototypes = []

        self.mark_tainted = []

        # scope name counter
        self.scope_counter = DictCounter()

        # contains a list of node ids based on the ast id
        self.call_stack = []  # deprecated, only for debugging
        self.for_stack = []  # for debugging
        self.call_counter = DictCounter()  # callers (instead of callees)
        self.call_limit = options.call_limit
        self.file_stack = []
        self.require_obj_stack = []
        self.cur_stmt = None  # for building data flows
        self.function_returns = defaultdict(lambda: [[], []])

        # Python-modeled built-in modules
        self.builtin_modules = {}

        # prototype pollution
        self.check_proto_pollution = False
        self.proto_pollution = set()
        self.func_entry_point = None

        # internal property tampering
        self.check_ipt = False

        # check useRef.innerHtml
        self.check_useRef = True
        self.check_a_href = True
        self.check_window_open = False
        self.on_message = False

        self.run_all = True
        self.function_time_limit = None
        self.single_branch = False
        self.print = False

        # task queues
        self.task_queue = deque()
        self.microtask_queue = deque()

        # dom events queues
        self.dom_events_queue = deque()
        self.comp_update_queue = deque()
        self.rerender_comp_set = set()
        self.jsx_tainted_objs = []
        self.jsx_comp_state_objs_map = {}

        self.parent_component = None

        # ES6 module
        self.module_registry = {}

        # API Route Map
        self.service_registry = {}

        self.entrance_files = []

        # format: {
        #   "file_path": '',
        #   "start_line": '',
        #   "end_line": '',
        # }

        self.pending_code_slice = PendingCodeSlice()

        self.code_slice_pending_nodes = []

        self.vul_type = None
        self.vul_graph_info = {}

        csv.field_size_limit(2**31 - 1)

        class joern_dialect(csv.excel_tab):
            doublequote = False
            escapechar = "\\"

        self.csv_dialect = joern_dialect

        self.num_of_ast_nodes = None

        self.cleanup_funcs = []
        self.updating_phase = False

    # Basic graph operations
    # node

    def _get_new_nodeid(self):
        """
        return a nodeid
        """
        self.cur_id += 1
        return str(self.cur_id - 1)
        # return str(uuid.uuid4().int)

    def add_node(self, node_for_adding, attr={}):
        self.op_cnt["add_node"] += 1
        attr["export"] = self.export_node
        self.graph.add_node(node_for_adding, **attr)
        return node_for_adding

    """
    def add_node_from_list(self, node_list):
        print(node_list)
        return self.graph.add_nodes_from(node_list)
    """

    def get_graph_size(self):
        """
        return the size of the graph
        """
        return self.graph.size()

    def set_node_attr(self, node_id, attr):
        """
        attr should be a tuple like (key, value)
        will be added to a node id
        """
        self.graph.nodes[node_id][attr[0]] = attr[1]

    def get_node_attr(self, node_id):
        """
        this function will return a dict with all the attrs and values
        """
        assert node_id is not None
        self.op_cnt["get_node_attr"] += 1
        return self.graph.nodes[node_id]

    def get_all_nodes(self):
        """
        return all nodes in the form of dict
        """
        return self.graph.nodes

    def get_nodes_by_type(self, node_type, data=True):
        """
        return a list of nodes with a specific node type
        as tuples of node id and attrs
        """
        return [node for node in self.graph.nodes(data=data) if node[1].get("type") == node_type]

    def get_nodes_by_type_and_flag(self, node_type, node_flag, data=True):
        """
        return a list of nodes with a specific node type and flag
        """
        return [node[0] for node in self.graph.nodes(data=data) if node[1].get("type") == node_type and node[1].get("flags:string[]") == node_flag]

    def get_nodes_by_type_and_label(self, node_type, node_label, data=True):
        return [node[0] for node in self.graph.nodes(data=data) if node[1].get("type") == node_type and node[1].get("labels:label") == node_label]

    def get_node_by_attr(self, key, value):
        """
        get a list of node by key and value
        """
        return [node[0] for node in self.graph.nodes(data=True) if key in node[1] and node[1][key] == value]

    def remove_nodes_from(self, remove_list):
        """
        remove a list of nodes from the graph
        """
        self.graph.remove_nodes_from(remove_list)

    def relabel_nodes(self):
        """
        relabel all the nodes to a uuid to make the graph globaly useful
        """
        mapping = {}
        for node in self.graph.nodes():
            # make a random uuid
            mapping[node] = str(uuid.uuid4().int)

        self.graph = nx.relabel_nodes(self.graph, mapping)

    # edges

    def add_edge(self, from_ID, to_ID, attr):
        """
        insert an edge to graph
        attr is like {key: value, key: value}
        """
        assert from_ID is not None, "Failed to add an edge, from_ID is None."
        assert to_ID is not None, "Failed to add an edge, to_ID is None."
        assert from_ID != "string" and to_ID != "string"
        self.op_cnt["add_edge"] += 1
        attr["timestamp"] = self.get_timestamp()
        self.graph.add_edge(from_ID, to_ID, None, **attr)

    def add_edge_if_not_exist(self, from_ID, to_ID, attr):
        """
        insert an edge to the graph if the graph does not already has the same edge
        """
        assert from_ID is not None, "Failed to add an edge, from_ID is None."
        assert to_ID is not None, "Failed to add an edge, to_ID is None."
        if not self.graph.has_edge(from_ID, to_ID):
            self.add_edge(from_ID, to_ID, attr)
        else:
            for key, edge_attr in self.graph[from_ID][to_ID].items():
                if edge_attr == attr:
                    self.logger.warning("Edge {}->{} exists: {}, {}. Duplicate edge " "will not be created.".format(from_ID, to_ID, key, edge_attr))
                    return
            self.add_edge(from_ID, to_ID, attr)

    def set_edge_attr(self, from_ID, to_ID, edge_id, attr):
        self.graph[from_ID][to_ID][attr[0]][edge_id] = attr[1]

    def get_edge_attr(self, from_ID, to_ID, edge_id=None):
        self.op_cnt["get_edge_attr"] += 1
        if edge_id == None:
            return self.graph.get_edge_data(from_ID, to_ID)
        return self.graph[from_ID][to_ID][edge_id]

    def add_edges_from_list(self, edge_list):
        return self.graph.add_edges_from(edge_list)

    def add_edges_from_list_if_not_exist(self, edge_list):
        for e in edge_list:
            if len(e) != 3:
                self.logger.error("Length of the edge tuple {} is not 3".format(e))
                continue
            self.add_edge_if_not_exist(*e)

    def get_edges_by_type(self, edge_type):
        """
        return the edges with a specific type
        """
        subEdges = [edge for edge in self.graph.edges(data=True, keys=True) if edge[3]["type:TYPE"] == edge_type]
        return subEdges

    def get_edges_between(self, u, v, edge_type=None) -> dict:
        result = {}
        for key, edge_attr in self.graph[u][v].items():
            if not edge_type or edge_attr.get("type:TYPE") == edge_type:
                result[key] = edge_attr
        return result

    def remove_all_edges_between(self, u, v):
        while True:
            try:
                self.graph.remove_edge(u, v)
            except nx.NetworkXError:
                break

    def get_out_edges(self, node_id, data=True, keys=True, edge_type=None):
        assert node_id is not None
        self.op_cnt["get_edge"] += 1
        if edge_type is None:
            return self.graph.out_edges(node_id, data=data, keys=keys)
        edges = self.graph.out_edges(node_id, data=data, keys=keys)
        idx = 1
        if keys == True:
            idx += 1
        if data == True:
            idx += 1
        out_edges = [edge for edge in edges if "type:TYPE" in edge[idx] and edge[idx]["type:TYPE"] == edge_type]
        return out_edges

    def get_in_edges(self, node_id, data=True, keys=True, edge_type=None):
        assert node_id is not None
        self.op_cnt["get_edge"] += 1
        if edge_type == None:
            return self.graph.in_edges(node_id, data=data, keys=keys)
        edges = self.graph.in_edges(node_id, data=data, keys=keys)
        idx = 2
        if keys == True:
            idx = 3
        in_edges = [edge for edge in edges if "type:TYPE" in edge[idx] and edge[idx]["type:TYPE"] == edge_type]
        return in_edges

    def get_sub_graph_by_edge_type(self, edge_type):
        """
        only keep edges with specific type
        return a sub graph
        """
        subEdges = self.get_edges_by_type(edge_type)
        return nx.MultiDiGraph(subEdges)

    def get_ancestors_in(self, node_id, edge_types=None, node_types=None, candidates=None, step=1):
        results = []
        if step > 1:
            _candidates = None
        else:
            _candidates = candidates
        for edge_type in edge_types:
            for e in self.get_in_edges(node_id, edge_type=edge_type):
                node = e[0]
                if _candidates is not None and node not in _candidates:
                    continue
                if node_types is not None and self.get_node_attr(node).get("type") not in node_types:
                    continue
                if step == 1:
                    results.append(node)
                else:
                    results.extend(self.get_ancestors_in(node, edge_types, node_types, candidates, step - 1))
        return results

    # traversal

    def dfs_edges(self, source, depth_limit=None):
        """
        Iterate over edges in a depth-first-search (DFS).
        """
        return nx.dfs_edges(self.graph, source, depth_limit)

    def has_path(self, source, target, edge_type=None):
        """
        Return True if there is a path from source to target, False
        otherwise.
        """
        if edge_type:
            sub_graph = self.get_sub_graph_by_edge_type(edge_type)
            return nx.algorithms.shortest_paths.generic.has_path(sub_graph, source, target)
        return nx.algorithms.shortest_paths.generic.has_path(self.graph, source, target)

    def get_all_simple_pathes(self, source, target, edge_type=None):
        """
        return all the simple pathes between two nodes
        """
        if edge_type:
            sub_graph = self.get_sub_graph_by_edge_type(edge_type)
        return nx.all_simple_edge_paths(sub_graph, source, target)

    # import/export

    def import_from_string(self, string):
        # print("before importing", self.graph.number_of_nodes())
        try:
            nodes, rels = string.split("\n\n")[:2]
        except ValueError as e:
            loggers.error_logger.error("AST generation failed!")
            self.logger.error("AST generation failed!")
            raise e

        with io.StringIO(nodes) as fp:
            reader = csv.DictReader(fp, dialect=self.csv_dialect)
            for row in reader:
                if "id:ID" not in row:
                    continue
                cur_id = row["id:ID"]
                self.add_node(cur_id)
                for attr, val in row.items():
                    if attr == "id:ID":
                        continue
                    self.set_node_attr(cur_id, (attr, val))

        with io.StringIO(rels) as fp:
            reader = csv.DictReader(fp, dialect=self.csv_dialect)
            edge_list = []
            for row in reader:
                attrs = dict(row)
                try:
                    del attrs["start:START_ID"]
                except:
                    continue
                del attrs["end:END_ID"]
                edge_list.append((row["start:START_ID"], row["end:END_ID"], attrs))
            self.add_edges_from_list(edge_list)
        self.logger.info(sty.ef.inverse + sty.fg.white + "Finished Importing" + sty.rs.all)

        # self.relabel_nodes()
        # reset cur_id
        self.cur_id = self.graph.number_of_nodes()

        self.num_of_ast_nodes = self.graph.number_of_nodes()

    def import_from_CSV(self, nodes_file_name, rels_file_name, offset=0, extra_info=None, vul_graph_info_file_path=None):
        with open(nodes_file_name) as fp:
            reader = csv.DictReader(fp, dialect=self.csv_dialect)
            for row in reader:
                cur_id = row["id:ID"]
                self.add_node(cur_id)
                for attr, val in row.items():
                    if attr == "id:ID":
                        continue
                    self.set_node_attr(cur_id, (attr, val))

        with open(rels_file_name) as fp:
            reader = csv.DictReader(fp, dialect=self.csv_dialect)
            edge_list = []
            for row in reader:
                attrs = dict(row)
                del attrs["start:START_ID"]
                del attrs["end:END_ID"]
                edge_list.append((row["start:START_ID"], row["end:END_ID"], attrs))
            self.add_edges_from_list(edge_list)
        self.logger.info(sty.ef.inverse + sty.fg.white + "Finished Importing" + sty.rs.all)

        self.cur_id = self.graph.number_of_nodes()

        if vul_graph_info_file_path and os.path.exists(vul_graph_info_file_path):
            with open(vul_graph_info_file_path, "r") as jf:
                self.vul_graph_info = json.load(jf)
            self.logger.info("Vulnerability graph info loaded from JSON")

    def export_to_CSV(self, nodes_file_name, rels_file_name, light=False, vul_graph_info_file_path=None):
        """
        export to CSV to import to neo4j
        """

        start_time = time.time()
        exported_nodes = []

        # Timing the nodes export
        nodes_start_time = time.time()
        with open(nodes_file_name, "w") as fp:
            headers = [
                "id:ID",
                "labels:label",
                "type",
                "flags:string[]",
                "jsx:label",
                "lineno:int",
                "code",
                "childnum:int",
                "funcid:int",
                "classname",
                "namespace",
                "endlineno:int",
                "name",
                "doccomment",
                "export",
                "tainted",
            ]
            writer = csv.DictWriter(fp, dialect=self.csv_dialect, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            nodes = list(self.graph.nodes(data=True))
            nodes.sort(key=lambda x: int(x[0]))
            for node in nodes:
                node_id, attr = node
                row = dict(attr)

                if light:
                    if "export" not in row:
                        self.logger.error("Node " + str(attr) + " ID: " + node_id + " was not generated by Graph.add_node method")
                        continue
                    if not row["export"]:
                        continue

                row["id:ID"] = node_id
                writer.writerow(row)
                exported_nodes.append(node_id)

        nodes_end_time = time.time()
        duration = nodes_end_time - nodes_start_time
        self.logger.info(f"Nodes export took {duration:.2f} seconds")

        # Timing the relationships export
        rels_start_time = time.time()
        exported_nodes_set = set(exported_nodes)
        with open(rels_file_name, "w") as fp:
            headers = ["start:START_ID", "end:END_ID", "type:TYPE", "var", "taint_src", "taint_dst"]
            writer = csv.DictWriter(fp, dialect=self.csv_dialect, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            edges = list(self.graph.edges(data=True, keys=True))

            for edge in edges:
                edge_from, edge_to, _, attr = edge

                if edge_from not in exported_nodes_set or edge_to not in exported_nodes_set:
                    continue

                row = dict(attr)
                row["start:START_ID"] = edge_from
                row["end:END_ID"] = edge_to
                writer.writerow(row)

        rels_end_time = time.time()
        self.logger.info(f"Relationships export took {rels_end_time - rels_start_time} seconds")

        if vul_graph_info_file_path:
            with open(vul_graph_info_file_path, "w") as jf:
                json.dump(self.vul_graph_info, jf, indent=2)
            loggers.code_slice_logger.info(f"Vulnerability graph info exported to {vul_graph_info_file_path}")

        end_time = time.time()  # End timing
        print(f"Graph exported to {nodes_file_name} and {rels_file_name} in {end_time - start_time} seconds")

    def testing_benchmark_export_graph(self, file_path):
        """
        export graph to pickle format
        """
        nx.readwrite.write_gpickle(self.graph, file_path)

    def export_graph(self, file_path):
        """
        export graph to pickle format
        """
        self.relabel_nodes()
        nx.readwrite.write_gpickle(self.graph, file_path)

    def import_graph(self, file_path):
        """
        import a graph from a exported file
        """
        with open(file_path, "r") as fp:
            dict_graph = json.load(fp)

        self.graph = nx.Graph(dict_graph)

    def recount_cur_id(self):
        self.cur_id = 0
        for node in self.graph.nodes:
            node_id = int(self.get_node_attr(node).get("id:ID"))
            if node_id >= self.cur_id:
                self.cur_id = node_id + 1

    # AST & CPG

    def _get_childern_by_childnum(self, node_id):
        """
        helper function, get the childern nodeid of the node_id
        return a dict, with {childnum: node_id}
        """
        edges = self.get_out_edges(node_id, edge_type="PARENT_OF")
        res = {}
        for edge in edges:
            node_attr = self.get_node_attr(edge[1])
            if "childnum:int" not in node_attr:
                continue
            res[node_attr["childnum:int"]] = edge[1]
        return res

    def get_ordered_ast_child_nodes(self, node_id):
        """
        return AST children of a node in childnum order
        """
        children = sorted(self._get_childern_by_childnum(node_id).items(), key=lambda x: int(x[0]))
        if children:
            children = list(zip(*children))[1]

        return children

    def get_child_nodes(self, node_id, edge_type=None, child_name=None, child_type=None, child_label=None):
        """
        return the children of node (with a specific edge type, name, or node type)
        """
        if edge_type is None and child_name is None and child_type is None and child_label is None:
            return self.graph.successors(node_id)
        res = set()
        edges = self.get_out_edges(node_id, edge_type=edge_type)
        for edge in edges:
            flag = True
            aim_node_attr = self.get_node_attr(edge[1])
            if child_type is not None and aim_node_attr.get("type") != child_type:
                flag = False
            if child_name is not None and aim_node_attr.get("name") != child_name:
                flag = False
            if flag:
                res.add(edge[1])
        return list(res)

    get_successors = get_child_nodes

    def get_name_from_child(self, nodeid, max_depth=None):
        """
        try to find the name of a nodeid
        we have to use bfs strategy
        """
        bfs_queue = []
        visited = set()
        bfs_queue.append((nodeid, 0))

        while len(bfs_queue):
            cur_node, cur_depth = bfs_queue.pop(0)
            if max_depth and cur_depth > max_depth:
                break

            # if visited before, stop here
            if cur_node in visited:
                continue
            else:
                visited.add(cur_node)

            cur_attr = self.get_node_attr(cur_node)

            if "type" not in cur_attr:
                continue
            if cur_attr["type"] == "string":
                if cur_attr.get("name"):
                    return cur_attr["name"]
                if cur_attr.get("code"):
                    return cur_attr["code"]
            elif cur_attr["type"] == "integer":
                return str(cur_attr["code"])

            out_edges = self.get_out_edges(cur_node, edge_type="PARENT_OF")
            out_nodes = [(edge[1], cur_depth + 1) for edge in out_edges]
            bfs_queue += out_nodes

        return None

    def is_statement(self, node_id):
        """
        Return wether a node is a statement node of not

        Args:
            node_id: the node_id
        """
        parent_edges = self.get_in_edges(node_id, edge_type="PARENT_OF")
        if parent_edges is None or len(parent_edges) == 0:
            return False
        parent_node = parent_edges[0][0]
        parent_node_attr = self.get_node_attr(parent_node)
        if parent_node_attr.get("type") in ["AST_STMT_LIST"] and parent_node_attr.get("labels:label") != "Artificial_AST":
            return True
        return False

    def find_nearest_upper_CPG_node(self, node_id):
        """
        Return the nearest upper CPG node of the input node.

        A CPG node is defined as a child of a block node
        (AST_STMT_LIST).
        """
        # follow the parent_of edge to research the stmt node
        if node_id in self.nearest_upper_CPG_cache:
            return self.nearest_upper_CPG_cache[node_id]

        ori_node_id = node_id
        result = None
        while True:
            assert node_id is not None
            parent_edges = self.get_in_edges(node_id, edge_type="PARENT_OF")
            if parent_edges is None or len(parent_edges) == 0:
                break
            parent_node = parent_edges[0][0]
            parent_node_attr = self.get_node_attr(parent_node)
            if parent_node_attr.get("type") in [
                "AST_STMT_LIST",
                "AST_JSXChildren",
                "AST_JSXAttributes",
                "AST_JSXAttribute",
            ]:
                result = node_id
                break
            node_id = parent_node

        self.nearest_upper_CPG_cache[ori_node_id] = result
        return result

    def get_all_child_nodes(self, node_id, max_depth=None):
        """
        return a list of child node id, by bfs order
        Args:
            node_id: the node id of the start node

        Return:
            a list of node in bfs order
        """
        bfs_queue = []
        visited = set()
        bfs_queue.append((node_id, 0))

        while len(bfs_queue):
            cur_node, cur_depth = bfs_queue.pop(0)
            if max_depth and cur_depth > max_depth:
                break

            # if visited before, stop here
            if cur_node in visited:
                continue
            else:
                visited.add(cur_node)

            cur_attr = self.get_node_attr(cur_node)

            out_edges = self.get_out_edges(cur_node, edge_type="PARENT_OF")
            out_nodes = [(edge[1], cur_depth + 1) for edge in out_edges]
            bfs_queue += out_nodes

        # sort the set to make it deterministic
        return sorted(visited, key=lambda v: int(v))

    def backtrace_to_function_nodes(self, nodes):
        pass

    # file_path: FULL PATH
    # returns (id, attr)[]
    def get_ast_nodes_by_file_path_and_line_number(self, full_filePath, line_number):
        # TODO: use lineno or namespace?
        line_nodes = [node for node in self.graph.nodes(data=True) if node[1].get("lineno:int") == str(line_number)]
        return_nodes = []
        for line_node in line_nodes:
            node_file_path = self.get_ast_node_file_path(line_node[0])
            # loggers.validate_logger.info(f"node_file_path:  {node_file_path}")
            # loggers.validate_logger.info(f"file_path:  {file_path}")
            if node_file_path == full_filePath:
                return_nodes.append(line_node)

        for return_node in return_nodes:
            node_label = return_node[1]["labels:label"]
            if node_label != "AST":
                raise ValueError("Nodes are not ASTs")
        return return_nodes

    def get_assign_function_node(self):
        pass

    # def get_function_node_ast_id_by_ast_node(self, ast_node_id):
    #     function_node_ast_id = None
    #     node_id = ast_node_id
    #     while True:
    #         in_edges = self.get_in_edges(node_id, edge_type="PARENT_OF")
    #         # TODOS: could there be multiple in edges for one ast node?
    #         if in_edges:
    #             node_id = in_edges[0][0]
    #             node_attr = self.get_node_attr(node_id)
    #             if node_attr.get("type") == "AST_CLOSURE":
    #                 function_node_ast_id = node_id
    #                 break
    #         else:
    #             break
    #     return function_node_ast_id

    def add_ast_node_to_pending_code_slice(self, ast_node_id):
        loggers.code_slice_logger.info(f"added ast node to pending code slice {ast_node_id}")
        ast_node_file_path = self.get_ast_node_file_path(ast_node_id)
        if ast_node_file_path:
            self.pending_code_slice.add_ast_node(ast_node_file_path, ast_node_id)
        else:
            raise ValueError(f"can not find the file path for AST {ast_node_id}")

    def add_ast_node_to_source_function_list(self, ast_node_id):
        ast_node_file_path = self.get_ast_node_file_path(ast_node_id)
        if ast_node_file_path:
            self.pending_code_slice.add_source_function_ast_node(ast_node_file_path, ast_node_id)
        else:
            raise ValueError(f"can not find the file path for AST {ast_node_id}")

    def add_ast_node_to_taint_function_list(self, ast_node_id):
        ast_node_file_path = self.get_ast_node_file_path(ast_node_id)
        if ast_node_file_path:
            self.pending_code_slice.add_taint_function_ast_node(ast_node_file_path, ast_node_id)
        else:
            raise ValueError(f"can not find the file path for AST {ast_node_id}")

    def add_line_range_to_pending_code_slice(self, file_path, start_line_number, end_line_number):
        self.pending_code_slice.add_line_range(file_path, start_line_number, end_line_number)

    def is_parent_of(self, parent, child, visited=None):
        if visited is None:
            visited = set()

        # Avoid cycles
        if parent in visited:
            return False
        visited.add(parent)

        # Get direct children of the current parent
        child_edges = self.get_out_edges(parent, True, edge_type="PARENT_OF")
        loggers.code_slice_logger.info(f"Checking children of {parent}: {child_edges}")

        for e in child_edges:
            c = e[1]
            # If we find the child directly or through recursion
            if c == child or self.is_parent_of(c, child, visited):
                return True

        return False

    def generate_code_slice(self) -> str:
        code_slices = []
        structured_code_slice = {}

        loggers.code_slice_logger.info(f"Ready to generate code slice from nodes: {pprint.pformat(self.pending_code_slice.file_path_and_nodes)}")

        all_file_paths = sorted(set(self.pending_code_slice.file_path_and_nodes.keys()) | set(self.pending_code_slice.file_path_and_line_ranges.keys()))

        for file_path in all_file_paths:
            import_nodes = self.get_import_ndoes_by_file_path(file_path)
            if options.slice_imports:
                for n in import_nodes:
                    self.add_ast_node_to_pending_code_slice(n[0])
            taint_function_nodes = self.pending_code_slice.file_path_and_taint_function_nodes.get(file_path, set())
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")
                continue

            # Collect ranges from AST nodes
            ast_ranges = []

            # for validation
            # pending_ast_nodes = None
            # if len(vul_paths) == 0 and taint_function_nodes:
            #     pending_ast_nodes = taint_function_nodes
            # else:
            #     pending_ast_nodes = self.pending_code_slice.file_path_and_nodes.get(file_path, [])

            pending_ast_nodes = set(taint_function_nodes) | set(self.pending_code_slice.file_path_and_nodes.get(file_path, set()))

            loggers.code_slice_logger.info(f"pending_ast_nodes:  {file_path} {pending_ast_nodes}")
            for ast_node in pending_ast_nodes:
                node_attr = self.get_node_attr(ast_node)
                start = int(node_attr["lineno:int"])
                end = int(node_attr["endlineno:int"])
                if start <= end:
                    ast_ranges.append((start, end))
                else:
                    raise ValueError("AST node line number range error")

            # Collect ranges from explicitly added line ranges
            explicit_ranges = self.pending_code_slice.file_path_and_line_ranges.get(file_path, [])
            loggers.code_slice_logger.info(f"explicit_ranges:  {explicit_ranges}")
            loggers.code_slice_logger.info(f"ast_ranges:  {ast_ranges}")
            all_ranges = ast_ranges + explicit_ranges
            all_ranges.sort()
            loggers.code_slice_logger.info(f"[Code Slice Generation Raw] {file_path} {pprint.pformat(all_ranges)}")

            # Merge overlapping or adjacent ranges
            merged = []
            for start, end in all_ranges:
                if not merged or start > merged[-1][1] + 1:
                    merged.append([start, end])
                else:
                    merged[-1][1] = max(merged[-1][1], end)

            loggers.code_slice_logger.info(f"[Code Slice Generation] {file_path} {pprint.pformat(merged)}")

            # Generate relative display path
            display_path = file_path
            if options.avr_app_path and file_path.startswith(options.avr_app_path):
                display_path = os.path.relpath(file_path, options.avr_app_path)

            file_slice = [f"// <FILE>: {display_path}\n"]
            structured_code_slice[display_path] = []

            loggers.code_slice_logger.info(f"merged:  {merged}")
            for start, end in merged:
                code_lines = lines[start - 1 : end]
                if not code_lines:  # happens when using added lines
                    continue
                file_slice.append("// <SLICE_START>\n")
                file_slice.extend(code_lines)
                if not code_lines[-1].endswith("\n"):
                    file_slice.append("\n// <SLICE_END>\n")
                else:
                    file_slice.append("// <SLICE_END>\n")
                structured_code_slice[display_path].append({"start_line": start, "end_line": end, "code": "".join(code_lines)})

            code_slices.append("".join(file_slice))

        printed_code_slice = "\n".join(code_slices)

        if not options.avr_app_path:
            raise ValueError("options.avr_app_path is not set")

        output_path = os.path.abspath(os.path.normpath(os.path.join(options.avr_app_path, "../..", "printed_code_slice.txt")))
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(printed_code_slice)

        structured_output_path = os.path.abspath(os.path.normpath(os.path.join(options.avr_app_path, "../..", "structured_code_slice.json")))

        with open(structured_output_path, "w", encoding="utf-8") as f:
            json.dump(structured_code_slice, f, indent=2)

        print(f"Code slice written to: {output_path}")
        print(f"Structured code slice written to: {structured_output_path}")
        return output_path

    def generate_taint_function_list(self):
        all_file_paths = sorted(set(self.pending_code_slice.file_path_and_taint_function_nodes.keys()))
        loggers.code_slice_logger.info(f"all_file_paths:  {all_file_paths}")
        source_function_ast_nodes = []
        for file_path in all_file_paths:
            display_path = file_path
            if options.avr_app_path and file_path.startswith(options.avr_app_path):
                display_path = os.path.relpath(file_path, options.avr_app_path)
            # Collect ranges from AST nodes
            for ast_node in self.pending_code_slice.file_path_and_taint_function_nodes.get(file_path, []):
                node_attr = self.get_node_attr(ast_node)
                start = int(node_attr["lineno:int"])
                end = int(node_attr["endlineno:int"])
                loggers.code_slice_logger.info(f"ast_node here:  {ast_node} {node_attr}")
                loggers.code_slice_logger.info(f"add taint function:  {ast_node} {node_attr}")
                source_function_ast_nodes.append(
                    {
                        "id": ast_node,
                        "file_path": display_path,
                        "node_attr": node_attr,
                    }
                )
        return source_function_ast_nodes

    def get_import_ndoes_by_file_path(self, full_file_path):
        import_nodes = self.get_nodes_by_type("AST_ImportDeclaration")
        filtered_nodes = []

        for n in import_nodes:
            loggers.code_slice_logger.info(f"n:  {n}")
            if self.get_ast_node_file_path(n[0]) == full_file_path:
                filtered_nodes.append(n)
                loggers.code_slice_logger.info(f"n and file_path:  {full_file_path}")

        deduped_nodes = list({n[0]: n for n in filtered_nodes}.values())
        return deduped_nodes

    def generate_source_function_list(self):
        all_file_paths = sorted(set(self.pending_code_slice.file_path_and_source_function_nodes.keys()))
        loggers.code_slice_logger.info(f"all_file_paths:  {all_file_paths}")

        source_function_ast_nodes = []
        source_statement_ast_nodes = []
        if not all_file_paths:
            if len(self.pending_code_slice.file_path_and_nodes) == 0 and len(self.pending_code_slice.file_path_and_line_ranges) != 0:
                for file_path, line_ranges in self.pending_code_slice.file_path_and_line_ranges.items():
                    for line_range in line_ranges:
                        start_line = line_range[0]
                        end_line = line_range[0]
                        for line in range(start_line, end_line + 1):
                            ast_nodes = self.get_ast_nodes_by_file_path_and_line_number(file_path, line_number=line)
                            for ast_node in ast_nodes:
                                source_statement_ast_nodes.append(ast_node)
                            loggers.code_slice_logger.info(f"ast_nodes:  {ast_nodes}")
                    loggers.code_slice_logger.info(f"line_ranges:  {line_ranges}")
                    loggers.code_slice_logger.info(f"file_path:  {file_path}")

        else:
            for file_path in all_file_paths:
                display_path = file_path
                if options.avr_app_path and file_path.startswith(options.avr_app_path):
                    display_path = os.path.relpath(file_path, options.avr_app_path)

                # Collect ranges from AST nodes
                for ast_node in self.pending_code_slice.file_path_and_source_function_nodes.get(file_path, []):
                    node_attr = self.get_node_attr(ast_node)
                    start = int(node_attr["lineno:int"])
                    end = int(node_attr["endlineno:int"])
                    loggers.code_slice_logger.info(f"ast_node here:  {ast_node} {node_attr}")
                    loggers.code_slice_logger.info(f"add source function:  {ast_node} {node_attr}")
                    source_function_ast_nodes.append(
                        {
                            "id": ast_node,
                            "file_path": display_path,
                            "node_attr": node_attr,
                        }
                    )
                    loggers.code_slice_logger.info(f"source_function_ast_nodes:  {source_function_ast_nodes}")
                # Generate relative display path
                display_path = file_path
                if options.avr_app_path and file_path.startswith(options.avr_app_path):
                    display_path = os.path.relpath(file_path, options.avr_app_path)

        if not options.avr_app_path:
            raise ValueError("options.avr_app_path is not set")

        self.vul_graph_info["source_function_list"] = source_function_ast_nodes
        return source_function_ast_nodes

    def backward_forward_analysis_by_functions(self, function_ast_node_id):
        if not function_ast_node_id:
            raise ValueError("backward analysis function ast id is not provided")

        loggers.code_slice_logger.info(f"backward analysis for func ast id: {function_ast_node_id}")
        visited = set()
        queue = [function_ast_node_id]
        queued = {function_ast_node_id}

        is_first_node_source_func = self.get_is_source_func(function_ast_node_id)
        # The first node is source
        if is_first_node_source_func:
            file_path = self.get_ast_node_file_path(function_ast_node_id)
            self.add_ast_node_to_pending_code_slice(function_ast_node_id)
            self.add_ast_node_to_source_function_list(function_ast_node_id)
            loggers.code_slice_logger.info(f"{function_ast_node_id} is source func. added")
            return
        else:
            loggers.code_slice_logger.info(f"{function_ast_node_id} is not source fun, started backward analysis")

        # traceback through call edges
        while queue:
            current_node_id = queue.pop(0)
            visited.add(current_node_id)

            file_path = self.get_ast_node_file_path(current_node_id)
            caller_edges = self.get_in_edges(current_node_id, edge_type="CALLS")
            caller_func_ids = [e[0] for e in caller_edges]
            caller_func_ids.sort()

            parent_edges = self.get_in_edges(current_node_id, edge_type="PARENT_OF")
            for parent_edge in parent_edges:
                loggers.code_slice_logger.info(f"parent_edge:  {parent_edge}")
                parent_node = parent_edge[0]
                caller_func_ids.append(parent_node)

            if not caller_func_ids:
                # current_node_id is the last caller function
                loggers.code_slice_logger.info(f"[Backward Analysis] No caller function for {current_node_id}. Backward analysis ends.")
                self.add_ast_node_to_source_function_list(current_node_id)
            else:
                loggers.code_slice_logger.info(f"caller_edges for {current_node_id}:  {caller_func_ids}")
                for caller_node_ast_id in caller_func_ids:
                    caller_file_path = self.get_ast_node_file_path(caller_node_ast_id)
                    caller_node_ast_attr = self.get_node_attr(caller_node_ast_id)
                    # if caller_node_ast_attr.get("type") == "AST_TOPLEVEL" and caller_node_ast_attr.get("flags:string[]") == "TOPLEVEL_FILE":
                    #     loggers.code_slice_logger.info(f"SKIP {caller_node_ast_attr} for backward analysis")
                    #     continue
                    # if caller_node_ast_attr.get("type") == "AST_STMT_LIST":
                    #     loggers.code_slice_logger.info(f"SKIP {caller_node_ast_attr} for backward analysis")
                    #     continue
                    # if caller_node_ast_attr.get("type") == "AST_ARG_LIST":
                    #     loggers.code_slice_logger.info(f"SKIP {caller_node_ast_attr} for backward analysis")
                    #     continue
                    start = int(caller_node_ast_attr["lineno:int"])
                    if caller_node_ast_attr.get("type") not in ["AST_FUNC_DECL", "AST_CLOSURE", "AST_METHOD"]:
                        loggers.code_slice_logger.info(f"SKIP {caller_node_ast_attr} for backward analysis")
                        continue
                    end = int(caller_node_ast_attr["endlineno:int"])
                    loggers.code_slice_logger.info(f"caller for {current_node_id} is: {caller_node_ast_id} {caller_file_path} {start} - {end} ")
                    is_source_func = self.get_is_source_func(caller_node_ast_id)

                    caller_node_ast_attr = self.get_node_attr(caller_node_ast_id)
                    loggers.code_slice_logger.info(f"caller node ast attr:  {caller_node_ast_id} {caller_node_ast_attr}")

                    func_decl_types = ["AST_FUNC_DECL", "AST_CLOSURE", "AST_METHOD"]
                    if caller_node_ast_attr.get("type") in func_decl_types:
                        self.add_ast_node_to_pending_code_slice(caller_node_ast_id)

                    if is_source_func:
                        self.add_ast_node_to_source_function_list(caller_node_ast_id)

                    # until the source func is reached
                    if (not is_source_func) and (caller_node_ast_id not in visited) and (caller_node_ast_id not in queued):
                        queue.append(caller_node_ast_id)
                        queued.add(caller_node_ast_id)

    # AVR
    def get_all_tainted_nodes(self):
        tainted_nodes = []
        obj_nodes = self.get_nodes_by_type("object")
        for obj_node in obj_nodes:
            obj_node_id = obj_node[0]
            obj_node_attr = self.get_node_attr(obj_node_id)
            if obj_node_attr.get("tainted") == True:
                tainted_nodes.append(obj_node_id)
        tainted_nodes.sort()
        loggers.validate_logger.info(f"tainted_nodes:  {tainted_nodes}")
        return tainted_nodes

    def path_to_line_number(self, path):
        line_number_path = []
        for node in path:
            node_attr = self.get_node_attr(node)
            node_type = node_attr.get("type")
            node_label = node_attr.get("labels:label")
            if node_type == "NAMENODE":
                continue

            if node_type == "object" or node_label == "Object":
                # consider other node types
                ast_node = self.get_obj_def_ast_node(node)
            else:
                raise ValueError(f"cannot find AST for {node} {node_type}  {node_attr}")

            if not ast_node:
                continue
            ast_node_attr = self.get_node_attr(ast_node)
            # "SCOPE_TO_AST" # JSX_TO_AST
            file_path = self.get_ast_node_file_path(ast_node)
            line_number = ast_node_attr.get("lineno:int")
            line_number_path.append((file_path, line_number))
        return line_number_path

    def get_func_args_obj_nodes_by_func_ast_id(self, func_ast_id, set_tainted=False):
        from src.plugins.internal.handlers.functions import call_function, run_exported_functions, ast_call_function

        func_args_obj_nodes = []
        obj_nodes = self.get_func_decl_objs_by_ast_node(func_ast_id)
        loggers.validate_logger.info(f"func_ast_id:  {func_ast_id}")
        loggers.validate_logger.info(f"obj_ndoes:  {obj_nodes}")
        if obj_nodes:
            for o in obj_nodes:
                if self.get_node_attr(o).get("type") == "function":
                    loggers.code_slice_logger.info(f"calling func:  {o} AST {func_ast_id}")
                    loggers.validate_logger.info(f"calling func:  {o} AST {func_ast_id}")
                    if set_tainted == True:
                        run_exported_functions(self, [o], None, mark_fake_args=True)
                        exported_nodes_file_path = os.path.join(options.log_base_location, "nodes.csv")
                        exported_rels_file_path = os.path.join(options.log_base_location, "rels.csv")
                        self.export_to_CSV(exported_nodes_file_path, exported_rels_file_path, light=False)

        function_scopes = self.get_in_edges(func_ast_id, data=True, edge_type="SCOPE_TO_AST")
        loggers.validate_logger.info(f"function_scopes:  {function_scopes}")
        for function_scope in function_scopes:
            func_scope_node_id = function_scope[0]
            function_arguments = self.get_out_edges(func_scope_node_id, edge_type="SCOPE_TO_VAR")
            for func_argument in function_arguments:
                func_arg_name_node_id = func_argument[1]
                func_arg_obj_nodes = self.get_objs_by_name_node(func_arg_name_node_id)
                for func_arg_obj_node in func_arg_obj_nodes:
                    func_arg_obj_node_attr = self.get_node_attr(func_arg_obj_node)
                    if func_arg_obj_node_attr.get("tainted") == True:
                        func_args_obj_nodes.append(func_arg_obj_node)
        return func_args_obj_nodes

    def get_is_source_func(self, func_ast_id):
        func_decl_types = ["AST_FUNC_DECL", "AST_CLOSURE", "AST_METHOD"]
        func_ast_attr = self.get_node_attr(func_ast_id)
        if func_ast_attr.get("type") not in func_decl_types:
            return False

        function_scopes = self.get_in_edges(func_ast_id, data=True, edge_type="SCOPE_TO_AST")
        for function_scope in function_scopes:
            func_scope_node_id = function_scope[0]
            function_arguments = self.get_out_edges(func_scope_node_id, edge_type="SCOPE_TO_VAR")
            for func_argument in function_arguments:
                func_arg_name_node_id = func_argument[1]
                func_arg_obj_nodes = self.get_objs_by_name_node(func_arg_name_node_id)
                for func_arg_obj_node in func_arg_obj_nodes:
                    func_arg_obj_node_attr = self.get_node_attr(func_arg_obj_node)
                    if func_arg_obj_node_attr.get("tainted") == True:
                        return True
        return False

    def get_function_decl_ast_nodes(self):
        func_decl_ast_nodes = []
        func_decl_types = ["AST_FUNC_DECL", "AST_CLOSURE", "AST_METHOD"]
        for t in func_decl_types:
            nodes = self.get_nodes_by_type_and_label(t, "AST")
            func_decl_ast_nodes.extend(nodes)
        return sorted(set(func_decl_ast_nodes))

    def get_function_node_by_file_name_and_line_number(self, file_name, start_line_number, end_line_number):
        matched_nodes = []
        func_nodes = self.get_function_decl_ast_nodes()
        for func_node in func_nodes:
            func_node_attr = self.get_node_attr(func_node)
            # loggers.validate_logger.info(f"func_node_attr:  {func_node} {func_node_attr}")
            if func_node_attr.get("lineno:int") == str(start_line_number) and func_node_attr.get("endlineno:int") == str(end_line_number):
                file_path = self.get_ast_node_file_path(func_node)
                loggers.validate_logger.info(f"file_path here:  {file_path} {file_name}")
                if file_path == file_name:
                    matched_nodes.append(func_node)
        unique_sorted_nodes = sorted(set(matched_nodes))
        return unique_sorted_nodes

    def get_function_node_by_function_name_and_file_name(self, function_name, file_name):
        pass

    # React.js Nodes
    def add_jsx_props_node(self, component_node=None, scope=None, ast_node=None):
        if not scope:
            scope = self.cur_scope

        props_obj_node = self.add_obj_node(ast_node=ast_node, js_type="object")

        self.add_jsx_data_flow_edge(component_node, props_obj_node)
        loggers.main_logger.info(f"React.js Added Props Node {props_obj_node} for {component_node}")

        # only for debugging
        self.set_node_attr(props_obj_node, (JSX_Label_Key, JSX_Labels.JSX_Props))
        if ast_node is not None:
            self.add_edge(props_obj_node, ast_node, {"type:TYPE": "OBJ_TO_AST"})

        return props_obj_node

    def get_jsx_props_node(self, component_node=None, scope=None, ast_node=None):
        component_props_nodes = self.get_child_nodes(component_node, "JSX_DATA_FLOW")
        if len(component_props_nodes) > 1:
            raise ValueError(f"Component {component_node} has more than one JSX_DATA_FLOW children:  {component_props_nodes}")
        if component_props_nodes and component_props_nodes[0]:
            return component_props_nodes[0]
        return None

    def get_or_add_jsx_props_node(self, component_node=None, scope=None, ast_node=None):
        component_props_nodes = self.get_child_nodes(component_node, "JSX_DATA_FLOW")
        if len(component_props_nodes) > 1:
            raise ValueError(f"Component {component_node} has more than one JSX_DATA_FLOW children:  {component_props_nodes}")
        if component_props_nodes and component_props_nodes[0]:
            return component_props_nodes[0]
        else:
            return self.add_jsx_props_node(component_node, scope, ast_node)

    def is_component_def(self, func_def_ast_node=None):
        stmt_list = self.get_child_nodes(func_def_ast_node, child_type="AST_STMT_LIST")
        if not stmt_list:
            return False
        ast_return = self.get_child_nodes(stmt_list[0], child_type="AST_RETURN")
        if not ast_return:
            return False
        returned_children = self.get_ordered_ast_child_nodes(ast_return[0])
        if not returned_children:
            return False
        first_returned_element = returned_children[0]
        if not first_returned_element:
            return False
        first_returned_element_attr = self.get_node_attr(first_returned_element)
        if first_returned_element_attr["type"] in ["AST_JSXElement"]:
            return True

    def get_func_return_ast_nodes_by_func_id(self, func_def_ast_node):
        if not func_def_ast_node:
            raise ValueError("func_def_ast_node should be string")
        loggers.validate_logger.info(f"func_def_ast_node:  {func_def_ast_node}")
        stmt_list = self.get_child_nodes(func_def_ast_node, child_type="AST_STMT_LIST")
        loggers.validate_logger.info(f"stmt_list:  {stmt_list}")
        ast_return_nodes = []

        def dfs(func_id):
            ast_child_nodes = self.get_ordered_ast_child_nodes(func_id)
            for ast_child_node in ast_child_nodes:
                if self.get_node_attr(ast_child_node).get("type") == "AST_RETURN":
                    ast_return_nodes.append(ast_child_node)
                else:
                    dfs(ast_child_node)

        dfs(func_def_ast_node)
        return ast_return_nodes

    def get_component_name(self, comp_def_obj=None):
        component_name = None
        obj_name_nodes = self.get_name_nodes_to_obj(comp_def_obj)
        for obj_name_node in obj_name_nodes:
            obj_name_node_attr = self.get_node_attr(obj_name_node)
            if obj_name_node_attr["name"] == "ES6_export_default" or obj_name_node_attr["name"] == "ES6_export_named":
                continue
            component_name = obj_name_node_attr["name"]
            break
        return component_name

    def get_component_node_by_name(self, name=None):
        name_nodes = self.get_node_by_attr("name", name)
        jsx_component_nodes = self.get_node_by_attr("labels:label", "JSX_Component")
        intersection = [value for value in name_nodes if value in jsx_component_nodes]
        return intersection[0]

    def get_all_jsx_component_nodes(self):
        jsx_component_nodes = self.get_node_by_attr("labels:label", "JSX_Component")
        return jsx_component_nodes

    def get_jsx_props_node_by_component_node(self, comp_node):
        tmp_edge = self.get_out_edges(comp_node, data=True, keys=True, edge_type=JSX_Edges.JSX_DATA_FLOW)

        if not tmp_edge:
            loggers.main_logger.warn(f"Couldn't find the props node for comp: {comp_node}")
            return None
        return tmp_edge[0][1]

    def get_jsx_comp_tree_snapshot(self):
        props_snapshot = {}
        all_jsx_comp_nodes = self.get_all_jsx_component_nodes()
        for jsx_comp in all_jsx_comp_nodes:
            props_node = self.get_jsx_props_node_by_component_node(jsx_comp)
            if props_node:
                props_obj_nodes = self.get_prop_obj_nodes(parent_obj=props_node)
                props_snapshot[jsx_comp] = set(props_obj_nodes)
        return props_snapshot

    def diff_snapshots(self, snapshot1, snapshot2):
        differences = set()

        for key in snapshot1:
            if key in snapshot2 and snapshot1[key] != snapshot2[key]:
                differences.add(key)

        return list(differences)

    def is_state_updated(self, objs1, objs2):
        updated = False

        if len(objs1) != len(objs2):
            updated = True

        for i in range(0, len(objs1) - 1):
            if objs1[i] != objs2[i]:
                updated = True
                break

        return updated

    def add_jsx_component_node(self, ast_node=None, name=None):
        """
        Add a React.js component node

        Args:
            ast_node (optional): The corresponding AST node.
                Defaults to None.
            name (str, optional): Name of a Component.

        Returns:
            Added object node's node id.
        """
        comp_node = str(self._get_new_nodeid())
        self.add_node(comp_node)
        self.set_node_attr(comp_node, ("labels:label", "JSX_Component"))
        self.set_node_attr(comp_node, ("name", name))
        self.set_node_attr(comp_node, ("type", "jsx"))

        if ast_node is not None:
            self.add_edge(comp_node, ast_node, {"type:TYPE": "JSX_TO_AST"})

        loggers.main_logger.info(f"added JSX Component Node {name} {comp_node}")
        return comp_node

    def add_dom_node(self, ast_node=None, name=None):
        """
        Add a React.js DOM node

        Args:
            ast_node (optional): The corresponding AST node.
                Defaults to None.
            name (str, optional): Name of a Component.

        Returns:
            Added object node's node id.
        """
        dom_node = str(self._get_new_nodeid())
        self.add_node(dom_node)
        self.set_node_attr(dom_node, ("labels:label", "JSX_DOM"))
        self.set_node_attr(dom_node, ("name", name))
        self.set_node_attr(dom_node, ("type", "jsx"))

        if ast_node is not None:
            self.add_edge(dom_node, ast_node, {"type:TYPE": "JSX_TO_AST"})

        loggers.main_logger.info(f"added JSX DOM Node {name} {dom_node}")
        return dom_node

    def add_jsx_attribute_node(self, ast_node=None, attr_name=None):
        """
        Add a JSX Attribute Node

        Args:
            ast_node (optional): The corresponding AST node.
                Defaults to None.
            name (str, optional): Name of a Component.

        Returns:
            Added object node's node id.
        """
        attr_node = str(self._get_new_nodeid())
        self.add_node(attr_node)
        self.set_node_attr(attr_node, ("labels:label", "JSX_Attribute"))
        self.set_node_attr(attr_node, ("name", attr_name))
        self.set_node_attr(attr_node, ("type", "jsx"))

        if ast_node is not None:
            self.add_edge(attr_node, ast_node, {"type:TYPE": "JSX_TO_AST"})

        self.logger.log(ATTENTION, f"Added JSX Attribute Node Name: {attr_name} Node: {attr_node}")
        return attr_node

    # React.js Edges

    def add_jsx_data_flow_edge(self, from_ID, to_ID, attr={}):
        self.logger.log(ATTENTION, f"Added JSX Data Flow Edge From {from_ID} to {to_ID}, {JSX_Edges.JSX_DATA_FLOW}")
        return self.add_edge_if_not_exist(from_ID, to_ID, {**attr, "type:TYPE": JSX_Edges.JSX_DATA_FLOW})

    def add_jsx_parent_of_edge(self, from_ID, to_ID, attr={}):
        self.logger.log(ATTENTION, f"Added JSX Parent Of Edge From {from_ID} to {to_ID}, type: {JSX_Edges.JSX_PARENT_OF}")
        return self.add_edge_if_not_exist(from_ID, to_ID, {**attr, "type:TYPE": JSX_Edges.JSX_PARENT_OF})

    def add_jsx_component_def_edge(self, comp_node, def_node, attr={}):
        self.logger.log(
            ATTENTION,
            f"Added JSX COMPONENT_DEF Edge From {comp_node} to {def_node}, type: {JSX_Edges.JSX_COMPONENT_DEF}",
        )
        return self.add_edge_if_not_exist(comp_node, def_node, {**attr, "type:TYPE": JSX_Edges.JSX_COMPONENT_DEF})

    def get_jsx_component_def_node(self, component_node):
        edges = self.get_out_edges(component_node, edge_type=JSX_Edges.JSX_COMPONENT_DEF)
        if edges:
            return edges[0][1]
        else:
            return None

    def get_ast_parent_node(self, node_id):
        """
        return AST children of a node in childnum order
        """
        parent_ast_node = self.get_in_edges(node_id, edge_type="PARENT_OF")[0][0]

        return parent_ast_node

    def get_jsx_def_ast_node(self, jsx_node):
        """
        Find where in the AST an object (especially a function) is
        defined.

        The AST node is the successor of the object node via the
        OBJ_TO_AST edge.
        """
        tmp_edge = self.get_out_edges(jsx_node, data=True, keys=True, edge_type="JSX_TO_AST")

        if not tmp_edge:
            loggers.main_logger.info(f"Couldn't find the JSX_TO_AST Edge for node: {jsx_node}")
            return None

        return tmp_edge[0][1]

    def get_import_declaration_source(self, ast_node):
        children_ast_nodes = self.get_ordered_ast_child_nodes(ast_node)
        source = children_ast_nodes[0]
        source_attr = self.get_node_attr(source)
        return source_attr

    def get_import_declaration_specifier_list(self, ast_node):
        children_ast_nodes = self.get_ordered_ast_child_nodes(ast_node)
        return [self.get_node_attr(node) for node in children_ast_nodes[1:]]

    def get_import_declaration_specifier_ast_list(self, ast_node):
        children_ast_nodes = self.get_ordered_ast_child_nodes(ast_node)
        # The first node is source
        return [node for node in children_ast_nodes[1:]]

    # React.js traversals
    def get_edges_by_type_list(self, edge_type_list=[]):
        """
        return the edges with specific types
        """
        if not isinstance(edge_type_list, list) or not edge_type_list:
            raise ValueError("edge_type_list must be a non-empty list")

        subEdges = [edge for edge in self.graph.edges(data=True, keys=True) if edge[3]["type:TYPE"] in edge_type_list]
        return subEdges

    def get_sub_graph_by_edge_type_list(self, edge_type_list):
        """
        only keep edges with specific edge types
        return a sub graph
        """
        subEdges = self.get_edges_by_type_list(edge_type_list)
        return nx.MultiDiGraph(subEdges)

    def get_in_edges_by_edge_type_list(self, node_id, data=True, keys=True, edge_type_list=[]):
        assert node_id is not None
        self.op_cnt["get_edge"] += 1
        edges = self.graph.in_edges(node_id, data=data, keys=keys)
        idx = 2
        if keys == True:
            idx = 3
        return [edge for edge in edges if "type:TYPE" in edge[idx] and edge[idx]["type:TYPE"] in edge_type_list]

    def get_out_edges_by_edge_type_list(self, node_id, data=True, keys=True, edge_type_list=[]):
        assert node_id is not None
        self.op_cnt["get_edge"] += 1
        edges = self.graph.out_edges(node_id, data=data, keys=keys)
        idx = 2
        if keys == True:
            idx = 3
        return [edge for edge in edges if "type:TYPE" in edge[idx] and edge[idx]["type:TYPE"] in edge_type_list]

    def dfs_down_for_validatation(self, source=None, filter_by_sink=True):
        """
        DFS from a node ID by specific types of edges.

        Args:
            source: the start node ID
        Returns:
            List of paths, each path is a list of node IDs.
        """
        if source is None:
            raise ValueError("dfs source is not specified.")

        out_edge_type_list = ["CONTRIBUTES_TO", JSX_Edges.JSX_DATA_FLOW]
        prop_edge_type_list = ["OBJ_TO_PROP", "NAME_TO_OBJ"]
        in_edge_type_list = ["NAME_TO_OBJ"]

        backup_graph = self.graph
        paths = []
        depth_limit = len(self.graph)

        def is_filtered_node(node_id):
            node_attr = self.get_node_attr(node_id)
            if "name" in node_attr and node_attr["name"] in {"__proto__", "constructor", "prototype", "length"}:
                return True
            if "code" in node_attr and isinstance(node_attr["code"], str) and node_attr["code"] == "prototype":
                return True
            return False

        def dfs(node, depth, path):
            if depth <= 0:
                return

            out_edges = self.get_out_edges_by_edge_type_list(node, edge_type_list=out_edge_type_list)
            next_nodes = set(edge[1] for edge in out_edges)

            if not next_nodes:
                # fallback to property edges
                prop_edges = self.get_out_edges_by_edge_type_list(node, edge_type_list=prop_edge_type_list)
                fallback_nodes = set()
                for edge in prop_edges:
                    if edge[3].get("type:TYPE") not in prop_edge_type_list:
                        continue
                    target = edge[1]
                    if is_filtered_node(target):
                        continue
                    if target in path:
                        continue
                    fallback_nodes.add(target)

                if not fallback_nodes:
                    paths.append(path + [node])
                else:
                    for next_node in fallback_nodes:
                        dfs(next_node, depth - 1, path + [node])
            else:
                for next_node in next_nodes:
                    if next_node in path:
                        continue
                    dfs(next_node, depth - 1, path + [node])

        dfs(source, depth_limit, [])

        paths.sort(key=lambda x: -len(x))

        # # for visualization, if the last node is a NAMENODE, remove it from the path
        # for i in range(len(paths)):
        #     path = paths[i]
        #     last_node = path[-1]
        #     last_node_attr = self.get_node_attr(last_node)
        #     if "type" in last_node_attr and last_node_attr["type"] == "NAMENODE":
        #         paths[i].pop()

        unique_pathes = set(tuple(path) for path in paths)
        paths = [list(path) for path in unique_pathes]

        loggers.code_slice_logger.info(f"vul paths before filtering by sink:  {paths}")
        loggers.validate_logger.info(f"vul paths before filtering by sink:  {paths}")

        has_sink_paths = []
        for path in paths:
            path_has_sink = False
            loggers.code_slice_logger.info("path start --------------------")
            loggers.code_slice_logger.info(f"{path}")

            for node in path:
                node_attr = self.get_node_attr(node)
                loggers.validate_logger.info(f"node_attr: {node} {node_attr}")
                loggers.code_slice_logger.info(f"node_attr: {node} {node_attr}")

            last_node = path[-1]
            last_node_attr = self.get_node_attr(last_node)
            loggers.validate_logger.info(f"last_node_attr db:  {last_node_attr}")
            last_node_ast = self.get_obj_def_ast_node(last_node)
            loggers.code_slice_logger.info(f"last_node_ast:  {last_node_ast}")
            if not last_node_ast:
                continue
            last_node_ast_attr = self.get_node_attr(last_node_ast)

            loggers.code_slice_logger.info(f"last_node_ast_attr:  {last_node_ast_attr}")
            loggers.validate_logger.info(f"last_node_ast_attr:  {last_node_ast_attr}")

            if last_node_ast_attr.get("type") == "AST_CALL":
                func_name = self.get_name_from_child(last_node_ast)
                if func_name and func_name.startswith("sink_hqbpillvul"):
                    path_has_sink = True
            if path_has_sink:
                has_sink_paths.append(path)
        self.graph = backup_graph
        if filter_by_sink:
            return has_sink_paths
        else:
            return paths

    def _dfs_upper_by_multi_edge_types(self, source=None, edge_type_list=[], depth_limit=None):
        """
        dfs from a node id by specific types of edges

        Args:
            source: the start node id
            edge_types: we only consider some types of edge types
        Return:
            nodes: list, nodes on the pathes, sorted by the length of the path
        """
        G = self.graph
        pathes = []
        start = source
        if source is None:
            raise ValueError("dfs source is not specified.")
        if depth_limit is None:
            depth_limit = len(G)
        # we do not have a global visited
        # each path, or stack should have a visited list but not global
        """
        if start in visited:
            continue
        visited.add(start)
        """
        # we do dfs on top of sub-graphs to save time
        sub_graph = self.get_sub_graph_by_edge_type_list(edge_type_list)

        backup_graph = self.graph
        # self.graph = sub_graph

        in_edge_type_list = ["CONTRIBUTES_TO", JSX_Edges.JSX_DATA_FLOW]
        out_edge_type_list = ["OBJ_TO_PROP", "NAME_TO_OBJ"]

        edge_group = self.get_in_edges_by_edge_type_list(start, edge_type_list=in_edge_type_list)
        nodes_group = set([edge[0] for edge in edge_group])

        if len(nodes_group) == 0:
            # we only have 1 start node, just return this node
            self.graph = backup_graph
            return [[start]]

        stack = [(start, depth_limit, iter(nodes_group))]
        visited = set()
        visited.add(start)
        while stack:
            parent, depth_now, children = stack[-1]
            try:
                child = next(children)
                if child not in [s[0] for s in stack]:
                    if child in visited:
                        continue
                    visited.add(child)
                    if depth_now > 1:
                        edge_group = self.get_in_edges_by_edge_type_list(child, edge_type_list=in_edge_type_list)
                        nodes_group = set([edge[0] for edge in edge_group])
                        if len(nodes_group) == 0:
                            out_edge_group = self.get_out_edges_by_edge_type_list(child, edge_type_list=out_edge_type_list)
                            out_nodes_group = set()
                            for edge in [edge for edge in out_edge_group if edge[3].get("type:TYPE") in out_edge_type_list]:
                                node_attr = self.get_node_attr(edge[1])
                                if "name" in node_attr and (node_attr["name"] == "__proto__" or node_attr["name"] == "constructor"):
                                    continue
                                if "code" in node_attr and isinstance(node_attr["code"], str) and ("prototype" == node_attr["code"]):
                                    continue
                                if edge[1] in visited:
                                    continue
                                out_nodes_group.add(edge[1])
                            stack.append((child, depth_now - 1, iter(out_nodes_group)))
                            if len(out_nodes_group) == 0:
                                new_path = [node[0] for node in stack]
                                str_pathes = [str(p) for p in pathes]
                                if str(new_path) not in str_pathes:
                                    pathes.append(new_path)
                        else:
                            stack.append((child, depth_now - 1, iter(nodes_group)))
            except StopIteration:
                poped = stack.pop()
                visited.remove(poped[0])
        pathes.sort(key=lambda x: -len(x))

        # for visualization, if the last node is a NAMENODE, remove it from the path
        for i in range(len(pathes)):
            path = pathes[i]
            last_node = path[-1]
            last_node_attr = self.get_node_attr(last_node)
            if "type" in last_node_attr and last_node_attr["type"] == "NAMENODE":
                pathes[i].pop()
        unique_pathes = set(tuple(path) for path in pathes)
        pathes = [list(path) for path in unique_pathes]

        self.graph = backup_graph
        return pathes

    # Object graph
    # name nodes and object nodes

    def add_obj_node(self, ast_node=None, js_type="object", value=None):
        """
        Add an object node (including literal).

        Args:
            ast_node (optional): The corresponding AST node.
                Defaults to None.
            js_type (str, optional): JavaScript type. Use None to avoid
                adding prototype (but type is still set to 'object').
                Use 'array' to quickly create an array (type is still
                'object'). Defaults to 'object'.
            value (str, optional): Value of a literal, represented by
                JavaScript code. Defaults to None.

        Returns:
            Added object node's node id.
        """
        obj_node = str(self._get_new_nodeid())
        self.add_node(obj_node)
        self.set_node_attr(obj_node, ("labels:label", "Object"))

        if ast_node is not None:
            self.add_edge(obj_node, ast_node, {"type:TYPE": "OBJ_TO_AST"})

        # Literals' constructors are immutable.
        # Even if you assigned another function to the constructors
        # (e.g. Object = function(){}), objects are still created with
        # original constructors (and prototypes).
        if js_type is None:
            js_type = "object"
        elif js_type == "function":
            self.add_obj_as_prop("prototype", ast_node, "object", parent_obj=obj_node)
            if self.function_prototype is not None:
                # prevent setting __proto__ before setup_object_and_function runs
                self.add_obj_as_prop(prop_name="__proto__", parent_obj=obj_node, tobe_added_obj=self.function_prototype)
                self.add_obj_as_prop(prop_name="constructor", parent_obj=obj_node, tobe_added_obj=self.function_cons)
        elif js_type == "object":
            if self.object_prototype is not None:
                # prevent setting __proto__ before setup_object_and_function runs
                self.add_obj_as_prop(prop_name="__proto__", parent_obj=obj_node, tobe_added_obj=self.object_prototype)
                self.add_obj_as_prop(prop_name="constructor", parent_obj=obj_node, tobe_added_obj=self.object_cons)
                if self.check_proto_pollution and value == wildcard:
                    self.add_obj_as_prop(prop_name="constructor", parent_obj=obj_node, tobe_added_obj=self.array_cons)
                    self.add_obj_as_prop(prop_name="constructor", parent_obj=obj_node, tobe_added_obj=self.number_cons)
        elif js_type == "array":
            # js_type = 'object'     # don't change, keep 'array' type in graph
            if self.array_prototype is not None:
                self.add_obj_as_prop(prop_name="__proto__", parent_obj=obj_node, tobe_added_obj=self.array_prototype)
                self.add_obj_as_prop(prop_name="constructor", parent_obj=obj_node, tobe_added_obj=self.array_cons)
        elif js_type == "string":
            if self.string_prototype is not None:
                # prevent setting __proto__ before setup_object_and_function runs
                self.add_obj_as_prop(prop_name="__proto__", parent_obj=obj_node, tobe_added_obj=self.string_prototype)
                self.add_obj_as_prop(prop_name="constructor", parent_obj=obj_node, tobe_added_obj=self.string_cons)
            if value is None or value == wildcard:
                length = wildcard
            else:
                value = str(value)
                length = len(value)
            self.add_obj_as_prop(prop_name="length", parent_obj=obj_node, js_type="number", value=length)

        self.set_node_attr(obj_node, ("type", js_type))

        if value is not None:
            self.set_node_attr(obj_node, ("code", value))

        return obj_node

    def convert_wildcard_obj_type(self, obj_node, to_type="array"):
        """
        the wildcard obj maybe every type. If we found a wildcard obj is a special type
        we need to convert the obj into the specified type.
        supported type: array
        """
        loggers.main_logger.info(f"convert obj {obj_node} type to {to_type}")
        self.set_node_attr(obj_node, ("type", to_type))

        if to_type == "array":
            type_prototype = self.array_prototype
            type_constructor = self.array_cons

        proto_name_node = self.get_child_nodes(obj_node, child_name="__proto__")
        cons_name_node = self.get_child_nodes(obj_node, child_name="constructor")

        if len(proto_name_node) != 0:
            proto_name_node = proto_name_node[0]
            cur_proto_target = self.get_child_nodes(proto_name_node, "NAME_TO_OBJ")
            if len(cur_proto_target) != 0:
                self.remove_all_edges_between(proto_name_node, cur_proto_target[0])
            self.add_edge_if_not_exist(proto_name_node, type_prototype, {"type:TYPE": "NAME_TO_OBJ"})
        else:
            self.add_obj_as_prop(prop_name="__proto__", parent_obj=obj_node, tobe_added_obj=type_prototype)

        if len(cons_name_node) != 0:
            cons_name_node = cons_name_node[0]
            cur_proto_target = self.get_child_nodes(cons_name_node, "NAME_TO_OBJ")
            if len(cur_proto_target) != 0:
                self.remove_all_edges_between(proto_name_node, cur_proto_target[0])
            self.add_edge_if_not_exist(cons_name_node, type_constructor, {"type:TYPE": "NAME_TO_OBJ"})
        else:
            self.add_obj_as_prop(prop_name="constructor", parent_obj=obj_node, tobe_added_obj=type_constructor)

        if to_type == "array":
            # if the type is array, we should add
            num_added_sub = 3
            if len(self.get_prop_obj_nodes(obj_node, prop_name="0")) == 0:
                # no child under this array node
                for i in range(num_added_sub):
                    added_sub_obj = self.add_obj_as_prop(prop_name=str(i), parent_obj=obj_node)
                    self.set_node_attr(added_sub_obj, ("tainted", True))
                    self.set_node_attr(added_sub_obj, ("code", wildcard))
                    loggers.main_logger.info(f"Adding sub obj {added_sub_obj} {self.get_node_attr(added_sub_obj)} to array {obj_node}")
            self.add_obj_as_prop(prop_name="length", parent_obj=obj_node, value=str(num_added_sub))

    def add_name_node(self, name, scope=None, ast_node=None):
        """
        helper function
        add a namenode to scope
        """
        cur_scope = self.cur_scope
        if scope != None:
            cur_scope = scope

        new_name_node = str(self._get_new_nodeid())
        self.add_node(new_name_node, {"labels:label": "Name", "name": name, "type": "NAMENODE"})
        self.add_edge(cur_scope, new_name_node, {"type:TYPE": "SCOPE_TO_VAR"})
        """
        self.set_node_attr(new_name_node, ('labels:label', 'Name'))
        self.set_node_attr(new_name_node, ('name', name))
        """
        return new_name_node

    def add_prop_name_node(self, name, parent_obj):
        """
        Add an empty name node (without a corresponding object) as a
        property of another object.

        obj -> name node

        For left side of an assignment (such that no dummy object node
        is created).
        """
        new_name_node = str(self._get_new_nodeid())
        self.add_node(new_name_node)
        self.set_node_attr(new_name_node, ("labels:label", "Name"))
        self.set_node_attr(new_name_node, ("name", name))
        self.set_node_attr(new_name_node, ("type", "NAMENODE"))
        self.add_edge_if_not_exist(parent_obj, new_name_node, {"type:TYPE": "OBJ_TO_PROP"})
        return new_name_node

    def add_obj_as_prop(
        self,
        prop_name=None,
        ast_node=None,
        js_type="object",
        value=None,
        parent_obj=None,
        tobe_added_obj=None,
        combined=True,
    ):
        """
        add (or put) an obj as a property of another obj
        parent_obj -> name node -> new obj / tobe_added_obj
        add edge from ast node to obj generation node
        """
        assert parent_obj is not None

        name_node = self.get_prop_name_node(prop_name, parent_obj)

        if name_node is None:
            name_node = self.add_prop_name_node(prop_name, parent_obj)

        if tobe_added_obj is None:
            tobe_added_obj = self.add_obj_node(ast_node, js_type, value)

        self.add_edge(name_node, tobe_added_obj, {"type:TYPE": "NAME_TO_OBJ"})

        if combined and parent_obj == self.BASE_OBJ:
            self.add_obj_to_scope(name=prop_name, scope=self.BASE_SCOPE, tobe_added_obj=tobe_added_obj, combined=False)
        return tobe_added_obj

    def add_obj_to_scope(self, name=None, ast_node=None, js_type="object", value=None, scope=None, tobe_added_obj=None, combined=True):
        """
        add a obj to a scope, if scope is None, add to current scope
        return the added node id
        the edge is: SCOPE_TO_VAR
        """
        if scope == None:
            scope = self.cur_scope

        # check if the name node exists first
        name_node = self.get_name_node(name, scope=scope, follow_scope_chain=False)
        if name_node == None:
            name_node = self.add_name_node(name, scope=scope)
            self.logger.debug(f"{sty.ef.b}Add name node{sty.rs.all} {name} {name_node} in scope {scope}")

        if tobe_added_obj == None:
            # here we do not add obj to current obj when add to scope
            # we just add a obj to scope
            tobe_added_obj = self.add_obj_node(ast_node, js_type, value)

        self.add_edge(name_node, tobe_added_obj, {"type:TYPE": "NAME_TO_OBJ"})

        if combined and scope == self.BASE_SCOPE:
            self.add_obj_as_prop(prop_name=name, parent_obj=self.BASE_OBJ, tobe_added_obj=tobe_added_obj, combined=False)

        return tobe_added_obj

    add_obj_to_name = add_obj_to_scope

    def add_obj_to_name_node(self, name_node, ast_node=None, js_type="object", value=None, tobe_added_obj=None):
        """
        Add a new object (or put a existing object) under a name node.

        name node -> new obj / tobe_added_obj
        """
        if tobe_added_obj is None:
            tobe_added_obj = self.add_obj_node(ast_node, js_type, value)

        self.add_edge(name_node, tobe_added_obj, {"type:TYPE": "NAME_TO_OBJ"})

        return tobe_added_obj

    def get_all_child_name_nodes(self, scope, follow_scope_chain=True, scope_type=None):
        """
        return all the name nodes of a under a scope node
        including only the name nodes that under scopes
        """
        res = set()
        scope_queue = [scope]

        while len(scope_queue) != 0:
            cur_scope = scope_queue.pop()
            var_edges = self.get_out_edges(cur_scope, data=True, keys=True, edge_type="SCOPE_TO_VAR")
            for cur_edge in var_edges:
                res.add(cur_edge[1])
            if not follow_scope_chain:
                break
            scope_edges = self.get_out_edges(cur_scope, data=False, keys=False, edge_type="PARENT_SCOPE_OF")
            scope_queue += [edge[1] for edge in scope_edges]
        return res

    def get_name_node(self, var_name, scope=None, follow_scope_chain=True):
        """
        Get the name node of a name based on scope.
        """
        if scope == None:
            scope = self.cur_scope

        while True:
            var_edges = self.get_out_edges(scope, data=True, keys=True, edge_type="SCOPE_TO_VAR")
            for cur_edge in var_edges:
                cur_var_attr = self.get_node_attr(cur_edge[1])
                if cur_var_attr["name"] == var_name:
                    return cur_edge[1]
            if not follow_scope_chain:
                break
            scope_edges = self.get_in_edges(scope, data=True, keys=True, edge_type="PARENT_SCOPE_OF")
            if len(scope_edges) == 0:
                break
            scope = list(scope_edges)[0][0]
        return None

    def get_objs_by_name_node(self, name_node_id, branches=None):
        """
        Get corresponding object nodes of a name node.

        Args:
            name_node: the name node.
            branches (BranchTagContainer, optional): branch information.
                Default to None.

        Returns:
            list: list of object nodes.
        """
        if name_node_id is None:
            return []
        out_edges = self.get_out_edges(name_node_id, edge_type="NAME_TO_OBJ")
        objs = set([edge[1] for edge in out_edges])
        if branches:
            # initiate a dictionary that records if the object exists in the current branch
            has_obj = {}
            for obj in objs:
                has_obj[obj] = False
            # check edges without branch tag
            for _, obj, _, attr in self.get_out_edges(name_node_id, edge_type="NAME_TO_OBJ"):
                branch_tag = attr.get("branch")
                for_tags = self.get_node_attr(obj).get("for_tags")
                if branch_tag is None:
                    has_obj[obj] = True
            # for each branch in branch history
            # we check from the oldest (shallowest) to the most recent (deepest)
            for branch in branches:
                # check which edge matches the current checking branch
                for _, obj, _, attr in self.get_out_edges(name_node_id, edge_type="NAME_TO_OBJ"):
                    tag = attr.get("branch")
                    if tag and tag.point == branch.point and tag.branch == branch.branch:
                        if tag.mark == "A":
                            # if the object is added (assigned) in that branch
                            has_obj[obj] = True
                        elif tag.mark == "D":
                            # if the object is removed in that branch
                            has_obj[obj] = False
                    for tag in self.get_node_attr(obj).get("for_tags", []):
                        if tag.point == branch.point:
                            if branch.branch is not None and tag.branch != branch.branch:
                                # if the object is used as the loop variable
                                # or created in another branch of that
                                # branching point
                                has_obj[obj] = False
                                break
            res = list(filter(lambda x: has_obj[x], objs))
        else:
            res = list(objs)
        # for now, mark the lookup edges
        for obj in objs:
            if self.cur_stmt:
                self.add_edge_if_not_exist(self.cur_stmt, obj, {"type:TYPE": "LOOKUP", "timestamp": self.get_timestamp()})
        return res

    get_obj_nodes = get_objs_by_name_node

    def get_objs_by_name(self, var_name, scope=None, branches=[]):
        """
        Get object nodes by a variable name.

        Args:
            var_name (str): variable name.
            scope (optional): scope to find the variable in. Defaults to
                current scope.
            branches (list, optional): branch information.

        Returns:
            list: list of object nodes.
        """
        # if var_name == 'this':    # "this" will be handled in handle_node
        #     return self.cur_objs
        name_node = self.get_name_node(var_name, scope)
        if name_node == None:
            return []
        res_objs = self.get_objs_by_name_node(name_node, branches)
        if var_name.startswith("source_hqbpillvul"):
            # built in source, mark as tainted
            for obj in res_objs:
                self.set_node_attr(obj, ("tainted", True))
                # also mark it as wildcard
                self.set_node_attr(obj, ("code", wildcard))

        return res_objs

    def get_prop_names(self, parent_obj, exclude_proto=True, numeric_only=False, exclude_wildcard=False):
        s = set()
        for name_node in self.get_prop_name_nodes(parent_obj):
            name = self.get_node_attr(name_node).get("name")
            if exclude_proto and name in ["prototype", "__proto__", "constructor"]:
                continue
            if numeric_only:
                if not (name == wildcard or isinstance(name, _SpecialValue)):
                    try:  # check if x is an integer
                        _ = int(name)
                    except ValueError:
                        continue
            if exclude_wildcard and name == wildcard:
                continue
            if name is not None:
                s.add(name)
        return list(s)

    get_keys = get_prop_names

    def get_prop_name_nodes(self, parent_obj=None, exclude_proto=False, numeric_only=False, exclude_wildcard=False):
        name_nodes = self.get_child_nodes(parent_obj, edge_type="OBJ_TO_PROP")
        if exclude_proto:
            name_nodes = filter(lambda x: self.get_node_attr(x).get("name") not in ["prototype", "__proto__", "constructor"], name_nodes)
        if numeric_only:

            def is_name_int(node):
                name = self.get_node_attr(node).get("name")
                if name == wildcard:
                    return True
                elif isinstance(name, _SpecialValue):
                    return False
                else:
                    try:  # check if x is an integer
                        _ = int(name)
                    except ValueError:
                        return False
                    return True

            name_nodes = filter(is_name_int, name_nodes)
        if exclude_wildcard:
            name_nodes = filter(lambda x: self.get_node_attr(x).get("name") != wildcard, name_nodes)
        return list(name_nodes)

    def get_prop_name_node(self, prop_name, parent_obj=None):
        for name_node in self.get_prop_name_nodes(parent_obj):
            if self.get_node_attr(name_node).get("name") == prop_name:
                return name_node
        return None

    def get_prop_obj_nodes(self, parent_obj, prop_name=None, branches: List[BranchTag] = [], exclude_proto=True, numeric_only=False):
        """
        Get object nodes of an object's property.

        Args:
            parent_obj (optional): Defaults to None (current object).
            prop_name (str, optional): Property name. Defaults to None,
                which means get all properties' object nodes.
            branches (List[BranchTag], optional): branch information.
                Defaults to [].
            exclude_proto (bool, optional): Whether exclude prototype
                and __proto__ when getting all properties.
                Defaults to True.

        Returns:
            list: object nodes.
        """
        s = set()
        if prop_name is None:  # this caused inconsistent run results
            name_nodes = self.get_prop_name_nodes(parent_obj, exclude_proto=exclude_proto, numeric_only=numeric_only)
            for name_node in name_nodes:
                s.update(self.get_obj_nodes(name_node, branches))
        else:
            name_node = self.get_prop_name_node(prop_name, parent_obj)
            s.update(self.get_obj_nodes(name_node, branches))
        return list(s)

    def get_prop_obj_nodes_recur(self, parent_obj, prop_name=None, branches: List[BranchTag] = [], exclude_proto=True, numeric_only=False):
        """
        Descrpted !!!!!!!!!!
        Get object nodes of an object's property, recursively.

        Args:
            parent_obj (optional): Defaults to None (current object).
            prop_name (str, optional): Property name. Defaults to None,
                which means get all properties' object nodes.
            branches (List[BranchTag], optional): branch information.
                Defaults to [].
            exclude_proto (bool, optional): Whether exclude prototype
                and __proto__ when getting all properties.
                Defaults to True.

        Returns:
            list: object nodes.
        """
        res = []
        cur_obj_nodes = self.get_prop_obj_nodes(parent_obj, prop_name=prop_name, branches=branches, exclude_proto=exclude_proto, numeric_only=numeric_only)
        res = res + cur_obj_nodes
        for node in cur_obj_nodes:
            res = res + self.get_prop_obj_nodes_recur(node, prop_name=prop_name, branches=branches, exclude_proto=exclude_proto, numeric_only=numeric_only)
        return res

    def assign_obj_nodes_to_name_node(self, name_node, obj_nodes, multi=False, branches=BranchTagContainer()):
        """
        Assign (multiple) object nodes to a name node.

        Args:
            name_node: where to put the objects.
            obj_nodes: objects to be assigned.
            multi (bool, optional):
                True: do NOT delete edges.
                False: delete existing edges.
                Defaults to False.
            branches (List[BranchTag], optional):
                List of branch tags. Defaults to [].
        """
        branch = branches.get_last_choice_tag()
        # remove previous objects
        pre_objs = self.get_objs_by_name_node(name_node, branches)
        self.logger.debug(f"Assigning Obj nodes {obj_nodes} to Name nodes {name_node}, " + f"pre_objs={pre_objs}, branches={branches}")
        if pre_objs and not multi:
            for obj in pre_objs:
                if branch:
                    # check if any addition (assignment) exists
                    # in current branch
                    flag = False
                    for key, edge_attr in self.get_edges_between(name_node, obj, "NAME_TO_OBJ").items():
                        tag = edge_attr.get("branch", BranchTag())
                        if tag == BranchTag(branch, mark="A"):
                            # if addition exists, delete the addition edge
                            self.graph.remove_edge(name_node, obj, key)
                            flag = True
                    if not flag:
                        # if no addition, add a deletion edge
                        self.add_edge(name_node, obj, {"type:TYPE": "NAME_TO_OBJ", "branch": BranchTag(branch, mark="D")})
                else:
                    # do not use "remove_edge", which cannot remove all edges
                    self.remove_all_edges_between(name_node, obj)
                    self.logger.debug("  Remove " + obj)
        # add new objects to name node
        for obj in obj_nodes:
            if branch:
                self.add_edge(name_node, obj, {"type:TYPE": "NAME_TO_OBJ", "branch": BranchTag(branch, mark="A")})
            else:
                self.add_edge(name_node, obj, {"type:TYPE": "NAME_TO_OBJ"})

    def get_name_nodes_by_ast_node(self, ast_node, aim_type=None):
        tmp_edges_by_name_nodes = self.get_in_edges(ast_node, data=True, keys=True, edge_type="NAME_TO_AST")

        if not tmp_edges_by_name_nodes:
            return None
        return [edge[0] for edge in tmp_edges_by_name_nodes]

    def get_obj_nodes_by_ast_node(self, ast_node, aim_type=None):
        tmp_edges_by_obj_nodes = self.get_in_edges(ast_node, data=True, keys=True, edge_type="OBJ_TO_AST")
        if not tmp_edges_by_obj_nodes:
            return None
        obj_nodes = [edge[0] for edge in tmp_edges_by_obj_nodes]
        if aim_type:
            aim_type_nodes = []
            for obj_node in obj_nodes:
                if self.get_node_attr(obj_node).get("type") == aim_type:
                    aim_type_nodes.append(obj_node)
            return aim_type_nodes
        else:
            return obj_nodes

    def get_obj_nodes_by_ast_node_through_name_node(self, ast_node, aim_type=None):
        tmp_edges_by_obj_nodes = self.get_in_edges(ast_node, data=True, keys=True, edge_type="OBJ_TO_AST")

        if not tmp_edges_by_obj_nodes:
            return None
        obj_nodes = [edge[0] for edge in tmp_edges_by_obj_nodes]
        return obj_nodes

    def get_obj_def_ast_node(self, obj_node, aim_type=None):
        """
        Find where in the AST an object (especially a function) is
        defined.

        The AST node is the successor of the object node via the
        OBJ_TO_AST edge.
        """
        aim_map = {"function": ["AST_FUNC_DECL", "AST_CLOSURE", "AST_METHOD"]}
        tmp_edge = self.get_out_edges(obj_node, data=True, keys=True, edge_type="OBJ_TO_AST")
        if not tmp_edge:
            return None
        else:
            if aim_type is not None:
                for edge in tmp_edge:
                    cur_type = self.get_node_attr(edge[1]).get("type")
                    if cur_type in aim_map[aim_type]:
                        return edge[1]
            else:
                for edge in tmp_edge:
                    cur_type = self.get_node_attr(edge[1]).get("type")
                    if cur_type not in aim_map["function"]:
                        return edge[1]

            return tmp_edge[0][1]

    def copy_obj(self, obj_node, ast_node=None, copied=None, deep=False):
        """
        Copy an object and its properties.
        """
        if copied is None:
            copied = set()
        # copy object node
        new_obj_node = str(self._get_new_nodeid())
        self.add_node(new_obj_node, self.get_node_attr(obj_node))
        # copy properties
        for i in self.get_out_edges(obj_node, edge_type="OBJ_TO_PROP"):
            # copy property name node
            prop_name_node = i[1]
            new_prop_name_node = str(self._get_new_nodeid())
            self.add_node(new_prop_name_node, self.get_node_attr(prop_name_node))
            self.add_edge(new_obj_node, new_prop_name_node, {"type:TYPE": "OBJ_TO_PROP"})
            if self.get_node_attr(prop_name_node).get("name") == "__proto__":
                for j in self.get_out_edges(prop_name_node, edge_type="NAME_TO_OBJ"):
                    self.add_edge(new_prop_name_node, j[1], {"type:TYPE": "NAME_TO_OBJ"})
                continue
            # copy property object nodes
            for j in self.get_out_edges(prop_name_node, edge_type="NAME_TO_OBJ"):
                if deep:
                    # sometimes this loop may dead inside a graph with a circle
                    # check whether we copied this node before
                    if j[1] in copied:
                        continue
                    copied.add(j[1])
                    new_prop_obj_node = self.copy_obj(j[1], ast_node, copied)
                    # self.add_node(new_prop_obj_node, self.get_node_attr(j[1])) # ?
                    self.add_edge(new_prop_name_node, new_prop_obj_node, {"type:TYPE": "NAME_TO_OBJ"})
                else:
                    self.add_edge(new_prop_name_node, j[1], {"type:TYPE": "NAME_TO_OBJ"})
        # copy OBJ_DECL edges
        for e in self.get_out_edges(obj_node, edge_type="OBJ_DECL"):
            self.add_edge(new_obj_node, e[1], {"type:TYPE": "OBJ_DECL"})
        if ast_node is not None:
            # assign new OBJ_TO_AST edges
            self.add_edge(new_obj_node, ast_node, {"type:TYPE": "OBJ_TO_AST"})
        else:
            # copy OBJ_TO_AST edges
            for e in self.get_out_edges(obj_node, edge_type="OBJ_TO_AST"):
                self.add_edge(new_obj_node, e[1], {"type:TYPE": "OBJ_TO_AST"})
        return new_obj_node

    def get_name_nodes_to_obj(self, obj_node):
        """
        return a list of name nodes that points to cur obj node
        """
        return [edge[0] for edge in self.get_in_edges(obj_node, edge_type="NAME_TO_OBJ")]

    def get_name_nodes_to_obj_by_scope(self, obj_node, scope_list):
        """
        return a list of name nodes that points to cur obj node
        """
        name_node_list = set()
        name_nodes_edge = self.get_in_edges(obj_node, edge_type="NAME_TO_OBJ")
        for edge in name_nodes_edge:
            name_node = edge[0]
            for scope_edge in self.get_in_edges(name_node, edge_type="SCOPE_TO_VAR"):
                scope_node = scope_edge[0]
                if not scope_list:
                    name_node_list.add(name_node)
                    break
                if scope_node in scope_list:
                    name_node_list.add(name_node)
                    break
        return list(name_node_list)

    def get_scope_by_file_ast(self, ast_node):
        return [edge[0] for edge in self.get_in_edges(ast_node, edge_type="SCOPE_TO_AST")]

    # scopes

    def add_scope(
        self,
        scope_type,
        decl_ast=None,
        scope_name=None,
        decl_obj=None,
        caller_ast=None,
        func_name=None,
        parent_scope=None,
    ):
        """
        Add a new scope under current scope.

        If the scope already exists, return it without adding a new one.
        """
        new_scope_node = str(self._get_new_nodeid())
        self.add_node(new_scope_node, {"labels:label": "Scope", "type": scope_type, "name": scope_name})
        if decl_ast is not None:
            self.add_edge(new_scope_node, decl_ast, {"type:TYPE": "SCOPE_TO_AST"})
        if parent_scope is None:
            if self.cur_scope is not None:
                self.add_edge(self.cur_scope, new_scope_node, {"type:TYPE": "PARENT_SCOPE_OF"})
            else:
                self.cur_scope = new_scope_node
        else:
            self.add_edge(parent_scope, new_scope_node, {"type:TYPE": "PARENT_SCOPE_OF"})
        if decl_obj is not None:
            self.add_edge(decl_obj, new_scope_node, {"type:TYPE": "OBJ_TO_SCOPE"})
        if caller_ast is not None:
            self.add_edge(new_scope_node, caller_ast, {"type:TYPE": "SCOPE_TO_CALLER"})
        if func_name is not None:
            self.set_node_attr(new_scope_node, ("func_name", func_name))
        return new_scope_node

    def find_ancestor_scope(self, scope_types=["FUNC_SCOPE", "FILE_SCOPE"], cur_scope=None):
        """
        Find ancestor (file/function) scope from the current (block)
        scope.
        """
        if cur_scope is None:
            cur_scope = self.cur_scope
        while True:
            if self.get_node_attr(cur_scope).get("type") in scope_types:
                return cur_scope
            edges = self.get_in_edges(cur_scope, edge_type="PARENT_SCOPE_OF")
            if edges:
                cur_scope = edges[0][0]
            else:
                return None

    # functions and calls

    def get_cur_function_decl(self):
        """
        get current running function definition ast node

        Return:
            the decl ast node of this function
        """
        # get the current running function scope
        cur_func_scope = self.find_ancestor_scope()
        cur_func_decl = self.get_out_edges(cur_func_scope, edge_type="SCOPE_TO_AST")[0][1]
        return cur_func_decl

    def get_ast_by_scope(self, scope_node):
        ast_node = self.get_out_edges(scope_node, edge_type="SCOPE_TO_AST")[0][1]
        return ast_node

    def get_func_decl_objs_by_ast_node(self, ast_node, scope=None):
        objs = []
        edges = self.get_in_edges(ast_node, edge_type="OBJ_TO_AST")
        for edge in edges:
            # avoid function run objects
            if self.get_node_attr(edge[0]).get("type") == "function":
                objs.append(edge[0])
        if scope is not None:
            objs = list(filter(lambda obj: self.has_path(scope, obj), objs))
            if len(objs) > 1:
                self.logger.warning("Function {} is declared as multiple objects in scope {}".format(ast_node, scope))
        return objs

    def get_func_scopes_by_obj_node(self, obj_node):
        if obj_node == None:
            return None
        scope_edges = self.get_out_edges(obj_node, edge_type="OBJ_TO_SCOPE")
        return [edge[1] for edge in scope_edges]

    def add_blank_func_to_scope(self, func_name, scope=None, python_func: Callable = None):
        """
        Add a blank function with component graph nodes to a scope.

        Args:
            func_name (str): function's name.
            scope (optional): where to add the function. Defaults to
                None, referring to the current scope.
            python_func (optional): a special Python function in lieu of
                the blank JS AST function. Defaults to None.
        """
        func_obj = self.add_blank_func_with_og_nodes(func_name)
        self.add_obj_to_name(func_name, scope=scope, tobe_added_obj=func_obj)
        if python_func is not None:
            self.set_node_attr(func_obj, ("pythonfunc", python_func))
        return func_obj

    def add_blank_func_as_prop(self, func_name, parent_obj=None, python_func: Callable = None):
        """
        Add a blank function with component graph nodes as a property of
        another object.

        Args:
            func_name (str): function's name.
            parent_obj (optional): function's parent object. Defaults to
                None, referring to the current object.
            python_func (optional): a special Python function in lieu of
                the blank JS AST function. Defaults to None.
        """
        func_obj = self.add_blank_func_with_og_nodes(func_name)
        self.add_obj_as_prop(func_name, parent_obj=parent_obj, tobe_added_obj=func_obj)
        if python_func is not None:
            self.set_node_attr(func_obj, ("pythonfunc", python_func))
        return func_obj

    def convert_obj_node_type_to_function(self, obj, func_ast=None):
        """
        Convert an object node of any type to function.
        Function's prototype will also be added.

        Args:
            obj: The object node.
            func_ast (optional): Function's AST node. Default to None.
        """
        assert obj != self.undefined_obj
        assert obj != self.null_obj
        if self.get_node_attr(obj).get("code") != wildcard:
            self.set_node_attr(obj, ("type", "function"))
        self.add_obj_as_prop("prototype", func_ast, "object", parent_obj=obj)
        if self.function_prototype is not None:
            # prevent setting __proto__ before setup_object_and_function runs
            self.add_obj_as_prop(prop_name="__proto__", parent_obj=obj, tobe_added_obj=self.function_prototype)

        """
        # for existing variable we do not need to remove obj to ast
            # remove old OBJ_TO_AST edges
        if func_ast is not None:
            edges = self.get_out_edges(obj, edge_type="OBJ_TO_AST")
            for edge in edges:
                self.graph.remove_edge(edge[0], edge[1])
        """

        if func_ast is not None:
            self.add_edge(obj, func_ast, {"type:TYPE": "OBJ_TO_AST"})

    def add_blank_func_with_og_nodes(self, func_name, func_obj=None, python_func=None):
        """
        Add a blank function with component graph nodes (name node, function
        scope, and function declaration object node).

        Args:
            func_name (str): Function's name.
            func_obj (optional): Function's object node if known. Use it
                when you want to overwrite an existing object node.
                Default to None.
        """
        ast_node = self.add_blank_func(func_name)
        if func_obj is None:
            func_obj = self.add_obj_node(ast_node, "function")
        else:
            self.convert_obj_node_type_to_function(func_obj, ast_node)
        if python_func is not None:
            self.set_node_attr(func_obj, ("pythonfunc", python_func))
        return func_obj

    def add_blank_func(self, func_name):
        """
        add a blank func
        used for built-in functions
        we need to run the function after the define
        """
        self.logger.debug(sty.ef.inverse + sty.fg(179) + "Add blank function" + sty.rs.all + " name: {}".format(func_name))

        # add a function decl node first
        func_ast = self._get_new_nodeid()
        self.add_node(func_ast)
        # self.set_node_attr(func_ast, ('funcid', func_ast))
        self.set_node_attr(func_ast, ("type", "AST_CLOSURE"))
        self.set_node_attr(func_ast, ("labels:label", "Artificial_AST"))

        # add a node as the name of the function
        namenode_id = self._get_new_nodeid()
        self.add_node(namenode_id)
        self.set_node_attr(namenode_id, ("type", "string"))
        self.set_node_attr(namenode_id, ("name", func_name))
        self.set_node_attr(namenode_id, ("labels:label", "Artificial_AST"))
        self.set_node_attr(namenode_id, ("childnum:int", 0))

        entry_id = self._get_new_nodeid()
        self.add_node(entry_id)
        self.set_node_attr(entry_id, ("funcid", func_ast))
        self.set_node_attr(entry_id, ("type", "CFG_FUNC_ENTRY"))
        self.set_node_attr(entry_id, ("labels:label", "Artificial"))

        exit_id = self._get_new_nodeid()
        self.add_node(exit_id)
        self.set_node_attr(exit_id, ("funcid", func_ast))
        self.set_node_attr(exit_id, ("type", "CFG_FUNC_EXIT"))
        self.set_node_attr(exit_id, ("labels:label", "Artificial"))

        params_id = self._get_new_nodeid()
        self.add_node(params_id)
        self.set_node_attr(params_id, ("funcid", func_ast))
        self.set_node_attr(params_id, ("type", "AST_PARAM_LIST"))
        self.set_node_attr(params_id, ("labels:label", "Artificial_AST"))
        self.set_node_attr(params_id, ("childnum:int", 1))

        # add edges
        self.add_edge(func_ast, entry_id, {"type:TYPE": "ENTRY"})
        self.add_edge(func_ast, exit_id, {"type:TYPE": "EXIT"})
        self.add_edge(func_ast, namenode_id, {"type:TYPE": "PARENT_OF"})
        self.add_edge(func_ast, params_id, {"type:TYPE": "PARENT_OF"})
        self.add_edge(entry_id, exit_id, {"type:TYPE": "FLOWS_TO"})

        # we need to run the function
        return func_ast

    def get_self_invoke_node_by_caller(self, caller_id):
        """
        Deprecated

        get the closure of self invoke function by the caller id

        Args:
            caller_id: the node id of the caller
        """
        return self._get_childern_by_childnum(caller_id)["0"]

    def get_cur_file_path(self, cur_scope=None):
        file_scope = self.find_ancestor_scope(cur_scope=cur_scope, scope_types=["FILE_SCOPE"])
        if not file_scope:
            return ""
        file_ast = self.get_out_edges(file_scope, edge_type="SCOPE_TO_AST")[0][1]
        return self.get_node_attr(file_ast).get("name")

    # prototype

    def _get_upper_level_prototype(self, obj_node):
        """
        get the upper level of prototype
        used for a helper function to link __proto__ and prototype

        Args:
            obj_node: the child obj node
            relation: obj_node -OBJ_DECL-> AST_FUNC_DECL -OBJ_TO_AST->
            FUNC_DECL -OBJ_TO_PROP-> prototype -NAME_TO_OBJ-> PROTOTYPE
        """
        ast_upper_func_node = self.get_child_nodes(obj_node, edge_type="OBJ_DECL")[0]
        edges = self.get_in_edges(ast_upper_func_node, edge_type="OBJ_TO_AST")
        func_decl_obj_node = None
        for edge in edges:
            if self.get_node_attr(edge[0])["type"] == "function":
                func_decl_obj_node = edge[0]
                break
        if func_decl_obj_node is None:  # TODO: what is cause of this bug?
            self.logger.error("Cannot find function object node!")
            return []
        else:
            prototype_obj_nodes = self.get_prop_obj_nodes(parent_obj=func_decl_obj_node, prop_name="prototype")
            self.logger.debug(f"prototype obj node is {prototype_obj_nodes}")
            return prototype_obj_nodes

    def build_proto(self, obj_node):
        """
        build the proto strcture of a object node

        Args:
            obj_node: the obj node need to be build
        """
        upper_level_prototype_objs = self._get_upper_level_prototype(obj_node)
        for obj in upper_level_prototype_objs:
            self.add_obj_as_prop("__proto__", parent_obj=obj_node, tobe_added_obj=obj)

    # Misc

    def setup1(self):
        """
        the init function of setup a run
        """
        # base scope is not related to any file
        self.BASE_SCOPE = self.add_scope("BASE_SCOPE", scope_name="Base")

        self.BASE_OBJ = self.add_obj_to_scope(name="global", scope=self.BASE_SCOPE, combined=False)
        self.cur_objs = [self.BASE_OBJ]

        # setup JavaScript built-in values
        self.null_obj = self.add_obj_to_scope(name="null", value="null", scope=self.BASE_SCOPE)

        self.true_obj = self.add_obj_node(None, "boolean", "true")
        self.add_obj_to_name("true", scope=self.BASE_SCOPE, tobe_added_obj=self.true_obj)
        self.false_obj = self.add_obj_node(None, "boolean", "false")
        self.add_obj_to_name("false", scope=self.BASE_SCOPE, tobe_added_obj=self.false_obj)

    def setup2(self):
        # self.tainted_user_input = self.add_obj_to_scope(
        #     name='pyTaintedUserInput', js_type=None,
        #     value='*', scope=self.BASE_SCOPE)
        # self.logger.debug("{} is mared as tainted for user input".format(self.tainted_user_input))
        # self.set_node_attr(self.tainted_user_input, ('tainted', True))

        # setup JavaScript built-in values
        self.undefined_obj = self.add_obj_node(None, "undefined", value="undefined")
        self.add_obj_to_name("undefined", scope=self.BASE_SCOPE, tobe_added_obj=self.undefined_obj)
        self.infinity_obj = self.add_obj_node(None, "number", "Infinity")
        self.add_obj_to_name("Infinity", scope=self.BASE_SCOPE, tobe_added_obj=self.infinity_obj)
        self.negative_infinity_obj = self.add_obj_node(None, "number", "-Infinity")
        self.nan_obj = self.add_obj_node(None, "number", float("nan"))
        self.add_obj_to_name("NaN", scope=self.BASE_SCOPE, tobe_added_obj=self.nan_obj)

        self.add_obj_as_prop(prop_name="__proto__", js_type="object", parent_obj=self.BASE_OBJ)

        self.internal_objs = {
            "undefined": self.undefined_obj,
            "null": self.null_obj,
            "global": self.BASE_OBJ,
            "infinity": self.infinity_obj,
            "-infinity": self.negative_infinity_obj,
            "NaN": self.nan_obj,
            "true": self.true_obj,
            "false": self.false_obj,
        }
        self.inv_internal_objs = {v: k for k, v in self.internal_objs.items()}
        self.logger.debug(sty.ef.inverse + "Internal objects\n" + str(self.internal_objs)[1:-1] + sty.rs.all)

        self.builtin_prototypes = [
            self.object_prototype,
            self.string_prototype,
            self.array_prototype,
            self.function_prototype,
            self.number_prototype,
            self.boolean_prototype,
            self.regexp_prototype,
            self.promise_prototype,
        ]
        self.pollutable_objs = set(chain(*[self.get_prop_obj_nodes(p) for p in self.builtin_prototypes]))
        self.pollutable_name_nodes = set(chain(*[self.get_prop_name_nodes(p) for p in self.builtin_prototypes]))

    def get_parent_object_def(self, node_id):
        """
        get the obj number and defination of the parent object

        Args:
            node_id: current node id, means the child id
        Return:
            parent_obj: the list of parent obj node of current node id
            def_id: the list of statements that defines the parent object
        """
        parent_obj_nodes = []
        parent_obj_defs = []
        # get the name node first
        name_edges = self.get_in_edges(node_id, edge_type="NAME_TO_OBJ")
        for name_edge in name_edges:
            name_node = name_edge[0]

            parent_obj_edges = self.get_in_edges(name_node, edge_type="OBJ_TO_PROP")
            for parent_obj_edge in parent_obj_edges:
                def_edges = self.get_out_edges(parent_obj_edge[0], edge_type="OBJ_TO_AST")
                if len(def_edges) == 0:
                    continue

                parent_obj_nodes.append(parent_obj_edge[0])
                for def_edge in def_edges:
                    # we return the flatten array
                    # if one obj has multiple defs, defs can not match obj
                    parent_obj_defs.append(def_edge[1])

        return parent_obj_nodes, parent_obj_defs

    def generate_obj_graph_for_python_obj(self, py_obj=None, ast_node=None):
        if py_obj is None:
            return self.null_obj
        elif type(py_obj) in [int, float]:
            return self.add_obj_node(ast_node=ast_node, js_type="number", value=py_obj)
        elif type(py_obj) is str:
            return self.add_obj_node(ast_node=ast_node, js_type="string", value=py_obj)
        elif type(py_obj) is list:
            obj = self.add_obj_node(ast_node=ast_node, js_type="array", value=py_obj)
            for i, u in enumerate(py_obj):
                member = self.generate_obj_graph_for_python_obj(u)
                self.add_obj_as_prop(prop_name=i, tobe_added_obj=member, parent_obj=obj)
            return obj
        elif type(py_obj) is dict:
            obj = self.add_obj_node(ast_node=ast_node, js_type="object", value=py_obj)
            for k, v in py_obj.items():
                member = self.generate_obj_graph_for_python_obj(v)
                self.add_obj_as_prop(prop_name=k, tobe_added_obj=member, parent_obj=obj)
            return obj

    def get_timestamp(self):
        # start from 1
        self.timestamp += 1
        return self.timestamp

    # Analysis

    def _dfs_upper_by_edge_type(self, source=None, edge_type="OBJ_REACHES", depth_limit=None):
        """
        dfs a specific type of edge upper from a node id

        Args:
            source: the start node id
            edge_types: we only consider some types of edge types
        Return:
            nodes: list, nodes on the pathes, sorted by the length of the path
        """
        G = self.graph
        pathes = []
        start = source
        if source is None:
            return [[]]
        if depth_limit is None:
            depth_limit = len(G)
        # we do not have a global visited
        # each path, or stack should have a visited list but not global
        """
        if start in visited:
            continue
        visited.add(start)
        """
        # we do dfs on top of sub-graphs to save time
        sub_graph = self.get_sub_graph_by_edge_type(edge_type)
        backup_graph = self.graph
        self.graph = sub_graph

        edge_group = self.get_in_edges(start, edge_type=edge_type)
        nodes_group = set([edge[0] for edge in edge_group])
        if len(nodes_group) == 0:
            # we only have 1 start node, just return this node
            self.graph = backup_graph
            return [[start]]

        stack = [(start, depth_limit, iter(nodes_group))]
        visited = set()
        visited.add(start)
        while stack:
            parent, depth_now, children = stack[-1]
            try:
                child = next(children)
                if child not in [s[0] for s in stack]:
                    if child in visited:
                        continue
                    visited.add(child)
                    # incase deadloop
                    if depth_now > 1:
                        edge_group = self.get_in_edges(child, edge_type=edge_type)
                        nodes_group = set([edge[0] for edge in edge_group])
                        stack.append((child, depth_now - 1, iter(nodes_group)))
                        if len(nodes_group) == 0:
                            new_path = [node[0] for node in stack]
                            str_pathes = [str(p) for p in pathes]
                            if str(new_path) not in str_pathes:
                                pathes.append(new_path)
            except StopIteration:
                poped = stack.pop()
                visited.remove(poped[0])
        pathes.sort(key=lambda x: -len(x))

        self.graph = backup_graph
        return pathes

    def get_ast_node_file_path(self, node_id):
        # it's a ast so a node only has one parent
        while True:
            node_attr = self.get_node_attr(node_id)
            if node_attr.get("flags:string[]") == "TOPLEVEL_FILE":
                return node_attr.get("name")
            in_edges = self.get_in_edges(node_id, edge_type="PARENT_OF")
            if in_edges:
                node_id = in_edges[0][0]
            else:
                # should be built in
                return None

    def get_ast_node_line_number(self, ast_node_id):
        node_attr = self.get_node_attr(ast_node_id)
        file_path = self.get_ast_node_file_path(ast_node_id)
        start = node_attr["lineno:int"]
        end = node_attr["endlineno:int"]

        return file_path, start, end

    def get_relative_path(self, full_path):
        """
        Convert an absolute path to a relative path under options.avr_app_path.
        Raises ValueError if the path is not a subpath.
        """
        if full_path is None:
            raise ValueError("Full path is None.")

        full_path_obj = Path(full_path).resolve()
        base_path_obj = Path(options.avr_app_path).resolve()

        if not str(full_path_obj).startswith(str(base_path_obj)):
            raise ValueError(f"Path {full_path_obj} is not under base path {base_path_obj}.")

        return str(full_path_obj.relative_to(base_path_obj))

    def get_variable_name_by_obj_node(self, obj_node_id):
        ast_node_id = self.get_obj_def_ast_node(obj_node_id)
        file_path = self.get_ast_node_file_path(ast_node_id)

        if not file_path or "builtin_packages" in file_path:
            return None, None

        ast_node_attr = self.get_node_attr(ast_node_id)
        code = ast_node_attr.get("code")
        start = ast_node_attr.get("lineno:int")
        end = ast_node_attr.get("endlineno:int")
        relative_path = self.get_relative_path(file_path)
        return code, relative_path, start, end

    def get_variable_name_by_ast_var(self, ast_var_id):
        child_nodes = self.get_ordered_ast_child_nodes(ast_var_id)
        variable_name = self.get_node_attr(child_nodes[0]).get("code")
        return variable_name

    def get_prop_names_for_obj_node(self, obj_node_id):
        pass

    def get_ast_node_line_code(self, node_id):
        """
        return the line code of a node
        """
        node_attr = self.get_node_attr(node_id)
        loggers.validate_logger.info(f"node_attr:  {node_id} {node_attr}")
        if "lineno:int" in node_attr:
            lineno = node_attr["lineno:int"]
        else:
            lineno = None
        if lineno is not None:
            file_content = self.get_node_file_content(node_id)
            if file_content:
                return "{}: {}".format(lineno, file_content[int(lineno)])
        return None

    def get_node_file_content(self, node_id, file_path=None):
        """
        find the file of a node
        return the dict with numbers and contents
        """
        file_name = file_path or self.get_ast_node_file_path(node_id)
        if file_name is None:
            return None
        if file_name not in self.file_contents:
            content_dict = [""]
            with open(file_name, "r") as fp:
                for file_line in fp:
                    content_dict.append(file_line)
            self.file_contents[file_name] = content_dict.copy()
        return self.file_contents[file_name]

    def check_signature_functions(self, func_names):
        """
        checking whether one of the func_names exist in the graph
        if not, we do not need to build the obj graph
        Args:
            func_names: the possible function names, if length is 0, return True
        Return:
            True for exist or False for not exist
        """
        if len(func_names) == 0:
            return True
        func_nodes = self.get_node_by_attr("type", "AST_METHOD_CALL")
        func_nodes += self.get_node_by_attr("type", "AST_CALL")
        for func_node in func_nodes:
            func_name = self.get_name_from_child(func_node)
            if func_name in func_names:
                return True
        return False

    def get_covered_statements(self):
        """
        return the covered statements
        """
        return self.covered_stat

    def add_excuted_module_to_statements(self, module_ast):
        """
        add a executed module to total number of statements
        used for adding dynamically added modules
        """
        if not module_ast:
            return

        all_nodes = self.get_all_child_nodes(module_ast)
        for n in all_nodes:
            node_attr = self.get_node_attr(n)
            if "type" in node_attr:
                if self.is_statement(n):
                    self.all_stat.add(n)

    def get_total_num_statements(self):
        """
        return the total number of statements of AST
        """
        if len(self.all_stat) != 0:
            return len(self.all_stat)

        all_nodes = self.get_all_nodes()
        for n in all_nodes:
            if "type" in all_nodes[n]:
                if "AST_" in all_nodes[n]["type"] and self.is_statement(n):
                    self.all_stat.add(n)
                    self.total_num_stat += 1
        # print(len(set(self.all_stat_list)), len(set(self.covered_list)), len(self.covered_list))
        return len(self.all_stat)

    def get_total_num_functions(self):
        """
        return the total number of statements of AST
        """
        if len(self.all_func) != 0:
            return len(self.all_func)

        all_nodes = self.get_all_nodes()
        for n in all_nodes:
            if "type" in all_nodes[n]:
                if all_nodes[n]["type"] in ["AST_FUNC_DECL", "AST_CLOSURE"]:
                    if "labels:label" in all_nodes[n] and all_nodes[n]["labels:label"] == "Artificial_AST":
                        pass
                    else:
                        self.all_func.add(n)
        return len(self.all_func)
