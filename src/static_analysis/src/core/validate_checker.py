from .trace_rule import TraceRule
from .vul_func_lists import Sinks
from .logger import ATTENTION, loggers
from src.core.options import options
from .graph import Graph
import os
import json
from enum import Enum
from pathlib import Path
import re
from .utils import wildcard
import pprint


class CheckStatus(Enum):
    NOT_CHECKED = 0
    NOT_PASSED = 1
    PASSED = 2


def is_subpath(short, long):
    if len(short) > len(long):
        return False
    iter_long = iter(long)
    return all(step in iter_long for step in short)


def match_ast_nodes(G: Graph):
    pass


EXTRA_TAINT_INFO = {}


def are_ast_nodes_equivalent(vul_node_id, repaired_node_id, vul_G, G, line_maps_by_file):
    vul_node = vul_G.get_node_attr(vul_node_id)
    repaired_node = G.get_node_attr(repaired_node_id)

    if vul_node is None or repaired_node is None:
        return False

    vul_full_path = vul_G.get_ast_node_file_path(vul_node_id)
    vul_relative_path = None
    if vul_full_path:
        marker = "temp_code_slice_generation/app_dir/"
        idx = vul_full_path.find(marker)
        if idx != -1:
            vul_relative_path = vul_full_path[idx + len(marker) :]
        else:
            loggers.validate_logger.info(f"Could not extract relative path from vulnerable path: {vul_full_path}")
            return False
    else:
        loggers.validate_logger.info("Missing vulnerable node file path")
        return False

    repaired_full_path = G.get_ast_node_file_path(repaired_node_id)
    if repaired_full_path is None:
        loggers.validate_logger.info("Missing repaired node file path")
        return False

    try:
        repaired_relative_path = str(Path(repaired_full_path).resolve().relative_to(Path(options.avr_app_path)))
    except Exception as e:
        loggers.validate_logger.info(f"Failed to compute relative path for repaired file path: {repaired_full_path} ({e})")
        return False

    line_map = line_maps_by_file.get(vul_relative_path)
    if line_map is None:
        loggers.validate_logger.info(f"Missing line map for: {vul_relative_path}")
        return False

    vul_lineno = vul_node.get("lineno:int")
    vul_endlineno = vul_node.get("endlineno:int")
    repaired_lineno = repaired_node.get("lineno:int")
    repaired_endlineno = repaired_node.get("endlineno:int")

    if None in (vul_lineno, vul_endlineno, repaired_lineno, repaired_endlineno):
        loggers.validate_logger.info(f"Missing line numbers: vul=({vul_lineno},{vul_endlineno}), repaired=({repaired_lineno},{repaired_endlineno})")
        return False

    try:
        mapped_lineno = line_map.get(vul_lineno)
        mapped_endlineno = line_map.get(vul_endlineno)
        repaired_lineno = repaired_lineno
        repaired_endlineno = repaired_endlineno
    except Exception as e:
        loggers.validate_logger.info(f"❌ Failed to cast line numbers to int: {e}")
        return False

    if None in (mapped_lineno, mapped_endlineno, repaired_lineno, repaired_endlineno):
        loggers.validate_logger.info(f"Missing line numbers: vul=({vul_lineno},{vul_endlineno}), repaired=({repaired_lineno},{repaired_endlineno})")
        return False

    if not is_line_number_same(mapped_lineno, repaired_lineno) or not is_line_number_same(mapped_endlineno, repaired_endlineno):
        loggers.validate_logger.info(
            f"Line number mismatch: vul=({vul_lineno},{vul_endlineno}) → mapped=({mapped_lineno},{mapped_endlineno}) "
            f"≠ repaired=({repaired_lineno},{repaired_endlineno})"
        )
        return False

    return True


def is_line_number_same(l1, l2):
    for val in (l1, l2):
        if not isinstance(val, (int, str)):
            raise TypeError(f"Expected int or str, got {type(val).__name__}")

    try:
        l1_int = int(l1)
        l2_int = int(l2)
    except ValueError as e:
        raise ValueError(f"Invalid integer string: {e}")

    return l1_int == l2_int


def is_node_the_same(n1, n2, line_maps_by_file):
    n1_file_path = n1.get("file_path")
    n2_file_path = n2.get("file_path")
    if n1_file_path != n2_file_path:
        return False

    n1_start = n1.get("start")
    n2_start = n2.get("start")

    line_map = line_maps_by_file.get(n1_file_path)

    if line_map:
        mapped_line_number = line_map.get(n1_start)
    else:
        mapped_line_number = n1_start

    if not (is_line_number_same(mapped_line_number, n2_start)):
        return False

    return True


def get_added_nodes(before_path, repaired_path, line_maps_by_file):
    def get_normalized_key(node, is_before_node: bool):
        file_path = node.get("file_path")
        start = node.get("start")

        if is_before_node:
            line_map = line_maps_by_file.get(file_path)
            mapped_line = line_map.get(start, start) if line_map else start
        else:
            mapped_line = start

        mapped_line = int(mapped_line)
        ast_node_attr = node.get("ast_node_attr") or {}
        node_type = ast_node_attr.get("type")
        node_code = ast_node_attr.get("code")

        return (file_path, mapped_line, node_type, node_code)

    left = 0
    while left < len(before_path) and left < len(repaired_path):
        if get_normalized_key(before_path[left], True) == get_normalized_key(repaired_path[left], False):
            left += 1
        else:
            break

    right_before = len(before_path) - 1
    right_repaired = len(repaired_path) - 1
    while right_before >= left and right_repaired >= left:
        if get_normalized_key(before_path[right_before], True) == get_normalized_key(repaired_path[right_repaired], False):
            right_before -= 1
            right_repaired -= 1
        else:
            break

    added_nodes = repaired_path[left : right_repaired + 1]
    return added_nodes


def is_path_the_same(p1, p2, line_maps_by_file):
    if len(p1) != len(p2):
        return False
    for n1, n2 in zip(p1, p2):
        n1_file_path = n1.get("file_path")
        n2_file_path = n2.get("file_path")
        if n1_file_path != n2_file_path:
            return False
        line_map = line_maps_by_file.get(n1_file_path)

        n1_start = n1.get("start")
        n2_start = n2.get("start")
        if line_map:
            mapped_line_number = line_map.get(n1_start)
        else:
            mapped_line_number = None
        loggers.validate_logger.info(f"mapped_line_number:  {mapped_line_number}")
        if not (n1_start == n1_start or mapped_line_number == n2_start):
            return False

    return True


def get_vul_paths_by_function_list(G: Graph, source_function_list, taint_function_list, filter_by_sink=True):
    from src.plugins.internal.handlers.functions import call_function, run_exported_functions, ast_call_function

    source_func_arg_nodes = set()
    for source_function in source_function_list:
        source_func_args = G.get_func_args_obj_nodes_by_func_ast_id(source_function.get("id"))
        source_func_arg_nodes.update(source_func_args)
    loggers.code_slice_logger.info(f"source_func_arg_nodes for slice trace back: {source_func_arg_nodes}")
    loggers.validate_logger.info(f"source_func_arg_nodes for slice trace back: {source_func_arg_nodes}")

    vul_paths = get_vul_paths(G, source_func_arg_nodes, filter_by_sink=True)

    taint_func_arg_nodes = set()
    if len(vul_paths) == 0:
        loggers.validate_logger.info("start checking taint functions")

        for taint_function in taint_function_list:
            loggers.code_slice_logger.info(f"taint_function: {taint_function}")
            taint_func_obj_nodes = G.get_obj_nodes_by_ast_node(taint_function.get("id"), aim_type="function")
            loggers.code_slice_logger.info(f"taint_func_obj_nodes: {taint_func_obj_nodes}")
            loggers.validate_logger.info(f"taint_func_obj_nodes: {taint_func_obj_nodes}")
            if taint_func_obj_nodes:
                loggers.validate_logger.info(f"calling taint function {taint_function} {taint_func_obj_nodes}")
                call_function(G, taint_func_obj_nodes, mark_fake_args=True)

        for taint_func in taint_function_list:
            taint_func_args = G.get_func_args_obj_nodes_by_func_ast_id(taint_func.get("id"))
            loggers.validate_logger.info(f"taint_func_args:  {taint_func_args}")
            taint_func_arg_nodes.update(taint_func_args)

        loggers.code_slice_logger.info(f"taint_func_arg_nodes: {taint_func_arg_nodes}")
        loggers.validate_logger.info(f"taint_func_arg_nodes: {taint_func_arg_nodes}")
        vul_paths = get_vul_paths(G, taint_func_arg_nodes, filter_by_sink=filter_by_sink)
        loggers.code_slice_logger.info(f"vul_paths for taint functions: {vul_paths}")
        loggers.validate_logger.info(f"vul_paths for taint functions: {vul_paths}")

    return vul_paths, source_func_arg_nodes, taint_func_arg_nodes


def get_vul_paths(G: Graph, func_args_obj_nodes, filter_by_sink=True, return_line_number=True):
    all_vul_paths = []
    for func_arg_obj_node in func_args_obj_nodes:
        path = G.dfs_down_for_validatation(func_arg_obj_node, filter_by_sink=filter_by_sink)
        all_vul_paths.extend(path)
    if not return_line_number:
        return all_vul_paths
    line_number_all_path = []
    for path in all_vul_paths:
        line_number_path = []
        for node in path:
            ast_node = G.get_obj_def_ast_node(node)
            if not ast_node:
                continue
            loggers.code_slice_logger.info(f"ast_node:  {ast_node} -- {node}")
            ast_node_attr = G.get_node_attr(ast_node)
            file_path, start, end = G.get_ast_node_line_number(ast_node)
            if file_path:
                file_path_obj = Path(file_path)
                if "builtin_packages" in file_path_obj.parts:
                    idx = file_path_obj.parts.index("builtin_packages")
                    relative_path = str(Path(*file_path_obj.parts[idx:]))
                else:
                    relative_path = str(file_path_obj.relative_to(options.avr_app_path))
                line_number_path.append(
                    {"file_path": relative_path, "start": start, "end": end, "node_id": node, "ast": ast_node, "ast_node_attr": ast_node_attr}
                )
        line_number_all_path.append(line_number_path)

    return line_number_all_path


def get_taint_variable_info_by_file_path_and_line_number(G: Graph, full_file_path, old_path, line_number, line_content):
    taint_variable_info = []
    ast_nodes = G.get_ast_nodes_by_file_path_and_line_number(str(full_file_path), line_number)
    for ast_node in ast_nodes:
        ast_node_id = ast_node[0]
        ast_node_attr = ast_node[1]
        loggers.code_slice_logger.info(f"ast_node_attr:  {ast_node_attr}")
        if ast_node_attr.get("type") == "AST_DIM":
            variable_name = ast_node_attr.get("code")
            loggers.code_slice_logger.info(f"variable_name:  {variable_name}")
            taint_variable_info.append(
                {"variable_name": variable_name, "file_path": old_path, "line_number": line_number, "line_content": line_content, "ast_id": ast_node_id}
            )
    for ast_node in ast_nodes:
        ast_node_id = ast_node[0]
        ast_node_attr = ast_node[1]
        loggers.code_slice_logger.info(f"ast_node_attr:  {ast_node_attr}")
        if ast_node_attr.get("type") == "AST_PROP":
            is_child = False
            variable_name = G.get_name_from_child(ast_node_id)
            for t in taint_variable_info:
                if G.is_parent_of(t.get("ast_id"), ast_node_id):
                    is_child = True
                    continue
            loggers.code_slice_logger.info(f"variable_name AST_PROP:  {variable_name}")
            if not is_child:
                taint_variable_info.append(
                    {
                        "variable_name": variable_name,
                        "file_path": old_path,
                        "line_number": line_number,
                        "line_content": line_content,
                        "ast_id": ast_node_id,
                    }
                )

    for ast_node in ast_nodes:
        ast_node_id = ast_node[0]
        ast_node_attr = ast_node[1]
        loggers.code_slice_logger.info(f"ast_node_attr:  {ast_node_attr}")
        if ast_node_attr.get("type") == "AST_VAR":
            is_child = False
            variable_name = G.get_name_from_child(ast_node_id)
            for t in taint_variable_info:
                if G.is_parent_of(t.get("ast_id"), ast_node_id):
                    is_child = True
                    continue

            parent_id = G.get_ast_parent_node(ast_node_id)
            if G.get_node_attr(parent_id).get("type") == "AST_ASSIGN":
                children = G.get_ordered_ast_child_nodes(parent_id)
                if children and children[0] == ast_node_id:
                    continue

            loggers.code_slice_logger.info(f"variable_name AST_PROP:  {variable_name}")
            if not is_child:
                taint_variable_info.append(
                    {
                        "variable_name": variable_name,
                        "file_path": old_path,
                        "line_number": line_number,
                        "line_content": line_content,
                        "ast_id": ast_node_id,
                    }
                )
    return taint_variable_info


def get_taint_variable_info_by_diff(G: Graph, diff_list, set_tainted=False):
    taint_variable_info = []
    for diff in diff_list:
        old_path = diff["old_path"]
        diff_parsed = diff["diff_parsed"]
        deleted = diff_parsed["deleted"]
        added = diff_parsed["added"]
        for d in deleted:
            line_number = d[0]
            line_content = d[1]
            full_file_path = Path(options.avr_app_path) / old_path
            v_info = get_taint_variable_info_by_file_path_and_line_number(G, full_file_path, old_path, line_number, line_content)
            taint_variable_info.extend(v_info)
    return taint_variable_info


def get_exisiting_sanitization_functions_in_code_base(G: Graph):
    sanitization_functions = []
    possible_sanitization_patterns = [
        r"\b(_\.escape)\s*\(",
        r"\b([\w\.]*escape\w*)\s*\(",
        r"\b(DOMPurify\.sanitize)\s*\(",
        r"\b(eval)\s*\(",
    ]

    method_call_nodes = G.get_nodes_by_type("AST_METHOD_CALL") + G.get_nodes_by_type("AST_CALL")
    var_nodes = G.get_nodes_by_type("AST_VAR")

    for node in method_call_nodes:
        node_id = node[0]
        node_attr = G.get_node_attr(node_id)
        code = node_attr.get("code")
        if code:
            for pattern in possible_sanitization_patterns:
                match = re.search(pattern, code)
                if match:
                    func_name = match.group(1)
                    if func_name == "eval":
                        func_name = "betterEval"
                    sanitization_functions.append(func_name)

    for node in var_nodes:
        node_id = node[0]
        name = G.get_name_from_child(node_id)
        if name:
            if name == "Prism":
                sanitization_functions.append("Prism.util.encode")

    tainted_nodes = G.get_all_tainted_nodes()
    loggers.code_slice_logger.info(f"tainted_nodes for sanitization:  {tainted_nodes}")
    return list(set(sanitization_functions))


def slice_traceback(G: Graph, diff_list):
    source_function_list = G.vul_graph_info["source_function_list"]
    taint_function_list = G.vul_graph_info["taint_function_list"]

    vul_paths, func_args_obj_nodes, func_args_obj_nodes_for_taint_func = get_vul_paths_by_function_list(G, source_function_list, taint_function_list)

    tainted_variable_names_and_paths = []

    if EXTRA_TAINT_INFO.get(options.cve_id):
        extra_taint_info = EXTRA_TAINT_INFO.get(options.cve_id)
        if extra_taint_info:
            tainted_variable_names_and_paths.extend(extra_taint_info)

    source_function_return_nodes = get_source_function_return_nodes(G, source_function_list=source_function_list)

    if len(tainted_variable_names_and_paths) == 0:
        tainted_variable_names_and_paths.extend(get_taint_variable_info_by_diff(G, diff_list=diff_list))

    sanitization_funcs = get_exisiting_sanitization_functions_in_code_base(G=G)
    loggers.code_slice_logger.info(f"sanitization_funcs:  {sanitization_funcs}")

    def deduplicate_tainted_vars(tainted_list):
        seen = set()
        deduped = []
        for item in tainted_list:
            key = (item["variable_name"], item["file_path"], item.get("line_number", ""), item.get("line_content", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(item)
        return deduped

    tainted_variable_names_and_paths = deduplicate_tainted_vars(tainted_variable_names_and_paths)

    vul_graph_info = {
        "source_function_list": source_function_list,
        "source_function_return_nodes": source_function_return_nodes,
        "vul_paths": vul_paths,
        "tainted_variable_names_and_paths": list(tainted_variable_names_and_paths),
        "sanitization_funcs": sanitization_funcs,
    }

    G.vul_graph_info.update(vul_graph_info)

    vul_graph_info_path = os.path.abspath(os.path.normpath(os.path.join(options.avr_app_path, "../..", "vul_graph_info.json")))
    with open(vul_graph_info_path, "w", encoding="utf-8") as f:
        json.dump(G.vul_graph_info, f, indent=2)

    return vul_graph_info


def condition_check_using_if_pattern():
    pass


def get_vul_graph_info(G: Graph, vul_G: Graph):
    vul_graph_info_file_path = os.path.abspath(os.path.normpath(options.vul_graph_info_file_path))
    loggers.validate_logger.info(f"vul_graph_info_file_path:  {vul_graph_info_file_path}")
    with open(vul_graph_info_file_path, "r", encoding="utf-8") as f:
        vul_graph_info = json.load(f)

    source_function_list = vul_graph_info.get("source_function_list")
    line_maps_by_file = vul_graph_info.get("line_maps_by_file")
    vul_paths = vul_graph_info.get("vul_paths")

    if not vul_paths:
        loggers.code_slice_logger.warning("vul_paths is missing or empty in vulnerability graph info")

    if not source_function_list:
        loggers.code_slice_logger.warning("source_function_list is missing or empty in vulnerability graph info")

    if not line_maps_by_file:
        raise ValueError("line_maps_by_file is missing or empty in vulnerability graph info")

    return source_function_list, line_maps_by_file, vul_paths


def map_func_to_repaired_version(G: Graph, func_list, line_maps_by_file):
    func_in_repaired_version = []

    for func in func_list:
        func_ast_node_id = func.get("id")
        func_file_path = G.get_ast_node_file_path(func_ast_node_id)
        if not func_file_path:
            loggers.validate_logger.warning(f"no func_file_path for AST {func_ast_node_id}")
            continue
        base_path = Path(options.avr_app_path).resolve()
        relative_file_path = str(Path(func_file_path).resolve().relative_to(base_path))
        repaired_file_path = str(base_path / relative_file_path)
        loggers.validate_logger.info(f"relative_file_path:  {relative_file_path}")
        loggers.validate_logger.info(f"repaired_file_path:  {repaired_file_path}")

        line_map = line_maps_by_file.get(relative_file_path)
        if not line_map:
            loggers.validate_logger.warning(f"no line maps for {relative_file_path}")
            continue
        func_ast_node_attr = func.get("node_attr")
        func_start_line_number = func_ast_node_attr.get("lineno:int")
        func_end_line_number = func_ast_node_attr.get("endlineno:int")

        repaired_start_line = line_map.get(str(func_start_line_number))
        repaired_end_line = line_map.get(str(func_end_line_number))

        loggers.validate_logger.info(f"mapping func from {func_start_line_number} - {func_end_line_number} TO {repaired_start_line} {repaired_end_line}")
        matched_func = G.get_function_node_by_file_name_and_line_number(
            repaired_file_path,
            repaired_start_line,
            repaired_end_line,
        )

        loggers.validate_logger.info(f"matched_func:  {matched_func}")

        if len(matched_func) > 1:
            loggers.validate_logger.warning("More than one func matched in repaired version")

        if len(matched_func) == 0:
            raise ValueError(f"No matched func for {func}")

        func_id = matched_func[0]

        func_in_repaired_version.append(
            {
                "id": func_id,
                "file_path": G.get_ast_node_file_path(func_id),
                "node_attr": G.get_node_attr(func_id),
            }
        )

    loggers.validate_logger.info(f"func_in_repaired_version: {func_in_repaired_version}")
    return func_in_repaired_version


def get_taint_source_args_in_repaired_version(G: Graph, source_function_list, line_maps_by_file):
    func_args_obj_nodes = set()
    source_functions_in_repaired_version = map_func_to_repaired_version(G, source_function_list, line_maps_by_file)
    for source_func_in_repaired_version in source_functions_in_repaired_version:
        source_func_ast_node_id_in_repaired_version = source_func_in_repaired_version
        func_args_objs = G.get_func_args_obj_nodes_by_func_ast_id(source_func_ast_node_id_in_repaired_version, set_tainted=True)
        func_args_obj_nodes.update(func_args_objs)
    loggers.validate_logger.info(f"func_args_obj_nodes taint source in repaired verison:  {func_args_obj_nodes}")
    return func_args_obj_nodes


def initialize_path_validation(before_paths):
    path_validation_map = {}
    num_entries = max(1, len(before_paths))
    for idx in range(num_entries):
        path_validation_map[idx] = {
            "security_check": CheckStatus.NOT_CHECKED,
            "condition_check_exist": CheckStatus.NOT_CHECKED,
            "condition_check_against_input_range": CheckStatus.NOT_CHECKED,
            "sanitization_check": CheckStatus.NOT_CHECKED,
        }
    return path_validation_map


def finalize_security_check(path_validation_map):
    if len(path_validation_map) == 0:
        return CheckStatus.NOT_CHECKED

    for checks in path_validation_map.values():
        exist = checks["condition_check_exist"]
        input_range = checks["condition_check_against_input_range"]
        sanitization = checks["sanitization_check"]

        if (exist == CheckStatus.PASSED and input_range == CheckStatus.PASSED) or sanitization == CheckStatus.PASSED:
            checks["security_check"] = CheckStatus.PASSED
        else:
            checks["security_check"] = CheckStatus.NOT_PASSED

    loggers.validate_logger.info(f"path_validation_map:  {path_validation_map}")
    for path in path_validation_map.values():
        if path["security_check"] != CheckStatus.PASSED:
            return CheckStatus.NOT_PASSED

    return CheckStatus.PASSED


def security_check_for_conditional_validation(G: Graph, before_path, repaired_path, line_maps_by_file):
    condition_check_exist = CheckStatus.NOT_CHECKED
    condition_check_against_input_range = CheckStatus.NOT_CHECKED

    added_nodes = get_added_nodes(before_path, repaired_path, line_maps_by_file)
    loggers.validate_logger.info(f"added_nodes for condition check:  {added_nodes}")

    for added_node in added_nodes:
        added_line_number = added_node.get("start")
        loggers.validate_logger.info(f"added_line_number:  {added_line_number}")
        modified_file_path = added_node.get("file_path")
        modified_file_path = str(Path(options.avr_app_path) / modified_file_path)
        if "builtin_packages" in modified_file_path:
            continue

        added_ast_nodes = G.get_ast_nodes_by_file_path_and_line_number(modified_file_path, added_line_number)

        for added_ast_node in added_ast_nodes:
            added_ast_node_id = added_ast_node[0]
            added_ast_node_attr = added_ast_node[1]
            loggers.validate_logger.info(f"added_ast_node_attr:  {added_ast_node_attr}")

            if added_ast_node_attr.get("type") == "AST_IF":
                condition_check_exist = CheckStatus.PASSED

            if condition_check_exist == CheckStatus.PASSED:
                added_obj_nodes = G.get_obj_nodes_by_ast_node(added_ast_node_id)
                added_name_nodes = G.get_name_nodes_by_ast_node(added_ast_node_id)
                if added_name_nodes:
                    loggers.validate_logger.info(f"added_name_nodes:  {added_name_nodes}")
                    for extra_name_node in added_name_nodes:
                        obj_nodes = G.get_objs_by_name_node(extra_name_node)
                        for obj_node in obj_nodes:
                            loggers.validate_logger.info(f"obj_node:  {obj_node}")
                            obj_node_attr = G.get_node_attr(obj_node)
                            loggers.validate_logger.info(f"obj_node_attr:  {obj_node_attr}")
                            if obj_node_attr.get("tainted") == True:
                                condition_check_against_input_range = CheckStatus.PASSED

                loggers.validate_logger.info(f"added_obj_nodes:  {added_obj_nodes}")

    return condition_check_exist, condition_check_against_input_range


def security_check_for_sanitization_check(G: Graph, vul_G: Graph, before_path, repaired_path, line_maps_by_file):
    sanitization_check = CheckStatus.NOT_CHECKED

    added_nodes = get_added_nodes(before_path, repaired_path, line_maps_by_file=line_maps_by_file)
    loggers.validate_logger.info(f"added_nodes:  {added_nodes}")

    for added_node in added_nodes:
        added_line_number = added_node.get("start")
        modified_file_path = added_node.get("file_path")
        modified_file_path = str(Path(options.avr_app_path) / modified_file_path)
        if "builtin_packages" in modified_file_path:
            continue

        added_node_id = added_node.get("node_id")
        added_node_attr = G.get_node_attr(added_node_id)
        loggers.validate_logger.info(f"added_node_id:  {added_node_id}")
        loggers.validate_logger.info(f"added_node_attr:  {added_node_attr}")

        added_node_ast_id = added_node.get("ast")
        added_node_ast_attr = G.get_node_attr(added_node_ast_id)
        added_node_ast_code = added_node_ast_attr.get("code")
        loggers.validate_logger.info(f"added_node_ast_code:  {added_node_ast_code}")
        if (
            (".replace" in added_node_ast_code)
            and added_node_attr.get("tainted") == True
            and "Prism.util.encode" not in vul_G.vul_graph_info["sanitization_funcs"]
        ):
            loggers.validate_logger.info(f"sanitized by .replace {added_node_ast_attr}")
            sanitization_check = CheckStatus.PASSED
        loggers.validate_logger.info(f"added_node_ast_id:  {added_node_ast_id}")
        loggers.validate_logger.info(f"added_node_ast_attr:  {added_node_ast_attr}")

        added_ast_node_code = added_node_ast_attr.get("code")
        if "parseInt" in added_ast_node_code:
            sanitization_check = CheckStatus.PASSED

    if not sanitization_check == CheckStatus.PASSED:
        sanitization_check = CheckStatus.NOT_PASSED
    return sanitization_check


def security_check_taint_path_sanitized(
    G: Graph,
    vul_G: Graph,
    before_paths,
    vul_paths_in_repaired_version,
    line_maps_by_file,
    diff_list,
    source_functions_in_repaired_version,
    taint_functions_in_repaired_version,
):
    loggers.validate_logger.info(f"taint_functions_in_repaired_version:  {taint_functions_in_repaired_version}")
    from src.plugins.internal.handlers.functions import call_function, run_exported_functions, ast_call_function

    for taint_func in taint_functions_in_repaired_version:
        loggers.validate_logger.info(f"taint_func:  {taint_func}")

    for taint_function in taint_functions_in_repaired_version:
        taint_func_arg_nodes = []
        loggers.code_slice_logger.info(f"taint_function: {taint_function}")
        taint_func_obj_nodes = G.get_obj_nodes_by_ast_node(taint_function.get("id"), aim_type="function")
        loggers.code_slice_logger.info(f"taint_func_obj_nodes: {taint_func_obj_nodes}")
        loggers.validate_logger.info(f"taint_func_obj_nodes: {taint_func_obj_nodes}")
        if taint_func_obj_nodes:
            loggers.validate_logger.info(f"calling taint function {taint_function} {taint_func_obj_nodes}")
            call_function(G, taint_func_obj_nodes, mark_fake_args=True)

        for taint_func in taint_functions_in_repaired_version:
            taint_func_args = G.get_func_args_obj_nodes_by_func_ast_id(taint_func.get("id"))
            loggers.validate_logger.info(f"taint_func_args:  {taint_func_args}")
            taint_func_arg_nodes.extend(taint_func_args)

        loggers.code_slice_logger.info(f"taint_func_arg_nodes: {taint_func_arg_nodes}")
        loggers.validate_logger.info(f"taint_func_arg_nodes: {taint_func_arg_nodes}")
        vul_paths = get_vul_paths(G, taint_func_arg_nodes, filter_by_sink=False, return_line_number=False)
        for path in vul_paths:
            last_node = path[-1]
            last_node_attr = G.get_node_attr(last_node)
            loggers.validate_logger.info(f"last_node_attr here: {last_node} {last_node_attr}")
            for n in path:
                n_attr = G.get_node_attr(n)
                loggers.validate_logger.info(f"n_attr here:   {n} {n_attr}")
                if n_attr.get("code"):
                    code = n_attr.get("code")
                    if code != "*" and code is not wildcard:
                        loggers.validate_logger.info((f"db code {code}"))
                loggers.validate_logger.info(f"n_attr db:  {n_attr}")

        loggers.validate_logger.info(f"vul_paths for db:  {vul_paths}")


def security_check_taint_node_sanitized(G: Graph, vul_G: Graph, before_paths, vul_paths_in_repaired_version, line_maps_by_file, diff_list):
    taint_nodes_sanitized = False

    loggers.validate_logger.info(f"vulG vul_graph_info:  {vul_G.vul_graph_info}")
    loggers.validate_logger.info(f"line_maps_by_file:  {line_maps_by_file}")
    vul_G_tainted_variable_names_and_paths = vul_G.vul_graph_info["tainted_variable_names_and_paths"]
    loggers.validate_logger.info(f"vul_G_tainted_variable_names_and_paths:  {vul_G_tainted_variable_names_and_paths}")

    for v_info in vul_G_tainted_variable_names_and_paths:
        for file_path in options.repair_diff:
            diff = options.repair_diff[file_path]
            added = diff["added"]
            deleted = diff["deleted"]
            for d in added:
                line_number = d[0]
                line_content = d[1]

                full_file_path = Path(options.avr_app_path) / file_path
                ast_nodes = G.get_ast_nodes_by_file_path_and_line_number(str(full_file_path), line_number)
                has_same_variable_node = False
                v_info_added = get_taint_variable_info_by_file_path_and_line_number(G, str(full_file_path), file_path, line_number, line_content)
                loggers.validate_logger.info(f"v_info_added:  {v_info_added}")
                for v_added in v_info_added:
                    if v_info["file_path"] == v_added["file_path"] and v_info["variable_name"] == v_added["variable_name"]:
                        has_same_variable_node = True
                loggers.validate_logger.info(f"has_same_variable_node:  {has_same_variable_node}")
                if has_same_variable_node:
                    for ast_node in ast_nodes:
                        ast_node_id = ast_node[0]
                        ast_node_attr = G.get_node_attr(ast_node_id)
                        loggers.validate_logger.info(f"ast_node_attr:  {ast_node_attr}")
                        if ast_node_attr.get("type") == "AST_METHOD_CALL" or ast_node_attr.get("type") == "AST_CALL":
                            loggers.validate_logger.info(f"ast_node_attr for tainted variable:  {ast_node_id} {ast_node_attr}")
                            code = ast_node_attr.get("code")
                            for san_func_name in vul_G.vul_graph_info["sanitization_funcs"]:
                                loggers.validate_logger.info(f"san_funcs:  {san_func_name} {code}")
                                if san_func_name in code:
                                    loggers.validate_logger.info(f"sanitized by {san_func_name}")
                                    v_info["sanitized"] = True
                        loggers.validate_logger.info(f"ast_node_attr for same variable node: {ast_node_id}  {ast_node_attr}")
                loggers.code_slice_logger.info(f"ast_nodes here:  {ast_nodes}")

    all_sanitized = True
    for v_info in vul_G_tainted_variable_names_and_paths:
        if not v_info.get("sanitized") == True:
            all_sanitized = False
    if all_sanitized:
        taint_nodes_sanitized = True
    return taint_nodes_sanitized


def security_check_sink_repalced(
    G: Graph,
    vul_G: Graph,
    before_paths,
    vul_paths_in_repaired_version,
    line_maps_by_file,
    diff_list,
    source_functions_in_repaired_version,
    taint_functions_in_repaired_version,
):
    san_sinks = ["execFile", "textContent"]

    def dfs_check_code(node_id, san_sinks):
        node_attr = G.get_node_attr(node_id)
        code = node_attr.get("code")
        if code in san_sinks:
            loggers.validate_logger.info(f"Found target code '{code}' at node {node_id}")
            return True

        children = G.get_ordered_ast_child_nodes(node_id)
        loggers.validate_logger.info(f"children:  {children}")
        for child in children:
            if dfs_check_code(child, san_sinks):
                return True
        return False

    sink_replaced = False
    loggers.validate_logger.info(f"vul_paths_in_repaired_version: (len{vul_paths_in_repaired_version}) {vul_paths_in_repaired_version}")

    if len(vul_paths_in_repaired_version) == 0:
        for taint_func in taint_functions_in_repaired_version:
            taint_func_id = taint_func.get("id")
            found = dfs_check_code(taint_func_id, san_sinks)
            if found:
                sink_replaced = True
    else:
        for vul_path in vul_paths_in_repaired_version:
            loggers.validate_logger.info(f"vul_path:  {vul_path}")
            last_node = vul_path[-1]
            last_node_ast_attr = last_node.get("ast_node_attr")
            if last_node_ast_attr.get("type") == "AST_CALL" and "sink_hqbpillvul_exec" in last_node_ast_attr.get("code"):
                sink_replaced = True
            for node in vul_path:
                ast_node_attr = node.get("ast_node_attr")
                loggers.validate_logger.info(f"node:  {ast_node_attr}")
    return sink_replaced


def security_check(
    G: Graph,
    vul_G: Graph,
    before_paths,
    vul_paths_in_repaired_version,
    line_maps_by_file,
    diff_list,
    source_functions_in_repaired_version,
    taint_functions_in_repaired_version,
):
    path_validation_map = initialize_path_validation(before_paths=before_paths)

    if len(before_paths) == 0:
        taint_node_sanitized = security_check_taint_node_sanitized(G, vul_G, before_paths, vul_paths_in_repaired_version, line_maps_by_file, diff_list)
        if taint_node_sanitized:
            return CheckStatus.PASSED, {}

    if len(before_paths) == 0:
        security_check_taint_path_sanitized(
            G,
            vul_G,
            before_paths,
            vul_paths_in_repaired_version,
            line_maps_by_file,
            diff_list,
            source_functions_in_repaired_version,
            taint_functions_in_repaired_version,
        )

    sink_replaced = security_check_sink_repalced(
        G,
        vul_G,
        before_paths,
        vul_paths_in_repaired_version,
        line_maps_by_file,
        diff_list,
        source_functions_in_repaired_version,
        taint_functions_in_repaired_version,
    )
    if sink_replaced:
        return CheckStatus.PASSED, {}

    if len(before_paths) == 0:
        has_sink_in_vul_version = False
        has_sink_in_repaired_version = False
        tainted_objs = []
        db_objs = []
        for file_path in options.repair_diff:
            diff = options.repair_diff[file_path]
            added = diff["added"]
            deleted = diff["deleted"]
            for d in deleted:
                deleted_line_number = d[0]
                deleted_line_content = d[1]
                if "innerHTML" in deleted_line_content:
                    has_sink_in_vul_version = True
                loggers.validate_logger.info(f"deleted_line_number:  {deleted_line_number} {deleted_line_content}")

            for a in added:
                added_line_number = a[0]
                added_line_content = a[1]
                if "innerHTML" in added_line_content:
                    has_sink_in_repaired_version = True
                modified_file_path = str(Path(options.avr_app_path) / file_path)
                if "builtin_packages" in modified_file_path:
                    continue
                added_ast_nodes = G.get_ast_nodes_by_file_path_and_line_number(modified_file_path, added_line_number)
                for added_ast_node in added_ast_nodes:
                    added_obj_nodes = []
                    added_ast_node_id = added_ast_node[0]
                    added_ast_node_attr = added_ast_node[1]
                    added_ast_node_code = added_ast_node_attr.get("code")
                    if "DOMPurify.sanitize" in added_ast_node_code or "entities.encodeXML" in added_ast_node_code or "escapeHtml" in added_ast_node_code:
                        for taint_v_in_vul_g in vul_G.vul_graph_info.get("tainted_variable_names_and_paths", []):
                            if taint_v_in_vul_g.get("variable_name") in added_ast_node_code:
                                path_validation_map[0]["sanitization_check"] = CheckStatus.PASSED
                    if ".replace" in added_ast_node_code:
                        for taint_v_in_vul_g in vul_G.vul_graph_info.get("tainted_variable_names_and_paths", []):
                            if taint_v_in_vul_g.get("variable_name") in added_ast_node_code:
                                path_validation_map[0]["sanitization_check"] = CheckStatus.PASSED
                    loggers.validate_logger.info(f"added ast node:  {added_ast_node_id} {added_ast_node_attr}")
                    obj_nodes_by_ast_node = G.get_obj_nodes_by_ast_node(added_ast_node_id)
                    if obj_nodes_by_ast_node:
                        added_obj_nodes.extend(obj_nodes_by_ast_node)
                    added_name_nodes = G.get_name_nodes_by_ast_node(added_ast_node_id)
                    if added_name_nodes:
                        for name_node in added_name_nodes:
                            obj_nodes_by_name_node = G.get_objs_by_name_node(name_node)
                            added_obj_nodes.extend(obj_nodes_by_name_node)
                    loggers.validate_logger.info(f"added obj nodes:  {added_obj_nodes}")
                    for obj in added_obj_nodes:
                        if G.get_node_attr(obj).get("tainted") == True:
                            tainted_objs.append(obj)
                    for obj in added_obj_nodes:
                        if G.get_node_attr(obj).get("db_param") == True:
                            db_objs.append(obj)
                            loggers.validate_logger.info(f"db_param handler:  {obj}")
        has_tainted_obj = len(tainted_objs) > 0
        loggers.validate_logger.info(f"has_tainted_obj:  {has_tainted_obj}")
        loggers.validate_logger.info(f"tainted_objs:  {tainted_objs}")
        loggers.validate_logger.info(f"has_sink_in_vul_version:  {has_sink_in_vul_version}")
        loggers.validate_logger.info(f"has_sink_in_repaired_version:  {has_sink_in_repaired_version}")

        if len(db_objs) > 0:
            path_validation_map[0]["sanitization_check"] = CheckStatus.PASSED
        if has_tainted_obj and has_sink_in_vul_version and (has_sink_in_repaired_version == False):
            loggers.validate_logger.info(f"sanitized by replacing sink")
            path_validation_map[0]["sanitization_check"] = CheckStatus.PASSED
        if has_sink_in_vul_version and has_sink_in_repaired_version and not has_tainted_obj:
            loggers.validate_logger.info(f"sanitized by sanitizing tainted objects")
            path_validation_map[0]["sanitization_check"] = CheckStatus.PASSED
        for taint_obj in tainted_objs:
            taint_obj_attr = G.get_node_attr(taint_obj)
            taint_obj_ast = G.get_obj_def_ast_node(taint_obj)
            taint_obj_ast_attr = G.get_node_attr(taint_obj_ast)
            if taint_obj_ast_attr.get("type") == "AST_METHOD_CALL":
                code = taint_obj_ast_attr.get("code")
                if code and ".replace" in code:
                    path_validation_map[0]["sanitization_check"] = CheckStatus.PASSED
            loggers.validate_logger.info(f"taint_obj_ast:  {taint_obj_ast} {G.get_node_attr(taint_obj_ast)}")
            contributes_to_edges = G.get_in_edges(taint_obj, edge_type="CONTRIBUTES_TO")
            for e in contributes_to_edges:
                loggers.validate_logger.info(f"e:  {e}")
                from_obj = e[1]
                loggers.validate_logger.info(f"from_obj:  {from_obj} {G.get_node_attr(from_obj)}")
            loggers.validate_logger.info(f"taint_obj_attr:  {taint_obj} {taint_obj_attr}")

    for before_path_index, before_path in enumerate(before_paths):
        for repaired_path in vul_paths_in_repaired_version:
            if not is_node_the_same(before_path[0], repaired_path[0], line_maps_by_file):
                loggers.validate_logger.info(f"skip path {repaired_path}")
                continue
            loggers.validate_logger.info(f"checking path {before_path}")
            condition_check_exist, condition_check_against_input_range = security_check_for_conditional_validation(
                G, before_path=before_path, repaired_path=repaired_path, line_maps_by_file=line_maps_by_file
            )
            sanitization_check = security_check_for_sanitization_check(G, vul_G, before_path, repaired_path, line_maps_by_file)

            checks = {
                "condition_check_exist": condition_check_exist,
                "condition_check_against_input_range": condition_check_against_input_range,
                "sanitization_check": sanitization_check,
            }

            for check_key, check_value in checks.items():
                if check_value == CheckStatus.PASSED:
                    path_validation_map[before_path_index][check_key] = CheckStatus.PASSED

        for check_key in ["condition_check_exist", "condition_check_against_input_range", "sanitization_check"]:
            if path_validation_map[before_path_index][check_key] != CheckStatus.PASSED:
                path_validation_map[before_path_index][check_key] = CheckStatus.NOT_PASSED

    overall_security_check = finalize_security_check(path_validation_map)
    return overall_security_check, path_validation_map


def get_source_function_return_nodes(G, source_function_list):
    source_function_return_nodes = []
    for source_function in source_function_list:
        source_function_ast_node_id = source_function.get("id") if isinstance(source_function, dict) else source_function
        if not source_function_ast_node_id:
            continue
        ast_return_nodes = G.get_func_return_ast_nodes_by_func_id(source_function_ast_node_id)
        source_function_return_nodes.extend(ast_return_nodes)
    return list(set(source_function_return_nodes))


def functionality_check(G: Graph, vul_G: Graph, source_function_list, line_maps_by_file):
    default_check_status = CheckStatus.NOT_CHECKED
    overall_functionality_check = default_check_status
    return_type_check = default_check_status

    source_functions_in_repaired_version = map_func_to_repaired_version(G, source_function_list, line_maps_by_file)
    loggers.validate_logger.info(f"source_function_return_nodes here:  {source_functions_in_repaired_version}")

    source_function_return_nodes_in_vul_version = get_source_function_return_nodes(vul_G, source_function_list=source_function_list)
    loggers.validate_logger.info(f"source_function_return_nodes_in_vul_version:  {source_function_return_nodes_in_vul_version}")

    source_function_return_nodes_in_repaired_version = get_source_function_return_nodes(G, source_function_list=source_functions_in_repaired_version)
    loggers.validate_logger.info(f"source_function_return_nodes_in_repaired_version:  {source_function_return_nodes_in_repaired_version}")

    if len(source_function_return_nodes_in_vul_version) != len(source_function_return_nodes_in_repaired_version):
        loggers.validate_logger.info("❌ Return node list lengths do not match.")
    else:
        all_match = True
        loggers.validate_logger.info(f"source_function_return_nodes_in_vul_version:  {source_function_return_nodes_in_vul_version}")
        loggers.validate_logger.info(f"source_function_return_nodes_in_repaired_version:  {source_function_return_nodes_in_repaired_version}")

        for nid1, nid2 in zip(source_function_return_nodes_in_vul_version, source_function_return_nodes_in_repaired_version):
            if not are_ast_nodes_equivalent(nid1, nid2, vul_G, G, line_maps_by_file):
                nid1_objs = G.get_obj_nodes_by_ast_node(nid1)
                nid2_objs = G.get_obj_nodes_by_ast_node(nid2)
                if nid1_objs and nid2_objs:
                    all_match = False
                    loggers.validate_logger.info(f"❌ Node mismatch: {nid1} vs {nid2} {nid1_objs} {nid2_objs}")
            else:
                loggers.validate_logger.info(f"✅ Node match: {nid1} vs {nid2}")

        if all_match:
            return_type_check = CheckStatus.PASSED
            loggers.validate_logger.info("All return nodes are equivalent.")

    for source_function_index, source_function in enumerate(source_function_list):
        source_function_ast_node_id = source_function.get("id")
        ast_return_nodes = G.get_func_return_ast_nodes_by_func_id(source_function_ast_node_id)

        for ast_return_node in ast_return_nodes:
            ast_return_node_attr = G.get_node_attr(ast_return_node)
            return_code = ast_return_node_attr.get("code")
            if "new Error" in return_code:
                return_type_check = CheckStatus.PASSED

        if return_type_check == CheckStatus.PASSED:
            functionality_check = CheckStatus.PASSED
            overall_functionality_check = CheckStatus.PASSED

    if return_type_check == CheckStatus.PASSED:
        overall_functionality_check = CheckStatus.PASSED

    if not overall_functionality_check == CheckStatus.PASSED:
        overall_functionality_check = CheckStatus.NOT_PASSED

    return overall_functionality_check, return_type_check


def check_sanitization_nodes(G: Graph, ast_nodes, vul_ast):
    for ast_node in ast_nodes:
        ast_node_attr = G.get_node_attr(ast_node)


def validate_traceback(G: Graph, diff_list):
    overall_security_check = CheckStatus.NOT_CHECKED
    overall_functionality_check = CheckStatus.NOT_CHECKED

    loggers.validate_logger.info(f"repair_diff:  {options.repair_diff}")
    vul_G: Graph = Graph()

    vul_G.import_from_CSV(
        "/Users/amam/avr/tmp_log/nodes.csv", "/Users/amam/avr/tmp_log/rels.csv", vul_graph_info_file_path="/Users/amam/avr/tmp_log/vul_graph_info.json"
    )

    source_function_list, line_maps_by_file, vul_paths_in_vul_version = get_vul_graph_info(G, vul_G)

    source_function_list = vul_G.vul_graph_info["source_function_list"]
    taint_function_list = vul_G.vul_graph_info["taint_function_list"]

    source_functions_in_repaired_version = map_func_to_repaired_version(G, source_function_list, line_maps_by_file)
    loggers.validate_logger.info(f"source_functions_in_repaired_version:  {source_functions_in_repaired_version}")
    taint_functions_in_repaired_version = map_func_to_repaired_version(G, taint_function_list, line_maps_by_file)
    loggers.validate_logger.info(f"taint_functions_in_repaired_version:  {taint_functions_in_repaired_version}")

    vul_paths_in_repaired_version, source_func_arg_nodes, taint_func_arg_nodes = get_vul_paths_by_function_list(
        G, source_functions_in_repaired_version, taint_functions_in_repaired_version
    )

    loggers.validate_logger.info(
        f"vul_paths_in_vulnerable_version {len(vul_paths_in_vul_version)}:\n%s", json.dumps(vul_paths_in_vul_version, indent=2, ensure_ascii=False)
    )
    loggers.validate_logger.info(f"vul_paths_in_repaired_version:  {vul_paths_in_repaired_version}")
    loggers.validate_logger.info(
        f"vul_paths_in_repaired_version {len(vul_paths_in_repaired_version)}:\n%s", json.dumps(vul_paths_in_repaired_version, indent=2, ensure_ascii=False)
    )
    loggers.validate_logger.info(f"vulnerable version has {len(vul_paths_in_vul_version)} vulnerable paths")

    overall_security_check, path_validation_map = security_check(
        G,
        vul_G,
        vul_paths_in_vul_version,
        vul_paths_in_repaired_version,
        line_maps_by_file,
        diff_list,
        source_functions_in_repaired_version,
        taint_functions_in_repaired_version,
    )

    if overall_security_check == CheckStatus.NOT_PASSED:
        return overall_security_check, overall_functionality_check, path_validation_map, CheckStatus.NOT_CHECKED

    overall_functionality_check, return_type_check = functionality_check(G, vul_G, source_function_list, line_maps_by_file=line_maps_by_file)

    return overall_security_check, overall_functionality_check, path_validation_map, return_type_check
