from typing import Dict, Set, List, Tuple
from .logger import loggers


class PendingCodeSlice:
    def __init__(self):
        self.file_path_and_nodes: Dict[str, Set[int]] = {}
        self.file_path_and_line_ranges: Dict[str, List[Tuple[int, int]]] = {}
        self.file_path_and_source_function_nodes: Dict[str, Set[int]] = {}
        self.file_path_and_taint_function_nodes: Dict[str, Set[int]] = {}

    def add_ast_node(self, file_path: str, ast_node_id: int) -> None:
        loggers.code_slice_logger.info(f"[Pending Slice] [AST] {file_path} {ast_node_id}")
        if file_path in self.file_path_and_nodes:
            self.file_path_and_nodes[file_path].add(ast_node_id)
        else:
            self.file_path_and_nodes[file_path] = {ast_node_id}

    def add_source_function_ast_node(self, file_path: str, ast_node_id: int) -> None:
        loggers.code_slice_logger.info(f"[Pending Slice] [Source Func AST] {file_path} {ast_node_id}")
        if file_path in self.file_path_and_source_function_nodes:
            self.file_path_and_source_function_nodes[file_path].add(ast_node_id)
        else:
            self.file_path_and_source_function_nodes[file_path] = {ast_node_id}

    def add_taint_function_ast_node(self, file_path: str, ast_node_id: int) -> None:
        loggers.code_slice_logger.info(f"[Pending Slice] [Taint Func AST] {file_path} {ast_node_id}")
        if file_path in self.file_path_and_taint_function_nodes:
            self.file_path_and_taint_function_nodes[file_path].add(ast_node_id)
        else:
            self.file_path_and_taint_function_nodes[file_path] = {ast_node_id}

    def add_line_range(self, file_path: str, start_lineno, end_lineno) -> None:
        if start_lineno is None or end_lineno is None:
            raise ValueError(f"Line numbers cannot be None: {start_lineno}, {end_lineno}")

        try:
            start_lineno = int(start_lineno)
            end_lineno = int(end_lineno)
        except (ValueError, TypeError):
            raise TypeError(f"Line numbers must be integers or strings representing integers: {start_lineno}, {end_lineno}")

        loggers.code_slice_logger.info(f"[Pending Slice] [Line Range] {file_path} {start_lineno} - {end_lineno}")

        if file_path not in self.file_path_and_line_ranges:
            self.file_path_and_line_ranges[file_path] = []
        self.file_path_and_line_ranges[file_path].append((start_lineno, end_lineno))

    def __str__(self) -> str:
        return (
            f"PendingCodeSlice("
            f"nodes={self.file_path_and_nodes}, "
            f"line_ranges={self.file_path_and_line_ranges}, "
            f"source_function_nodes={self.file_path_and_source_function_nodes})"
        )
