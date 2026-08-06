"""Builder engine for constructing CallGraph and ProjectGraph from AST and SemanticGraph."""

import re
from pathlib import Path

from karsasec.graph.edge import EdgeType, GraphEdge, ResolutionMechanism
from karsasec.graph.graph import CallGraph, ProjectGraph
from karsasec.graph.node import GraphNode, NodeKind, Visibility
from karsasec.graph.types import CallEdge, CallNode, CallType
from karsasec.parser.ast_nodes import FileNode
from karsasec.semantic.resolver import SemanticGraph


class ProjectGraphBuilder:
    """Aggregates per-file SemanticGraphs and ASTs into a unified ProjectGraph."""

    def build(self, file_nodes: list[FileNode], semantic_graphs: dict[Path, SemanticGraph]) -> ProjectGraph:
        """Constructs and returns a unified ProjectGraph with rich GraphNode and GraphEdge metadata."""
        project_graph = ProjectGraph()

        # Helper maps
        qname_to_node: dict[str, GraphNode] = {}
        node_id_to_graph_node: dict[str, GraphNode] = {}

        # Step 1: Register Module, Class, and Function GraphNodes
        for file_node in file_nodes:
            source_bytes = b""
            if file_node.file_path and file_node.file_path.exists():
                try:
                    source_bytes = file_node.file_path.read_bytes()
                except Exception:
                    pass

            module_name = file_node.file_path.stem if file_node.file_path else "module"

            # Register Module node
            module_node = GraphNode(
                uuid=file_node.node_id,
                kind=NodeKind.MODULE,
                language=file_node.language,
                qualified_name=module_name,
                namespace=module_name,
                file_path=file_node.file_path,
                line=file_node.start.line,
                column=file_node.start.column,
            )
            project_graph.add_node(module_node)
            node_id_to_graph_node[file_node.node_id] = module_node

            # Iterate AST nodes for classes, functions, variables
            for node_id, node in file_node.nodes_map.items():
                if node.node_type in ("class_definition", "class_declaration"):
                    text = node.get_text(source_bytes)
                    class_name = self._extract_class_name(text)
                    qname = f"{module_name}.{class_name}" if class_name else module_name

                    class_node = GraphNode(
                        uuid=node_id,
                        kind=NodeKind.CLASS,
                        language=file_node.language,
                        qualified_name=qname,
                        namespace=module_name,
                        file_path=file_node.file_path,
                        line=node.start.line,
                        column=node.start.column,
                    )
                    project_graph.add_node(class_node)
                    node_id_to_graph_node[node_id] = class_node
                    qname_to_node[qname] = class_node

                    # Add DEFINES edge from module to class
                    project_graph.add_edge(GraphEdge(
                        caller_id=file_node.node_id,
                        callee_id=node_id,
                        edge_type=EdgeType.DEFINES,
                        confidence=1.0,
                        resolved_symbol=qname,
                        resolved_by=ResolutionMechanism.AST_NATIVE,
                    ))

                elif node.node_type in (
                    "function_definition",
                    "function_declaration",
                    "method_declaration",
                    "method_definition",
                    "arrow_function",
                ):
                    text = node.get_text(source_bytes)
                    fn_name = self._extract_function_name(text, node.node_type)
                    class_owner = self._get_enclosing_class_name(node_id, file_node, source_bytes)

                    if class_owner:
                        qname = f"{module_name}.{class_owner}.{fn_name}"
                    else:
                        qname = f"{module_name}.{fn_name}"

                    signature = self._extract_signature(text)
                    visibility = Visibility.PRIVATE if fn_name.startswith("_") else Visibility.PUBLIC

                    fn_node = GraphNode(
                        uuid=node_id,
                        kind=NodeKind.FUNCTION,
                        language=file_node.language,
                        qualified_name=qname,
                        namespace=module_name,
                        signature=signature,
                        visibility=visibility,
                        file_path=file_node.file_path,
                        line=node.start.line,
                        column=node.start.column,
                    )
                    project_graph.add_node(fn_node)
                    node_id_to_graph_node[node_id] = fn_node
                    qname_to_node[qname] = fn_node

                    # DEFINES edge from module/class to function
                    parent_def_id = self._find_enclosing_def_id(node_id, file_node, node_id_to_graph_node) or file_node.node_id
                    project_graph.add_edge(GraphEdge(
                        caller_id=parent_def_id,
                        callee_id=node_id,
                        edge_type=EdgeType.DEFINES,
                        confidence=1.0,
                        resolved_symbol=qname,
                        resolved_by=ResolutionMechanism.AST_NATIVE,
                    ))

        # Step 2: Build CALLS and IMPORTS Edges
        for file_node in file_nodes:
            source_bytes = b""
            if file_node.file_path and file_node.file_path.exists():
                try:
                    source_bytes = file_node.file_path.read_bytes()
                except Exception:
                    pass

            sem_graph = semantic_graphs.get(file_node.file_path) if file_node.file_path else None

            # Process imports to create IMPORTS edges
            if sem_graph and sem_graph.alias_tracker:
                for alias_name, orig_symbol in sem_graph.alias_tracker.aliases.items():
                    target_node = qname_to_node.get(orig_symbol)
                    callee_id = target_node.uuid if target_node else "external_module"
                    project_graph.add_edge(GraphEdge(
                        caller_id=file_node.node_id,
                        callee_id=callee_id,
                        edge_type=EdgeType.IMPORTS,
                        confidence=1.0,
                        resolved_symbol=orig_symbol,
                        resolved_by=ResolutionMechanism.ALIAS_TRACKER,
                    ))

            # Process calls to create CALLS edges
            for node_id, node in file_node.nodes_map.items():
                if node.node_type in ("call", "call_expression"):
                    caller_id = self._find_enclosing_caller_id(node_id, file_node, node_id_to_graph_node) or file_node.node_id
                    text = node.get_text(source_bytes)
                    raw_target = self._extract_call_target(text)
                    resolved_target = raw_target
                    mech = ResolutionMechanism.AST_NATIVE

                    if sem_graph:
                        node_scope = self._find_enclosing_scope(node_id, sem_graph.scopes, file_node)
                        parts = raw_target.split(".", 1)
                        if parts:
                            base = parts[0]
                            resolved_base = node_scope.lookup(base) if node_scope else None
                            if not resolved_base:
                                resolved_base = sem_graph.alias_tracker.resolve(base)
                            if resolved_base and resolved_base != base:
                                resolved_target = ".".join([resolved_base] + parts[1:])
                                mech = ResolutionMechanism.ALIAS_TRACKER

                    callee_node = self._match_callee(resolved_target, qname_to_node, file_node.file_path)
                    callee_id = callee_node.uuid if callee_node else "external"

                    project_graph.add_edge(GraphEdge(
                        caller_id=caller_id,
                        callee_id=callee_id,
                        edge_type=EdgeType.CALLS,
                        confidence=0.9 if callee_node else 0.5,
                        resolved_symbol=resolved_target,
                        resolved_by=mech,
                        call_site_id=node_id,
                    ))

        return project_graph

    def _extract_class_name(self, text: str) -> str:
        match = re.search(r'\bclass\s+([a-zA-Z_][a-zA-Z0-9_]*)\b', text)
        return match.group(1) if match else ""

    def _extract_function_name(self, text: str, node_type: str) -> str:
        go_match = re.search(r'\bfunc\s+(?:\([^)]*\)\s*)?([a-zA-Z_][a-zA-Z0-9_]*)\b', text)
        if go_match:
            return go_match.group(1)
        py_match = re.search(r'\bdef\s+([a-zA-Z_][a-zA-Z0-9_]*)\b', text)
        if py_match:
            return py_match.group(1)
        js_match = re.search(r'\bfunction\s+([a-zA-Z_][a-zA-Z0-9_]*)\b', text)
        if js_match:
            return js_match.group(1)
        word_match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', text)
        return word_match.group(1) if word_match else "anonymous"

    def _extract_signature(self, text: str) -> str:
        match = re.search(r'\(([^)]*)\)', text)
        return f"({match.group(1)})" if match else "()"

    def _get_enclosing_class_name(self, node_id: str, file_node: FileNode, source_bytes: bytes) -> str | None:
        curr_id = node_id
        while curr_id:
            p_node = file_node.nodes_map.get(curr_id)
            if not p_node:
                break
            if p_node.node_type in ("class_definition", "class_declaration"):
                class_text = p_node.get_text(source_bytes)
                match = re.search(r'\bclass\s+([a-zA-Z_][a-zA-Z0-9_]*)\b', class_text)
                if match:
                    return match.group(1)
            curr_id = p_node.parent_id
        return None

    def _find_enclosing_def_id(self, node_id: str, file_node: FileNode, registered: dict[str, GraphNode]) -> str | None:
        curr_id = node_id
        while curr_id:
            p_node = file_node.nodes_map.get(curr_id)
            if not p_node:
                break
            if p_node.parent_id and p_node.parent_id in registered:
                return p_node.parent_id
            curr_id = p_node.parent_id
        return None

    def _find_enclosing_caller_id(self, node_id: str, file_node: FileNode, registered: dict[str, GraphNode]) -> str | None:
        curr_id = node_id
        while curr_id:
            p_node = file_node.nodes_map.get(curr_id)
            if not p_node:
                break
            if curr_id != node_id and curr_id in registered and registered[curr_id].kind == NodeKind.FUNCTION:
                return curr_id
            curr_id = p_node.parent_id
        return None

    def _extract_call_target(self, text: str) -> str:
        match = re.match(r'^([a-zA-Z0-9_\.\$]+)', text.strip())
        return match.group(1) if match else text.strip()

    def _find_enclosing_scope(self, node_id: str, scopes: dict, file_node: FileNode) -> object | None:
        curr_id = node_id
        while curr_id:
            if curr_id in scopes:
                return scopes[curr_id]
            p_node = file_node.nodes_map.get(curr_id)
            curr_id = p_node.parent_id if p_node else None
        return None

    def _match_callee(self, target: str, qname_to_node: dict[str, GraphNode], current_file: Path | None) -> GraphNode | None:
        if target in qname_to_node:
            return qname_to_node[target]
        if current_file:
            local_key = f"{current_file.stem}.{target}"
            if local_key in qname_to_node:
                return qname_to_node[local_key]
        for qname, node in qname_to_node.items():
            if qname.endswith(f".{target}"):
                return node
        return None


class CallGraphBuilder:
    """Traverses multi-language ASTs and SemanticGraphs to construct a unified CallGraph."""

    def __init__(self) -> None:
        pass

    def build(self, file_nodes: list[FileNode], semantic_graphs: dict[Path, SemanticGraph]) -> CallGraph:
        """Constructs and returns a unified CallGraph from parsed files and their semantic contexts."""
        cg = CallGraph()

        # Step 1: Discover and register all function/method definitions as nodes
        qualified_to_node: dict[str, CallNode] = {}
        id_to_node: dict[str, CallNode] = {}

        for file_node in file_nodes:
            source_bytes = b""
            if file_node.file_path and file_node.file_path.exists():
                try:
                    source_bytes = file_node.file_path.read_bytes()
                except Exception:
                    pass

            global_node_id = file_node.node_id
            global_qname = f"{file_node.file_path.stem}.<global>" if file_node.file_path else "<global>"
            global_node = CallNode(
                node_id=global_node_id,
                name="<global>",
                qualified_name=global_qname,
                file_path=file_node.file_path or Path(""),
                parameters=[],
                is_async=False,
                class_owner=None,
                language=file_node.language,
            )
            cg.add_node(global_node)
            id_to_node[global_node_id] = global_node
            qualified_to_node[global_qname] = global_node

            for node_id, node in file_node.nodes_map.items():
                if node.node_type in (
                    "function_definition",
                    "function_declaration",
                    "method_declaration",
                    "method_definition",
                    "arrow_function",
                ):
                    text = node.get_text(source_bytes)
                    name = self._extract_function_name(text, node.node_type)
                    class_owner = self._get_enclosing_class_name(node_id, file_node, source_bytes)

                    module_name = file_node.file_path.stem if file_node.file_path else "module"
                    if class_owner:
                        qualified_name = f"{module_name}.{class_owner}.{name}"
                    else:
                        qualified_name = f"{module_name}.{name}"

                    parameters = self._extract_parameters(text)
                    is_async = "async" in text.lower() or getattr(node, "is_async", False)

                    call_node = CallNode(
                        node_id=node_id,
                        name=name,
                        qualified_name=qualified_name,
                        file_path=file_node.file_path or Path(""),
                        parameters=parameters,
                        is_async=is_async,
                        class_owner=class_owner,
                        language=file_node.language,
                    )
                    cg.add_node(call_node)
                    id_to_node[node_id] = call_node
                    qualified_to_node[qualified_name] = call_node
                    qualified_to_node[f"{module_name}.{name}"] = call_node

        # Step 2: Traverse call sites and resolve caller-callee edges
        for file_node in file_nodes:
            source_bytes = b""
            if file_node.file_path and file_node.file_path.exists():
                try:
                    source_bytes = file_node.file_path.read_bytes()
                except Exception:
                    pass

            sem_graph = semantic_graphs.get(file_node.file_path) if file_node.file_path else None

            for node_id, node in file_node.nodes_map.items():
                if node.node_type in ("call", "call_expression"):
                    caller_id = self._find_enclosing_caller_id(node_id, file_node, id_to_node)
                    if not caller_id:
                        caller_id = file_node.node_id

                    text = node.get_text(source_bytes)
                    raw_target = self._extract_call_target(text)
                    resolved_target = raw_target
                    if sem_graph:
                        node_scope = self._find_enclosing_scope(node_id, sem_graph.scopes, file_node)
                        parts = raw_target.split(".", 1)
                        if parts:
                            base = parts[0]
                            resolved_base = node_scope.lookup(base) if node_scope else None
                            if not resolved_base:
                                resolved_base = sem_graph.alias_tracker.resolve(base)
                            if resolved_base and resolved_base != base:
                                resolved_target = ".".join([resolved_base] + parts[1:])
                            else:
                                if node_scope:
                                    resolved_target = node_scope.lookup(raw_target) or raw_target
                                else:
                                    resolved_target = sem_graph.alias_tracker.resolve(raw_target)

                    class_owner = self._get_enclosing_class_name(node_id, file_node, source_bytes)
                    if resolved_target.startswith("self."):
                        if class_owner:
                            resolved_target = resolved_target.replace("self.", f"{class_owner}.", 1)
                        else:
                            resolved_target = resolved_target.replace("self.", "", 1)
                    elif resolved_target.startswith("this."):
                        if class_owner:
                            resolved_target = resolved_target.replace("this.", f"{class_owner}.", 1)
                        else:
                            resolved_target = resolved_target.replace("this.", "", 1)
                    elif resolved_target.startswith("$this->"):
                        if class_owner:
                            resolved_target = resolved_target.replace("$this->", f"{class_owner}.", 1)
                        else:
                            resolved_target = resolved_target.replace("$this->", "", 1)

                    callee_id = "external"
                    matching_node = self._match_callee(resolved_target, qualified_to_node, file_node.file_path)
                    if matching_node:
                        callee_id = matching_node.node_id

                    call_type = CallType.STATIC
                    if "." in raw_target:
                        call_type = CallType.DYNAMIC
                    elif re.search(r'\b(?:callback|cb|handler|fn)\b', raw_target.lower()):
                        call_type = CallType.INDIRECT

                    edge = CallEdge(
                        caller_id=caller_id,
                        callee_id=callee_id,
                        call_site_id=node_id,
                        call_type=call_type,
                        resolved_symbol=resolved_target,
                        line=node.start.line,
                        column=node.start.column,
                    )
                    cg.add_edge(edge)

        return cg

    def _extract_function_name(self, text: str, node_type: str) -> str:
        go_match = re.search(r'\bfunc\s+(?:\([^)]*\)\s*)?([a-zA-Z_][a-zA-Z0-9_]*)\b', text)
        if go_match:
            return go_match.group(1)
        py_match = re.search(r'\bdef\s+([a-zA-Z_][a-zA-Z0-9_]*)\b', text)
        if py_match:
            return py_match.group(1)
        js_match = re.search(r'\bfunction\s+([a-zA-Z_][a-zA-Z0-9_]*)\b', text)
        if js_match:
            return js_match.group(1)
        word_match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', text)
        return word_match.group(1) if word_match else "anonymous"

    def _get_enclosing_class_name(self, node_id: str, file_node: FileNode, source_bytes: bytes) -> str | None:
        curr_id = node_id
        while curr_id:
            p_node = file_node.nodes_map.get(curr_id)
            if not p_node:
                break
            if p_node.node_type in ("class_definition", "class_declaration"):
                class_text = p_node.get_text(source_bytes)
                match = re.search(r'\bclass\s+([a-zA-Z_][a-zA-Z0-9_]*)\b', class_text)
                if match:
                    return match.group(1)
            curr_id = p_node.parent_id
        return None

    def _extract_parameters(self, text: str) -> list[str]:
        param_match = re.search(r'\(([^)]*)\)', text)
        params = []
        if param_match:
            param_str = param_match.group(1)
            for p in param_str.split(","):
                p_clean = p.split(":")[0].split("=")[0].strip()
                if p_clean and p_clean not in ("self", "cls"):
                    params.append(p_clean)
        return params

    def _find_enclosing_caller_id(self, node_id: str, file_node: FileNode, id_to_node: dict[str, CallNode]) -> str | None:
        curr_id = node_id
        while curr_id:
            p_node = file_node.nodes_map.get(curr_id)
            if not p_node:
                break
            if curr_id != node_id and curr_id in id_to_node:
                return curr_id
            curr_id = p_node.parent_id
        return None

    def _extract_call_target(self, text: str) -> str:
        match = re.match(r'^([a-zA-Z0-9_\.\$]+)', text.strip())
        return match.group(1) if match else text.strip()

    def _find_enclosing_scope(self, node_id: str, scopes: dict, file_node: FileNode) -> object | None:
        curr_id = node_id
        while curr_id:
            if curr_id in scopes:
                return scopes[curr_id]
            p_node = file_node.nodes_map.get(curr_id)
            curr_id = p_node.parent_id if p_node else None
        return None

    def _match_callee(self, target: str, qualified_to_node: dict[str, CallNode], current_file: Path | None) -> CallNode | None:
        if target in qualified_to_node:
            return qualified_to_node[target]
        if current_file:
            local_key = f"{current_file.stem}.{target}"
            if local_key in qualified_to_node:
                return qualified_to_node[local_key]
        for qname, node in qualified_to_node.items():
            if qname.endswith(f".{target}") or node.name == target:
                return node
        return None
