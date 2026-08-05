"""Semantic symbol resolution engine and semantic graph builder."""

import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from karsasec.parser.ast_nodes import ASTNode, FileNode
from karsasec.semantic.scope import Scope, ScopeType
from karsasec.semantic.alias_tracker import AliasTracker

def get_node_text(node: ASTNode, source_bytes: bytes) -> str:
    """Extracts node text accurately using byte offsets or falling back to line slicing."""
    if not source_bytes:
        return ""
    if node.node_type == "file":
        return source_bytes.decode("utf-8", errors="ignore")
    if getattr(node, "byte_start", 0) > 0 or getattr(node, "byte_end", 0) < len(source_bytes):
        return source_bytes[node.byte_start:node.byte_end].decode("utf-8", errors="ignore")
    try:
        lines = source_bytes.decode("utf-8", errors="ignore").splitlines()
        start_line = node.start.line - 1
        end_line = node.end.line - 1
        if 0 <= start_line < len(lines):
            if start_line == end_line:
                return lines[start_line][node.start.column:node.end.column]
            else:
                slice_lines = [lines[start_line][node.start.column:]]
                for l in range(start_line + 1, end_line):
                    if l < len(lines):
                        slice_lines.append(lines[l])
                if end_line < len(lines):
                    slice_lines.append(lines[end_line][:node.end.column])
                return "\n".join(slice_lines)
    except Exception:
        pass
    return node.get_text(source_bytes)

class SemanticGraph:
    """Stores resolved symbol bindings, aliases, and scopes for a parsed AST file."""

    __slots__ = ("node_symbols", "scopes", "alias_tracker")

    def __init__(self) -> None:
        self.node_symbols: Dict[str, str] = {}  # Maps node_id to fully-qualified resolved symbol
        self.scopes: Dict[str, Scope] = {}      # Maps block/function node_id to its Scope
        self.alias_tracker = AliasTracker()

    def resolve_node(self, node_id: str) -> Optional[str]:
        """Resolves the fully qualified symbol name for a given node ID."""
        return self.node_symbols.get(node_id)


class SemanticResolver:
    """Performs semantic analysis to resolve scopes, imports, and symbol aliases in ASTs."""

    def resolve_file(self, file_node: FileNode) -> SemanticGraph:
        """Analyzes FileNode and returns its populated SemanticGraph."""
        graph = SemanticGraph()
        if not file_node:
            return graph

        # 1. Read source bytes to extract accurate node text
        source_bytes = b""
        if file_node.file_path and file_node.file_path.exists():
            try:
                source_bytes = file_node.file_path.read_bytes()
            except Exception:
                pass

        # 2. Build scope map (Pre-pass)
        global_scope = Scope(ScopeType.GLOBAL)
        graph.scopes[file_node.node_id] = global_scope

        # Identify all scope-defining block nodes
        for node_id, node in file_node.nodes_map.items():
            if node.node_type in ("function_definition", "class_definition", "function_declaration", "class_declaration"):
                scope_type = ScopeType.CLASS if "class" in node.node_type else ScopeType.FUNCTION
                # Parent scope will be resolved in second pass, temporary set parent to None
                graph.scopes[node_id] = Scope(scope_type)

        # Link parent scopes
        for node_id, scope in graph.scopes.items():
            if node_id == file_node.node_id:
                continue
            node = file_node.nodes_map.get(node_id)
            if node:
                parent_scope = self._find_enclosing_scope(node.parent_id, graph.scopes, file_node)
                scope.parent = parent_scope

        # 3. Analyze imports and assignments to populate scopes and aliases
        # Walk DFS to resolve bindings chronologically
        stack = [file_node.node_id]
        visited: Set[str] = set()

        while stack:
            curr_id = stack.pop()
            if curr_id in visited:
                continue
            visited.add(curr_id)

            if curr_id == file_node.node_id:
                node = file_node
            else:
                node = file_node.nodes_map.get(curr_id)

            if not node:
                continue

            node_scope = self._find_enclosing_scope(curr_id, graph.scopes, file_node)
            node_text = get_node_text(node, source_bytes).strip()

            # Process imports
            is_import = self._process_imports(node, node_text, node_scope, graph)

            # Process assignments
            if not is_import:
                self._process_assignments(node, node_text, node_scope, graph)

            # Push children
            for child_id in reversed(node.children):
                if child_id not in visited:
                    stack.append(child_id)

        # 4. Resolve node identifiers (calls, names) to fully qualified symbols
        for node_id, node in file_node.nodes_map.items():
            node_scope = self._find_enclosing_scope(node_id, graph.scopes, file_node)
            node_text = get_node_text(node, source_bytes).strip()

            # For call nodes or name nodes, try to resolve target
            resolved = None
            if node.node_type in ("call", "name", "identifier"):
                # Clean function/variable name from call (e.g. runner(cmd) -> runner)
                name = node_text
                if "(" in name:
                    name = name.split("(", 1)[0].strip()
                
                # Clean PHP prefix
                name_clean = name.replace("$", "").strip()
                
                # Check scope bindings
                resolved = node_scope.lookup(name_clean)
                if not resolved:
                    # Check transitive aliases
                    resolved = graph.alias_tracker.resolve(name_clean)
                    if resolved == name_clean:
                        resolved = None

            if resolved:
                graph.node_symbols[node_id] = resolved

        return graph

    def _find_enclosing_scope(self, node_id: Optional[str], scopes: Dict[str, Scope], file_node: FileNode) -> Scope:
        """Finds the closest enclosing lexical scope for a given node ID."""
        curr_id = node_id
        while curr_id:
            if curr_id in scopes:
                return scopes[curr_id]
            node = file_node.nodes_map.get(curr_id)
            if not node:
                break
            curr_id = node.parent_id
        return scopes[file_node.node_id]

    def _process_imports(self, node: ASTNode, node_text: str, scope: Scope, graph: SemanticGraph) -> bool:
        """Parses import declarations across Python, JS, Go, and PHP, registering scope bindings."""
        # Python: import module [as alias]
        py_imp_match = re.match(r"^\s*import\s+([a-zA-Z0-9_\.]+)(?:\s+as\s+([a-zA-Z0-9_]+))?", node_text)
        if py_imp_match:
            module, alias = py_imp_match.groups()
            bound_name = alias if alias else module
            scope.define(bound_name, module)
            graph.alias_tracker.register_alias(bound_name, module)
            return True

        # Python: from module import name [as alias]
        py_from_match = re.match(r"^\s*from\s+([a-zA-Z0-9_\.]+)\s+import\s+([a-zA-Z0-9_]+)(?:\s+as\s+([a-zA-Z0-9_]+))?", node_text)
        if py_from_match:
            module, name, alias = py_from_match.groups()
            bound_name = alias if alias else name
            fqn = f"{module}.{name}"
            scope.define(bound_name, fqn)
            graph.alias_tracker.register_alias(bound_name, fqn)
            return True

        # JS/TS: import name from 'module'
        js_imp_match = re.match(r'^\s*import\s+([a-zA-Z0-9_]+)\s+from\s+[\'"]([^\'"]+)[\'"]', node_text)
        if js_imp_match:
            name, module = js_imp_match.groups()
            scope.define(name, module)
            graph.alias_tracker.register_alias(name, module)
            return True

        # JS/TS: require('module')
        js_req_match = re.search(r'require\([\'"]([^\'"]+)[\'"]\)', node_text)
        if js_req_match:
            module = js_req_match.group(1)
            # Try to find assigned name in same statement, e.g., const os = require('os')
            assign_match = re.match(r"^\s*(?:const|let|var)\s+([a-zA-Z0-9_]+)\s*=", node_text)
            if assign_match:
                name = assign_match.group(1)
                scope.define(name, module)
                graph.alias_tracker.register_alias(name, module)
            return True

        # Go: import "module" or import alias "module"
        go_imp_match = re.match(r'^\s*import\s+(?:([a-zA-Z0-9_]+)\s+)?[\'"]([^\'"]+)[\'"]', node_text)
        if go_imp_match:
            alias, module = go_imp_match.groups()
            bound_name = alias if alias else module.split("/")[-1]
            scope.define(bound_name, module)
            graph.alias_tracker.register_alias(bound_name, module)
            return True

        # PHP: use Namespace as Alias
        php_use_match = re.match(r"^\s*use\s+([a-zA-Z0-9_\\]+)(?:\s+as\s+([a-zA-Z0-9_]+))?;", node_text)
        if php_use_match:
            ns, alias = php_use_match.groups()
            normalized_ns = ns.replace("\\", ".")
            bound_name = alias if alias else normalized_ns.split(".")[-1]
            scope.define(bound_name, normalized_ns)
            graph.alias_tracker.register_alias(bound_name, normalized_ns)
            return True

        return False

    def _process_assignments(self, node: ASTNode, node_text: str, scope: Scope, graph: SemanticGraph) -> None:
        """Parses assignment statements across languages, tracking variable aliasing."""
        # Generic assignment matching: target = value
        # Python / JS: runner = os.system
        assign_match = re.match(r"^\s*(?:const\s+|let\s+|var\s+)?([a-zA-Z0-9_\$]+)\s*(?::=|=)\s*([a-zA-Z0-9_\.]+)", node_text)
        if assign_match:
            target, value = assign_match.groups()
            
            # Strip standard JS/PHP prefixes
            target_clean = target.replace("const ", "").replace("let ", "").replace("var ", "").replace("$", "").strip()
            
            # Resolve value in scope or alias tracker
            parts = value.split(".")
            resolved_base = scope.lookup(parts[0]) or graph.alias_tracker.resolve(parts[0])
            
            if resolved_base and resolved_base != parts[0]:
                resolved_value = ".".join([resolved_base] + parts[1:])
            else:
                resolved_value = value

            scope.define(target_clean, resolved_value)
            graph.alias_tracker.register_alias(target_clean, resolved_value)
