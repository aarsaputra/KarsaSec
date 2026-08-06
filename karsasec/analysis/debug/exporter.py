"""Graph Visualization Exporter for AST, IR, CFG, SymbolGraph, and CallGraph debugging."""

from __future__ import annotations

import json

from karsasec.analysis.callgraph.models import CallGraph
from karsasec.analysis.symbol.models import SymbolGraph
from karsasec.ir.nodes import IRFunction
from karsasec.parser.ast_nodes import FileNode


class GraphDebuggerExporter:
    """Exports pipeline analysis artifacts (AST, IR, SymbolGraph, CallGraph, CFG) to HTML, Mermaid, and JSON."""

    def render_html_page(self, title: str, mermaid_content: str, json_content: str) -> str:
        """Generates a self-contained interactive HTML page for visualizing graph artifacts."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>KarsaSec Debugger — {title}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; background: #0f172a; color: #f8fafc; }}
        h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
        .container {{ display: flex; gap: 20px; flex-wrap: wrap; }}
        .card {{ background: #1e293b; border-radius: 8px; padding: 20px; flex: 1; min-width: 400px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5); }}
        pre {{ background: #090d16; padding: 15px; border-radius: 6px; overflow-x: auto; color: #a5f3fc; font-size: 13px; }}
        .mermaid {{ background: #ffffff; padding: 20px; border-radius: 6px; text-align: center; }}
    </style>
</head>
<body>
    <h1>🔍 KarsaSec Analysis Debugger — {title}</h1>
    <div class="container">
        <div class="card">
            <h2>Graph Diagram</h2>
            <div class="mermaid">
{mermaid_content}
            </div>
        </div>
        <div class="card">
            <h2>Raw JSON Representation</h2>
            <pre>{json_content}</pre>
        </div>
    </div>
    <script>
        mermaid.initialize({{ startOnLoad: true, theme: 'default' }});
    </script>
</body>
</html>"""

    def export_ast(self, file_node: FileNode) -> tuple[str, str]:
        """Returns (mermaid_str, json_str) for an AST FileNode."""
        lines = ["graph TD", "    %% AST Visualization"]
        nodes_dict = {}

        for nid, node in file_node.nodes_map.items():
            safe_id = nid.replace("::", "_").replace(".", "_").replace("-", "_")
            label = f"{node.node_type} (L{node.start.line})"
            lines.append(f'    {safe_id}["{label}"]')
            if node.parent_id and node.parent_id in file_node.nodes_map:
                parent_safe = node.parent_id.replace("::", "_").replace(".", "_").replace("-", "_")
                lines.append(f"    {parent_safe} --> {safe_id}")

            nodes_dict[nid] = {
                "node_type": node.node_type,
                "line": node.start.line,
                "language": node.language,
            }

        return "\n".join(lines), json.dumps(nodes_dict, indent=2)

    def export_ir(self, ir_functions: list[IRFunction]) -> tuple[str, str]:
        """Returns (mermaid_str, json_str) for Universal IR functions."""
        lines = ["graph TD", "    %% Universal IR Visualization"]
        json_data = [fn.to_dict() for fn in ir_functions]

        for fn in ir_functions:
            fn_id = fn.id.replace("::", "_").replace(".", "_").replace("-", "_")
            lines.append(f'    {fn_id}["IR Function: {fn.name}"]')

            for idx, stmt in enumerate(fn.body_statements):
                stmt_id = f"{fn_id}_stmt_{idx}"
                stmt_label = f"{stmt.__class__.__name__} (L{stmt.line_number})"
                lines.append(f'    {stmt_id}["{stmt_label}"]')
                lines.append(f"    {fn_id} --> {stmt_id}")

        return "\n".join(lines), json.dumps(json_data, indent=2)

    def export_symbols(self, symbol_graph: SymbolGraph) -> tuple[str, str]:
        """Returns (mermaid_str, json_str) for SymbolGraph."""
        lines = ["graph LR", "    %% SymbolGraph Visualization"]
        json_data = symbol_graph.to_dict()

        for sym in symbol_graph.symbols.values():
            sym_id = sym.qualified_name.replace("::", "_").replace(".", "_").replace("-", "_")
            lines.append(f'    {sym_id}["{sym.kind.value}: {sym.qualified_name}"]')

        return "\n".join(lines), json.dumps(json_data, indent=2)

    def export_callgraph(self, callgraph: CallGraph) -> tuple[str, str]:
        """Returns (mermaid_str, json_str) for CallGraph."""
        lines = ["graph TD", "    %% CallGraph Visualization"]
        json_data = callgraph.to_dict()

        for fn_name in callgraph.nodes:
            safe_fn = fn_name.replace("::", "_").replace(".", "_").replace("-", "_")
            lines.append(f'    {safe_fn}["Function: {fn_name}"]')

        for edge in callgraph.edges:
            src = edge.caller.replace("::", "_").replace(".", "_").replace("-", "_")
            tgt = edge.callee.replace("::", "_").replace(".", "_").replace("-", "_")
            lines.append(f"    {src} --> {tgt}")

        return "\n".join(lines), json.dumps(json_data, indent=2)
