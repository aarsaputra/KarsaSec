"""FrameworkReporter module exporting FrameworkGraph and FrameworkMetadata to JSON, Mermaid, DOT, and HTML formats."""

from __future__ import annotations

import json
from typing import Any

from karsasec.framework.models import FrameworkGraph, FrameworkMetadata


class FrameworkReporter:
    """Exports FrameworkGraph and FrameworkMetadata into JSON (primary), Mermaid, DOT, and HTML formats."""

    def export_json(self, graph: FrameworkGraph, metadata: FrameworkMetadata | None = None) -> str:
        """Exports FrameworkGraph and optional FrameworkMetadata to formatted JSON string (primary format)."""
        data: dict[str, Any] = {
            "graph": graph.to_dict(),
        }
        if metadata:
            data["metadata"] = metadata.to_dict()
        return json.dumps(data, indent=2)

    def export_mermaid(self, graph: FrameworkGraph) -> str:
        """Exports FrameworkGraph to Mermaid diagram syntax for CLI rendering."""
        lines = ["graph TD"]
        for node in graph.nodes.values():
            label = f"{node.name} ({node.node_type.value})"
            lines.append(f'  {node.id}["{label}"]')
        for edge in graph.edges:
            lines.append(f"  {edge.source_id} -->|{edge.edge_type}| {edge.target_id}")
        return "\n".join(lines)

    def export_dot(self, graph: FrameworkGraph) -> str:
        """Exports FrameworkGraph to Graphviz DOT format."""
        lines = ["digraph FrameworkGraph {", '  rankdir="LR";', '  node [shape="box", style="rounded,filled", fillcolor="#eef2ff"];']
        for node in graph.nodes.values():
            lines.append(f'  "{node.id}" [label="{node.name}\\n({node.node_type.value})"];')
        for edge in graph.edges:
            lines.append(f'  "{edge.source_id}" -> "{edge.target_id}" [label="{edge.edge_type}"];')
        lines.append("}")
        return "\n".join(lines)

    def export_html(self, graph: FrameworkGraph, metadata: FrameworkMetadata | None = None) -> str:
        """Exports FrameworkGraph to standalone HTML report document."""
        json_str = self.export_json(graph, metadata)
        mermaid_str = self.export_mermaid(graph)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>KarsaSec Framework Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #0f172a; color: #f8fafc; }}
        h1 {{ color: #38bdf8; }}
        pre {{ background: #1e293b; padding: 1rem; border-radius: 8px; overflow-x: auto; }}
        .mermaid {{ background: #1e293b; padding: 1.5rem; border-radius: 8px; margin-top: 1rem; }}
    </style>
</head>
<body>
    <h1>KarsaSec Framework Analysis Report</h1>
    <h2>Topology Visualization</h2>
    <div class="mermaid">
{mermaid_str}
    </div>
    <h2>JSON Data Output</h2>
    <pre><code>{json_str}</code></pre>
    <script>mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});</script>
</body>
</html>
"""
