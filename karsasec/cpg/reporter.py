"""CPGReporter rendering multi-format visualizations (JSON, Mermaid, DOT, interactive HTML) for CPGGraph."""

from __future__ import annotations

from karsasec.cpg.models import CPGGraph


class CPGReporter:
    """Exports interactive HTML, JSON, Mermaid, and Graphviz DOT renderings for Code Property Graphs."""

    def render_mermaid(self, graph: CPGGraph, max_nodes: int = 50) -> str:
        """Generates Mermaid flowchart diagram for CPG graph nodes and edges."""
        mermaid_lines = ["flowchart TB", "    %% KarsaSec Code Property Graph (CPG)"]

        for idx, (nid, node) in enumerate(graph.nodes.items()):
            if idx >= max_nodes:
                break
            safe_id = f"n_{nid[:8]}"
            clean_label = node.label.replace('"', '\\"')
            mermaid_lines.append(f'    {safe_id}["{node.node_type.value}: {clean_label}"]')

        for idx, edge in enumerate(graph.edges):
            if idx >= max_nodes:
                break
            s_id = f"n_{edge.source_id[:8]}"
            t_id = f"n_{edge.target_id[:8]}"
            if edge.source_id in graph.nodes and edge.target_id in graph.nodes:
                mermaid_lines.append(f"    {s_id} -->|{edge.edge_type.value}| {t_id}")

        return "\n".join(mermaid_lines)

    def render_dot(self, graph: CPGGraph) -> str:
        """Generates Graphviz DOT representation for CPG graph."""
        dot_lines = [
            "digraph CodePropertyGraph {",
            '    rankdir="TB";',
            '    node [shape="box", style="filled", fillcolor="#1e293b", fontcolor="#ffffff"];',
        ]

        for nid, node in graph.nodes.items():
            safe_id = f"n_{nid[:8]}"
            clean_label = node.label.replace('"', '\\"')
            dot_lines.append(f'    "{safe_id}" [label="{node.node_type.value}\\n{clean_label}"];')

        for edge in graph.edges:
            s_id = f"n_{edge.source_id[:8]}"
            t_id = f"n_{edge.target_id[:8]}"
            dot_lines.append(f'    "{s_id}" -> "{t_id}" [label="{edge.edge_type.value}"];')

        dot_lines.append("}")
        return "\n".join(dot_lines)

    def render_html_report(self, graph: CPGGraph) -> str:
        """Generates self-contained interactive HTML visualizer for CPG."""
        mermaid_code = self.render_mermaid(graph)
        json_data = graph.to_json(indent=2)
        meta = graph.metadata.to_dict()

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>KarsaSec Code Property Graph (CPG) Visualizer</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; background: #0f172a; color: #f8fafc; }}
        h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
        .badge {{ background: #3b82f6; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; margin-right: 10px; }}
        .container {{ display: flex; gap: 20px; flex-wrap: wrap; margin-top: 20px; }}
        .card {{ background: #1e293b; border-radius: 8px; padding: 20px; flex: 1; min-width: 450px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5); }}
        pre {{ background: #090d16; padding: 15px; border-radius: 6px; overflow-x: auto; color: #a5f3fc; font-size: 12px; max-height: 500px; }}
        .mermaid {{ background: #ffffff; padding: 20px; border-radius: 6px; text-align: center; }}
    </style>
</head>
<body>
    <h1>⚡ KarsaSec Enterprise Code Property Graph (CPG)</h1>
    <p>
        <span class="badge">Schema v{meta.get("schema_version")}</span>
        <strong>Project:</strong> {meta.get("project_name")} &nbsp;|&nbsp;
        <strong>Nodes:</strong> {meta.get("node_count")} &nbsp;|&nbsp;
        <strong>Edges:</strong> {meta.get("edge_count")} &nbsp;|&nbsp;
        <strong>Build Duration:</strong> {meta.get("duration_seconds")}s
    </p>

    <div class="container">
        <div class="card">
            <h2>Unified Code Property Graph</h2>
            <div class="mermaid">
{mermaid_code}
            </div>
        </div>
        <div class="card">
            <h2>CPG Metadata & Artifact JSON</h2>
            <pre>{json_data}</pre>
        </div>
    </div>
    <script>
        mermaid.initialize({{ startOnLoad: true, theme: 'default' }});
    </script>
</body>
</html>"""
