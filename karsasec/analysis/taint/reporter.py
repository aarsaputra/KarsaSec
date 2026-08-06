"""TaintGraph Visualizer and Interactive HTML/JSON Reporter."""

from __future__ import annotations

from karsasec.analysis.taint.models import TaintGraph, TaintState


class TaintReporter:
    """Exports interactive HTML and JSON visualizations for TaintGraph analysis artifacts."""

    def render_html_report(self, taint_graph: TaintGraph) -> str:
        """Generates a self-contained interactive HTML page highlighting Taint flow paths."""
        mermaid_lines = ["flowchart TD", f"    %% Taint Flow for {taint_graph.function_name}"]

        for nid, node in taint_graph.nodes.items():
            safe_id = nid.replace("::", "_").replace(".", "_").replace("-", "_")

            # Determine color styling
            if node.is_source or node.state == TaintState.TAINTED:
                color = "#ef4444"  # Red for Source/Tainted
            elif node.is_sanitizer or node.state == TaintState.SANITIZED:
                color = "#10b981"  # Green for Sanitizer
            elif node.is_sink:
                color = "#9333ea"  # Purple for Sink
            else:
                color = "#64748b"  # Slate for normal

            label = f"{node.var_name} (L{node.line_number}): {node.state.value}"
            mermaid_lines.append(f'    {safe_id}["{label}"]:::cls_{safe_id}')

        for edge in taint_graph.edges:
            src = edge.source_id.replace("::", "_").replace(".", "_").replace("-", "_")
            tgt = edge.target_id.replace("::", "_").replace(".", "_").replace("-", "_")
            mermaid_lines.append(f"    {src} --> {tgt}")

        mermaid_code = "\n".join(mermaid_lines)
        json_data = taint_graph.to_json(indent=2)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>KarsaSec Taint Analysis — {taint_graph.function_name}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; background: #0f172a; color: #f8fafc; }}
        h1 {{ color: #f43f5e; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
        .badge-vuln {{ background: #ef4444; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
        .badge-safe {{ background: #10b981; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
        .container {{ display: flex; gap: 20px; flex-wrap: wrap; margin-top: 20px; }}
        .card {{ background: #1e293b; border-radius: 8px; padding: 20px; flex: 1; min-width: 400px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5); }}
        pre {{ background: #090d16; padding: 15px; border-radius: 6px; overflow-x: auto; color: #a5f3fc; font-size: 13px; }}
        .mermaid {{ background: #ffffff; padding: 20px; border-radius: 6px; text-align: center; }}
    </style>
</head>
<body>
    <h1>🛡️ KarsaSec Taint Flow Visualizer — {taint_graph.function_name}</h1>
    <p>
        <strong>Vulnerable Paths:</strong> <span class="badge-vuln">{len(taint_graph.vulnerable_paths)}</span> &nbsp;|&nbsp;
        <strong>Safe/Sanitized Paths:</strong> <span class="badge-safe">{len(taint_graph.safe_paths)}</span>
    </p>

    <div class="container">
        <div class="card">
            <h2>Taint Flow Graph</h2>
            <div class="mermaid">
{mermaid_code}
            </div>
        </div>
        <div class="card">
            <h2>Raw Artifact JSON</h2>
            <pre>{json_data}</pre>
        </div>
    </div>
    <script>
        mermaid.initialize({{ startOnLoad: true, theme: 'default' }});
    </script>
</body>
</html>"""
