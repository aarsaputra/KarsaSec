"""Interprocedural Taint Visualizer rendering cross-function flow chains in HTML, JSON, Mermaid, and DOT formats."""

from __future__ import annotations

from karsasec.analysis.interprocedural.models import InterproceduralTaintGraph


class InterproceduralReporter:
    """Exports interactive HTML, JSON, Mermaid, and DOT visualizations for InterproceduralTaintGraph artifacts."""

    def render_mermaid(self, itg: InterproceduralTaintGraph) -> str:
        """Generates Mermaid flowchart diagram for cross-function taint flows."""
        mermaid_lines = ["flowchart LR", "    %% Cross-Function Interprocedural Flow Chain"]

        for idx, path in enumerate(itg.vulnerable_paths):
            src_func = path.source_func.replace("::", "_").replace(".", "_")
            snk_func = path.sink_func.replace("::", "_").replace(".", "_")
            mermaid_lines.append(f'    subgraph CallChain_{idx} ["Call Chain #{idx+1}"]')
            mermaid_lines.append(f'        {src_func}_src["Source: {path.source_func}"]')
            for cs in path.call_chain:
                c_name = cs.callee_name.replace("::", "_").replace(".", "_")
                mermaid_lines.append(f'        {src_func}_src -->|Line {cs.line_number}| {c_name}')
            mermaid_lines.append(f'        {snk_func}_snk["Sink: {path.sink_func}"]')
            mermaid_lines.append("    end")

        return "\n".join(mermaid_lines)

    def render_dot(self, itg: InterproceduralTaintGraph) -> str:
        """Generates DOT Graphviz representation for cross-function taint flows."""
        dot_lines = ["digraph InterproceduralTaint {", '    rankdir="LR";', '    node [shape="box", style="filled", fillcolor="#1e293b", fontcolor="#ffffff"];']

        for path in itg.vulnerable_paths:
            src = path.source_func.replace("::", "_").replace(".", "_")
            snk = path.sink_func.replace("::", "_").replace(".", "_")
            dot_lines.append(f'    "{src}" -> "{snk}" [color="red", label="vulnerable"];')

        for path in itg.safe_paths:
            src = path.source_func.replace("::", "_").replace(".", "_")
            snk = path.sink_func.replace("::", "_").replace(".", "_")
            dot_lines.append(f'    "{src}" -> "{snk}" [color="green", label="sanitized"];')

        dot_lines.append("}")
        return "\n".join(dot_lines)

    def render_html_report(self, itg: InterproceduralTaintGraph) -> str:
        """Generates self-contained interactive HTML page highlighting cross-function call chains."""
        mermaid_code = self.render_mermaid(itg)
        json_data = itg.to_json(indent=2)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>KarsaSec Interprocedural Taint Analysis</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; background: #0f172a; color: #f8fafc; }}
        h1 {{ color: #a855f7; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
        .badge-vuln {{ background: #ef4444; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
        .badge-safe {{ background: #10b981; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
        .container {{ display: flex; gap: 20px; flex-wrap: wrap; margin-top: 20px; }}
        .card {{ background: #1e293b; border-radius: 8px; padding: 20px; flex: 1; min-width: 400px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5); }}
        pre {{ background: #090d16; padding: 15px; border-radius: 6px; overflow-x: auto; color: #a5f3fc; font-size: 13px; }}
        .mermaid {{ background: #ffffff; padding: 20px; border-radius: 6px; text-align: center; }}
    </style>
</head>
<body>
    <h1>🌐 KarsaSec Interprocedural Flow Visualizer</h1>
    <p>
        <strong>Total Summaries:</strong> {len(itg.function_summaries)} &nbsp;|&nbsp;
        <strong>Vulnerable Call Chains:</strong> <span class="badge-vuln">{len(itg.vulnerable_paths)}</span> &nbsp;|&nbsp;
        <strong>Safe Call Chains:</strong> <span class="badge-safe">{len(itg.safe_paths)}</span>
    </p>

    <div class="container">
        <div class="card">
            <h2>Cross-Function Call Graph</h2>
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
