"""Serializer engine for exporting and importing ProjectGraph to/from SQLite and JSON."""

import json
import sqlite3
from pathlib import Path

from karsasec.graph.edge import EdgeType, GraphEdge, ResolutionMechanism
from karsasec.graph.graph import ProjectGraph
from karsasec.graph.node import GraphNode, NodeKind, Visibility


class GraphSerializer:
    """Handles persistence of ProjectGraph to disk (SQLite database or JSON format)."""

    def save_sqlite(self, graph: ProjectGraph, db_path: str | Path) -> None:
        """Serializes ProjectGraph nodes and edges into an indexed SQLite database."""
        path = Path(db_path)
        if path.exists():
            path.unlink()

        conn = sqlite3.connect(path)
        cursor = conn.cursor()

        # Create schema tables
        cursor.execute("""
            CREATE TABLE nodes (
                uuid TEXT PRIMARY KEY,
                kind TEXT,
                language TEXT,
                qualified_name TEXT,
                namespace TEXT,
                signature TEXT,
                visibility TEXT,
                file_path TEXT,
                line INTEGER,
                column INTEGER,
                attributes TEXT
            )
        """)
        cursor.execute("CREATE INDEX idx_nodes_qname ON nodes (qualified_name)")

        cursor.execute("""
            CREATE TABLE edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                caller_id TEXT,
                callee_id TEXT,
                edge_type TEXT,
                confidence REAL,
                resolved_symbol TEXT,
                resolved_by TEXT,
                call_site_id TEXT,
                attributes TEXT
            )
        """)
        cursor.execute("CREATE INDEX idx_edges_caller ON edges (caller_id)")
        cursor.execute("CREATE INDEX idx_edges_callee ON edges (callee_id)")

        # Insert nodes
        node_rows = []
        for node in graph.nodes.values():
            node_rows.append(
                (
                    node.uuid,
                    node.kind.value if isinstance(node.kind, NodeKind) else str(node.kind),
                    node.language,
                    node.qualified_name,
                    node.namespace,
                    node.signature,
                    node.visibility.value if isinstance(node.visibility, Visibility) else str(node.visibility),
                    str(node.file_path) if node.file_path else "",
                    node.line,
                    node.column,
                    json.dumps(node.attributes),
                )
            )

        cursor.executemany(
            """
            INSERT INTO nodes (uuid, kind, language, qualified_name, namespace, signature, visibility, file_path, line, column, attributes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            node_rows,
        )

        # Insert edges
        edge_rows = []
        for edge in graph.edges:
            edge_rows.append(
                (
                    edge.caller_id,
                    edge.callee_id,
                    edge.edge_type.value if isinstance(edge.edge_type, EdgeType) else str(edge.edge_type),
                    edge.confidence,
                    edge.resolved_symbol,
                    edge.resolved_by.value
                    if isinstance(edge.resolved_by, ResolutionMechanism)
                    else str(edge.resolved_by),
                    edge.call_site_id or "",
                    json.dumps(edge.attributes),
                )
            )

        cursor.executemany(
            """
            INSERT INTO edges (caller_id, callee_id, edge_type, confidence, resolved_symbol, resolved_by, call_site_id, attributes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            edge_rows,
        )

        conn.commit()
        conn.close()

    def load_sqlite(self, db_path: str | Path) -> ProjectGraph:
        """Loads and reconstructs a ProjectGraph from an SQLite database."""
        path = Path(db_path)
        if not path.exists():
            raise FileNotFoundError(f"Database file not found: {path}")

        graph = ProjectGraph()
        conn = sqlite3.connect(path)
        cursor = conn.cursor()

        # Read nodes
        cursor.execute(
            "SELECT uuid, kind, language, qualified_name, namespace, signature, visibility, file_path, line, column, attributes FROM nodes"
        )
        for row in cursor.fetchall():
            uuid_val, kind_str, lang, qname, ns, sig, vis_str, fp_str, line_val, col_val, attr_json = row
            try:
                kind_enum = NodeKind(kind_str)
            except ValueError:
                kind_enum = NodeKind.UNKNOWN

            try:
                vis_enum = Visibility(vis_str)
            except ValueError:
                vis_enum = Visibility.PUBLIC

            node = GraphNode(
                uuid=uuid_val,
                kind=kind_enum,
                language=lang,
                qualified_name=qname,
                namespace=ns,
                signature=sig,
                visibility=vis_enum,
                file_path=Path(fp_str) if fp_str else None,
                line=line_val,
                column=col_val,
                attributes=json.loads(attr_json) if attr_json else {},
            )
            graph.add_node(node)

        # Read edges
        cursor.execute(
            "SELECT caller_id, callee_id, edge_type, confidence, resolved_symbol, resolved_by, call_site_id, attributes FROM edges"
        )
        for row in cursor.fetchall():
            caller_id, callee_id, edge_type_str, conf, res_sym, res_by_str, cs_id, attr_json = row
            try:
                type_enum = EdgeType(edge_type_str)
            except ValueError:
                type_enum = EdgeType.CALLS

            try:
                mech_enum = ResolutionMechanism(res_by_str)
            except ValueError:
                mech_enum = ResolutionMechanism.AST_NATIVE

            edge = GraphEdge(
                caller_id=caller_id,
                callee_id=callee_id,
                edge_type=type_enum,
                confidence=conf,
                resolved_symbol=res_sym,
                resolved_by=mech_enum,
                call_site_id=cs_id if cs_id else None,
                attributes=json.loads(attr_json) if attr_json else {},
            )
            graph.add_edge(edge)

        conn.close()
        return graph

    def save_json(self, graph: ProjectGraph, json_path: str | Path) -> None:
        """Exports ProjectGraph to a structured JSON file."""
        data = {
            "nodes": [
                {
                    "uuid": n.uuid,
                    "kind": n.kind.value if isinstance(n.kind, NodeKind) else str(n.kind),
                    "language": n.language,
                    "qualified_name": n.qualified_name,
                    "namespace": n.namespace,
                    "signature": n.signature,
                    "visibility": n.visibility.value if isinstance(n.visibility, Visibility) else str(n.visibility),
                    "file_path": str(n.file_path) if n.file_path else "",
                    "line": n.line,
                    "column": n.column,
                    "attributes": n.attributes,
                }
                for n in graph.nodes.values()
            ],
            "edges": [
                {
                    "caller_id": e.caller_id,
                    "callee_id": e.callee_id,
                    "edge_type": e.edge_type.value if isinstance(e.edge_type, EdgeType) else str(e.edge_type),
                    "confidence": e.confidence,
                    "resolved_symbol": e.resolved_symbol,
                    "resolved_by": e.resolved_by.value
                    if isinstance(e.resolved_by, ResolutionMechanism)
                    else str(e.resolved_by),
                    "call_site_id": e.call_site_id or "",
                    "attributes": e.attributes,
                }
                for e in graph.edges
            ],
        }
        Path(json_path).write_text(json.dumps(data, indent=2))

    def load_json(self, json_path: str | Path) -> ProjectGraph:
        """Imports and reconstructs ProjectGraph from a JSON file."""
        data = json.loads(Path(json_path).read_text())
        graph = ProjectGraph()

        for item in data.get("nodes", []):
            node = GraphNode(
                uuid=item["uuid"],
                kind=NodeKind(item["kind"]) if item["kind"] in NodeKind._value2member_map_ else NodeKind.UNKNOWN,
                language=item.get("language", ""),
                qualified_name=item.get("qualified_name", ""),
                namespace=item.get("namespace", ""),
                signature=item.get("signature", ""),
                visibility=Visibility(item["visibility"])
                if item.get("visibility") in Visibility._value2member_map_
                else Visibility.PUBLIC,
                file_path=Path(item["file_path"]) if item.get("file_path") else None,
                line=item.get("line", 1),
                column=item.get("column", 0),
                attributes=item.get("attributes", {}),
            )
            graph.add_node(node)

        for item in data.get("edges", []):
            edge = GraphEdge(
                caller_id=item["caller_id"],
                callee_id=item["callee_id"],
                edge_type=EdgeType(item["edge_type"])
                if item["edge_type"] in EdgeType._value2member_map_
                else EdgeType.CALLS,
                confidence=item.get("confidence", 1.0),
                resolved_symbol=item.get("resolved_symbol", ""),
                resolved_by=ResolutionMechanism(item["resolved_by"])
                if item["resolved_by"] in ResolutionMechanism._value2member_map_
                else ResolutionMechanism.AST_NATIVE,
                call_site_id=item.get("call_site_id") if item.get("call_site_id") else None,
                attributes=item.get("attributes", {}),
            )
            graph.add_edge(edge)

        return graph
