"""Attack Graph Construction & Exploit Path Correlation Engine for Batch C13."""

from __future__ import annotations

from collections import defaultdict, deque

from karsasec.analysis.attack_graph.models import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    EdgeType,
    ImpactNode,
    NodeType,
)


class AttackGraphConstructionEngine:
    """Deterministic reasoning engine for constructing Directed Acyclic Attack Graphs (DAGs) from multi-batch vulnerability context."""

    def is_acyclic(self, nodes: list[AttackNode], edges: list[AttackEdge]) -> bool:
        """Verifies that the graph is strictly Acyclic (DAG) using Kahn's topological sort (INV-C13-03)."""
        node_ids = {n.node_id for n in nodes}
        in_degree = {nid: 0 for nid in node_ids}
        adj = defaultdict(list)

        for edge in edges:
            if edge.source_id in in_degree and edge.target_id in in_degree:
                adj[edge.source_id].append(edge.target_id)
                in_degree[edge.target_id] += 1

        queue = deque([nid for nid, deg in in_degree.items() if deg == 0])
        visited_count = 0

        while queue:
            curr = queue.popleft()
            visited_count += 1
            for nxt in adj[curr]:
                in_degree[nxt] -= 1
                if in_degree[nxt] == 0:
                    queue.append(nxt)

        return visited_count == len(node_ids)

    def trace_root_causes(self, target_id: str, nodes_dict: dict[str, AttackNode], parent_map: dict[str, list[str]]) -> list[str]:
        """Traces back all root causes leading to target_id (INV-C13-02)."""
        root_causes = set()
        visited = set()
        queue = deque([target_id])

        while queue:
            curr = queue.popleft()
            if curr in visited:
                continue
            visited.add(curr)

            node = nodes_dict.get(curr)
            if node and node.node_type == NodeType.ROOT_CAUSE:
                root_causes.add(node.label)

            for parent in parent_map.get(curr, []):
                queue.append(parent)

        return sorted(list(root_causes))

    def build_graph(self, graph_id: str, nodes: list[AttackNode], edges: list[AttackEdge]) -> AttackGraph:
        """Constructs and validates an Attack Graph enforcing INV-C13-01 through INV-C13-04."""
        nodes_dict = {n.node_id: n for n in nodes}

        # Step 1: Check Acyclicity (INV-C13-03)
        if not self.is_acyclic(nodes, edges):
            raise ValueError(f"Attack graph '{graph_id}' contains cycles. INV-C13-03 Violation: Graph must be acyclic (DAG).")

        # Step 2: Validate Edge & Node Invariants
        parent_map = defaultdict(list)
        for edge in edges:
            src_node = nodes_dict.get(edge.source_id)
            tgt_node = nodes_dict.get(edge.target_id)

            if not src_node or not tgt_node:
                continue

            # INV-C13-01: ROOT_CAUSE cannot directly link to IMPACT without intermediate CAPABILITY
            if src_node.node_type == NodeType.ROOT_CAUSE and tgt_node.node_type == NodeType.IMPACT:
                raise ValueError(f"Direct edge from ROOT_CAUSE '{src_node.label}' to IMPACT '{tgt_node.label}' is forbidden. INV-C13-01 Violation.")

            # INV-C13-04: UNKNOWN node cannot generate capability or edge transitions
            if src_node.node_type == NodeType.UNKNOWN or src_node.resolution == "UNKNOWN":
                raise ValueError(f"UNKNOWN node '{src_node.label}' cannot generate capability edge. INV-C13-04 Violation.")

            parent_map[edge.target_id].append(edge.source_id)

        # Step 3: Populate Root Causes, Capabilities, Impacts
        root_causes = [n.label for n in nodes if n.node_type == NodeType.ROOT_CAUSE]
        capabilities = [n.label for n in nodes if n.node_type == NodeType.CAPABILITY]
        impacts = [n.label for n in nodes if n.node_type == NodeType.IMPACT]

        # Step 4: Trace Root Causes for Impact Nodes (INV-C13-02)
        for node in nodes:
            if isinstance(node, ImpactNode) or node.node_type == NodeType.IMPACT:
                rc_chain = self.trace_root_causes(node.node_id, nodes_dict, parent_map)
                if isinstance(node, ImpactNode):
                    node.root_cause_chain = rc_chain

        return AttackGraph(
            graph_id=graph_id,
            nodes=nodes,
            edges=edges,
            root_causes=sorted(list(set(root_causes))),
            capabilities=sorted(list(set(capabilities))),
            impacts=sorted(list(set(impacts))),
        )

    def build_chain_m_ssrf_metadata_credential_compromise(self, graph_id: str = "CHAIN_M") -> AttackGraph:
        """Chain M: SSRF -> Metadata Access -> AWS Key -> Credential Compromise."""
        n1 = AttackNode("n1", NodeType.ROOT_CAUSE, "SSRF", "url_param")
        n2 = AttackNode("n2", NodeType.CAPABILITY, "METADATA_ACCESS", "169.254.169.254")
        n3 = AttackNode("n3", NodeType.CAPABILITY, "AWS_KEY_EXPOSURE", "IAM_ROLE_CREDENTIALS")
        n4 = ImpactNode("n4", NodeType.IMPACT, "CREDENTIAL_COMPROMISE", "AWS_ACCOUNT_COMPROMISE")

        e1 = AttackEdge("e1", "n1", "n2", EdgeType.ENABLES)
        e2 = AttackEdge("e2", "n2", "n3", EdgeType.EXPOSES)
        e3 = AttackEdge("e3", "n3", "n4", EdgeType.EXECUTES)

        return self.build_graph(graph_id, [n1, n2, n3, n4], [e1, e2, e3])

    def build_chain_n_xxe_file_read_env_db_pass(self, graph_id: str = "CHAIN_N") -> AttackGraph:
        """Chain N: XXE -> File Read -> .env Leak -> Database Password."""
        n1 = AttackNode("n1", NodeType.ROOT_CAUSE, "XXE", "xml_payload")
        n2 = AttackNode("n2", NodeType.CAPABILITY, "FILE_READ", "/app/.env")
        n3 = AttackNode("n3", NodeType.CAPABILITY, "DATABASE_PASSWORD_LEAK", "DB_PASSWORD")
        n4 = ImpactNode("n4", NodeType.IMPACT, "DATABASE_DESTRUCTION", "PROD_DATABASE")

        e1 = AttackEdge("e1", "n1", "n2", EdgeType.ENABLES)
        e2 = AttackEdge("e2", "n2", "n3", EdgeType.EXPOSES)
        e3 = AttackEdge("e3", "n3", "n4", EdgeType.DESTROYS)

        return self.build_graph(graph_id, [n1, n2, n3, n4], [e1, e2, e3])

    def build_chain_o_ssti_rce_env_dump_secrets(self, graph_id: str = "CHAIN_O") -> AttackGraph:
        """Chain O: SSTI -> RCE -> Environment Dump -> Secrets."""
        n1 = AttackNode("n1", NodeType.ROOT_CAUSE, "SSTI", "template_input")
        n2 = AttackNode("n2", NodeType.CAPABILITY, "RCE", "PROCESS_SPAWN")
        n3 = AttackNode("n3", NodeType.CAPABILITY, "ENV_DUMP", "ENV_VARIABLES")
        n4 = ImpactNode("n4", NodeType.IMPACT, "SECRET_EXPOSURE", "AWS_SECRET_KEY")

        e1 = AttackEdge("e1", "n1", "n2", EdgeType.ENABLES)
        e2 = AttackEdge("e2", "n2", "n3", EdgeType.ESCALATES_TO)
        e3 = AttackEdge("e3", "n3", "n4", EdgeType.EXPOSES)

        return self.build_graph(graph_id, [n1, n2, n3, n4], [e1, e2, e3])

    def build_chain_p_idor_tenant_escape_bulk_delete_tenant_wipe(self, graph_id: str = "CHAIN_P") -> AttackGraph:
        """Chain P: IDOR -> Tenant Scope Escape -> Bulk Delete -> Tenant Wipe."""
        n1 = AttackNode("n1", NodeType.ROOT_CAUSE, "IDOR", "tenant_id")
        n2 = AttackNode("n2", NodeType.CAPABILITY, "TENANT_SCOPE_ESCAPE", "UNAUTHORIZED_TENANT_ACCESS")
        n3 = AttackNode("n3", NodeType.CAPABILITY, "BULK_DELETE", "UNSCOPED_DELETE_FROM")
        n4 = ImpactNode("n4", NodeType.IMPACT, "TENANT_WIPE", "ALL_TENANT_DATA")

        e1 = AttackEdge("e1", "n1", "n2", EdgeType.ENABLES)
        e2 = AttackEdge("e2", "n2", "n3", EdgeType.ESCALATES_TO)
        e3 = AttackEdge("e3", "n3", "n4", EdgeType.DESTROYS)

        return self.build_graph(graph_id, [n1, n2, n3, n4], [e1, e2, e3])
