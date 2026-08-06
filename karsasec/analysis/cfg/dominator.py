"""Dominator Analysis and Sanitizer Verification Engine for Control Flow Graphs."""

from __future__ import annotations

from karsasec.analysis.cfg.models import CFG


class DominatorAnalysis:
    """Computes Dominator Trees, Immediate Dominators, Post Dominators, and Dominance Frontiers."""

    def __init__(self, cfg: CFG) -> None:
        self.cfg: CFG = cfg
        self.dominators: dict[str, set[str]] = self._compute_dominators()
        self.immediate_dominators: dict[str, str | None] = self._compute_idom()
        self.post_dominators: dict[str, set[str]] = self._compute_post_dominators()

    def _compute_dominators(self) -> dict[str, set[str]]:
        """Iterative Lengauer-Tarjan / Fixpoint algorithm for computing Dominators."""
        all_nodes = set(self.cfg.nodes.keys())
        entry_id = self.cfg.entry_node_id

        dom: dict[str, set[str]] = {}
        for nid in all_nodes:
            if nid == entry_id:
                dom[nid] = {entry_id}
            else:
                dom[nid] = set(all_nodes)

        changed = True
        while changed:
            changed = False
            for nid in all_nodes:
                if nid == entry_id:
                    continue

                preds = self.cfg.get_predecessors(nid)
                if not preds:
                    new_dom = {nid}
                else:
                    pred_dom_intersection = set.intersection(*(dom[p] for p in preds))
                    new_dom = {nid} | pred_dom_intersection

                if new_dom != dom[nid]:
                    dom[nid] = new_dom
                    changed = True

        return dom

    def _compute_idom(self) -> dict[str, str | None]:
        """Computes Immediate Dominator (idom) for each node."""
        idom: dict[str, str | None] = {}
        for nid, dom_set in self.dominators.items():
            strict_doms = dom_set - {nid}
            if not strict_doms:
                idom[nid] = None
                continue

            # Immediate dominator is the strictly dominating node that does not dominate any other strictly dominating node
            curr_idom = None
            for d in strict_doms:
                if all(d in self.dominators[other] for other in strict_doms if other != d):
                    curr_idom = d
                    break
            idom[nid] = curr_idom or next(iter(strict_doms))

        return idom

    def _compute_post_dominators(self) -> dict[str, set[str]]:
        """Computes Post-Dominators (dominators on the reversed control flow graph)."""
        all_nodes = set(self.cfg.nodes.keys())
        exit_id = self.cfg.exit_node_id

        pdom: dict[str, set[str]] = {}
        for nid in all_nodes:
            if nid == exit_id:
                pdom[nid] = {exit_id}
            else:
                pdom[nid] = set(all_nodes)

        changed = True
        while changed:
            changed = False
            for nid in all_nodes:
                if nid == exit_id:
                    continue

                succs = self.cfg.get_successors(nid)
                if not succs:
                    new_pdom = {nid}
                else:
                    succ_pdom_intersection = set.intersection(*(pdom[s] for s in succs))
                    new_pdom = {nid} | succ_pdom_intersection

                if new_pdom != pdom[nid]:
                    pdom[nid] = new_pdom
                    changed = True

        return pdom

    def dominates(self, node_a: str, node_b: str) -> bool:
        """Returns True if node_a dominates node_b (all paths to b must pass through a)."""
        return node_a in self.dominators.get(node_b, set())

    def post_dominates(self, node_a: str, node_b: str) -> bool:
        """Returns True if node_a post-dominates node_b (all paths from b to EXIT must pass through a)."""
        return node_a in self.post_dominators.get(node_b, set())

    def get_dominance_frontier(self, node_id: str) -> set[str]:
        """Computes Dominance Frontier for a given node."""
        df: set[str] = set()
        for y_id in self.cfg.nodes:
            preds = self.cfg.get_predecessors(y_id)
            for p in preds:
                if self.dominates(node_id, p) and not (self.dominates(node_id, y_id) and node_id != y_id):
                    df.add(y_id)
        return df


class SanitizerDominanceVerifier:
    """Verifies sanitizer dominance over execution sinks to eliminate false positive findings."""

    def __init__(self, dom_analysis: DominatorAnalysis) -> None:
        self.dom: DominatorAnalysis = dom_analysis

    def is_sanitized(self, sanitizer_node_id: str, sink_node_id: str) -> bool:
        """Returns True if sanitizer_node_id DOMINATES sink_node_id, rendering the execution SAFE."""
        return self.dom.dominates(sanitizer_node_id, sink_node_id)
