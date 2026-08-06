"""Reaching Definitions Analysis computing GEN, KILL, IN, and OUT sets across basic blocks."""

from __future__ import annotations

from karsasec.analysis.cfg.models import CFG
from karsasec.analysis.dataflow.models import VariableRef
from karsasec.analysis.ssa.models import SSAFunction


class ReachingDefinitionsAnalysis:
    """Computes Reaching Definitions for a function using an iterative worklist fixpoint algorithm."""

    def __init__(self, cfg: CFG, ssa_func: SSAFunction) -> None:
        self.cfg: CFG = cfg
        self.ssa_func: SSAFunction = ssa_func
        self.gen_sets: dict[str, set[tuple[str, int, int]]] = {}
        self.kill_sets: dict[str, set[tuple[str, int, int]]] = {}
        self.in_sets: dict[str, set[tuple[str, int, int]]] = {}
        self.out_sets: dict[str, set[tuple[str, int, int]]] = {}
        self.all_defs: set[tuple[str, int, int]] = set()

    def analyze(self) -> None:
        """Executes fixpoint iterative worklist algorithm."""
        self._compute_gen_kill_sets()
        self._compute_in_out_sets()

    def _compute_gen_kill_sets(self) -> None:
        # Collect all definitions (var_name, ssa_version, line_number)
        for ssa_node in self.ssa_func.nodes:
            if ssa_node.target:
                def_tuple = (ssa_node.target.base_name, ssa_node.target.version, ssa_node.line_number)
                self.all_defs.add(def_tuple)

        for nid, node in self.cfg.nodes.items():
            gen: set[tuple[str, int, int]] = set()
            kill: set[tuple[str, int, int]] = set()

            # Find definitions in node
            node_defs = [
                (sn.target.base_name, sn.target.version, sn.line_number)
                for sn in self.ssa_func.nodes
                if sn.id.startswith(nid) and sn.target
            ]

            for dname, dver, dline in node_defs:
                gen.add((dname, dver, dline))
                # Kill other definitions of the same variable name
                for other_def in self.all_defs:
                    if other_def[0] == dname and other_def != (dname, dver, dline):
                        kill.add(other_def)

            self.gen_sets[nid] = gen
            self.kill_sets[nid] = kill
            self.in_sets[nid] = set()
            self.out_sets[nid] = set(gen)

    def _compute_in_out_sets(self) -> None:
        changed = True
        while changed:
            changed = False
            for nid in self.cfg.nodes:
                preds = self.cfg.get_predecessors(nid)
                if preds:
                    in_set = set.union(*(self.out_sets[p] for p in preds))
                else:
                    in_set = set()

                out_set = self.gen_sets[nid] | (in_set - self.kill_sets[nid])

                if in_set != self.in_sets[nid] or out_set != self.out_sets[nid]:
                    self.in_sets[nid] = in_set
                    self.out_sets[nid] = out_set
                    changed = True

    def get_reaching_definitions(self, node_id: str) -> list[VariableRef]:
        """Returns reaching definitions for a given node ID."""
        defs = self.in_sets.get(node_id, set())
        return [VariableRef(name=name, ssa_version=ver, line_number=line) for name, ver, line in defs]
