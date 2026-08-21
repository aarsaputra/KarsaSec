"""Full Multi-Step Breach Simulation & Business Risk Engine for Batch C15."""

from __future__ import annotations

import hashlib
from typing import Any

from karsasec.analysis.attack_graph.models import AttackGraph
from karsasec.analysis.breach_simulation.models import (
    BreachScenario,
    BreachStep,
    ConfidenceLevel,
    RiskFactor,
    RiskLevel,
    ScenarioType,
    SimulationStatus,
)
from karsasec.analysis.destructive.models import DestructiveEvidence
from karsasec.analysis.privilege.models import PrivilegeEvidence, PrivilegeGraph
from karsasec.analysis.secrets.models import SecretEvidence

BUSINESS_IMPACT_WEIGHTS = {
    "NO_BUSINESS_IMPACT": 0.0,
    "LIMITED_DATA_ACCESS": 0.1,
    "SENSITIVE_DATA_EXPOSURE": 0.3,
    "CREDENTIAL_COMPROMISE": 0.5,
    "PRIVILEGE_ESCALATION": 0.6,
    "TENANT_COMPROMISE": 0.7,
    "DATABASE_COMPROMISE": 0.8,
    "SERVICE_COMPROMISE": 0.85,
    "DATA_DESTRUCTION": 0.9,
    "AVAILABILITY_LOSS": 0.9,
    "MULTI_TENANT_COMPROMISE": 0.95,
    "FULL_SYSTEM_COMPROMISE": 1.0,
    "BUSINESS_CRITICAL_BREACH": 1.0,
}


class BreachSimulationEngine:
    """Deterministic, read-only Full Multi-Step Breach Simulation & Business Risk Engine."""

    def simulate(
        self,
        attack_graph: AttackGraph | None = None,
        privilege_graph: PrivilegeGraph | None = None,
        privilege_evidence: PrivilegeEvidence | None = None,
        secret_evidence: SecretEvidence | None = None,
        destructive_evidence: DestructiveEvidence | None = None,
        authorization_context: dict[str, Any] | None = None,
        evidence_list: list[Any] | None = None,
    ) -> list[BreachScenario]:
        """Runs deterministic, read-only multi-step breach simulation enforcing INV-C15-01 through INV-C15-15."""
        scenarios: list[BreachScenario] = []

        # 1. INV-C15-08 & INV-C15-15: Check DAG acyclicity on input attack_graph
        if attack_graph is not None:
            if not self._is_dag(attack_graph):
                return [
                    BreachScenario(
                        scenario_id="INVALID_CYCLIC_GRAPH",
                        scenario_type=ScenarioType.UNKNOWN_SCENARIO,
                        root_causes=("INVALID",),
                        capabilities=(),
                        impacts=(),
                        steps=(),
                        privilege_transition=None,
                        business_impact=("INVALID_CYCLIC_GRAPH",),
                        risk_factors=(),
                        risk_score=None,
                        risk_level=RiskLevel.UNKNOWN,
                        confidence=ConfidenceLevel.UNKNOWN,
                        resolution=SimulationStatus.INVALID,
                        evidence_ids=(),
                        evidence_path=(),
                    )
                ]

        # 2. Extract Evidence & Data safely without mutation (INV-C15-15)
        priv_ev = privilege_evidence or (privilege_graph.evidence if privilege_graph else None)

        # 3. Handle Explicit SAFE Cases (INV-C15-05: Authorized operation performed by identity with required privilege)
        if priv_ev and priv_ev.resolution == "SAFE":
            scenario_id = self._compute_scenario_id(["SAFE_OPERATION"], ["AUTHORIZED_ACCESS"], ["NO_IMPACT"], None, ["NO_BUSINESS_IMPACT"])
            return [
                BreachScenario(
                    scenario_id=scenario_id,
                    scenario_type=ScenarioType.SINGLE_HOP,
                    root_causes=tuple(sorted(priv_ev.root_cause_chain or [priv_ev.transition_trigger])),
                    capabilities=("AUTHORIZED_ACCESS",),
                    impacts=("NO_IMPACT",),
                    steps=(
                        BreachStep(
                            step_id="STEP_1",
                            source_node=priv_ev.initial_identity,
                            capability="AUTHORIZED_OPERATION",
                            target_node=priv_ev.resulting_identity,
                            edge_type="REQUIRES",
                            resolution=SimulationStatus.SAFE,
                            evidence_path=tuple(priv_ev.evidence_path),
                        ),
                    ),
                    privilege_transition=(str(priv_ev.initial_privilege), str(priv_ev.resulting_privilege)),
                    business_impact=("NO_BUSINESS_IMPACT",),
                    risk_factors=(
                        RiskFactor("EXPLOITABILITY", 0.0, 0.20, 0.0, ("AUTHORIZED",)),
                        RiskFactor("CAPABILITY", 0.0, 0.20, 0.0, ("AUTHORIZED",)),
                        RiskFactor("PRIVILEGE", 0.0, 0.20, 0.0, ("AUTHORIZED",)),
                        RiskFactor("BUSINESS_IMPACT", 0.0, 0.20, 0.0, ("NO_BUSINESS_IMPACT",)),
                        RiskFactor("BOUNDARY_CROSSING", 0.0, 0.10, 0.0, ("SAME_TENANT",)),
                        RiskFactor("CONFIDENCE", 1.0, 0.10, 0.10, ("VERIFIED_AUTHZ",)),
                    ),
                    risk_score=0.0,
                    risk_level=RiskLevel.INFO,
                    confidence=ConfidenceLevel.HIGH,
                    resolution=SimulationStatus.SAFE,
                    evidence_ids=tuple(sorted(priv_ev.evidence_path)),
                    evidence_path=tuple(sorted(priv_ev.evidence_path)),
                )
            ]

        # 4. Handle UNKNOWN Preservation (INV-C15-03 & INV-C15-11: UNKNOWN != SAFE, risk_score = None)
        if priv_ev and priv_ev.resolution == "UNKNOWN":
            scenario_id = self._compute_scenario_id(["UNKNOWN_TRIGGER"], ["UNKNOWN_CAPABILITY"], ["UNKNOWN_IMPACT"], None, ["UNKNOWN_IMPACT"])
            return [
                BreachScenario(
                    scenario_id=scenario_id,
                    scenario_type=ScenarioType.UNKNOWN_SCENARIO,
                    root_causes=tuple(sorted(priv_ev.root_cause_chain or [priv_ev.transition_trigger])),
                    capabilities=("UNKNOWN_CAPABILITY",),
                    impacts=("UNKNOWN_IMPACT",),
                    steps=(
                        BreachStep(
                            step_id="STEP_1",
                            source_node=priv_ev.initial_identity,
                            capability="UNRESOLVED_TRANSITION",
                            target_node=priv_ev.resulting_identity,
                            edge_type="REQUIRES",
                            resolution=SimulationStatus.UNKNOWN,
                            evidence_path=tuple(priv_ev.evidence_path),
                        ),
                    ),
                    privilege_transition=(str(priv_ev.initial_privilege), str(priv_ev.resulting_privilege)),
                    business_impact=("UNKNOWN_BUSINESS_IMPACT",),
                    risk_factors=(),
                    risk_score=None,
                    risk_level=RiskLevel.UNKNOWN,
                    confidence=ConfidenceLevel.UNKNOWN,
                    resolution=SimulationStatus.UNKNOWN,
                    evidence_ids=tuple(sorted(priv_ev.evidence_path)),
                    evidence_path=tuple(sorted(priv_ev.evidence_path)),
                )
            ]

        # 5. Build Vulnerable Multi-Step Scenarios from Graph and Evidence
        roots = sorted(attack_graph.root_causes if attack_graph else [priv_ev.transition_trigger if priv_ev else "UNKNOWN_ROOT"])
        caps = sorted(attack_graph.capabilities if attack_graph else [priv_ev.capability_chain[0] if priv_ev and priv_ev.capability_chain else "UNKNOWN_CAPABILITY"])
        impacts = sorted(attack_graph.impacts if attack_graph else [priv_ev.impact_chain[0] if priv_ev and priv_ev.impact_chain else "UNAUTHORIZED_ACCESS"])

        priv_trans = (str(priv_ev.initial_privilege), str(priv_ev.resulting_privilege)) if priv_ev else None
        bus_impact = self._derive_business_impact(caps, impacts, priv_trans, destructive_evidence)

        # 6. Deduplication ID using SHA256 (INV-C15-14)
        scenario_id = self._compute_scenario_id(roots, caps, impacts, priv_trans, bus_impact)

        # 7. Scenario Type Determination
        scen_type = self._determine_scenario_type(caps, impacts, priv_trans)

        # 8. Steps Construction (Canonical Order)
        steps = self._construct_breach_steps(attack_graph, priv_ev, secret_evidence, destructive_evidence)

        # 9. Explainable Risk Factors & Scoring (INV-C15-10 & INV-C15-13)
        risk_factors, score, level, confidence = self._calculate_explainable_risk(roots, caps, impacts, priv_trans, bus_impact, priv_ev, secret_evidence)

        scenarios.append(
            BreachScenario(
                scenario_id=scenario_id,
                scenario_type=scen_type,
                root_causes=tuple(roots),
                capabilities=tuple(caps),
                impacts=tuple(impacts),
                steps=tuple(steps),
                privilege_transition=priv_trans,
                business_impact=tuple(bus_impact),
                risk_factors=tuple(risk_factors),
                risk_score=score,
                risk_level=level,
                confidence=confidence,
                resolution=SimulationStatus.VULNERABLE,
                evidence_ids=tuple(sorted(priv_ev.evidence_path if priv_ev else roots)),
                evidence_path=tuple(sorted(priv_ev.evidence_path if priv_ev else roots + caps + impacts)),
            )
        )

        # 10. Deduplicate scenarios list
        return self._deduplicate_scenarios(scenarios)

    def _is_dag(self, graph: AttackGraph) -> bool:
        """Verifies graph acyclicity using Kahn's topological sort (INV-C15-08)."""
        if isinstance(graph.nodes, dict):
            nodes = set(graph.nodes.keys())
        else:
            nodes = {n.node_id for n in graph.nodes}

        in_degree = {n: 0 for n in nodes}
        adj: dict[str, list[str]] = {n: [] for n in nodes}

        for edge in graph.edges:
            if edge.source_id in nodes and edge.target_id in nodes:
                adj[edge.source_id].append(edge.target_id)
                in_degree[edge.target_id] += 1

        queue = [n for n in nodes if in_degree[n] == 0]
        visited_count = 0

        while queue:
            node = queue.pop(0)
            visited_count += 1
            for neighbor in adj[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        return visited_count == len(nodes)

    def _compute_scenario_id(
        self,
        roots: list[str],
        caps: list[str],
        impacts: list[str],
        priv_trans: tuple[str, str] | None,
        bus_impact: list[str],
    ) -> str:
        """Computes a canonical SHA256 scenario identity string (INV-C15-14)."""
        raw_key = f"{sorted(roots)}:{sorted(caps)}:{sorted(impacts)}:{priv_trans}:{sorted(bus_impact)}"
        digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:12].upper()
        return f"SCENARIO_{digest}"

    def _determine_scenario_type(
        self,
        caps: list[str],
        impacts: list[str],
        priv_trans: tuple[str, str] | None,
    ) -> ScenarioType:
        """Determines ScenarioType from capabilities and impacts."""
        cap_set = set(caps)
        imp_set = set(impacts)

        if "CLOUD_ADMIN_ACCESS" in cap_set or "ROOT_ACCESS" in cap_set or "FULL_SYSTEM_COMPROMISE" in imp_set or (priv_trans and priv_trans[1] in ("ROOT", "CLOUD_ADMIN")):
            return ScenarioType.FULL_COMPROMISE
        if "TENANT_WIPE" in cap_set or "DATABASE_DESTRUCTION" in cap_set or "DATA_DESTRUCTION" in imp_set or "TENANT_WIPE" in imp_set:
            return ScenarioType.DESTRUCTIVE_BREACH
        if priv_trans and priv_trans[0] != priv_trans[1]:
            return ScenarioType.PRIVILEGE_ESCALATION
        if "TENANT_BOUNDARY_ESCAPE" in cap_set:
            return ScenarioType.TENANT_BOUNDARY_BREACH
        if "METADATA_ACCESS" in cap_set or "INTERNAL_NETWORK_ACCESS" in cap_set:
            return ScenarioType.INTERNAL_NETWORK_BREACH
        if "CREDENTIAL_COMPROMISE" in cap_set or "CREDENTIAL_COMPROMISE" in imp_set:
            return ScenarioType.CREDENTIAL_BREACH
        if "SECRET_EXPOSURE" in cap_set or "FILE_READ" in cap_set:
            return ScenarioType.DATA_EXFILTRATION
        if len(caps) > 1:
            return ScenarioType.MULTI_HOP
        return ScenarioType.SINGLE_HOP

    def _derive_business_impact(
        self,
        caps: list[str],
        impacts: list[str],
        priv_trans: tuple[str, str] | None,
        destructive_ev: DestructiveEvidence | None,
    ) -> list[str]:
        """Derives business impact ordering canonically."""
        bus_impacts = set()
        cap_set = set(caps)
        imp_set = set(impacts)

        if "CLOUD_ADMIN_ACCESS" in cap_set or "ROOT_ACCESS" in cap_set:
            bus_impacts.add("BUSINESS_CRITICAL_BREACH")
            bus_impacts.add("FULL_SYSTEM_COMPROMISE")
        if "TENANT_WIPE" in cap_set or "DATABASE_DESTRUCTION" in cap_set or (destructive_ev and destructive_ev.resolution == "VULNERABLE"):
            bus_impacts.add("DATA_DESTRUCTION")
            bus_impacts.add("SERVICE_COMPROMISE")
        if "TENANT_BOUNDARY_ESCAPE" in cap_set or "MULTI_TENANT_COMPROMISE" in imp_set:
            bus_impacts.add("MULTI_TENANT_COMPROMISE")
        if priv_trans and priv_trans[1] in ("TENANT_ADMIN", "ORG_ADMIN", "CLOUD_ADMIN", "ROOT"):
            bus_impacts.add("PRIVILEGE_ESCALATION")
        if "CREDENTIAL_COMPROMISE" in cap_set or "CREDENTIAL_COMPROMISE" in imp_set:
            bus_impacts.add("CREDENTIAL_COMPROMISE")
        if "SECRET_EXPOSURE" in cap_set or "FILE_READ" in cap_set:
            bus_impacts.add("SENSITIVE_DATA_EXPOSURE")

        if not bus_impacts:
            bus_impacts.add("LIMITED_DATA_ACCESS")

        return sorted(bus_impacts, key=lambda x: BUSINESS_IMPACT_WEIGHTS.get(x, 0.0), reverse=True)

    def _construct_breach_steps(
        self,
        attack_graph: AttackGraph | None,
        priv_ev: PrivilegeEvidence | None,
        secret_ev: SecretEvidence | None,
        dest_ev: DestructiveEvidence | None,
    ) -> list[BreachStep]:
        """Constructs canonical breach steps."""
        steps = []
        if attack_graph:
            for idx, edge in enumerate(sorted(attack_graph.edges, key=lambda e: (e.source_id, e.target_id))):
                steps.append(
                    BreachStep(
                        step_id=f"STEP_{idx + 1}",
                        source_node=edge.source_id,
                        capability=edge.edge_type.value if hasattr(edge.edge_type, "value") else str(edge.edge_type),
                        target_node=edge.target_id,
                        edge_type="ENABLES",
                        resolution=SimulationStatus.VULNERABLE,
                        evidence_path=tuple(sorted([edge.source_id, edge.target_id])),
                    )
                )
        elif priv_ev:
            steps.append(
                BreachStep(
                    step_id="STEP_1",
                    source_node=priv_ev.initial_identity,
                    capability=priv_ev.transition_trigger,
                    target_node=priv_ev.resulting_identity,
                    edge_type="ESCALATES_TO",
                    resolution=SimulationStatus.VULNERABLE,
                    evidence_path=tuple(sorted(priv_ev.evidence_path)),
                )
            )
        return steps

    def _calculate_explainable_risk(
        self,
        roots: list[str],
        caps: list[str],
        impacts: list[str],
        priv_trans: tuple[str, str] | None,
        bus_impacts: list[str],
        priv_ev: PrivilegeEvidence | None,
        secret_ev: SecretEvidence | None,
    ) -> tuple[list[RiskFactor], float, RiskLevel, ConfidenceLevel]:
        """Calculates transparent, explainable risk score (INV-C15-10 & INV-C15-13)."""
        exp_val = 0.90 if any(r in ("SSRF", "SSTI", "COMMAND_INJECTION", "IDOR", "XXE") for r in roots) else 0.70
        cap_val = 0.95 if any(c in ("ROOT_ACCESS", "CLOUD_ADMIN_ACCESS", "TENANT_WIPE") for c in caps) else 0.75
        priv_val = 1.00 if priv_trans and priv_trans[1] in ("ROOT", "CLOUD_ADMIN") else (0.80 if priv_trans and priv_trans[1] in ("TENANT_ADMIN", "ORG_ADMIN") else 0.40)
        bus_val = max(BUSINESS_IMPACT_WEIGHTS.get(b, 0.0) for b in bus_impacts)
        bound_val = 0.90 if any(c in ("TENANT_BOUNDARY_ESCAPE", "INTERNAL_NETWORK_ACCESS") for c in caps) else 0.50
        conf_val = 1.00

        factors = [
            RiskFactor("EXPLOITABILITY", exp_val, 0.20, exp_val * 0.20, tuple(roots)),
            RiskFactor("CAPABILITY", cap_val, 0.20, cap_val * 0.20, tuple(caps)),
            RiskFactor("PRIVILEGE", priv_val, 0.20, priv_val * 0.20, (priv_trans[1],) if priv_trans else ("USER",)),
            RiskFactor("BUSINESS_IMPACT", bus_val, 0.20, bus_val * 0.20, tuple(bus_impacts)),
            RiskFactor("BOUNDARY_CROSSING", bound_val, 0.10, bound_val * 0.10, tuple(caps)),
            RiskFactor("CONFIDENCE", conf_val, 0.10, conf_val * 0.10, ("EVIDENCE_VERIFIED",)),
        ]

        total_score = round(sum(f.contribution for f in factors) * 100.0, 2)

        if total_score >= 80.0:
            level = RiskLevel.CRITICAL
        elif total_score >= 60.0:
            level = RiskLevel.HIGH
        elif total_score >= 40.0:
            level = RiskLevel.MEDIUM
        elif total_score >= 20.0:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.INFO

        return factors, total_score, level, ConfidenceLevel.HIGH

    def _deduplicate_scenarios(self, scenarios: list[BreachScenario]) -> list[BreachScenario]:
        """Deduplicates scenarios list based on scenario_id (INV-C15-14)."""
        seen = set()
        deduped = []
        for s in sorted(scenarios, key=lambda x: x.scenario_id):
            if s.scenario_id not in seen:
                seen.add(s.scenario_id)
                deduped.append(s)
        return deduped
