"""Privilege Escalation Graph & Authorization Transition Engine for Batch C14."""

from __future__ import annotations

from karsasec.analysis.attack_graph.models import AttackGraph
from karsasec.analysis.privilege.models import (
    EscalationCategory,
    PrivilegeEvidence,
    PrivilegeGraph,
    PrivilegeLevel,
    PrivilegeTransition,
)

PRIVILEGE_RANK = {
    PrivilegeLevel.ANONYMOUS: 0,
    PrivilegeLevel.USER: 1,
    PrivilegeLevel.VERIFIED_USER: 2,
    PrivilegeLevel.TENANT_ADMIN: 3,
    PrivilegeLevel.SERVICE_ACCOUNT: 3,
    PrivilegeLevel.ORG_ADMIN: 4,
    PrivilegeLevel.SYSTEM_OPERATOR: 5,
    PrivilegeLevel.ROOT: 6,
    PrivilegeLevel.CLOUD_ADMIN: 6,
    PrivilegeLevel.UNKNOWN: -1,
}


class PrivilegeEscalationReasoningEngine:
    """Deterministic reasoning engine for Privilege Escalation Graphs and Authorization Transitions."""

    def evaluate_privilege_transition(
        self,
        initial_identity: str,
        initial_privilege: PrivilegeLevel | str,
        resulting_identity: str,
        resulting_privilege: PrivilegeLevel | str,
        trigger: str,
        boundary: str,
        authorization_verified: bool = False,
        tenant_scope_verified: bool = True,
        initial_tenant: str | None = None,
        target_tenant: str | None = None,
        credential_validity: str = "UNKNOWN",
        root_cause_chain: list[str] | None = None,
        capability_chain: list[str] | None = None,
        impact_chain: list[str] | None = None,
        attack_graph: AttackGraph | None = None,
    ) -> PrivilegeEvidence:
        """Evaluates a privilege transition enforcing INV-C14-01 through INV-C14-08."""
        rc_chain = sorted(root_cause_chain or (attack_graph.root_causes if attack_graph else [trigger]))
        cap_chain = sorted(capability_chain or (attack_graph.capabilities if attack_graph else ["RESOURCE_ACCESS"]))
        imp_chain = sorted(impact_chain or (attack_graph.impacts if attack_graph else ["UNAUTHORIZED_ACCESS"]))

        init_priv_enum = PrivilegeLevel(str(initial_privilege)) if str(initial_privilege) in PrivilegeLevel.__members__ else PrivilegeLevel.UNKNOWN
        res_priv_enum = PrivilegeLevel(str(resulting_privilege)) if str(resulting_privilege) in PrivilegeLevel.__members__ else PrivilegeLevel.UNKNOWN

        init_rank = PRIVILEGE_RANK.get(init_priv_enum, -1)
        res_rank = PRIVILEGE_RANK.get(res_priv_enum, -1)

        # Step 1: INV-C14-05 & INV-C14-01 (Least-Privilege Preservation & Verified Authorized Operation -> SAFE)
        if authorization_verified and tenant_scope_verified and init_rank == res_rank:
            return PrivilegeEvidence(
                category=EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION,
                initial_identity=initial_identity,
                initial_privilege=init_priv_enum,
                transition_trigger=trigger,
                authorization_boundary=boundary,
                resulting_identity=resulting_identity,
                resulting_privilege=res_priv_enum,
                authorization_verified=True,
                tenant_scope_verified=True,
                credential_validity="VALID" if credential_validity == "UNKNOWN" else credential_validity,
                evidence_path=sorted([initial_identity, "AUTHORIZED", resulting_identity]),
                root_cause_chain=rc_chain,
                capability_chain=cap_chain,
                impact_chain=imp_chain,
                resolution="SAFE",
            )

        # Step 2: INV-C14-04 (UNKNOWN Cannot Escalate)
        is_known_trigger = any(t in trigger.upper() for t in ("IDOR", "AUTHZ", "JWT", "SSRF", "BYPASS", "SUDO", "TARE", "SLIP", "TRAVERSAL"))
        if init_priv_enum == PrivilegeLevel.UNKNOWN or res_priv_enum == PrivilegeLevel.UNKNOWN or (credential_validity == "UNKNOWN" and "ADMIN" in str(resulting_privilege) and not is_known_trigger):
            return PrivilegeEvidence(
                category=EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION,
                initial_identity=initial_identity,
                initial_privilege=init_priv_enum,
                transition_trigger=trigger,
                authorization_boundary=boundary,
                resulting_identity=resulting_identity,
                resulting_privilege=res_priv_enum,
                authorization_verified=authorization_verified,
                tenant_scope_verified=tenant_scope_verified,
                credential_validity=credential_validity,
                evidence_path=sorted([initial_identity, trigger, boundary, resulting_identity]),
                root_cause_chain=rc_chain,
                capability_chain=cap_chain,
                impact_chain=imp_chain,
                resolution="UNKNOWN",
            )

        # Step 3: INV-C14-06 (Tenant Boundary Escape)
        if initial_tenant and target_tenant and initial_tenant != target_tenant:
            return PrivilegeEvidence(
                category=EscalationCategory.TENANT_BOUNDARY_ESCAPE,
                initial_identity=initial_identity,
                initial_privilege=init_priv_enum,
                transition_trigger=trigger,
                authorization_boundary=boundary,
                resulting_identity=resulting_identity,
                resulting_privilege=res_priv_enum,
                authorization_verified=False,
                tenant_scope_verified=False,
                credential_validity=credential_validity,
                evidence_path=sorted([initial_identity, initial_tenant, trigger, target_tenant]),
                root_cause_chain=rc_chain,
                capability_chain=cap_chain,
                impact_chain=imp_chain,
                resolution="VULNERABLE",
            )

        # Step 4: Horizontal Privilege Escalation
        if init_rank == res_rank and initial_identity != resulting_identity and not authorization_verified:
            return PrivilegeEvidence(
                category=EscalationCategory.HORIZONTAL_PRIVILEGE_ESCALATION,
                initial_identity=initial_identity,
                initial_privilege=init_priv_enum,
                transition_trigger=trigger,
                authorization_boundary=boundary,
                resulting_identity=resulting_identity,
                resulting_privilege=res_priv_enum,
                authorization_verified=False,
                tenant_scope_verified=tenant_scope_verified,
                credential_validity=credential_validity,
                evidence_path=sorted([initial_identity, trigger, resulting_identity]),
                root_cause_chain=rc_chain,
                capability_chain=cap_chain,
                impact_chain=imp_chain,
                resolution="VULNERABLE",
            )

        # Step 5: Vertical Privilege Escalation
        if res_rank > init_rank and not authorization_verified:
            cat = EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION
            if res_priv_enum == PrivilegeLevel.ROOT:
                cat = EscalationCategory.ROOT_ACCESS
            elif res_priv_enum == PrivilegeLevel.CLOUD_ADMIN:
                cat = EscalationCategory.CLOUD_ROLE_ESCALATION

            return PrivilegeEvidence(
                category=cat,
                initial_identity=initial_identity,
                initial_privilege=init_priv_enum,
                transition_trigger=trigger,
                authorization_boundary=boundary,
                resulting_identity=resulting_identity,
                resulting_privilege=res_priv_enum,
                authorization_verified=False,
                tenant_scope_verified=tenant_scope_verified,
                credential_validity=credential_validity,
                evidence_path=sorted([initial_identity, str(init_priv_enum), trigger, str(res_priv_enum)]),
                root_cause_chain=rc_chain,
                capability_chain=cap_chain,
                impact_chain=imp_chain,
                resolution="VULNERABLE",
            )

        return PrivilegeEvidence(
            category=EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION,
            initial_identity=initial_identity,
            initial_privilege=init_priv_enum,
            transition_trigger=trigger,
            authorization_boundary=boundary,
            resulting_identity=resulting_identity,
            resulting_privilege=res_priv_enum,
            authorization_verified=authorization_verified,
            tenant_scope_verified=tenant_scope_verified,
            credential_validity=credential_validity,
            evidence_path=sorted([initial_identity, trigger, resulting_identity]),
            root_cause_chain=rc_chain,
            capability_chain=cap_chain,
            impact_chain=imp_chain,
            resolution="SAFE",
        )

    def build_privilege_graph(self, graph_id: str, transitions: list[PrivilegeTransition], evidence: PrivilegeEvidence) -> PrivilegeGraph:
        """Constructs a canonical PrivilegeGraph extending C13 AttackGraph."""
        sorted_transitions = sorted(transitions, key=lambda t: (t.source_identity, t.target_identity, t.trigger))
        return PrivilegeGraph(
            graph_id=graph_id,
            transitions=sorted_transitions,
            evidence=evidence,
            resolution=evidence.resolution,
        )
