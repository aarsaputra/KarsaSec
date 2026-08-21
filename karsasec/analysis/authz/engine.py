"""Authorization Reasoning Engine for Batch B1 (IDOR, BOLA, Mass Assignment, Tenant Isolation, BFLA)."""

from __future__ import annotations

from karsasec.analysis.authz.models import (
    AuthzDecisionNode,
    AuthzEvidence,
    AuthzVulnerabilityType,
    ObjectNode,
    SubjectNode,
)


class AuthorizationReasoningEngine:
    """Deterministic reasoning engine for authorization boundary violations."""

    def evaluate_authorization(
        self,
        subject: SubjectNode,
        obj: ObjectNode,
        action: str,
        decisions: AuthzDecisionNode,
        is_admin_action: bool = False,
        is_mass_assignment: bool = False,
    ) -> AuthzEvidence | None:
        """Evaluates Subject-Object-Action triples against authorization decision nodes.

        Returns AuthzEvidence if a vulnerability is detected, else None.
        """
        # B1.5: Broken Function Level Authorization (BFLA)
        if is_admin_action and not decisions.has_role_check:
            if "ADMIN" not in subject.roles:
                return AuthzEvidence(
                    subject_id=subject.subject_id,
                    object_id=obj.object_id,
                    action=action,
                    ownership_check=decisions.has_ownership_check,
                    tenant_check=decisions.has_tenant_check,
                    role_check=decisions.has_role_check,
                    vulnerability_type=AuthzVulnerabilityType.BFLA,
                    description="Administrative endpoint exposed without role verification.",
                )

        # B1.4: Cross-Tenant Data Access Failure
        if subject.tenant_id and obj.tenant_id and subject.tenant_id != obj.tenant_id:
            if not decisions.has_tenant_check:
                return AuthzEvidence(
                    subject_id=subject.subject_id,
                    object_id=obj.object_id,
                    action=action,
                    ownership_check=decisions.has_ownership_check,
                    tenant_check=decisions.has_tenant_check,
                    role_check=decisions.has_role_check,
                    vulnerability_type=AuthzVulnerabilityType.TENANT_ISOLATION_FAILURE,
                    description=f"Subject tenant '{subject.tenant_id}' accessed object of tenant '{obj.tenant_id}' without tenant boundary predicate.",
                )

        # B1.3: Mass Assignment & Property Injection
        if is_mass_assignment and not decisions.has_field_allowlist:
            return AuthzEvidence(
                subject_id=subject.subject_id,
                object_id=obj.object_id,
                action=action,
                ownership_check=decisions.has_ownership_check,
                tenant_check=decisions.has_tenant_check,
                role_check=decisions.has_role_check,
                vulnerability_type=AuthzVulnerabilityType.MASS_ASSIGNMENT,
                description="Unfiltered request body binding permitted privileged property mutation.",
            )

        # B1.1 & B1.2: IDOR / BOLA (Missing Ownership Check)
        if obj.owner_id and subject.subject_id != obj.owner_id:
            if not decisions.has_ownership_check:
                vuln = AuthzVulnerabilityType.BOLA if obj.resource_type == "API_RESOURCE" else AuthzVulnerabilityType.IDOR
                return AuthzEvidence(
                    subject_id=subject.subject_id,
                    object_id=obj.object_id,
                    action=action,
                    ownership_check=False,
                    tenant_check=decisions.has_tenant_check,
                    role_check=decisions.has_role_check,
                    vulnerability_type=vuln,
                    description=f"Subject '{subject.subject_id}' accessed object owned by '{obj.owner_id}' without ownership verification.",
                )

        return None
