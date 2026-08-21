"""SSRF Capability & Internal Network Reasoning Engine for Batch C10."""

from __future__ import annotations

import re
from karsasec.analysis.ssrf.models import (
    NetworkZone,
    SSRFCategory,
    SSRFContext,
    SSRFEvidence,
    TargetClassification,
)


class SSRFReasoningEngine:
    """Deterministic reasoning engine for SSRF, Blind SSRF, Metadata Access, Protocol Abuse, and Network Boundaries."""

    def classify_target(self, target_url: str) -> TargetClassification:
        """Classifies target URL into NetworkZone (LOOPBACK, LINK_LOCAL, PRIVATE, METADATA, KUBERNETES, PUBLIC)."""
        raw = target_url.strip()
        scheme = ""
        host_part = raw

        if "://" in raw:
            scheme, rest = raw.split("://", 1)
            scheme = scheme.lower()
            host_part = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        elif raw.startswith("//"):
            host_part = raw[2:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]

        # Extract hostname & port
        if "@" in host_part:
            host_part = host_part.rsplit("@", 1)[1]
        if ":" in host_part and not host_part.endswith("]"):
            host_part = host_part.split(":", 1)[0]

        host_lower = host_part.lower()

        # Metadata services check
        metadata_provider = None
        if host_lower in ("169.254.169.254", "metadata.google.internal", "100.100.100.200"):
            if host_lower == "metadata.google.internal":
                metadata_provider = "GCP"
            elif host_lower == "100.100.100.200":
                metadata_provider = "Alibaba"
            elif "/latest/meta-data" in raw or "aws" in raw.lower():
                metadata_provider = "AWS"
            elif "/metadata/v1" in raw:
                metadata_provider = "DigitalOcean"
            else:
                metadata_provider = "AWS/Azure"

            return TargetClassification(
                hostname=host_lower,
                ip_address=host_lower if host_lower != "metadata.google.internal" else "169.254.169.254",
                zone=NetworkZone.METADATA,
                is_internal=True,
                metadata_service=metadata_provider,
            )

        # Kubernetes check
        if "kubernetes" in host_lower or host_lower == "10.96.0.1":
            return TargetClassification(
                hostname=host_lower,
                ip_address=host_lower,
                zone=NetworkZone.KUBERNETES,
                is_internal=True,
                metadata_service="Kubernetes",
            )

        # Loopback check
        if host_lower in ("127.0.0.1", "localhost", "::1") or host_lower.startswith("127."):
            return TargetClassification(
                hostname=host_lower,
                ip_address=host_lower,
                zone=NetworkZone.LOOPBACK,
                is_internal=True,
            )

        # Link-local check
        if host_lower.startswith("169.254."):
            return TargetClassification(
                hostname=host_lower,
                ip_address=host_lower,
                zone=NetworkZone.LINK_LOCAL,
                is_internal=True,
            )

        # Private RFC1918 check (10.x.x.x, 172.16.x.x - 172.31.x.x, 192.168.x.x)
        if host_lower.startswith("10.") or host_lower.startswith("192.168."):
            return TargetClassification(
                hostname=host_lower,
                ip_address=host_lower,
                zone=NetworkZone.PRIVATE,
                is_internal=True,
            )

        if host_lower.startswith("172."):
            parts = host_lower.split(".")
            if len(parts) >= 2 and parts[1].isdigit():
                sec = int(parts[1])
                if 16 <= sec <= 31:
                    return TargetClassification(
                        hostname=host_lower,
                        ip_address=host_lower,
                        zone=NetworkZone.PRIVATE,
                        is_internal=True,
                    )

        return TargetClassification(
            hostname=host_lower,
            ip_address=host_lower if re.match(r"^\d+\.\d+\.\d+\.\d+$", host_lower) else None,
            zone=NetworkZone.PUBLIC,
            is_internal=False,
        )

    def evaluate_ssrf(self, ctx: SSRFContext) -> SSRFEvidence | None:
        """Evaluates SSRF context, scheme smuggling, network boundaries, metadata, and rebinding risks."""
        # Step 1: Safe Allowlist with Canonicalization -> SAFE
        if ctx.is_host_allowlisted and ctx.canonicalized_before_validation is True:
            target_cls = self.classify_target(ctx.target_url)
            return SSRFEvidence(
                category=SSRFCategory.SSRF,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                target={"hostname": target_cls.hostname, "zone": target_cls.zone.value},
                network_sink={"library": ctx.sink_library, "operation": ctx.sink_operation},
                canonicalization=True,
                allowlist=True,
                trust_boundary_crossed=False,
                evidence_path=[ctx.source_kind, ctx.source_symbol, "allowlist_validated"],
                resolution="SAFE",
            )

        # Step 2: Validation BEFORE Canonicalization -> UNKNOWN (INV-GLOBAL-01 & INV-GLOBAL-10)
        if ctx.canonicalized_before_validation is False:
            target_cls = self.classify_target(ctx.target_url)
            return SSRFEvidence(
                category=SSRFCategory.SSRF,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                target={"hostname": target_cls.hostname, "zone": target_cls.zone.value},
                network_sink={"library": ctx.sink_library, "operation": ctx.sink_operation},
                canonicalization=False,
                allowlist=False,
                trust_boundary_crossed=True,
                evidence_path=[ctx.source_kind, ctx.source_symbol, "validation_before_canonicalization"],
                resolution="UNKNOWN",
            )

        # Step 3: Protocol Smuggling (file://, gopher://, dict://, etc.)
        scheme = ""
        if "://" in ctx.target_url:
            scheme = ctx.target_url.split("://", 1)[0].lower()

        if scheme in ("file", "gopher", "dict", "ftp", "ldap", "jar", "phar"):
            target_cls = self.classify_target(ctx.target_url)
            return SSRFEvidence(
                category=SSRFCategory.PROTOCOL_SMUGGLING,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                target={"hostname": target_cls.hostname, "scheme": scheme},
                network_sink={"library": ctx.sink_library, "operation": ctx.sink_operation},
                canonicalization=True,
                allowlist=False,
                trust_boundary_crossed=True,
                evidence_path=[ctx.source_kind, ctx.source_symbol, scheme, "PROTOCOL_SMUGGLING"],
                resolution="VULNERABLE",
            )

        # Step 4: URL Parser Disagreement SSRF (C9 integration)
        if ctx.has_parser_disagreement:
            target_cls = self.classify_target(ctx.target_url)
            return SSRFEvidence(
                category=SSRFCategory.URL_PARSER_CONFUSION_SSRF,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                target={"hostname": target_cls.hostname, "zone": target_cls.zone.value},
                network_sink={"library": ctx.sink_library, "operation": ctx.sink_operation},
                canonicalization=True,
                allowlist=False,
                trust_boundary_crossed=True,
                evidence_path=[ctx.source_kind, ctx.source_symbol, "parser_disagreement", "SSRF"],
                resolution="VULNERABLE",
            )

        # Step 5: DNS Rebinding Risk
        if ctx.dns_evidence and ctx.dns_evidence.changes_zone:
            target_cls = self.classify_target(ctx.target_url)
            return SSRFEvidence(
                category=SSRFCategory.DNS_REBINDING_RISK,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                target={"hostname": ctx.dns_evidence.hostname, "first": ctx.dns_evidence.first_resolution, "second": ctx.dns_evidence.second_resolution},
                network_sink={"library": ctx.sink_library, "operation": ctx.sink_operation},
                canonicalization=True,
                allowlist=False,
                trust_boundary_crossed=True,
                evidence_path=[ctx.source_kind, ctx.source_symbol, "dns_rebinding"],
                resolution="VULNERABLE",
            )

        target_cls = self.classify_target(ctx.target_url)

        # Step 6: Redirect-based SSRF (Redirect chain leading internal)
        if ctx.redirect_chain:
            final_target = ctx.redirect_chain[-1]
            final_cls = self.classify_target(final_target)
            if final_cls.is_internal:
                return SSRFEvidence(
                    category=SSRFCategory.REDIRECT_BASED_SSRF,
                    source_kind=ctx.source_kind,
                    source_symbol=ctx.source_symbol,
                    target={"hostname": final_cls.hostname, "zone": final_cls.zone.value, "redirect_chain": ctx.redirect_chain},
                    network_sink={"library": ctx.sink_library, "operation": ctx.sink_operation},
                    canonicalization=True,
                    allowlist=False,
                    trust_boundary_crossed=True,
                    evidence_path=[ctx.source_kind, ctx.source_symbol, "redirect_chain", final_cls.hostname],
                    resolution="VULNERABLE",
                )

        # Step 7: Metadata & Cluster Services
        if target_cls.zone == NetworkZone.KUBERNETES:
            return SSRFEvidence(
                category=SSRFCategory.KUBERNETES_METADATA_ACCESS,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                target={"hostname": target_cls.hostname, "zone": target_cls.zone.value, "metadata_service": target_cls.metadata_service},
                network_sink={"library": ctx.sink_library, "operation": ctx.sink_operation},
                canonicalization=True,
                allowlist=False,
                trust_boundary_crossed=True,
                evidence_path=[ctx.source_kind, ctx.source_symbol, ctx.sink_library, target_cls.hostname],
                resolution="VULNERABLE",
            )

        if target_cls.zone == NetworkZone.METADATA:
            return SSRFEvidence(
                category=SSRFCategory.CLOUD_METADATA_ACCESS,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                target={"hostname": target_cls.hostname, "zone": target_cls.zone.value, "metadata_service": target_cls.metadata_service},
                network_sink={"library": ctx.sink_library, "operation": ctx.sink_operation},
                canonicalization=True,
                allowlist=False,
                trust_boundary_crossed=True,
                evidence_path=[ctx.source_kind, ctx.source_symbol, ctx.sink_library, target_cls.hostname],
                resolution="VULNERABLE",
            )

        # Step 8: Internal Private / Loopback / Link-Local Network Access
        if target_cls.zone in (NetworkZone.PRIVATE, NetworkZone.LOOPBACK, NetworkZone.LINK_LOCAL):
            return SSRFEvidence(
                category=SSRFCategory.INTERNAL_NETWORK_ACCESS,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                target={"hostname": target_cls.hostname, "zone": target_cls.zone.value},
                network_sink={"library": ctx.sink_library, "operation": ctx.sink_operation},
                canonicalization=True,
                allowlist=False,
                trust_boundary_crossed=True,
                evidence_path=[ctx.source_kind, ctx.source_symbol, ctx.sink_library, target_cls.hostname],
                resolution="VULNERABLE",
            )

        # Step 9: Blind SSRF (Inaccessible response)
        if not ctx.is_response_accessible:
            return SSRFEvidence(
                category=SSRFCategory.BLIND_SSRF,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                target={"hostname": target_cls.hostname, "zone": target_cls.zone.value},
                network_sink={"library": ctx.sink_library, "operation": ctx.sink_operation},
                canonicalization=True,
                allowlist=False,
                trust_boundary_crossed=True,
                evidence_path=[ctx.source_kind, ctx.source_symbol, ctx.sink_library, "BLIND_SSRF"],
                resolution="VULNERABLE",
            )

        # Step 10: General SSRF
        return SSRFEvidence(
            category=SSRFCategory.SSRF,
            source_kind=ctx.source_kind,
            source_symbol=ctx.source_symbol,
            target={"hostname": target_cls.hostname, "zone": target_cls.zone.value},
            network_sink={"library": ctx.sink_library, "operation": ctx.sink_operation},
            canonicalization=True,
            allowlist=False,
            trust_boundary_crossed=True,
            evidence_path=[ctx.source_kind, ctx.source_symbol, ctx.sink_library, "SSRF"],
            resolution="VULNERABLE",
        )
