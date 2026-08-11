"""Normalizer converting FlaskAuthState candidates into AuthDefinition ISR v1.0 objects."""

from __future__ import annotations

from karsasec.framework.extractors.flask.auth.state import FlaskAuthState
from karsasec.framework.intermediate import CURRENT_ISR_SCHEMA_VERSION, AuthDefinition, OriginMetadata
from karsasec.framework.origin import ExtractorInfo, SourceLocation


class FlaskAuthNormalizer:
    """Normalizes candidate auth state into deterministic AuthDefinition ISR v1.0 instances."""

    def normalize(self, state: FlaskAuthState) -> tuple[AuthDefinition, ...]:
        seen_keys: set[tuple[str, str, str, str, str, int]] = set()
        auth_definitions: list[AuthDefinition] = []

        # Process auth candidates
        for cand in state.auth_candidates:
            dedup_key = (
                "FLASK",
                cand.provider,
                cand.scheme,
                cand.handler,
                cand.file_path,
                cand.line,
            )
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            bp_name = cand.blueprint or state.blueprints.get(cand.handler.split(".")[0], "")
            roles = cand.roles
            permissions = cand.permissions

            # Merge roles/permissions from dedicated role/permission candidates if handler matches
            if cand.handler:
                for r_cand in state.role_candidates:
                    if r_cand.handler == cand.handler and r_cand.file_path == cand.file_path:
                        roles = tuple(sorted(set(roles + r_cand.roles)))
                for p_cand in state.permission_candidates:
                    if p_cand.handler == cand.handler and p_cand.file_path == cand.file_path:
                        permissions = tuple(sorted(set(permissions + p_cand.permissions)))

            origin = OriginMetadata(
                extractor_info=ExtractorInfo(extractor_name="FlaskAuthExtractor", framework="FLASK"),
                location_info=SourceLocation(
                    file_path=cand.file_path,
                    line=cand.line,
                    column=1,
                ),
            )

            evidence_strings = tuple(e.snippet for e in cand.evidence if e.snippet)

            # Determine mechanism, auth_strength, and jwt_algorithm deterministically
            jwt_alg = cand.metadata.get("jwt_algorithm")
            auth_type_upper = cand.auth_type.upper()
            provider_lower = cand.provider.lower()
            scheme_lower = cand.scheme.lower()

            if "JWT" in auth_type_upper or "JWT" in provider_lower or "jwt" in scheme_lower:
                mechanism = "JWT"
                if jwt_alg == "none":
                    auth_strength = "WEAK"
                else:
                    auth_strength = "STRONG"
            elif "HTTPAUTH" in provider_lower or scheme_lower in ("basic", "httpbasic"):
                mechanism = "BASIC"
                auth_strength = "WEAK"
            elif "LOGIN" in provider_lower or scheme_lower in ("session", "cookie"):
                mechanism = "SESSION"
                auth_strength = "STRONG"
            else:
                mechanism = "UNKNOWN"
                auth_strength = "UNKNOWN"

            auth_def = AuthDefinition(
                auth_type=cand.auth_type,
                provider=cand.provider,
                scheme=cand.scheme,
                handler=cand.handler,
                blueprint=bp_name,
                protected_routes=(cand.handler,) if cand.handler else (),
                roles_or_scopes=roles,
                roles=roles,
                permissions=permissions,
                session_keys=cand.session_keys,
                cookie_names=cand.cookie_names,
                manager=cand.manager,
                evidence=evidence_strings,
                auth_strength=auth_strength,
                mechanism=mechanism,
                jwt_algorithm=jwt_alg,
                language="Python",
                framework="FLASK",
                confidence=cand.confidence,
                schema_version=CURRENT_ISR_SCHEMA_VERSION,
                origin=origin,
            )
            auth_definitions.append(auth_def)

        # Sort deterministically by file_path, line, provider, handler
        auth_definitions.sort(
            key=lambda x: (
                x.origin.location_info.file_path,
                x.origin.location_info.line,
                x.provider,
                x.handler,
            )
        )
        return tuple(auth_definitions)
