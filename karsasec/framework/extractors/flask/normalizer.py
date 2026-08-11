"""Flask Route Normalizer resolving URL converters, blueprint prefixes, evidence, and confidence scores."""

from __future__ import annotations

import re

from karsasec.framework.extractors.flask.state import FlaskSemanticState, RawRouteRecord
from karsasec.framework.intermediate import CURRENT_ISR_SCHEMA_VERSION, RouteDefinition
from karsasec.framework.origin import Evidence, EvidenceProvenance, ExtractorInfo, OriginMetadata, SourceLocation


class FlaskRouteNormalizer:
    """Normalizes raw route records into formal RouteDefinition ISR objects."""

    # Regex for Flask URL converters: <converter:name> or <name>
    CONVERTER_REGEX = re.compile(r"<([^:>]+:)?([^>]+)>")

    def __init__(self, state: FlaskSemanticState) -> None:
        self.state = state

    def normalize(self, raw_records: list[RawRouteRecord]) -> list[RouteDefinition]:
        """Converts raw route records into RouteDefinition ISR objects."""
        normalized: list[RouteDefinition] = []

        # Build blueprint prefix resolution map
        bp_prefix_map = self._compute_blueprint_prefixes()

        for rec in raw_records:
            # 1. Resolve full path with blueprint prefixes
            bp_prefix = ""
            bp_name = rec.blueprint_name or ""
            if bp_name in bp_prefix_map:
                bp_prefix = bp_prefix_map[bp_name]

            full_path = self._combine_paths(bp_prefix, rec.path)

            # 2. Extract path parameters and URL converters
            clean_path, params = self._parse_url_converters(full_path)

            # 3. MethodView expansion if MethodView
            if rec.is_method_view and rec.handler_name in self.state.method_views:
                mv_rec = self.state.method_views[rec.handler_name]
                for http_method, method_fn in mv_rec.methods_map.items():
                    r_def = self._build_route_definition(
                        rec=rec,
                        path=clean_path,
                        methods=(http_method,),
                        handler=f"{rec.handler_name}.{method_fn}",
                        blueprint=bp_name,
                    )
                    normalized.append(r_def)
                continue

            # Standard routes
            for method in rec.methods:
                r_def = self._build_route_definition(
                    rec=rec,
                    path=clean_path,
                    methods=(method,),
                    handler=rec.handler_name,
                    blueprint=bp_name,
                )
                normalized.append(r_def)

        return normalized

    def _compute_blueprint_prefixes(self) -> dict[str, str]:
        """Computes effective URL prefixes for all registered blueprints."""
        prefixes: dict[str, str] = {}

        # Direct blueprint url_prefix
        for var_or_name, bp in self.state.blueprints.items():
            if bp.url_prefix:
                prefixes[bp.name] = bp.url_prefix
                prefixes[bp.variable_name] = bp.url_prefix

        # Registration url_prefix overrides or additions
        for reg in self.state.blueprint_registrations:
            bp_key = reg.blueprint_var
            existing_prefix = prefixes.get(bp_key, "")
            combined = self._combine_paths(reg.url_prefix, existing_prefix)
            if combined:
                prefixes[bp_key] = combined
                if bp_key in self.state.blueprints:
                    prefixes[self.state.blueprints[bp_key].name] = combined

        return prefixes

    def _combine_paths(self, prefix: str, path: str) -> str:
        p1 = prefix.strip("/")
        p2 = path.strip("/")
        if not p1 and not p2:
            return "/"
        if not p1:
            return f"/{p2}"
        if not p2:
            return f"/{p1}"
        if p1 == p2 or p1.endswith(p2):
            return f"/{p1}"
        if p2.startswith(p1):
            return f"/{p2}"
        return f"/{p1}/{p2}"


    def _parse_url_converters(self, raw_path: str) -> tuple[str, list[dict[str, str]]]:
        """Parses <int:id> URL converters into parameter metadata."""
        params: list[dict[str, str]] = []

        def replace_fn(match: re.Match[str]) -> str:
            converter_part = match.group(1) or ""
            var_name = match.group(2).strip()

            c_type = converter_part.rstrip(":").strip() if converter_part else "string"
            params.append({"name": var_name, "type": c_type})
            return f"{{{var_name}}}"

        clean_path = self.CONVERTER_REGEX.sub(replace_fn, raw_path)
        return clean_path, params

    def _build_route_definition(
        self,
        rec: RawRouteRecord,
        path: str,
        methods: tuple[str, ...],
        handler: str,
        blueprint: str,
    ) -> RouteDefinition:
        loc = SourceLocation(file_path=rec.file_path, line=rec.line)
        ext_info = ExtractorInfo(extractor_name="FlaskRouteExtractor", version="1.0.0")

        evidence_items = [
            Evidence(
                snippet=ev,
                rule_or_marker="FlaskRouteExtractor",
                file_path=rec.file_path,
                line=rec.line,
            )
            for ev in rec.evidence
        ]


        origin = OriginMetadata(
            extractor_info=ext_info,
            location_info=loc,
            evidence_list=tuple(evidence_items),
            framework_name="FLASK",
        )


        method_str = methods[0] if methods else "GET"

        # Determine sensitivity and exposure deterministically with explicit conflict resolution (CONFLICT -> UNKNOWN)
        lower_decs = [d.lower() for d in rec.decorators]

        has_high = any(d in lower_decs for d in ("sensitive", "high_sensitivity", "admin_only", "requires_admin"))
        has_low = any(d in lower_decs for d in ("low_sensitivity", "public_access"))
        has_normal = any(d in lower_decs for d in ("normal_sensitivity", "standard_sensitivity"))

        if (has_high and (has_low or has_normal)) or (has_low and has_normal):
            sensitivity = "UNKNOWN"
            sens_source_kind = "unknown"
        elif has_high:
            sensitivity = "HIGH"
            sens_source_kind = "explicit_decorator"
        elif has_low:
            sensitivity = "LOW"
            sens_source_kind = "explicit_decorator"
        elif has_normal:
            sensitivity = "NORMAL"
            sens_source_kind = "explicit_decorator"
        else:
            sensitivity = "UNKNOWN"
            sens_source_kind = "unknown"

        has_internal = any(d in lower_decs for d in ("internal", "private", "internal_only"))
        has_public = any(d in lower_decs for d in ("public", "external"))

        if has_internal and has_public:
            exposure = "UNKNOWN"
            exp_source_kind = "unknown"
        elif has_internal:
            exposure = "INTERNAL"
            exp_source_kind = "explicit_decorator"
        elif has_public:
            exposure = "PUBLIC"
            exp_source_kind = "explicit_decorator"
        else:
            exposure = "UNKNOWN"
            exp_source_kind = "unknown"

        prov_map = {
            "sensitivity": EvidenceProvenance(
                value=sensitivity,
                source_kind=sens_source_kind,
                file_path=rec.file_path,
                line=rec.line,
                origin_id=f"route:{method_str}:{path}",
            ),
            "exposure": EvidenceProvenance(
                value=exposure,
                source_kind=exp_source_kind,
                file_path=rec.file_path,
                line=rec.line,
                origin_id=f"route:{method_str}:{path}",
            ),
        }

        return RouteDefinition(
            path=path,
            method=method_str,
            handler=handler,
            middleware_chain=(),
            sensitivity=sensitivity,
            exposure=exposure,
            provenance_map=prov_map,
            language="Python",
            framework="FLASK",
            confidence=rec.confidence,
            schema_version=CURRENT_ISR_SCHEMA_VERSION,
            origin=origin,
        )
