"""Transforms raw Flask configuration candidates into ISR v1.0 ConfigDefinition objects."""

from __future__ import annotations

from karsasec.framework.extractors.flask.config.state import FlaskConfigState
from karsasec.framework.intermediate import ConfigDefinition
from karsasec.framework.origin import EvidenceProvenance, OriginMetadata, SourceLocation


class FlaskConfigNormalizer:
    """Normalizes ConfigCandidates into ISR v1.0 ConfigDefinition objects."""

    def __init__(self, state: FlaskConfigState) -> None:
        self.state = state

    def normalize(self) -> list[ConfigDefinition]:
        config_defs: list[ConfigDefinition] = []
        seen_keys_locations: set[tuple[str, str, int]] = set()

        # 1. Scan for explicit environment declarations (e.g. ENV="production", FLASK_ENV="production") with conflict detection
        detected_envs: set[str] = set()
        for c in self.state.configs:
            if c.key in ("ENV", "FLASK_ENV", "ENVIRONMENT", "APP_ENV"):
                val_str = str(c.value).upper() if c.value is not None else ""
                if val_str in ("PRODUCTION", "PROD"):
                    detected_envs.add("PRODUCTION")
                elif val_str in ("DEVELOPMENT", "DEV"):
                    detected_envs.add("DEVELOPMENT")
                elif val_str in ("STAGING", "STAGE"):
                    detected_envs.add("STAGING")

        # Conflict resolution: if contradictory explicit environment declarations exist -> UNKNOWN
        if len(detected_envs) == 1:
            explicit_env = next(iter(detected_envs))
        else:
            explicit_env = "UNKNOWN"

        for c in self.state.configs:
            key_loc = (c.key, c.file_path, c.line)
            if key_loc in seen_keys_locations:
                continue
            seen_keys_locations.add(key_loc)

            loc = SourceLocation(file_path=c.file_path, line=c.line)
            origin = OriginMetadata(location_info=loc, evidence_list=c.evidence)

            source_desc = f"app.config.{c.source_type}" if c.source_type else "app.config"
            if c.loader:
                source_desc = f"{source_desc}({c.loader})"

            # Determine source_kind
            if c.source_type in ("env_lookup", "from_envvar", "env_var"):
                source_kind = "env_var"
            elif c.source_type in ("from_pyfile", "from_json", "from_file"):
                source_kind = "file"
            elif isinstance(c.value, (str, int, float, bool)):
                source_kind = "literal"
            else:
                source_kind = "unknown"

            # Determine provenance_type
            if c.source_type in ("update", "from_mapping", "from_object"):
                provenance_type = "update"
            elif c.source_type in ("from_envvar", "from_pyfile"):
                provenance_type = "loader"
            elif c.source_type == "env_lookup":
                provenance_type = "env_lookup"
            else:
                provenance_type = "assignment"

            env_source_kind = "explicit_env" if explicit_env != "UNKNOWN" else "unknown"
            prov_map = {
                "environment": EvidenceProvenance(
                    value=explicit_env,
                    source_kind=env_source_kind,
                    file_path=c.file_path,
                    line=c.line,
                    origin_id=f"config:{c.key}",
                ),
                "source_kind": EvidenceProvenance(
                    value=source_kind,
                    source_kind="explicit_assignment" if source_kind == "literal" else "unknown",
                    file_path=c.file_path,
                    line=c.line,
                    origin_id=f"config:{c.key}",
                ),
            }

            c_def = ConfigDefinition(
                key=c.key,
                value=c.value,
                category=c.category,
                source=source_desc,
                is_sensitive=c.is_sensitive,
                source_kind=source_kind,
                provenance_type=provenance_type,
                environment=explicit_env,
                provenance_map=prov_map,
                language="Python",
                framework="FLASK",
                confidence=c.confidence,
                origin=origin,
            )
            config_defs.append(c_def)

        return config_defs
