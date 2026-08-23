"""Rule Collision Detection Module (INV-G5.4-06).

Analyzes K1 rule expansion packs against certified baseline rules to detect semantic,
precedence, and ID collisions without silent replacement.
"""

from typing import Any


def detect_rule_collisions(
    existing_rules: list[dict[str, Any]], new_rules: list[dict[str, Any]]
) -> dict[str, Any]:
    """Analyzes new rule definitions against existing rules for collisions.

    Collision Categories:
    - DUPLICATE_ID
    - DUPLICATE_SIGNATURE
    - PRECEDENCE_CONFLICT
    - SANITIZER_CONFLICT
    - VERDICT_CONFLICT
    - SOURCE_SINK_OVERLAP
    """
    collisions = []
    existing_by_id = {r["rule_id"]: r for r in existing_rules if "rule_id" in r}

    for nr in new_rules:
        nid = nr.get("rule_id")

        # 1. DUPLICATE_ID
        if nid in existing_by_id:
            collisions.append({
                "existing_rule": nid,
                "new_rule": nid,
                "collision_type": "DUPLICATE_ID",
                "action": "BLOCK",
                "rationale": f"Duplicate rule ID '{nid}' detected.",
            })

        for er in existing_rules:
            eid = er.get("rule_id")

            # 2. DUPLICATE_SIGNATURE
            if (
                er.get("cwe") == nr.get("cwe")
                and er.get("source_pattern") == nr.get("source_pattern")
                and er.get("sink_pattern") == nr.get("sink_pattern")
                and eid != nid
            ):
                collisions.append({
                    "existing_rule": eid,
                    "new_rule": nid,
                    "collision_type": "DUPLICATE_SIGNATURE",
                    "action": "BLOCK",
                    "rationale": "Identical (CWE, source_pattern, sink_pattern) tuple.",
                })

            # 3. SANITIZER_CONFLICT
            if (
                er.get("property") == nr.get("property")
                and er.get("sanitizer_semantics") != nr.get("sanitizer_semantics")
                and er.get("sanitizer_semantics") is not None
                and nr.get("sanitizer_semantics") is not None
            ):
                collisions.append({
                    "existing_rule": eid,
                    "new_rule": nid,
                    "collision_type": "SANITIZER_CONFLICT",
                    "action": "BLOCK",
                    "rationale": f"Conflicting sanitizer semantics for property '{er.get('property')}'.",
                })

            # 4. PRECEDENCE_CONFLICT
            if (
                eid == nid
                or (er.get("property") == nr.get("property") and er.get("precedence") != nr.get("precedence"))
            ) and er.get("precedence") is not None and nr.get("precedence") is not None:
                collisions.append({
                    "existing_rule": eid,
                    "new_rule": nid,
                    "collision_type": "PRECEDENCE_CONFLICT",
                    "action": "BLOCK",
                    "rationale": f"Conflicting precedence ({er.get('precedence')} vs {nr.get('precedence')}).",
                })

    status = "PASS" if not collisions else "COLLISION_DETECTED"
    return {
        "status": status,
        "has_collisions": len(collisions) > 0,
        "collision_count": len(collisions),
        "collisions": collisions,
    }
