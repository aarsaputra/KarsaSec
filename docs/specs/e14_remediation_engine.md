# Sprint E14 — Remediation Intelligence Engine

## Overview
The **Remediation Engine** generates deterministic, category-specific remediation plans (`RemediationPlan`) based on validated sink categories and negative barrier matrices.

## Remediation Pattern Registry

Built-in remediation patterns are mapped to specific sink categories with explicit negative matrices to reject fake or cross-category sanitizers:

| Sink Category | Preferred Fix | Alternative Fixes | Negative Barrier Matrix (Forbidden Fixes) |
|---|---|---|---|
| **SQL** | `parameterized_query` | `prepared_statement`, `sanitize_sql` | `str()`, `trim()`, `escape_html()` |
| **COMMAND** | `command_allowlist` | `shlex.quote`, `safe_exec` | `str()`, `trim()`, `sanitize_sql()` |
| **HTML** | `context_aware_html_escape` | `framework_auto_escape` | `str()`, `trim()`, `sanitize_sql()` |
| **PATH** | `safe_join` | `realpath_boundary_check` | `string replacement only`, `escape_html()`, `str()` |
| **CODE** | `static_dispatch` | `ast.literal_eval` | `eval()`, `exec()`, `compile()`, `str()` |

## Status Mapping & Sink Compatibility

- **Sink Compatibility Check (`is_sink_compatible`)**: Patterns verify exact matching between pattern sink category and cluster sink category.
- **Status Determination**:
  - `ClusterStatus.CONFIRMED` $\rightarrow$ `RemediationStatus.REQUIRED`
  - `ClusterStatus.CANDIDATE` $\rightarrow$ `RemediationStatus.RECOMMENDED`
  - `ClusterStatus.BLOCKED` $\rightarrow$ `RemediationStatus.BLOCKED`
  - `ClusterStatus.UNKNOWN` $\rightarrow$ `RemediationStatus.UNKNOWN`

## Remediation Plan Identity

Remediation plans are assigned a 64-character SHA-256 identity (`plan_id`):

$$
\text{PlanID} = \text{SHA256}\left(\text{"E14-PLAN:"} + \text{CanonicalJSON}(\text{ClusterID}, \text{PatternID}, \text{Status}, \text{PrimaryFix}, \text{schema\_version})\right)
$$

> [!IMPORTANT]
> `REMEDIATION_REQUIRED` indicates that a remediation plan is available and required for a confirmed finding; it does NOT imply that the vulnerability has already been fixed.
