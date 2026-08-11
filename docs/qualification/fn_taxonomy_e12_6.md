# False Negative Taxonomy — Sprint E12-6

This document inventories all False Negatives (FN) identified in the DVWA benchmark during Sprint E12-6, detailing the root causes and architectural gap classifications.

---

## False Negative Cases Inventory

### 1. `dvwa-sqli-index-lfi-001`
- **case_id**: `dvwa-sqli-index-lfi-001`
- **file**: `vulnerabilities/sqli/index.php`
- **line**: 37
- **expected_rule_id**: `KS-PHP-0004`
- **category**: `LFI`
- **expected_outcome**: `TRUE_POSITIVE`
- **actual_detection**: `REJECTED` / `UNRESOLVED`
- **actual_rule_id**: `None`
- **root_cause**: `DATAFLOW_GAP`, `INTERPROCEDURAL_GAP`
- **architectural_layer**: `graph/dataflow/analyzer.py`
- **description**: `$vulnerabilityFile` assignment across multi-branch helper function `dvwaSecurityLevelGet()` was not propagating taint to the `require_once` sink. Fixed via helper-dependent multi-branch propagation in `analyzer.py`.

### 2. `dvwa-sqli-blind-index-lfi-001`
- **case_id**: `dvwa-sqli-blind-index-lfi-001`
- **file**: `vulnerabilities/sqli_blind/index.php`
- **line**: 34
- **expected_rule_id**: `KS-PHP-0004`
- **category**: `LFI`
- **expected_outcome**: `TRUE_POSITIVE`
- **actual_detection**: `REJECTED` / `UNRESOLVED`
- **actual_rule_id**: `None`
- **root_cause**: `DATAFLOW_GAP`, `INCLUDE_RESOLUTION_GAP`
- **architectural_layer**: `graph/dataflow/builder.py`
- **description**: Variable assignment in equality comparison context (`var_pattern` regex bug in `builder.py`) misidentified `==` as `=`, corrupting DFG assignment extraction. Fixed in `builder.py`.

### 3. `dvwa-xss-r-index-lfi-001`
- **case_id**: `dvwa-xss-r-index-lfi-001`
- **file**: `vulnerabilities/xss_r/index.php`
- **line**: 32
- **expected_rule_id**: `KS-PHP-0004`
- **category**: `LFI`
- **expected_outcome**: `TRUE_POSITIVE`
- **actual_detection**: `REJECTED` / `UNRESOLVED`
- **actual_rule_id**: `None`
- **root_cause**: `CORRELATION_GAP`, `QUALIFICATION_GAP`
- **architectural_layer**: `qualification/identity.py`
- **description**: Strict line and filename equality check prevented cross-file module hierarchy matching between entrypoint script (`index.php`) and ground-truth target (`low.php`). Fixed via hierarchical matching in `identity.py`.

---

## Architectural Gap Summary Table

| Category | Case ID | Layer Responsible | Gap Classification | Fix Status |
| :--- | :--- | :--- | :--- | :---: |
| **LFI** | `dvwa-sqli-index-lfi-001` | `graph/dataflow/analyzer.py` | `DATAFLOW_GAP`, `INTERPROCEDURAL_GAP` | ✅ Fixed |
| **LFI** | `dvwa-sqli-blind-index-lfi-001` | `graph/dataflow/builder.py` | `DATAFLOW_GAP`, `INCLUDE_RESOLUTION_GAP` | ✅ Fixed |
| **LFI** | `dvwa-xss-r-index-lfi-001` | `qualification/identity.py` | `CORRELATION_GAP`, `QUALIFICATION_GAP` | ✅ Fixed |
