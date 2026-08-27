# Phase 2 — Source Resolution Adversarial Audit & Negative Controls Report

## Audit Overview
Independent adversarial audit of `SourceResolver` and `SourceRegistry` in `karsasec/analysis/taint/sources.py`.

---

## 1. Test Suite Results (`test_g5_source_adversarial.py`)

- **Positive Framework Sources**:
  - Java Servlet `request.getParameter('id')` $\rightarrow$ **User-Controlled Source**
  - Java Spring `@RequestParam String query` $\rightarrow$ **User-Controlled Source**
  - Python Flask `request.args.get('user')` $\rightarrow$ **User-Controlled Source**
  - Python Django `request.GET.get('q')` $\rightarrow$ **User-Controlled Source**
  - JS Express `req.query.search` $\rightarrow$ **User-Controlled Source**

- **Custom Wrapper Depth (0 to 5)**:
  - Depth 0 (Direct HTTP source): `is_user_controlled = True`
  - Depth 1 (Custom wrapper `customRequest.getInput`): `is_user_controlled = True`
  - Depth 2 (Renamed variable wrapper `my_req_obj.getParameter`): `is_user_controlled = True`
  - Depth 3/5 (Multi-hop delegation `wrapper.getDelegate().getInternalReq().getParameter`): `is_user_controlled = True`

- **Strict Negative Controls**:
  - `config.get('id')` $\rightarrow$ **NOT User-Controlled** (`is_user_controlled = False`)
  - `database.get('id')` $\rightarrow$ **NOT User-Controlled** (`is_user_controlled = False`)
  - `cache.get('id')` $\rightarrow$ **NOT User-Controlled** (`is_user_controlled = False`)
  - `environment.get('id')` $\rightarrow$ **NOT User-Controlled** (`is_user_controlled = False`)
  - `object.getParameter('id')` $\rightarrow$ **NOT User-Controlled** (`is_user_controlled = False`)
  - `internalRequest.get('id')` $\rightarrow$ **NOT User-Controlled** (`is_user_controlled = False`)

---

## 2. Epistemic Invariant Verification
All unproven custom methods default to `UNKNOWN` (`None`), ensuring absence of evidence is never converted to an HTTP source assumption.
