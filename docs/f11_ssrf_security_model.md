# Sprint F11 — SSRF & Endpoint Security Model

**Date**: 2026-08-20  
**Target Component**: `EndpointSecurityPolicy` & AI Provider HTTP Transport  
**Status**: Architecture & Security Specification  

---

## 1. Objective & Security Scope

The `EndpointSecurityPolicy` component enforces strict Server-Side Request Forgery (SSRF) prevention across all external AI provider HTTP calls. It guarantees that malicious prompt payloads, compromised provider configs, or dynamic redirects can never cause KarsaSec workers to issue HTTP requests to internal networks, loopback interfaces, or cloud metadata services.

---

## 2. Forbidden Address Ranges (Strict Blacklist)

The security policy rejects any destination resolving to the following IP networks:

| Range Category | IPv4 CIDR Block | IPv6 CIDR Block | Justification / Vulnerability Risk |
| :--- | :--- | :--- | :--- |
| **Loopback** | `127.0.0.0/8` | `::1/128` | Localhost access to local admin/debug ports |
| **RFC 1918 Private** | `10.0.0.0/8`<br>`172.16.0.0/12`<br>`192.168.0.0/16` | `fc00::/7` | Internal corporate/cluster network pivoting |
| **Link-Local / Cloud Metadata** | `169.254.0.0/16` | `fe80::/10` | AWS/GCP/Azure IMDS metadata credential theft |
| **Shared Address Space** | `100.64.0.0/10` | N/A | Carrier-grade NAT / Kubernetes pod networks |
| **Multicast & Reserved** | `224.0.0.0/4`<br>`240.0.0.0/4` | `ff00::/8` | Internal multicast & experimental addresses |
| **Unspecified / Current** | `0.0.0.0/8` | `::/128` | Local host default routes |

---

## 3. Protocol & Scheme Rules

- **Allowed Schemes**: `https://` ONLY.
- **Forbidden Schemes**: `http://` (unless explicitly allowed in local dev mode via `allow_insecure_http=True`), `file://`, `ftp://`, `gopher://`, `dict://`, `php://`.
- **Port Rules**: Standard HTTPS (`443`) or custom allowed ports $\ge 1024$. Standard HTTP (`80`) only when `allow_insecure_http` is set.

---

## 4. DNS Rebinding & TOCTOU Defense Architecture

To prevent Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks:

1. **Pre-flight Socket Address Resolution**: Before initiating HTTP connection, `EndpointSecurityPolicy.validate_url()` resolves hostname to IP addresses via `socket.getaddrinfo()`.
2. **IP Range Check**: Every resolved IP address is verified against the forbidden range list. If ANY resolved IP falls into a forbidden block, the request is REJECTED.
3. **Resolved Address Pinning**: The HTTP transport client binds the connection directly to the pre-validated IP address (passing original hostname in HTTP `Host` header and TLS SNI extension), preventing secondary DNS resolution at TCP connect time.

---

## 5. Redirect Policy Engine

1. **Auto-Redirect Disabling**: Default HTTP client disables automatic redirect following (`follow_redirects=False`).
2. **Explicit Redirect Handling**: If `HTTP 301`, `302`, `307`, or `308` is returned:
   - Increments redirect counter ($N_{redirect} \le 3$).
   - Extracts target URL from `Location` response header.
   - Re-evaluates target URL against `EndpointSecurityPolicy` (Scheme, IP Range, Hostname checks).
   - If validation passes, issues new HTTP request to target URL.
   - If validation fails or $N_{redirect} > 3$, aborts request with `ATTEMPT_ERROR_INVALID_REQUEST`.

---

## 6. Adversarial Bypass Cases & Validation Matrix

| Bypass Attack Vector | Example Attack Payload | Expected Result | Enforcement Layer |
| :--- | :--- | :--- | :--- |
| **Dotted Decimal IPv4** | `http://2130706433/` (127.0.0.1) | **REJECTED** | IP Parser Normalization |
| **Hex/Octal IPv4** | `http://0x7f.0x0.0.0x1/` | **REJECTED** | IP Parser Normalization |
| **IPv6 Embedded IPv4** | `http://[::ffff:127.0.0.1]/` | **REJECTED** | IPv6 Normalization |
| **Shortened IPv4** | `http://127.1/` | **REJECTED** | `ipaddress.ip_address()` |
| **AWS Metadata DNS** | `http://instance-data/` | **REJECTED** | DNS Pre-flight Resolution |
| **DNS Rebinding** | `http://rebind.attacker.com` | **REJECTED** | Resolved IP Pinning |
| **Redirect to Metadata** | `302 Location: http://169.254.169.254` | **REJECTED** | Per-Hop Redirect Policy |
