"""Enumerations for Severity, Confidence, Supported Languages, and OWASP Top 10 categories."""

from enum import Enum


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Confidence(str, Enum):
    """Rule matching confidence levels."""
    CONFIDENT = "CONFIDENT"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"
    HIGH = "CONFIDENT"
    MEDIUM = "LIKELY"
    LOW = "POSSIBLE"

class LanguageEnum(str, Enum):
    """Supported target programming languages."""
    PYTHON = "Python"
    JAVASCRIPT = "JavaScript"
    TYPESCRIPT = "TypeScript"
    PHP = "PHP"
    GO = "Go"
    RUST = "Rust"
    JAVA = "Java"
    GENERIC = "Generic"

class TargetKindEnum(str, Enum):
    """Broad category classification of analysis targets."""
    SOURCE_CODE = "SOURCE_CODE"
    CONFIG = "CONFIG"
    PIPELINE = "PIPELINE"
    IAC = "IAC"
    MANIFEST = "MANIFEST"

class TargetFormatEnum(str, Enum):
    """File format/specification identifier."""
    PYTHON = "Python"
    JAVASCRIPT = "JavaScript"
    TYPESCRIPT = "TypeScript"
    PHP = "PHP"
    GO = "Go"
    RUST = "Rust"
    JAVA = "Java"
    DOCKERFILE = "Dockerfile"
    KUBERNETES = "Kubernetes"
    GITHUB_ACTIONS = "GitHub-Actions"
    TERRAFORM = "Terraform"
    HELM = "Helm"

class IaCTaxonomyEnum(str, Enum):
    """Taxonomy categories for Infrastructure as Code security risks."""
    MISCONFIGURATION = "misconfiguration"
    PRIVILEGE = "privilege"
    SECRETS = "secrets"
    SUPPLY_CHAIN = "supply_chain"
    NETWORKING = "networking"
    RUNTIME = "runtime"
    POLICY = "policy"

class AnalysisCapability(str, Enum):
    """Strongly-typed capabilities exported by parsers and required by security rules."""
    AST = "ast"
    POSITION = "position"
    COMMENTS = "comments"
    HIERARCHY = "hierarchy"
    SEMANTIC = "semantic"
    TYPE_INFO = "type_info"
    CONTROL_FLOW = "control_flow"
    DATAFLOW = "dataflow"
    CALLGRAPH = "callgraph"

class OWASPCategory(str, Enum):
    """OWASP Top 10 (2025/2026 & 2021) and OWASP API Category Mappings."""
    # OWASP Top 10 (Latest 2025/2026 Standard)
    A01_2025_BROKEN_ACCESS_CONTROL = "A01:2025-Broken Access Control"
    A02_2025_CRYPTOGRAPHIC_FAILURES = "A02:2025-Cryptographic Failures"
    A03_2025_INJECTION = "A03:2025-Injection and Input Validation"
    A04_2025_INSECURE_DESIGN = "A04:2025-Insecure Design"
    A05_2025_SECURITY_MISCONFIGURATION = "A05:2025-Security Misconfiguration"
    A06_2025_VULNERABLE_COMPONENTS = "A06:2025-Vulnerable and Outdated Components"
    A07_2025_IDENTIFICATION_FAILURES = "A07:2025-Identification and Authentication Failures"
    A08_2025_SOFTWARE_INTEGRITY = "A08:2025-Software and Data Integrity Failures"
    A09_2025_LOGGING_FAILURES = "A09:2025-Security Logging and Monitoring Failures"
    A10_2025_SSRF = "A10:2025-Server-Side Request Forgery"

    # OWASP Top 10 (2021 Standard - Backward Compatibility)
    A01_2021_BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    A02_2021_CRYPTOGRAPHIC_FAILURES = "A02:2021-Cryptographic Failures"
    A03_2021_INJECTION = "A03:2021-Injection"
    A04_2021_INSECURE_DESIGN = "A04:2021-Insecure Design"
    A05_2021_SECURITY_MISCONFIGURATION = "A05:2021-Security Misconfiguration"
    A06_2021_VULNERABLE_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    A07_2021_IDENTIFICATION_FAILURES = "A07:2021-Identification and Authentication Failures"
    A08_2021_SOFTWARE_INTEGRITY = "A08:2021-Software and Data Integrity Failures"
    A09_2021_LOGGING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    A10_2021_SSRF = "A10:2021-Server-Side Request Forgery"

    # OWASP API Security Top 10
    API01_BOLA = "API1:2023-Broken Object Level Authorization"
    API02_AUTHENTICATION = "API2:2023-Broken Authentication"
    API03_BOPLA = "API3:2023-Broken Object Property Level Authorization"
    API04_RESOURCE_CONSUMPTION = "API4:2023-Unrestricted Resource Consumption"
    API05_BFLA = "API5:2023-Broken Function Level Authorization"
