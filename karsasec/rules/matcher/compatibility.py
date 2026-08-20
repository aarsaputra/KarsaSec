"""RuleCompatibility validator verifying rule version and schema compatibility with ASTMatcher."""

from karsasec.rules.schema import Rule

CURRENT_MATCHER_VERSION = "1.0"
SUPPORTED_MAJOR_VERSIONS = {"0", "1", "2"}


class RuleIncompatibleError(Exception):
    """Exception raised when a Rule definition is incompatible with the current ASTMatcher version."""

    pass


def check_rule_compatibility(rule: Rule) -> None:
    """Verifies rule compatibility with current matcher engine version.

    Raises:
        RuleIncompatibleError: If rule version or schema is unsupported.
    """
    if not rule or not rule.id:
        raise RuleIncompatibleError("Invalid rule structure: missing rule ID.")

    version_str = str(rule.metadata.version)
    major_version = version_str.split(".")[0] if "." in version_str else version_str

    if major_version not in SUPPORTED_MAJOR_VERSIONS:
        raise RuleIncompatibleError(
            f"Rule '{rule.id}' version '{rule.metadata.version}' is incompatible with ASTMatcher v{CURRENT_MATCHER_VERSION}."
        )
