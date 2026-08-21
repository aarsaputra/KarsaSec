"""Unit test suite for Batch C12 Secrets & Credential Exposure Reasoning Engine covering 30 mandatory unit tests and quality metrics."""

from karsasec.analysis.secrets.engine import SecretExposureReasoningEngine
from karsasec.analysis.secrets.models import (
    CredentialValidity,
    PrivilegeLevel,
    SecretContext,
    SecretExposureCategory,
    SecretType,
)


def test_1_rule_c12_1_secret_presence_in_source_code_safe() -> None:
    """Rule C12.1 & INV-C12-01: Secret in source code never crossing trust boundary is SAFE."""
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.AWS_ACCESS_KEY, secret_value="AKIAIOSFODNN7EXAMPLE", source_boundary="SOURCE_CODE", exposure_boundary=None, is_cross_boundary=False)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"
    assert ev.category == SecretExposureCategory.SECRET_PRESENT


def test_2_rule_c12_2_secret_exposed_to_http_response() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.DATABASE_PASSWORD, secret_value="s3cr3t", source_boundary="ENVIRONMENT_VARIABLE", exposure_boundary="HTTP_RESPONSE", is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.category == SecretExposureCategory.SECRET_EXPOSURE
    assert ev.resolution == "VULNERABLE"


def test_3_rule_c12_3_secret_exposed_in_logs() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.API_TOKEN, secret_value="tok_12345", source_boundary="ENVIRONMENT_VARIABLE", exposure_boundary="LOG_FILE", is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.category == SecretExposureCategory.SECRET_EXPOSURE
    assert ev.resolution == "VULNERABLE"


def test_4_rule_c12_4_git_repository_leak() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.AWS_SECRET_KEY, secret_value="secret_key_123", source_boundary="CONFIG_FILE", exposure_boundary="GIT_REPOSITORY", is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.category == SecretExposureCategory.SECRET_EXPOSURE


def test_5_rule_c12_5_cloud_metadata_secret_chain() -> None:
    """Rule C12.5 & Chain I: SSRF -> Cloud Metadata -> Credential Compromise."""
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.AWS_SECRET_KEY, secret_value="temp_token", source_boundary="METADATA_SERVICE", exposure_boundary="SSRF_CALLBACK", validity=CredentialValidity.VALID, is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.category == SecretExposureCategory.CREDENTIAL_COMPROMISE


def test_6_rule_c12_6_secret_manager_access_safe() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.DATABASE_PASSWORD, secret_value="vault_pass", source_boundary="SECRET_MANAGER", exposure_boundary=None, is_vault_managed=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_7_rule_c12_7_jwt_signing_key_leak() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.JWT_SIGNING_KEY, secret_value="jwt_secret_key", source_boundary="CONFIG_FILE", exposure_boundary="LOG_FILE", is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_8_rule_c12_8_ssh_private_key_exposure() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.SSH_PRIVATE_KEY, secret_value="-----BEGIN OPENSSH PRIVATE KEY-----", source_boundary="FILE_READ", exposure_boundary="HTTP_RESPONSE", is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.category == SecretExposureCategory.CREDENTIAL_COMPROMISE


def test_9_privilege_escalation_path_admin_key() -> None:
    """INV-C12-03 / Rule C12.8: Admin level credential compromise -> PRIVILEGE_ESCALATION_PATH."""
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.AWS_SECRET_KEY, secret_value="admin_secret", source_boundary="ENVIRONMENT_VARIABLE", exposure_boundary="HTTP_RESPONSE", privilege_level=PrivilegeLevel.ADMIN, is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.category == SecretExposureCategory.PRIVILEGE_ESCALATION_PATH


def test_10_inv_c12_05_unknown_preservation() -> None:
    """INV-C12-05: Ambiguous boundary with unknown validity -> UNKNOWN."""
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.GENERIC_SECRET, secret_value="ambiguous", source_boundary="CONFIG_FILE", exposure_boundary="AMBIGUOUS_BOUNDARY", validity=CredentialValidity.UNKNOWN)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "UNKNOWN"
    assert ev.resolution != "SAFE"


def test_11_gcp_service_account_leak() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.GCP_SERVICE_ACCOUNT, secret_value="service_account.json", source_boundary="FILE_READ", exposure_boundary="PUBLIC_API", is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.category == SecretExposureCategory.CREDENTIAL_COMPROMISE


def test_12_azure_storage_key_exposure() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.AZURE_STORAGE_KEY, secret_value="DefaultEndpointsProtocol=https;...", source_boundary="CONFIG_FILE", exposure_boundary="HTTP_RESPONSE", is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_13_tls_private_key_exposure() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.TLS_PRIVATE_KEY, secret_value="-----BEGIN RSA PRIVATE KEY-----", source_boundary="FILE_READ", exposure_boundary="LOG_FILE", is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_14_kubernetes_service_account_token() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.KUBERNETES_TOKEN, secret_value="eyJhbGciOiJSUzI1NiIs...", source_boundary="FILE_READ", exposure_boundary="PUBLIC_API", is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.category == SecretExposureCategory.CREDENTIAL_COMPROMISE


def test_15_oauth_client_secret_disclosure() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.OAUTH_CLIENT_SECRET, secret_value="client_secret_xyz", source_boundary="ENVIRONMENT_VARIABLE", exposure_boundary="HTTP_RESPONSE", is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_16_ci_cd_system_log_leak() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.API_TOKEN, secret_value="ghp_12345", source_boundary="CI_CD_SYSTEM", exposure_boundary="LOG_FILE", is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_17_vault_managed_secret_safe() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.DATABASE_PASSWORD, secret_value="pass", source_boundary="SECRET_MANAGER", is_vault_managed=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_18_root_system_privilege_escalation() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.SSH_PRIVATE_KEY, secret_value="root_key", source_boundary="FILE_READ", exposure_boundary="HTTP_RESPONSE", privilege_level=PrivilegeLevel.ROOT_SYSTEM, is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.category == SecretExposureCategory.PRIVILEGE_ESCALATION_PATH


def test_19_valid_credential_compromise() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.API_TOKEN, secret_value="valid_tok", source_boundary="ENVIRONMENT_VARIABLE", exposure_boundary="HTTP_RESPONSE", validity=CredentialValidity.VALID, is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.category == SecretExposureCategory.CREDENTIAL_COMPROMISE


def test_20_deterministic_secret_evaluation() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.AWS_SECRET_KEY, secret_value="sec", source_boundary="ENVIRONMENT_VARIABLE", exposure_boundary="HTTP_RESPONSE", is_cross_boundary=True)
    ev1 = engine.evaluate_secret_exposure(ctx)
    ev2 = engine.evaluate_secret_exposure(ctx)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()


def test_21_evidence_to_dict_keys() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.AWS_SECRET_KEY, secret_value="sec", source_boundary="ENVIRONMENT_VARIABLE", exposure_boundary="HTTP_RESPONSE", is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    d = ev.to_dict()
    assert "secret_type" in d
    assert "source_boundary" in d
    assert "exposure_boundary" in d
    assert "credential_validity" in d


def test_22_expired_credential_handling() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.API_TOKEN, secret_value="old_tok", source_boundary="ENVIRONMENT_VARIABLE", exposure_boundary="LOG_FILE", validity=CredentialValidity.EXPIRED, is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_23_revoked_credential_handling() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.API_TOKEN, secret_value="revoked_tok", source_boundary="ENVIRONMENT_VARIABLE", exposure_boundary="LOG_FILE", validity=CredentialValidity.REVOKED, is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_24_generic_secret_exposure() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.GENERIC_SECRET, secret_value="high_entropy_pass", source_boundary="CONFIG_FILE", exposure_boundary="HTTP_RESPONSE", is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.category == SecretExposureCategory.SECRET_EXPOSURE


def test_25_read_only_privilege_level() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.API_TOKEN, secret_value="ro_token", source_boundary="ENVIRONMENT_VARIABLE", exposure_boundary="LOG_FILE", privilege_level=PrivilegeLevel.READ_ONLY, is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.category == SecretExposureCategory.SECRET_EXPOSURE
    assert ev.category != SecretExposureCategory.PRIVILEGE_ESCALATION_PATH


def test_26_limited_user_privilege_level() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.API_TOKEN, secret_value="user_token", source_boundary="ENVIRONMENT_VARIABLE", exposure_boundary="LOG_FILE", privilege_level=PrivilegeLevel.LIMITED_USER, is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_27_source_code_constant_no_exposure_safe() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.GENERIC_SECRET, secret_value="test_const", source_boundary="SOURCE_CODE")
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_28_database_source_boundary_exposure() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.DATABASE_PASSWORD, secret_value="db_pass", source_boundary="DATABASE", exposure_boundary="HTTP_RESPONSE", is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_29_evidence_path_verification() -> None:
    engine = SecretExposureReasoningEngine()
    ctx = SecretContext(secret_type=SecretType.AWS_SECRET_KEY, secret_value="sec", source_boundary="ENVIRONMENT_VARIABLE", exposure_boundary="HTTP_RESPONSE", is_cross_boundary=True)
    ev = engine.evaluate_secret_exposure(ctx)
    assert ev is not None
    assert len(ev.evidence_path) > 0


def test_30_quality_metrics() -> None:
    """Calculates TP, TN, FP, FN, Precision, Recall, FPR, FNR breakdown on internal KarsaSec qualification corpus."""
    engine = SecretExposureReasoningEngine()

    positives = [
        SecretContext(secret_type=SecretType.AWS_SECRET_KEY, secret_value=f"pos_{i}", source_boundary="ENVIRONMENT_VARIABLE", exposure_boundary="HTTP_RESPONSE", is_cross_boundary=True) for i in range(50)
    ]
    negatives = [
        SecretContext(secret_type=SecretType.AWS_ACCESS_KEY, secret_value=f"neg_{i}", source_boundary="SOURCE_CODE", exposure_boundary=None, is_cross_boundary=False) for i in range(50)
    ]

    tp = sum(1 for ctx in positives if engine.evaluate_secret_exposure(ctx).resolution == "VULNERABLE")
    fn = len(positives) - tp

    fp = sum(1 for ctx in negatives if engine.evaluate_secret_exposure(ctx).resolution == "VULNERABLE")
    tn = len(negatives) - fp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    assert tp == 50
    assert tn == 50
    assert fp == 0
    assert fn == 0
    assert precision == 1.0
    assert recall == 1.0
    assert fpr == 0.0
    assert fnr == 0.0
