"""Unit test for LLMPatchProvider anti-hallucination guardrails and JSON schema validation."""

from karsasec.ai.remediation.models import RemediationStrategy, RemediationStrategyType
from karsasec.ai.remediation.provider import LLMPatchProvider


class MockLLMWithInjectionResponse:

    def __init__(self, response_text: str) -> None:
        self.response_text = response_text

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        return self.response_text


def test_llm_provider_valid_json_schema():
    json_resp = (
        '{"hunks": [{"start_line": 10, "end_line": 10, '
        '"original_text": "echo $_GET[\'q\'];", '
        '"proposed_text": "echo htmlspecialchars($_GET[\'q\'], ENT_QUOTES, \'UTF-8\');", '
        '"context": "main", "evidence_reference": "index.php:10"}]}'
    )
    mock_llm = MockLLMWithInjectionResponse(json_resp)

    provider = LLMPatchProvider(llm_provider=mock_llm)

    strat = RemediationStrategy(
        finding_id="find-1",
        root_cause_category="UNSANITIZED_INPUT",
        strategy_type=RemediationStrategyType.ADD_OUTPUT_ENCODING,
        rationale="Encode XSS",
        target_file="index.php",
        target_locations=("index.php:10",),
        affected_symbols=("echo",),
        evidence_references=("index.php:10",),
        knowledge_references=(),
        confidence=0.9,
        assumptions=(),
        limitations=(),
        strategy_fingerprint="fp1",
    )
    hunks = provider.generate_hunks(strat, "echo $_GET['q'];", start_line=10)

    assert len(hunks) == 1
    assert hunks[0].start_line == 10
    assert "htmlspecialchars" in hunks[0].proposed_text


def test_llm_provider_invalid_json_fallback():
    mock_llm = MockLLMWithInjectionResponse("Invalid non-JSON hallucinated text response from model")
    provider = LLMPatchProvider(llm_provider=mock_llm)

    strat = RemediationStrategy(
        finding_id="find-2",
        root_cause_category="UNSANITIZED_INPUT",
        strategy_type=RemediationStrategyType.ADD_OUTPUT_ENCODING,
        rationale="Encode XSS",
        target_file="app.php",
        target_locations=("app.php:5",),
        affected_symbols=("echo",),
        evidence_references=("app.php:5",),
        knowledge_references=(),
        confidence=0.9,
        assumptions=(),
        limitations=(),
        strategy_fingerprint="fp2",
    )
    hunks = provider.generate_hunks(strat, "echo $user;", start_line=5)

    # Should gracefully fall back to TemplatePatchProvider
    assert len(hunks) == 1
    assert "htmlspecialchars" in hunks[0].proposed_text

