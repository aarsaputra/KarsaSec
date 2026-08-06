"""Unit test suite for KarsaSec Reusable Analysis Ecosystem (Pass Manager, Artifact Store, HIR/MIR/LIR, Query Optimizer, Capability Negotiation)."""

from karsasec.ir.hir_mir import HIRNode, LIRSink, LIRSource, MIRConditional
from karsasec.query.optimizer import query_optimizer
from karsasec.rules.enums import AnalysisCapability
from karsasec.runtime.artifact_store import ArtifactStore
from karsasec.runtime.pass_manager import AnalysisPass, PassDescriptor, PassManager
from karsasec.sdk.api import AnalysisAPIVersion, PluginManifest
from karsasec.sdk.negotiator import capability_negotiator


class DummyPass(AnalysisPass):
    def run(self, store: ArtifactStore) -> bool:
        store.put("dummy_artifact", "computed_value")
        return True


def test_pass_manager_and_artifact_store() -> None:
    """Verify PassManager executes registered passes and writes artifacts to ArtifactStore."""
    store = ArtifactStore()
    pm = PassManager()

    descriptor = PassDescriptor(
        name="DummyPass",
        inputs=[],
        outputs=["dummy_artifact"],
        required_capabilities=[AnalysisCapability.AST],
    )
    pm.register_pass(DummyPass(descriptor))

    results = pm.run_passes(store)
    assert results["DummyPass"] is True
    assert store.has("dummy_artifact") is True
    assert store.get("dummy_artifact") == "computed_value"


def test_multi_layered_ir_hir_mir_lir() -> None:
    """Verify construction of High-Level, Medium-Level, and Analysis-Level IR primitives."""
    hir = HIRNode(node_id="hir_1", language="Python", syntax_kind="IfStatement")
    assert hir.language == "Python"

    mir = MIRConditional(node_id="mir_1", condition_var="user_input")
    assert mir.condition_var == "user_input"

    lir_src = LIRSource(node_id="lir_s", source_type="HTTP_PARAM", var_name="page")
    lir_snk = LIRSink(node_id="lir_k", sink_type="EXEC_CMD", target_callee="subprocess.call")
    assert lir_src.source_type == "HTTP_PARAM"
    assert lir_snk.target_callee == "subprocess.call"


def test_query_optimizer_predicate_pushdown() -> None:
    """Verify QueryOptimizer performs predicate pushdown and capability selection."""
    predicates = ["callee==eval", "tainted==True", "node_type==Call"]
    plan = query_optimizer.optimize(target_kind="Call", predicates=predicates)

    assert "callee==eval" in plan.pushed_predicates
    assert AnalysisCapability.DATAFLOW in plan.required_capabilities
    assert plan.estimated_cost_ms > 0.0


def test_capability_negotiator_validation() -> None:
    """Verify CapabilityNegotiator accepts valid manifests and rejects unsupported versions."""
    valid_manifest = PluginManifest(
        name="JavaParser",
        version="1.0.0",
        author="KarsaSec",
        api_version=AnalysisAPIVersion.V3,
    )
    result = capability_negotiator.negotiate(valid_manifest)
    assert result.is_compatible is True

    invalid_manifest = PluginManifest(
        name="LegacyPlugin",
        version="0.1.0",
        author="Unknown",
        api_version="v0_unsupported",
    )
    invalid_result = capability_negotiator.negotiate(invalid_manifest)
    assert invalid_result.is_compatible is False
    assert len(invalid_result.rejection_reasons) > 0
