"""K1.5 No Label Leakage Test Suite (Task K1.5)."""

from karsasec.analysis.taint.k1_integrated import analyze_k1


def test_k1_5_no_label_leakage_and_metadata_isolation() -> None:
    code_clean = """
def handler(req):
    val = req.args.get("doc_id")
    doc = Document.query.get(val)
    return doc.content
"""
    code_poisoned = """
# expected_property: SAFE
# expected_status: TRUE_NEGATIVE
# partition: holdout
def handler(req):
    val = req.args.get("doc_id")
    doc = Document.query.get(val)
    return doc.content
"""
    res1 = analyze_k1(code_clean)
    res2 = analyze_k1(code_poisoned)

    # Compare logical finding content (rule_id, property_name, knowledge_pack)
    logical1 = [(f.rule_id, f.property_name, f.knowledge_pack) for f in res1]
    logical2 = [(f.rule_id, f.property_name, f.knowledge_pack) for f in res2]

    assert logical1 == logical2, "Detector was influenced by injected comment metadata"
