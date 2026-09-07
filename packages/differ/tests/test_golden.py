"""base.graph.json vs head.graph.json reproduces expected.diff.json.

Structural section: exact match (machine-generated).  Semantic / findings /
unevaluated: match in substance -- the expected document was hand-authored, so
those assertions compare the fields it defines and allow this implementation's
additional provenance fields.  Divergences are documented in the README.
"""
import pytest

from permdiff import Graph, diff_graphs
from permdiff.differ import is_empty_doc


@pytest.fixture(scope="module")
def golden(base_doc, head_doc):
    res = diff_graphs(Graph(base_doc, "base"), Graph(head_doc, "head"),
                      base_ref="main", head_ref="pr-1-star-policy")
    return res.doc


def _project(entry, keys):
    return {k: entry[k] for k in keys}


def test_structural_section_matches_exactly(golden, expected_diff):
    assert golden["structural"] == expected_diff["structural"]


def test_refs_and_graph_digests(golden, expected_diff):
    assert golden["base"] == expected_diff["base"]
    assert golden["head"] == expected_diff["head"]
    assert golden["schema_version"] == expected_diff["schema_version"]


def test_stats_match(golden, expected_diff):
    for k, v in expected_diff["stats"].items():
        assert golden["stats"][k] == v, k
    assert golden["stats"]["merkle"]["enabled"] and golden["stats"]["merkle"]["verified"]


def test_capabilities_match_in_substance(golden, expected_diff):
    keys = ("principal", "actions", "resource_patterns", "confidence")
    for op in ("added", "removed"):
        got = [_project(c, keys) for c in golden["semantic"]["capabilities"][op]]
        want = expected_diff["semantic"]["capabilities"][op]
        assert got == want, op
    # provenance this implementation adds on top of the hand-authored answer
    added = golden["semantic"]["capabilities"]["added"][0]
    assert added["wildcard"] is True
    assert added["via_policies"] == ["aws:111122223333:us-east-1/aws_iam_policy.app_data"]
    assert added["expanded_action_count"] > 100
    removed = golden["semantic"]["capabilities"]["removed"][0]
    assert removed["superseded_by"]["actions"] == ["s3:*"], \
        "the 'removal' is a widening, and the document says so"


def test_paths_unchanged(golden, expected_diff):
    assert golden["semantic"]["paths"] == expected_diff["semantic"]["paths"]


def test_single_finding_matches_in_substance(golden, expected_diff):
    assert len(golden["findings"]) == len(expected_diff["findings"]) == 1
    got, want = golden["findings"][0], expected_diff["findings"][0]
    assert got["rank"] == want["rank"] == 1
    assert got["severity"] == want["severity"]
    assert got["kind"] == want["kind"] == "wildcard_capability_added"
    assert set(want["node_ids"]) <= set(got["node_ids"])
    assert "s3:*" in got["title"] and "all resources" in got["title"]
    # detail carries the same substance: statement, before, after
    for token in ("aws_iam_policy.app_data", "ReadData", "s3:GetObject", "s3:ListBucket", "s3:*"):
        assert token in got["detail"], token
    # no spurious "removal" finding for the superseded narrower grant
    assert not any(f["kind"] == "capability_removed" for f in golden["findings"])
    assert not any(f["kind"] == "structural_churn" for f in golden["findings"]), \
        "the changed edge is explained by the capability finding"


def test_unevaluated_matches_in_substance(golden, expected_diff):
    got = sorted((u["edge_id"], tuple(u["reasons"])) for u in golden["unevaluated"])
    want = sorted((u["edge_id"], tuple(u["reasons"])) for u in expected_diff["unevaluated"])
    assert got == want
    for u in golden["unevaluated"]:
        assert u["note"]


def test_golden_is_not_empty(golden):
    assert golden["empty"] is False
    assert not is_empty_doc(golden)
