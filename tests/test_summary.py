from osint.models import ProviderResult, ResultStatus, Verdict
from osint.orchestrator import compute_rollup
from osint.summary import tlp_prefix, render_summary


def test_tlp_prefix_normalizes():
    assert tlp_prefix("amber") == "TLP:AMBER"
    assert tlp_prefix("TLP:RED") == "TLP:RED"
    assert tlp_prefix("nope") == "TLP:CLEAR"
    assert tlp_prefix(None) == "TLP:CLEAR"


def test_rollup_consensus_independent_tags():
    results = [
        ProviderResult(
            provider="a",
            provider_name="A",
            status=ResultStatus.OK,
            verdict=Verdict.MALICIOUS,
            tags=["emotet", "c2"],
        ),
        ProviderResult(
            provider="b",
            provider_name="B",
            status=ResultStatus.OK,
            verdict=Verdict.MALICIOUS,
            tags=["emotet"],
        ),
        ProviderResult(
            provider="c",
            provider_name="C",
            status=ResultStatus.OK,
            verdict=Verdict.INFO,
            tags=["resolver"],
        ),
    ]
    roll = compute_rollup(results, {})
    assert any("emotet" in x for x in roll.consensus)
    assert not any("resolver" in x for x in roll.consensus)
    assert roll.malicious == 2


def test_render_summary_unknown_lookup_is_emptyish():
    text = render_summary("does-not-exist", tlp="GREEN")
    assert text.startswith("TLP:GREEN")
