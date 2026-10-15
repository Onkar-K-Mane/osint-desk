from osint.models import ParsedResult, ResultStatus, Verdict
from osint.registry import SourceSpec, VerdictConfig
from osint.models import IndicatorType
from osint.verdict import map_verdict


def spec(style, mal=None, sus=None):
    return SourceSpec(
        id="x",
        name="x",
        types={IndicatorType.IP},
        mode="api",
        verdict=VerdictConfig(style=style, malicious_at=mal, suspicious_at=sus),
    )


def test_reputation_no_reports_is_unknown():
    p = ParsedResult(score=0)
    v = map_verdict(spec("reputation", 75, 25), p, ResultStatus.OK)
    assert v == Verdict.UNKNOWN


def test_reputation_thresholds():
    v = map_verdict(spec("reputation", 75, 25), ParsedResult(score=80), ResultStatus.OK)
    assert v == Verdict.MALICIOUS
    v = map_verdict(spec("reputation", 75, 25), ParsedResult(score=40), ResultStatus.OK)
    assert v == Verdict.SUSPICIOUS


def test_allowlist():
    v = map_verdict(spec("allowlist"), ParsedResult(allowlist_hit=True), ResultStatus.OK)
    assert v == Verdict.BENIGN
    v = map_verdict(spec("allowlist"), ParsedResult(allowlist_hit=False), ResultStatus.OK)
    assert v == Verdict.UNKNOWN


def test_informational():
    v = map_verdict(spec("informational"), ParsedResult(score=99), ResultStatus.OK)
    assert v == Verdict.INFO


def test_non_ok_has_no_verdict():
    v = map_verdict(spec("reputation", 1, 1), ParsedResult(score=99), ResultStatus.ERROR)
    assert v is None
