import json

from osint.models import Indicator, IndicatorType, RawResponse, ResultStatus, Verdict
from osint.providers.abuseipdb import AbuseIPDB
from osint.providers.hashlookup import Hashlookup
from osint.providers.internetdb import InternetDB
from osint.providers.malwarebazaar import MalwareBazaar
from osint.providers.ipqualityscore import IPQualityScore
from osint.providers.hunter import Hunter
from osint.providers.hybrid_analysis import HybridAnalysis
from osint.verdict import map_verdict
from osint.registry import get_registry


def _ind_ip(v="203.0.113.7"):
    return Indicator(type=IndicatorType.IP, value=v, original=v)


def test_abuseipdb_fixture():
    raw = RawResponse(
        status_code=200,
        body=json.dumps(
            {
                "data": {
                    "abuseConfidenceScore": 87,
                    "totalReports": 214,
                    "isp": "Example Hosting",
                    "countryCode": "XX",
                    "usageType": "Data Center",
                    "lastReportedAt": "2026-09-19T00:00:00Z",
                }
            }
        ).encode(),
    )
    parsed = AbuseIPDB().parse(raw, _ind_ip())
    assert parsed.score == 87
    spec = get_registry().get("abuseipdb")
    assert map_verdict(spec, parsed, ResultStatus.OK).value == "malicious"


def test_internetdb_fixture():
    raw = RawResponse(
        status_code=200,
        body=json.dumps(
            {"ip": "8.8.8.8", "ports": [53, 443], "hostnames": ["dns.google"], "tags": [], "vulns": []}
        ).encode(),
    )
    parsed = InternetDB().parse(raw, _ind_ip("8.8.8.8"))
    assert "53" in parsed.summary
    assert any(r.value == "dns.google" for r in parsed.related)


def test_hashlookup_miss_is_unknown_not_clean():
    raw = RawResponse(status_code=404, body=b"Non existing hash")
    parsed = Hashlookup().parse(raw, Indicator(type=IndicatorType.HASH, value="ab" * 16, original="ab" * 16, hash_algo="md5"))
    assert parsed.allowlist_hit is False
    spec = get_registry().get("hashlookup")
    v = map_verdict(spec, parsed, parsed.status)
    assert v.value == "unknown"


def test_hashlookup_hit_is_benign():
    raw = RawResponse(
        status_code=200,
        body=json.dumps({"FileName": "notepad.exe", "Product": "Windows", "hashlookup:trust": 100}).encode(),
    )
    parsed = Hashlookup().parse(
        raw, Indicator(type=IndicatorType.HASH, value="aa" * 16, original="aa" * 16, hash_algo="md5")
    )
    assert parsed.allowlist_hit is True
    spec = get_registry().get("hashlookup")
    assert map_verdict(spec, parsed, ResultStatus.OK).value == "benign"


def test_malwarebazaar_not_found():
    raw = RawResponse(status_code=200, body=json.dumps({"query_status": "hash_not_found"}).encode())
    parsed = MalwareBazaar().parse(
        raw, Indicator(type=IndicatorType.HASH, value="ab" * 16, original="x", hash_algo="md5")
    )
    assert parsed.score == 0.0
    assert "unknown" in parsed.summary.lower()


def test_ipqs_fraud_score():
    raw = RawResponse(
        status_code=200,
        body=json.dumps(
            {"success": True, "fraud_score": 92, "proxy": True, "vpn": False, "isp": "Example"}
        ).encode(),
    )
    parsed = IPQualityScore().parse(raw, _ind_ip())
    assert parsed.score == 92
    assert "proxy" in parsed.tags


def test_hunter_domain_facts():
    raw = RawResponse(
        status_code=200,
        body=json.dumps({"data": {"organization": "Example Co", "pattern": "{first}.{last}", "emails": [1, 2]}}).encode(),
    )
    parsed = Hunter().parse(
        raw, Indicator(type=IndicatorType.DOMAIN, value="example.com", original="example.com")
    )
    assert "Example Co" in parsed.summary
    assert any(f.label == "Organization" for f in parsed.facts)


def test_hybrid_empty_is_not_found():
    raw = RawResponse(status_code=200, body=json.dumps([]).encode())
    parsed = HybridAnalysis().parse(
        raw, Indicator(type=IndicatorType.HASH, value="ab" * 16, original="x", hash_algo="md5")
    )
    assert parsed.status == ResultStatus.NOT_FOUND
