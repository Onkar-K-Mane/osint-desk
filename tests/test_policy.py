from osint.detect import classify_one
from osint.policy import evaluate


def test_private_ip_blocked():
    ind = classify_one("10.0.0.8")
    d = evaluate(ind)
    assert d.allow_external is False
    assert "private" in (d.reason or "")


def test_loopback_blocked():
    d = evaluate(classify_one("127.0.0.1"))
    assert d.allow_external is False


def test_doc_domain_blocked():
    d = evaluate(classify_one("example.com"))
    assert d.allow_external is False


def test_google_lightweight():
    d = evaluate(classify_one("google.com"))
    assert d.allow_external is True
    assert d.lightweight is True


def test_private_ip_no_external_deeplink():
    from osint.orchestrator import deeplink_for
    from osint.registry import get_registry
    from osint.policy import evaluate
    from osint.detect import classify_one

    ind = classify_one("192.168.1.1")
    assert evaluate(ind).allow_external is False
    spec = get_registry().get("talos")
    assert spec is not None
    url = deeplink_for(spec, ind)
    assert "192.168.1.1" in url


def test_email_has_domain():
    from osint.detect import classify_one

    ind = classify_one("alice@example.com")
    assert ind is not None
    assert ind.email_domain == "example.com"


