from osint.detect import classify_one, extract_indicators
from osint.defang import refang, defang
from osint.models import IndicatorType


def test_refang_url():
    assert "http://evil.example.com/a" in refang("hxxp://evil[.]example[.]com/a")
    assert refang("foo[.]bar(.)baz") == "foo.bar.baz"
    assert refang("user[@]evil[.]com") == "user@evil.com"
    assert refang("host[:]8443") == "host:8443"


def test_classify_ip():
    ind = classify_one("203.0.113.7")
    assert ind and ind.type == IndicatorType.IP and ind.value == "203.0.113.7"
    ind = classify_one("2001:db8::1")
    assert ind and ind.type == IndicatorType.IP


def test_classify_hash_vs_domain():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    ind = classify_one(md5)
    assert ind and ind.type == IndicatorType.HASH and ind.hash_algo == "md5"
    ind = classify_one("evil.example.com")
    # example.com is a real PSL domain
    assert ind and ind.type == IndicatorType.DOMAIN


def test_classify_email_subaddress():
    ind = classify_one("Alice+alerts@Example.COM")
    assert ind and ind.type == IndicatorType.EMAIL
    assert ind.value.startswith("alice+alerts@")
    assert ind.email_domain == "example.com"


def test_classify_url_without_scheme():
    ind = classify_one("evil.example.com/login")
    assert ind and ind.type == IndicatorType.URL
    assert ind.url_host == "evil.example.com"


def test_classify_defanged_url():
    inds = extract_indicators("hxxp://malware[.]example[.]com/gate.php")
    assert len(inds) == 1
    assert inds[0].type == IndicatorType.URL
    assert "malware.example.com" in inds[0].value


def test_punycode():
    ind = classify_one("bücher.de")
    assert ind and ind.type == IndicatorType.DOMAIN
    assert ind.value.startswith("xn--")


def test_blob_extract():
    blob = """
    From: bad@evil.example.com
    URL: hxxp://malware[.]example[.]com/gate.php
    IP: 203[.]0[.]113[.]7
    Hash: 44d88612fea8a8f36de82e1278abb02f
    """
    inds = extract_indicators(blob)
    types = {i.type for i in inds}
    assert IndicatorType.EMAIL in types
    assert IndicatorType.URL in types
    assert IndicatorType.IP in types
    assert IndicatorType.HASH in types


def test_defang_display():
    assert "[.]" in defang("203.0.113.7")
    assert "[@]" in defang("a@b.com")
