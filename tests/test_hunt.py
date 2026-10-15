from osint.detect import extract_indicators, classify_one
from osint.hunt import hunt_pack


def test_hunt_pack_skips_private_ip():
    inds = [classify_one("10.0.0.8"), classify_one("8.8.8.8")]
    inds = [i for i in inds if i]
    pack = hunt_pack(inds)
    assert "8.8.8.8" in pack["splunk"]
    assert "10.0.0.8" not in pack["splunk"]
    assert pack["skipped_private"] == 1
    assert pack["counts"]["ip"] == 1


def test_hunt_pack_blob():
    blob = """
    From: bad@not-example.org
    URL: hxxp://malware[.]not-example[.]org/gate.php
    IP: 8.8.8.8
    Hash: 44d88612fea8a8f36de82e1278abb02f
    """
    pack = hunt_pack(extract_indicators(blob))
    assert pack["counts"]["ip"] >= 1
    assert pack["counts"]["hash"] >= 1
    assert pack["kql"]
    assert pack["elastic"]
    assert "ip\t" in pack["defanged"]
