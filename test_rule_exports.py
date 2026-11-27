import hashlib
import sqlite3
from xml.etree import ElementTree

import pytest
import yara
from fastapi.testclient import TestClient
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

from app.engines.soc_generator import generate_blue_team_arsenal
from app.main import app


@pytest.mark.parametrize("encoding", ["ascii", "utf-16le"])
def test_hostname_yara_token_boundaries(encoding):
    rules = generate_blue_team_arsenal("portal.example")
    compiled = yara.compile(source=rules["yara_rule"])
    for text in ("portal.example", "https://PORTAL.EXAMPLE./help"):
        assert compiled.match(data=text.encode(encoding))
    for text in ("sub.portal.example", "portal.example.org", "not-portal.example", "portal.example2"):
        assert not compiled.match(data=text.encode(encoding))
    assert ElementTree.fromstring(rules["wazuh_rule"]).find("rule/field").get("name") == "dns.question.name"


@pytest.mark.parametrize(("host", "field", "values", "hits"), [
    ("portal.example", "QueryName", ["portal.example", "PORTAL.EXAMPLE.", "sub.portal.example", "portal.example.org"], [1, 2]),
    ("1.1.1.1", "DestinationIp", ["1.1.1.1", "1.1.1.10"], [1]),
    ("2606:4700:4700::1111", "DestinationIp", ["2606:4700:4700::1111", "2606:4700:4700::1112"], [1]),
])
def test_sigma_hunts_execute_against_mapped_events(host, field, values, hits):
    sigma = SigmaCollection.from_yaml(generate_blue_team_arsenal(host)["sigma_rule"])
    assert sigma.rules[0].logsource.product == "windows"
    query, = sqliteBackend().convert(sigma)
    with sqlite3.connect(":memory:") as db:
        db.execute(f"CREATE TABLE logs (id INTEGER PRIMARY KEY, {field} TEXT COLLATE NOCASE)")
        db.executemany(f"INSERT INTO logs ({field}) VALUES (?)", [(v,) for v in values])
        assert [row[0] for row in db.execute(query)] == hits


@pytest.mark.parametrize("algorithm", ["md5", "sha1", "sha256"])
@pytest.mark.parametrize("status", ["Match", "No record", "Auth rejected"])
def test_hash_case_matches_file_and_process_telemetry(monkeypatch, algorithm, status):
    sample = b"PhishMatrix harmless fixture"
    digest = hashlib.new(algorithm, sample).hexdigest()

    async def lookup(client, target):
        assert target == digest
        return {"status": status, "scope": "hash"}

    monkeypatch.setattr("app.main.malshare_lookup", lookup)
    case = TestClient(app).post("/api/v1/hash-lookup", json={"hash": digest.upper()}).json()
    event = case["siem_event"]
    assert (event["event"]["id"], event["@timestamp"]) == (case["case_id"], case["timestamp"])
    assert event["file"]["hash"] == {algorithm: digest}
    assert case["status"] == status
    assert case["verdict"] == ("SUSPICIOUS" if status == "Match" else "INCONCLUSIVE")
    rules = case["soc_arsenal"]
    compiled = yara.compile(source=rules["yara_hash"])
    assert compiled.match(data=sample)
    assert not compiled.match(data=sample + b".")
    query, = sqliteBackend().convert(SigmaCollection.from_yaml(rules["sigma_process_hash"]))
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs (Hashes TEXT)")
        db.executemany("INSERT INTO logs VALUES (?)", [(f"{algorithm.upper()}={digest}",), ("other",)])
        assert len(db.execute(query).fetchall()) == 1


@pytest.mark.parametrize("foreign", [True, False])
def test_offline_cases_and_shared_hosting(foreign):
    other = "bravo" if foreign else "alpha"
    html = f'<form action="https://{other}.github.io/login"><input type="password"></form>'
    case = TestClient(app).post("/api/v1/html-scan", json={"html": html, "url":"https://alpha.github.io/"}).json()
    assert ("HTML_CROSS_ORIGIN_FORM" in case["siem_event"]["phishmatrix"]["rule_ids"]) == foreign
    assert ("sigma_case" in case["soc_arsenal"]) == foreign
    assert case["siem_event"]["related"]["hosts"] == ["alpha.github.io"]
    if foreign:
        rule = SigmaCollection.from_yaml(case["soc_arsenal"]["sigma_case"]).rules[0]
        assert rule.logsource.product == "phishmatrix"
    assert yara.compile(source=case["soc_arsenal"]["yara_hash"]).match(data=html.encode())


def test_email_export_correlates_without_creating_sender_ioc():
    raw = "From: user@alpha.example\r\nSubject: sample\r\n\r\nHello"
    case = TestClient(app).post("/api/v1/email-scan", json={"raw_email": raw}).json()
    assert case["siem_event"]["phishmatrix"]["artifact_type"] == "email"
    assert "related" not in case["siem_event"]
    assert set(case["soc_arsenal"]) == {"yara_hash"}
    compiled = yara.compile(source=case["soc_arsenal"]["yara_hash"])
    assert compiled.match(data=raw.encode())
    assert not compiled.match(data=raw.replace("\r\n", "\n").encode())
