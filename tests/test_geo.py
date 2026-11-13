import itertools

import pytest

from analysis.statistics import geo_summary, load_attacks, load_geo, summary
from backend.app import create_app
from database.db import get_connection, init_db, insert_events
from geo.geolocate import PRIVATE_LABEL, enrich, is_private, seed_geo

_n = itertools.count()


def ev(ip, etype="login_failed", ts="2026-11-05T10:00:00Z"):
    return {"event_id": f"g{next(_n)}", "event_type": etype, "timestamp": ts,
            "source_ip": ip, "session_id": f"s-{ip}", "username": "root",
            "password_masked": "p***", "password_hash": "h", "command": None,
            "duration_s": None}


PARIS = {"country": "France", "country_code": "FR", "city": "Paris", "lat": 48.85, "lon": 2.35}


def fake_provider(calls):
    def provider(ips):
        calls.append(list(ips))
        return {ip: (PARIS if ip == "8.8.8.8" else None) for ip in ips}
    return provider


def test_is_private():
    for ip in ("192.168.56.20", "10.0.0.5", "127.0.0.1", "172.16.0.9", "not-an-ip"):
        assert is_private(ip)
    assert not is_private("8.8.8.8")


def test_enrich_private_needs_no_network(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    insert_events([ev("192.168.56.20")], db)

    def must_not_be_called(ips):
        raise AssertionError("network used for a private IP")

    r = enrich(db, provider=must_not_be_called)
    assert r["private"] == 1
    row = get_connection(db).execute("SELECT * FROM ip_geo").fetchone()
    assert row["is_private"] == 1 and row["country"] == PRIVATE_LABEL


def test_enrich_caches_and_handles_unknown(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    insert_events([ev("8.8.8.8"), ev("9.9.9.9")], db)
    calls = []
    r = enrich(db, provider=fake_provider(calls))
    assert r["located"] == 1 and r["unknown"] == 1
    enrich(db, provider=fake_provider(calls))
    assert len(calls) == 1                       # second run: everything cached


def test_enrich_survives_network_failure_and_retries(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    insert_events([ev("8.8.8.8")], db)

    def offline(ips):
        raise OSError("no internet")

    r = enrich(db, provider=offline)
    assert r["pending"] == 1 and r["located"] == 0
    assert load_geo(db).empty                    # nothing cached, so it is retried later
    assert enrich(db, provider=fake_provider([]))["located"] == 1


def test_geo_can_be_switched_off(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    init_db(db)
    insert_events([ev("8.8.8.8"), ev("192.168.1.5")], db)
    monkeypatch.setenv("SENTINEL_GEO", "off")
    r = enrich(db)
    assert r["skipped"] and r["private"] == 1 and r["pending"] == 1


def test_geo_summary_groups_countries_private_and_unlocated(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    insert_events([ev("8.8.8.8"), ev("8.8.8.8"), ev("1.2.3.4"), ev("192.168.56.20"),
                   ev("5.6.7.8")], db)
    seed_geo({"8.8.8.8": PARIS, "1.2.3.4": PARIS}, db)
    enrich(db, provider=lambda ips: {})          # classifies the private IP; 5.6.7.8 -> unknown
    g = geo_summary(load_attacks(db), load_geo(db))
    assert g["countries"] == [{"country": "France", "country_code": "FR", "events": 3,
                               "failed_logins": 3, "ips": 2}]
    assert {p["ip"] for p in g["points"]} == {"8.8.8.8", "1.2.3.4"}
    assert g["private"] == {"ips": 1, "events": 1, "failed_logins": 1}
    assert g["unlocated"]["ips"] == 1


def test_summary_works_with_no_geo_rows(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    insert_events([ev("8.8.8.8")], db)
    s = summary(db)
    assert s["geo"]["points"] == [] and s["geo"]["unlocated"]["ips"] == 1
    assert s["top_ips"][0]["country"] == "-"


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "t.db"
    app = create_app(db)
    insert_events([ev("8.8.8.8"), ev("192.168.56.20")], db)
    seed_geo({"8.8.8.8": PARIS}, db)
    enrich(db, provider=lambda ips: {})
    return app.test_client()


def test_geo_endpoint_and_filters(client):
    j = client.get("/api/geo").get_json()
    assert j["countries"][0]["country"] == "France" and j["private"]["ips"] == 1
    only = client.get("/api/geo?ip=192.168.56.20").get_json()
    assert only["points"] == [] and only["private"]["ips"] == 1
    assert client.get("/api/geo?ip=bad").status_code == 400


def test_attackers_endpoint_includes_country(client):
    rows = client.get("/api/attackers").get_json()
    by_ip = {r["source_ip"]: r["country"] for r in rows}
    assert by_ip == {"8.8.8.8": "France", "192.168.56.20": PRIVATE_LABEL}
