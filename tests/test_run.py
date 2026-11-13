import json
from datetime import datetime, timezone

from collector.log_collector import parse_line
from database.db import count_rows
from demo.generate_demo import build_log, prepare_demo
from run import describe, pipeline_once

NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)

NEW_RULES = {"dictionary_attack", "connection_flood", "download_and_execute", "distributed_attack"}


def test_demo_log_is_valid_cowrie_format():
    lines, ips = build_log(NOW)
    events = [parse_line(l) for l in lines]
    assert all(events)                                     # every line is usable by the collector
    assert {e["event_type"] for e in events} == {
        "connect", "login_failed", "login_success", "command", "session_closed"}
    assert len({e["event_id"] for e in events}) == len(events)   # no accidental duplicates
    assert "192.168.56.20" in ips                          # the lab's attacker VM
    assert any(e["duration_s"] for e in events if e["event_type"] == "session_closed")


def test_demo_log_is_deterministic():
    assert build_log(NOW, seed=3) == build_log(NOW, seed=3)


def test_demo_triggers_every_rule_including_new_ones(tmp_path):
    prepare_demo(tmp_path, now=NOW)
    import sqlite3
    found = {r[0] for r in sqlite3.connect(tmp_path / "demo.db").execute(
        "SELECT DISTINCT alert_type FROM alerts")}
    assert NEW_RULES <= found
    assert {"brute_force", "rapid_attack", "password_spraying", "username_enumeration",
            "repeated_attacks", "success_after_failures", "suspicious_commands"} <= found


def test_demo_geo_has_map_points_and_a_lan_attacker(tmp_path):
    from analysis.statistics import load_attacks, load_geo, geo_summary
    r = prepare_demo(tmp_path, now=NOW)
    g = geo_summary(load_attacks(r["db"]), load_geo(r["db"]))
    assert len(g["points"]) >= 10 and g["private"]["ips"] == 1 and g["unlocated"]["ips"] == 0


def test_pipeline_once_end_to_end_and_repeatable(tmp_path):
    from demo.generate_demo import write_demo_files
    log, _ = write_demo_files(tmp_path / "d", now=NOW)
    kw = dict(log_path=log, state_path=tmp_path / "state.json", db_path=tmp_path / "t.db",
              use_geo=False)
    first = pipeline_once(**kw)
    assert first["ingest"]["new"] > 100 and first["detect"]["new_alerts"] > 10
    second = pipeline_once(**kw)                           # nothing new in the log
    assert second["ingest"]["new"] == 0 and second["detect"]["new_alerts"] == 0
    assert count_rows(tmp_path / "t.db")["alerts"] == first["detect"]["new_alerts"]
    assert "new events" in describe(first)


def test_pipeline_survives_missing_log(tmp_path):
    res = pipeline_once(log_path=tmp_path / "nope.json", state_path=tmp_path / "s.json",
                        db_path=tmp_path / "t.db", use_geo=False)
    assert res["ingest"] is None and "not found" in res["warning"]
    assert res["detect"]["alerts_found"] == 0              # still ran, just empty


def test_geo_off_still_classifies_private_ips(tmp_path, monkeypatch):
    """--no-geo must not leak anything, yet the LAN attacker is still labelled offline."""
    from demo.generate_demo import write_demo_files
    from analysis.statistics import load_geo
    monkeypatch.setenv("SENTINEL_GEO", "off")
    log, _ = write_demo_files(tmp_path / "d", now=NOW)
    res = pipeline_once(log_path=log, state_path=tmp_path / "s.json", db_path=tmp_path / "t.db")
    assert res["geo"]["private"] == 16 and res["geo"]["located"] == 0      # offline, nothing sent
    assert set(load_geo(tmp_path / "t.db")["is_private"]) == {1}

