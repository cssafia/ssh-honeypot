import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from database.db import init_db, transaction
from run import pipeline_once
from siem.forward import forward_new_alerts, parse_target, to_cef, to_syslog


def add_alert(db, n=1, severity="high", desc="5 failed logins | in 60s = test", ip="203.0.113.7"):
    init_db(db)
    with transaction(db) as conn:
        for i in range(n):
            conn.execute(
                "INSERT INTO alerts (source_ip, alert_type, severity, description, created_at, dedup_key) "
                "VALUES (?,?,?,?,?,?)",
                (ip, "brute_force", severity, desc, "2026-11-15T10:00:00Z", f"k{i}-{desc}-{severity}"))


def test_parse_targets():
    assert parse_target("syslog://10.0.0.5")["port"] == 514
    t = parse_target("syslog+tcp://siem.lan:6514")
    assert (t["proto"], t["port"], t["host"]) == ("tcp", 6514, "siem.lan")
    assert parse_target("http://h:8088/x")["kind"] == "http"
    assert parse_target("file:/tmp/a.json")["path"] == "/tmp/a.json"
    for bad in ("", "ftp://x", "syslog://", "file:"):
        with pytest.raises(ValueError):
            parse_target(bad)


def test_cef_format_and_escaping():
    a = {"id": 7, "source_ip": "203.0.113.7", "alert_type": "brute_force", "severity": "critical",
         "description": "a|b=c\nline2", "created_at": "2026-11-15T10:00:00Z", "country": "China"}
    cef = to_cef(a)
    assert cef.startswith("CEF:0|SSHSentinel|SSHSentinel|1.0|brute_force|brute force|10|")
    assert "src=203.0.113.7" in cef and "cs1=China" in cef
    assert "a|b\\=c\\nline2" in cef                    # '=' and newline escaped in the extension
    assert "\n" not in cef
    assert to_syslog(a).startswith("<" + str(20 * 8 + 2) + ">1 ")      # local4.crit


def test_file_target_writes_json_lines_once(tmp_path):
    db, out = tmp_path / "t.db", tmp_path / "alerts.json"
    add_alert(db, 3)
    assert forward_new_alerts(db, f"file:{out}")["sent"] == 3
    assert forward_new_alerts(db, f"file:{out}")["sent"] == 0       # nothing is sent twice
    lines = [json.loads(l) for l in out.read_text().splitlines()]
    assert len(lines) == 3 and lines[0]["alert_type"] == "brute_force"
    assert "password" not in out.read_text().lower()
    add_alert(db, 1, severity="low", desc="later")                    # only the new one goes out
    assert forward_new_alerts(db, f"file:{out}")["sent"] == 1


def test_udp_syslog(tmp_path):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0)); srv.settimeout(3)
    port = srv.getsockname()[1]
    db = tmp_path / "t.db"; add_alert(db, 2)
    assert forward_new_alerts(db, f"syslog://127.0.0.1:{port}")["sent"] == 2
    msgs = [srv.recvfrom(65535)[0].decode() for _ in range(2)]
    assert all("CEF:0|SSHSentinel" in m and "src=203.0.113.7" in m for m in msgs)
    srv.close()


def test_tcp_syslog(tmp_path):
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); srv.settimeout(3)
    port = srv.getsockname()[1]; got = []

    def accept():
        c, _ = srv.accept()
        with c, c.makefile("r") as f:
            got.extend(f.readlines())
    th = threading.Thread(target=accept); th.start()
    db = tmp_path / "t.db"; add_alert(db, 1)
    assert forward_new_alerts(db, f"syslog+tcp://127.0.0.1:{port}")["sent"] == 1
    th.join(3); srv.close()
    assert len(got) == 1 and "CEF:0" in got[0]


def test_http_webhook_with_auth_header(tmp_path, monkeypatch):
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append((self.headers.get("Authorization"), json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.send_response(200); self.end_headers()

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("SENTINEL_SIEM_AUTH", "Splunk abc")
    db = tmp_path / "t.db"; add_alert(db, 2)
    assert forward_new_alerts(db, f"http://127.0.0.1:{srv.server_port}/ev")["sent"] == 2
    srv.shutdown()
    assert seen[0][0] == "Splunk abc" and seen[0][1]["product"] == "ssh-sentinel"


def test_siem_down_never_raises_and_alerts_are_retried(tmp_path):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()   # nothing listens
    db = tmp_path / "t.db"; add_alert(db, 2)
    r = forward_new_alerts(db, f"syslog+tcp://127.0.0.1:{port}")
    assert r["sent"] == 0 and r["failed"] == 2 and r["error"]
    srv = socket.socket(); srv.bind(("127.0.0.1", port)); srv.listen(5); srv.settimeout(3)
    got = []

    def accept():
        c, _ = srv.accept()
        with c, c.makefile("r") as f:
            got.extend(f.readlines())
    th = threading.Thread(target=accept); th.start()
    assert forward_new_alerts(db, f"syslog+tcp://127.0.0.1:{port}")["sent"] == 2   # came back online
    th.join(3); srv.close()
    assert len(got) == 2


def test_bad_target_is_reported_not_raised(tmp_path):
    db = tmp_path / "t.db"; add_alert(db)
    r = forward_new_alerts(db, "nonsense")
    assert r["sent"] == 0 and "unknown SIEM target" in r["error"]


def test_pipeline_forwards_alerts(tmp_path):
    from demo.generate_demo import prepare_demo
    r = prepare_demo(str(tmp_path / "demo"))
    out = tmp_path / "siem.json"
    res = pipeline_once(str(tmp_path / "none.json"), str(tmp_path / "st.json"), str(r["db"]),
                        use_geo=False, siem=f"file:{out}")
    assert res["siem"]["sent"] > 0
    first = json.loads(out.read_text().splitlines()[0])
    assert first["source_ip"] and first["severity"]
