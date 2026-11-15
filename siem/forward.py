"""Forward SSH Sentinel alerts to a SIEM (Wazuh, Splunk, Graylog, Elastic, QRadar...).

Targets (one string, passed with --siem or SENTINEL_SIEM):

    syslog://HOST[:PORT]        syslog over UDP, CEF payload     (default port 514)
    syslog+tcp://HOST[:PORT]    syslog over TCP, CEF payload
    http://HOST/path            POST one JSON document per alert (also https://)
    file:/path/alerts.json      append one JSON object per line (Filebeat / Wazuh can tail it)

Rules of the game:
  * every alert is sent once per target (tracked in the siem_sent table);
  * sending never raises: if the SIEM is down the alert stays "unsent" and is retried
    on the next cycle, and the rest of the project keeps working;
  * passwords are never sent (the database only holds masked values anyway).
"""
import json
import logging
import os
import socket
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

from database.db import DEFAULT_DB, init_db, transaction

log = logging.getLogger("siem")

TIMEOUT_S = 3
BATCH = 200                                            # max alerts sent per cycle
CEF_SEVERITY = {"low": 3, "medium": 5, "high": 8, "critical": 10}
SYSLOG_SEVERITY = {"low": 6, "medium": 5, "high": 4, "critical": 2}   # info, notice, warning, crit
FACILITY = 20                                          # local4


# ------------------------------------------------------------------ target
def parse_target(text: str) -> dict:
    t = (text or "").strip()
    if not t:
        raise ValueError("empty SIEM target")
    if t.startswith("file:"):
        path = t[len("file:"):]
        if path.startswith("//"):
            path = path[2:]
        if not path:
            raise ValueError("file target needs a path, e.g. file:/tmp/alerts.json")
        return {"kind": "file", "path": path, "text": t}
    u = urlparse(t)
    if u.scheme in ("syslog", "syslog+tcp", "syslog+udp"):
        if not u.hostname:
            raise ValueError("syslog target needs a host, e.g. syslog://192.168.1.50:514")
        return {"kind": "syslog", "host": u.hostname, "port": u.port or 514,
                "proto": "tcp" if u.scheme == "syslog+tcp" else "udp", "text": t}
    if u.scheme in ("http", "https") and u.hostname:
        return {"kind": "http", "url": t, "text": t}
    raise ValueError(f"unknown SIEM target {t!r}. Use syslog://, syslog+tcp://, http(s):// or file:")


# ------------------------------------------------------------------ formats
def _cef_header(v) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _cef_ext(v) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "")


def _epoch_ms(iso: str) -> int:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except (ValueError, AttributeError):
        return 0


def to_cef(a: dict) -> str:
    """ArcSight Common Event Format, understood by nearly every SIEM."""
    head = "|".join(_cef_header(x) for x in (
        "CEF:0", "SSHSentinel", "SSHSentinel", "1.0",
        a["alert_type"], a["alert_type"].replace("_", " "), CEF_SEVERITY.get(a["severity"], 5)))
    ext = {
        "src": a["source_ip"], "rt": _epoch_ms(a["created_at"]), "msg": a["description"],
        "externalId": a["id"], "cs1Label": "country", "cs1": a.get("country") or "unknown",
        "cs2Label": "status", "cs2": a.get("status", "open"),
    }
    return head + "|" + " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items())


def to_json(a: dict) -> dict:
    return {
        "product": "ssh-sentinel", "id": a["id"], "alert_type": a["alert_type"],
        "severity": a["severity"], "source_ip": a["source_ip"],
        "country": a.get("country"), "city": a.get("city"),
        "description": a["description"], "created_at": a["created_at"],
        "status": a.get("status", "open"),
    }


def to_syslog(a: dict) -> str:
    """RFC 5424 envelope around the CEF text."""
    pri = FACILITY * 8 + SYSLOG_SEVERITY.get(a["severity"], 5)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    host = socket.gethostname().replace(" ", "-") or "-"
    return f"<{pri}>1 {stamp} {host} ssh-sentinel - - - {to_cef(a)}"


# ------------------------------------------------------------------ sending
def _send_file(t, alerts, ok):
    with open(t["path"], "a", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(to_json(a), ensure_ascii=False) + "\n")
            f.flush()
            ok(a)


def _send_http(t, alerts, ok):
    headers = {"Content-Type": "application/json"}
    auth = os.environ.get("SENTINEL_SIEM_AUTH")        # e.g. "Splunk <hec-token>" or "Bearer <token>"
    if auth:
        headers["Authorization"] = auth
    for a in alerts:
        req = urllib.request.Request(t["url"], json.dumps(to_json(a)).encode(), headers, method="POST")
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            if r.status >= 300:
                raise OSError(f"SIEM answered HTTP {r.status}")
        ok(a)


def _send_syslog(t, alerts, ok):
    if t["proto"] == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for a in alerts:
                sock.sendto(to_syslog(a).encode("utf-8"), (t["host"], t["port"]))
                ok(a)
        finally:
            sock.close()
        return
    with socket.create_connection((t["host"], t["port"]), timeout=TIMEOUT_S) as sock:   # one connection per cycle
        for a in alerts:
            sock.sendall(to_syslog(a).encode("utf-8") + b"\n")
            ok(a)


_SENDERS = {"file": _send_file, "http": _send_http, "syslog": _send_syslog}


def _unsent(db_path, key, limit):
    with transaction(db_path) as conn:
        rows = conn.execute(
            """SELECT a.id, a.source_ip, a.alert_type, a.severity, a.description,
                      a.created_at, a.status, g.country, g.city
               FROM alerts a
               LEFT JOIN ip_geo g ON g.ip = a.source_ip
               WHERE a.id NOT IN (SELECT alert_id FROM siem_sent WHERE target = ?)
               ORDER BY a.id LIMIT ?""", (key, limit)).fetchall()
    return [dict(r) for r in rows]


def forward_new_alerts(db_path=DEFAULT_DB, target=None) -> dict:
    """Send every alert this target has not received yet. Never raises."""
    result = {"sent": 0, "failed": 0, "error": None}
    try:
        t = parse_target(target)
        init_db(db_path)
        alerts = _unsent(db_path, t["text"], BATCH)
        if not alerts:
            return result
        send = _SENDERS[t["kind"]]
        done = []
        try:
            send(t, alerts, lambda a: done.append(a["id"]))     # only confirmed alerts are marked as sent
        except Exception as exc:                         # SIEM down, DNS failure, bad path...
            result["error"] = f"{type(exc).__name__}: {exc}"
            result["failed"] = len(alerts) - len(done)
            log.warning("SIEM %s unreachable (%s); %d alert(s) will be retried",
                        t["text"], result["error"], result["failed"])
        if done:
            with transaction(db_path) as conn:
                conn.executemany("INSERT OR IGNORE INTO siem_sent (target, alert_id) VALUES (?,?)",
                                 [(t["text"], i) for i in done])
        result["sent"] = len(done)
    except Exception as exc:                              # bad target string etc.
        result["error"] = f"{type(exc).__name__}: {exc}"
        log.warning("SIEM forwarding disabled for this cycle: %s", result["error"])
    return result
