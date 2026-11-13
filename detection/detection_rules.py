import re
from collections import defaultdict, deque
from datetime import datetime, timezone

from collector.log_collector import hash_password

DEFAULT_CONFIG = {
    "brute_force":            {"enabled": True, "max_failures": 5, "window_s": 60, "severity": "medium"},
    "rapid_attack":           {"enabled": True, "max_failures": 10, "window_s": 30, "severity": "high"},
    "username_enumeration":   {"enabled": True, "distinct_usernames": 5, "window_s": 60, "severity": "medium"},
    "password_spraying":      {"enabled": True, "distinct_usernames": 3, "window_s": 300, "severity": "high"},
    "repeated_attacks":       {"enabled": True, "min_periods": 3, "period_s": 3600,
                               "min_failures_per_period": 3, "severity": "medium"},
    "success_after_failures": {"enabled": True, "min_failures": 5, "lookback_s": 600, "severity": "critical"},
    "suspicious_commands":    {"enabled": True},
    # --- added rules ---
    "dictionary_attack":      {"enabled": True, "distinct_passwords": 5, "window_s": 300, "severity": "medium"},
    "connection_flood":       {"enabled": True, "max_connections": 20, "window_s": 60, "severity": "medium"},
    "download_and_execute":   {"enabled": True, "severity": "critical"},
    "distributed_attack":     {"enabled": True, "min_ips": 3, "min_shared_credentials": 3,
                               "window_s": 600, "severity": "high"},
}

# Passwords stored in the database are only SHA-256 fingerprints, so we hash this
# list the same way and compare fingerprints. The clear text is never recovered.
COMMON_PASSWORDS = (
    "123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon "
    "123123 baseball abc123 football monkey letmein shadow master 666666 qwertyuiop "
    "123321 mustang 1234567890 654321 superman 1qaz2wsx 121212 000000 qazwsx 123qwe "
    "killer trustno1 zxcvbnm asdfgh hunter soccer batman tigger sunshine iloveyou "
    "starwars 112233 computer pepper 1111 zxcvbn 555555 11111111 131313 freedom "
    "777777 pass 159753 aaaaaa princess cheese summer love access 987654321 matrix "
    "admin root toor test guest user ubnt raspberry pi support changeme default "
    "oracle postgres 1234qwer admin123 root123 password1 P@ssw0rd welcome login "
    "administrator 12345678910 qwerty123 1q2w3e4r"
).split()
COMMON_PASSWORD_HASHES = frozenset(hash_password(p) for p in COMMON_PASSWORDS)

DISCLAIMER = "This is a threshold-based signal, not proof of compromise."

COMMAND_PATTERNS = {
    "reconnaissance": ("low", [r"\b(uname|whoami|id|ifconfig|netstat|lscpu|hostname)\b",
                               r"\bip\s+a\b", r"\bps\s+aux", r"/proc/(cpuinfo|meminfo)"]),
    "credential_access": ("medium", [r"/etc/(passwd|shadow)"]),
    "download": ("high", [r"\b(wget|curl|tftp|ftpget)\b"]),
    "execution": ("high", [r"\bchmod\s+\+?[0-7x]+", r"\bbash\s+-i\b", r"/dev/tcp/",
                           r"\b(nc|ncat|netcat)\b.*\s-e\b"]),
    "persistence": ("high", [r"\bcrontab\b", r"authorized_keys", r"\b(useradd|adduser)\b",
                             r"/etc/rc\.local"]),
    "destruction": ("high", [r"\brm\s+-\w+\s+(/\s*$|/\*|/(etc|var|home|boot|usr|bin)\b|~)",
                             r"\bmkfs(\.\w+)?\b", r"\bdd\s+if=/dev/(zero|random|urandom)",
                             r":\(\)\s*\{"]),
    "defense_evasion": ("high", [r"\bhistory\s+-c\b", r"unset\s+HISTFILE", r"HISTFILE=/dev/null",
                                 r"\brm\b.*(/var/log|\.bash_history)", r"\biptables\s+-F",
                                 r"\bsystemctl\s+(stop|disable)\s+(firewalld|ufw|auditd)",
                                 r"\bchattr\b"]),
    "cryptomining": ("high", [r"\b(xmrig|minerd|cpuminer|cgminer)\b", r"stratum\+tcp://",
                              r"\bmonero\b"]),
}

DOWNLOAD_RE = re.compile(r"\b(wget|curl|tftp|ftpget)\b", re.IGNORECASE)
EXECUTE_RE = re.compile(r"\bchmod\s+\+?[0-7x]+|(^|[;&|]\s*)\./\S+|"
                        r"\b(sh|bash|python\d?|perl)\s+\S+|\bnohup\b", re.IGNORECASE)
_COMPILED = {cat: (sev, [re.compile(p, re.IGNORECASE) for p in pats])
             for cat, (sev, pats) in COMMAND_PATTERNS.items()}
_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _alert(ip, atype, severity, description, created_at, key):
    return {"source_ip": ip, "alert_type": atype, "severity": severity,
            "description": f"{description} {DISCLAIMER}",
            "created_at": created_at, "dedup_key": key}


def _failures(events):
    return [e for e in events if e["event_type"] == "login_failed"]


def rule_failure_burst(ip, events, cfg, atype):
    alerts, window = [], deque()
    for e in _failures(events):
        window.append(e)
        while (e["dt"] - window[0]["dt"]).total_seconds() > cfg["window_s"]:
            window.popleft()
        if len(window) >= cfg["max_failures"]:
            first = window[0]
            span = (e["dt"] - first["dt"]).total_seconds()
            alerts.append(_alert(
                ip, atype, cfg["severity"],
                f"{len(window)} failed logins in {span:.0f}s "
                f"(threshold: {cfg['max_failures']} in {cfg['window_s']}s). "
                f"Possible brute-force activity.",
                e["timestamp"], f"{atype}:{ip}:{first['timestamp']}"))
            window.clear()          # one alert per burst
    return alerts


def rule_username_enumeration(ip, events, cfg):
    alerts, window = [], deque()
    for e in _failures(events):
        window.append(e)
        while (e["dt"] - window[0]["dt"]).total_seconds() > cfg["window_s"]:
            window.popleft()
        names = {w["username"] for w in window if w["username"]}
        if len(names) >= cfg["distinct_usernames"]:
            alerts.append(_alert(
                ip, "username_enumeration", cfg["severity"],
                f"{len(names)} different usernames tried within {cfg['window_s']}s.",
                e["timestamp"], f"username_enumeration:{ip}:{window[0]['timestamp']}"))
            window.clear()
    return alerts


def rule_password_spraying(ip, events, cfg):
    by_hash = defaultdict(list)
    for e in _failures(events):
        if e["password_hash"]:
            by_hash[e["password_hash"]].append(e)

    alerts = []
    for pw_hash, evs in by_hash.items():
        window = deque()
        for e in evs:
            window.append(e)
            while (e["dt"] - window[0]["dt"]).total_seconds() > cfg["window_s"]:
                window.popleft()
            names = {w["username"] for w in window if w["username"]}
            if len(names) >= cfg["distinct_usernames"]:
                alerts.append(_alert(
                    ip, "password_spraying", cfg["severity"],
                    f"The same password ({e['password_masked']}) was tried against "
                    f"{len(names)} usernames within {cfg['window_s']}s.",
                    e["timestamp"], f"password_spraying:{ip}:{pw_hash}:{window[0]['timestamp']}"))
                window.clear()
    return alerts


def rule_repeated_attacks(ip, events, cfg):
    buckets = defaultdict(int)
    fails = _failures(events)
    for e in fails:
        buckets[int(e["dt"].timestamp() // cfg["period_s"])] += 1
    active = [b for b, n in buckets.items() if n >= cfg["min_failures_per_period"]]
    if len(active) >= cfg["min_periods"]:
        return [_alert(
            ip, "repeated_attacks", cfg["severity"],
            f"Failed logins in {len(active)} separate {cfg['period_s']}s periods "
            f"(at least {cfg['min_failures_per_period']} each). Persistent source.",
            fails[-1]["timestamp"], f"repeated_attacks:{ip}")]
    return []


def rule_success_after_failures(ip, events, cfg):
    fails = _failures(events)
    alerts = []
    for e in events:
        if e["event_type"] != "login_success":
            continue
        prior = [f for f in fails
                 if 0 <= (e["dt"] - f["dt"]).total_seconds() <= cfg["lookback_s"]]
        if len(prior) >= cfg["min_failures"]:
            alerts.append(_alert(
                ip, "success_after_failures", cfg["severity"],
                f"Simulated login succeeded for '{e['username']}' after {len(prior)} "
                f"failures in the previous {cfg['lookback_s']}s. High-priority investigation.",
                e["timestamp"], f"success_after_failures:{ip}:{e['session_id']}"))
    return alerts


def rule_suspicious_commands(ip, events, cfg):
    sessions = {}
    for e in events:
        if e["event_type"] != "command" or not e["command"]:
            continue
        for cat, (sev, patterns) in _COMPILED.items():
            if any(p.search(e["command"]) for p in patterns):
                s = sessions.setdefault(e["session_id"], {
                    "cats": set(), "sev": "low", "first_ts": e["timestamp"],
                    "example": e["command"][:80]})
                s["cats"].add(cat)
                if _SEV_ORDER[sev] > _SEV_ORDER[s["sev"]]:
                    s["sev"], s["example"] = sev, e["command"][:80]
    return [_alert(
        ip, "suspicious_commands", s["sev"],
        f"Session {sid} ran commands in categories: {', '.join(sorted(s['cats']))}. "
        f"Example: {s['example']!r}.",
        s["first_ts"], f"suspicious_commands:{sid}")
        for sid, s in sessions.items()]


def rule_dictionary_attack(ip, events, cfg):
    """Many different passwords from a well-known common-password list."""
    alerts, window = [], deque()
    for e in _failures(events):
        if e["password_hash"] not in COMMON_PASSWORD_HASHES:
            continue
        window.append(e)
        while (e["dt"] - window[0]["dt"]).total_seconds() > cfg["window_s"]:
            window.popleft()
        distinct = {w["password_hash"] for w in window}
        if len(distinct) >= cfg["distinct_passwords"]:
            alerts.append(_alert(
                ip, "dictionary_attack", cfg["severity"],
                f"{len(distinct)} different well-known passwords tried within "
                f"{cfg['window_s']}s. Looks like a wordlist-driven attack.",
                e["timestamp"], f"dictionary_attack:{ip}:{window[0]['timestamp']}"))
            window.clear()
    return alerts


def rule_connection_flood(ip, events, cfg):
    """Lots of connections in a short time (scanner or connection flood)."""
    alerts, window = [], deque()
    for e in events:
        if e["event_type"] != "connect":
            continue
        window.append(e)
        while (e["dt"] - window[0]["dt"]).total_seconds() > cfg["window_s"]:
            window.popleft()
        if len(window) >= cfg["max_connections"]:
            alerts.append(_alert(
                ip, "connection_flood", cfg["severity"],
                f"{len(window)} connections within {cfg['window_s']}s "
                f"(threshold: {cfg['max_connections']}). Possible scan or flood.",
                e["timestamp"], f"connection_flood:{ip}:{window[0]['timestamp']}"))
            window.clear()
    return alerts


def rule_download_and_execute(ip, events, cfg):
    """In one session: a file is downloaded and then run. The classic malware drop."""
    alerts, state = [], {}
    for e in events:
        if e["event_type"] != "command" or not e["command"]:
            continue
        cmd, sid = e["command"], e["session_id"]
        s = state.setdefault(sid, {"downloaded": False, "done": False})
        if s["done"]:
            continue
        if DOWNLOAD_RE.search(cmd):
            s["downloaded"] = True
        if s["downloaded"] and EXECUTE_RE.search(cmd):
            s["done"] = True
            alerts.append(_alert(
                ip, "download_and_execute", cfg["severity"],
                f"Session {sid} downloaded a file and then tried to run it. "
                f"Example: {cmd[:80]!r}. Likely malware installation attempt.",
                e["timestamp"], f"download_and_execute:{sid}"))
    return alerts


def rule_distributed_attack(events_by_ip, cfg):
    """Several different IPs trying the same credentials in the same period (botnet)."""
    buckets = defaultdict(lambda: defaultdict(set))      # bucket -> credential -> {ips}
    volume = defaultdict(lambda: defaultdict(int))       # bucket -> ip -> failed attempts
    last_ts = {}
    for ip, events in events_by_ip.items():
        for e in events:
            if e["event_type"] != "login_failed" or not e["password_hash"] or not e["username"]:
                continue
            b = int(e["dt"].timestamp() // cfg["window_s"])
            buckets[b][(e["username"], e["password_hash"])].add(ip)
            volume[b][ip] += 1
            last_ts[b] = max(last_ts.get(b, e["timestamp"]), e["timestamp"])
    alerts = []
    for b, creds in buckets.items():
        shared = [c for c, ips in creds.items() if len(ips) >= cfg["min_ips"]]
        if len(shared) < cfg["min_shared_credentials"]:
            continue
        ips = sorted({ip for c in shared for ip in creds[c]}, key=lambda i: -volume[b][i])
        alerts.append(_alert(
            ips[0], "distributed_attack", cfg["severity"],
            f"{len(ips)} different IPs tried {len(shared)} identical username/password "
            f"pairs in the same {cfg['window_s']}s period (e.g. {', '.join(ips[:4])}). "
            f"Looks like a coordinated botnet.",
            last_ts[b], f"distributed_attack:{b}"))
    return alerts


def merged_config(overrides=None) -> dict:
    cfg = {k: dict(v) for k, v in DEFAULT_CONFIG.items()}
    for k, v in (overrides or {}).items():
        cfg.setdefault(k, {}).update(v)
    return cfg


def run_rules(ip, events, config=None) -> list:
    """Run every enabled rule on one IP's events."""
    cfg = merged_config(config)
    events = sorted(({**e, "dt": parse_ts(e["timestamp"])} for e in events),
                    key=lambda e: e["dt"])
    alerts = []
    if cfg["brute_force"]["enabled"]:
        alerts += rule_failure_burst(ip, events, cfg["brute_force"], "brute_force")
    if cfg["rapid_attack"]["enabled"]:
        alerts += rule_failure_burst(ip, events, cfg["rapid_attack"], "rapid_attack")
    if cfg["username_enumeration"]["enabled"]:
        alerts += rule_username_enumeration(ip, events, cfg["username_enumeration"])
    if cfg["password_spraying"]["enabled"]:
        alerts += rule_password_spraying(ip, events, cfg["password_spraying"])
    if cfg["repeated_attacks"]["enabled"]:
        alerts += rule_repeated_attacks(ip, events, cfg["repeated_attacks"])
    if cfg["success_after_failures"]["enabled"]:
        alerts += rule_success_after_failures(ip, events, cfg["success_after_failures"])
    if cfg["suspicious_commands"]["enabled"]:
        alerts += rule_suspicious_commands(ip, events, cfg["suspicious_commands"])
    if cfg["dictionary_attack"]["enabled"]:
        alerts += rule_dictionary_attack(ip, events, cfg["dictionary_attack"])
    if cfg["connection_flood"]["enabled"]:
        alerts += rule_connection_flood(ip, events, cfg["connection_flood"])
    if cfg["download_and_execute"]["enabled"]:
        alerts += rule_download_and_execute(ip, events, cfg["download_and_execute"])
    return alerts


def run_global_rules(events_by_ip, config=None) -> list:
    """Rules that look across several IPs at once."""
    cfg = merged_config(config)
    prepared = {ip: sorted(({**e, "dt": parse_ts(e["timestamp"])} for e in evs),
                           key=lambda e: e["dt"])
                for ip, evs in events_by_ip.items()}
    alerts = []
    if cfg["distributed_attack"]["enabled"]:
        alerts += rule_distributed_attack(prepared, cfg["distributed_attack"])
    return alerts
