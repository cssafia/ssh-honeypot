#!/usr/bin/env python3
"""SSH Sentinel launcher: one command instead of running every step by hand.

    python run.py                 # live: watch the Cowrie log + dashboard on http://127.0.0.1:5000
    python run.py live --host 0.0.0.0    # let another machine open the dashboard (no login!)
    python run.py once            # run the analysis a single time and print a summary
    python run.py --siem syslog://192.168.1.50:514   # also send every new alert to a SIEM
    python run.py demo            # fake attacks, no honeypot needed (great for presentations)

Every cycle does: read new honeypot log lines -> store -> detect attacks -> locate IPs.
"""
import argparse
import json
import logging
import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def pipeline_once(log_path, state_path, db_path, config=None, use_geo=True, siem=None) -> dict:
    """One full pass. Never raises for the usual 'log not there yet' situations."""
    from collector.ingest import run as ingest_run
    from detection.detector import run_detection
    from geo.geolocate import enrich

    out = {"ingest": None, "detect": None, "geo": None, "siem": None, "warning": None}
    try:
        out["ingest"] = ingest_run(log_path, state_path, db_path)
    except FileNotFoundError:
        out["warning"] = f"Cowrie log not found yet: {log_path} (is the honeypot running?)"
    except PermissionError:
        out["warning"] = (f"No permission to read {log_path}. Give your user read access "
                          f"(e.g. add it to the cowrie group) or set SENTINEL_COWRIE_LOG.")
    out["detect"] = run_detection(db_path, config)
    if use_geo:
        out["geo"] = enrich(db_path)
    if siem:                                           # after geo, so the country travels with the alert
        from siem.forward import forward_new_alerts
        out["siem"] = forward_new_alerts(db_path, siem)
    return out


def describe(res) -> str:
    parts = []
    if res["warning"]:
        parts.append(res["warning"])
    if res["ingest"]:
        parts.append(f"{res['ingest']['new']} new events")
    if res["detect"]:
        parts.append(f"{res['detect']['new_alerts']} new alerts")
    s = res.get("siem")
    if s and s["sent"]:
        parts.append(f"{s['sent']} alerts sent to SIEM")
    if s and s["error"]:
        parts.append(f"SIEM problem: {s['error']} (will retry)")
    g = res["geo"]
    if g and (g["located"] or g["private"]):
        parts.append(f"{g['located']} IPs located, {g['private']} private")
    if g and g["pending"]:
        parts.append(f"{g['pending']} IPs waiting for geolocation")
    return ", ".join(parts) or "nothing new"


def watch(stop, interval, **kw):
    first = False                                       # main() already printed the first pass
    while not stop.is_set():
        try:
            res = pipeline_once(**kw)
            line = describe(res)
            changed = bool(res["warning"] or (res["ingest"] and res["ingest"]["new"])
                           or (res["detect"] and res["detect"]["new_alerts"])
                           or (res.get("siem") and (res["siem"]["sent"] or res["siem"]["error"])))
            if first or changed:
                print(f"[{time.strftime('%H:%M:%S')}] {line}", flush=True)
        except Exception as exc:                       # keep the loop alive no matter what
            logging.exception("pipeline error: %s", exc)
        first = False
        stop.wait(interval)


def serve(db_path, host, port):
    from backend.app import create_app
    if host not in ("127.0.0.1", "localhost"):
        print(f"WARNING: the dashboard has no login and is now reachable from the network "
              f"on {host}:{port}. Only do this on a trusted lab network.")
    create_app(db_path).run(host=host, port=port, debug=False, threaded=True)


def main(argv=None):
    from collector.log_collector import DEFAULT_LOG, DEFAULT_STATE
    from database.db import DEFAULT_DB

    p = argparse.ArgumentParser(description="SSH Sentinel launcher")
    p.add_argument("mode", nargs="?", default="live", choices=["live", "once", "demo"])
    p.add_argument("--log", default=DEFAULT_LOG, help="Cowrie JSON log (default: %(default)s)")
    p.add_argument("--db", default=str(DEFAULT_DB), help="SQLite file (default: %(default)s)")
    p.add_argument("--interval", type=int, default=5, help="seconds between analysis cycles")
    p.add_argument("--host", default="127.0.0.1", help="dashboard address")
    p.add_argument("--port", type=int, default=5000, help="dashboard port")
    p.add_argument("--config", help="JSON file with detection threshold overrides")
    p.add_argument("--siem", default=os.environ.get("SENTINEL_SIEM"),
                   help="forward new alerts to a SIEM: syslog://HOST:514, syslog+tcp://HOST:514, "
                        "http(s)://HOST/path or file:/path.json (default: off)")
    p.add_argument("--no-geo", action="store_true", help="never contact the geolocation service")
    p.add_argument("--no-dashboard", action="store_true", help="analysis loop only")
    args = p.parse_args(argv)

    args.log, args.db = os.path.abspath(args.log), os.path.abspath(args.db)
    config = json.loads(Path(args.config).read_text()) if args.config else None
    if args.no_geo:
        os.environ["SENTINEL_GEO"] = "off"
    os.chdir(ROOT)                                    # data/ lives next to the code
    sys.path.insert(0, str(ROOT))
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.mode == "demo":
        from demo.generate_demo import prepare_demo
        os.environ["SENTINEL_DEMO"] = "1"             # dashboard shows "demo mode", not "honeypot down"
        r = prepare_demo("data/demo")
        print(f"Demo data ready: {r['ingest']['new']} events, {r['detect']['new_alerts']} alerts "
              f"(fake attackers, nothing real). Opening dashboard...")
        print(f"Open http://{args.host}:{args.port}   (Ctrl+C to stop)")
        serve(str(r["db"]), args.host, args.port)
        return

    kw = dict(log_path=args.log, state_path=str(DEFAULT_STATE), db_path=args.db,
              config=config, use_geo=True, siem=args.siem)                  # --no-geo is honoured via SENTINEL_GEO=off:
                                                      # private IPs are still classified, nothing is sent out
    if args.mode == "once":
        print(describe(pipeline_once(**kw)))
        return

    print(f"Watching {args.log} every {args.interval}s")
    res = pipeline_once(**kw)                         # first pass so the dashboard has data
    print(f"[{time.strftime('%H:%M:%S')}] {describe(res)}")
    stop = threading.Event()
    worker = threading.Thread(target=watch, args=(stop, args.interval), kwargs=kw, daemon=True)
    worker.start()
    try:
        if args.no_dashboard:
            while worker.is_alive():
                time.sleep(1)
        else:
            print(f"Dashboard: http://{args.host}:{args.port}   (Ctrl+C to stop)")
            serve(args.db, args.host, args.port)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()


if __name__ == "__main__":
    main()
