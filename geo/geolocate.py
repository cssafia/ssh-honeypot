"""IP geolocation with a local cache.

Public IPs are looked up once through the free ip-api.com batch endpoint and stored in
the ip_geo table, so each IP is only ever sent over the network a single time.
Private / LAN addresses (192.168.x.x, 10.x.x.x, 127.x ...) have no location, so they are
stored as "Private network" without any network call. This matters for a lab with two
machines on the same network: the attacker VM will appear as a private-network source.

Set SENTINEL_GEO=off to disable all outgoing lookups (offline / privacy mode).
"""
import argparse
import ipaddress
import json
import logging
import os
import time
import urllib.request
from datetime import datetime, timezone

from database.db import DEFAULT_DB, init_db, transaction

log = logging.getLogger("geo")

PRIVATE_LABEL = "Private network"
API_URL = "http://ip-api.com/batch?fields=status,message,country,countryCode,city,lat,lon,query"
BATCH_SIZE = 100            # ip-api.com batch limit
MAX_PER_RUN = 300           # keeps one pipeline cycle short
PAUSE_BETWEEN_BATCHES = 4.5  # free tier allows 15 batch requests per minute


def is_private(ip: str) -> bool:
    """True for LAN, loopback, link-local and reserved addresses (no real location)."""
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return True


def ip_api_provider(ips: list) -> dict:
    """Look up up to 100 public IPs. Returns {ip: record or None}. Raises on network errors."""
    req = urllib.request.Request(
        API_URL, data=json.dumps(ips).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "ssh-sentinel"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.load(resp)
    out = {}
    for item in data:
        if item.get("status") == "success" and item.get("lat") is not None:
            out[item["query"]] = {
                "country": item.get("country"), "country_code": item.get("countryCode"),
                "city": item.get("city"), "lat": item["lat"], "lon": item["lon"]}
        else:
            out[item.get("query")] = None        # permanent failure (e.g. reserved range)
    return out


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _save(conn, ip, rec, private=False):
    rec = rec or {}
    conn.execute(
        """INSERT OR REPLACE INTO ip_geo
           (ip, country, country_code, city, lat, lon, is_private, looked_up_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (ip, PRIVATE_LABEL if private else rec.get("country"),
         None if private else rec.get("country_code"), None if private else rec.get("city"),
         rec.get("lat"), rec.get("lon"), int(private), _now()))


def seed_geo(mapping: dict, db_path=DEFAULT_DB) -> int:
    """Store known locations directly (used by the demo data). mapping: ip -> record."""
    init_db(db_path)
    with transaction(db_path) as conn:
        for ip, rec in mapping.items():
            _save(conn, ip, rec)
    return len(mapping)


def enrich(db_path=DEFAULT_DB, provider=None, sleep=time.sleep) -> dict:
    """Locate every source IP that is not in the ip_geo table yet."""
    result = {"private": 0, "located": 0, "unknown": 0, "pending": 0, "skipped": False}
    init_db(db_path)
    with transaction(db_path) as conn:
        todo = [r[0] for r in conn.execute(
            "SELECT DISTINCT source_ip FROM attacks "
            "WHERE source_ip NOT IN (SELECT ip FROM ip_geo)")]
    if not todo:
        return result

    public = []
    with transaction(db_path) as conn:
        for ip in todo:
            if is_private(ip):
                _save(conn, ip, None, private=True)
                result["private"] += 1
            else:
                public.append(ip)

    if not public:
        return result
    if provider is None and os.environ.get("SENTINEL_GEO", "on").lower() == "off":
        result["skipped"], result["pending"] = True, len(public)
        return result

    provider = provider or ip_api_provider
    batch_list = public[:MAX_PER_RUN]
    result["pending"] = len(public) - len(batch_list)
    for i in range(0, len(batch_list), BATCH_SIZE):
        batch = batch_list[i:i + BATCH_SIZE]
        try:
            found = provider(batch)
        except Exception as exc:            # offline, rate limited, ... -> retry next cycle
            log.warning("Geolocation lookup failed (%s); will retry later", exc)
            result["pending"] += len(batch_list) - i
            break
        with transaction(db_path) as conn:
            for ip in batch:
                rec = found.get(ip)
                _save(conn, ip, rec)
                result["located" if rec else "unknown"] += 1
        if i + BATCH_SIZE < len(batch_list):
            sleep(PAUSE_BETWEEN_BATCHES)
    return result


def main():
    parser = argparse.ArgumentParser(description="Locate attacker IPs (cached in the database)")
    parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    print(enrich())


if __name__ == "__main__":
    main()
