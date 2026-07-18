#!/usr/bin/env python3
"""
wpfind rrrnnn — look up WP directory info via itcdir REST API.

  1. GET /api/find?wp=rrrnnn on a host (starts at localhost:4014)
  2. On {"referral":[...]}, try those hosts (port 4014), max 5 referral hops
  3. On {"servers":[...]}, print them, then GET /api/get?wp=rrrnnn from one
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

PORT = 4014
MAX_REFERRALS = 5
TIMEOUT_SEC = 10


def usage() -> None:
    print(f"usage: {sys.argv[0]} rrrnnn", file=sys.stderr)
    print("  rrrnnn = 6-digit WP id (e.g. 802123)", file=sys.stderr)
    sys.exit(2)


def http_get_json(host: str, path_query: str) -> tuple[int, object | None, str]:
    """
    GET http://host:4014/path_query
    Returns (status, parsed_json_or_None, raw_body_or_error_text).
    """
    url = f"http://{host}:{PORT}{path_query}"
    req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            status = resp.getcode()
            try:
                return status, json.loads(body), body
            except json.JSONDecodeError:
                return status, None, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body), body
        except json.JSONDecodeError:
            return e.code, None, body
    except urllib.error.URLError as e:
        return -1, None, f"connection error to {host}:{PORT}: {e.reason}"
    except TimeoutError:
        return -1, None, f"timeout connecting to {host}:{PORT}"
    except OSError as e:
        return -1, None, f"os error for {host}:{PORT}: {e}"


def find_servers(wp: str) -> list[dict] | None:
    """
    Walk find/referral chain starting at localhost:4014.
    Counts each referral response; quits after more than MAX_REFERRALS.
    Returns servers list, or None on error.
    """
    hosts_to_try = ["localhost"]
    referrals_seen = 0
    visited: set[str] = set()

    while hosts_to_try:
        host = hosts_to_try.pop(0)
        if not host or host in visited:
            continue
        visited.add(host)

        print(f"find: http://{host}:{PORT}/api/find?wp={wp}")
        status, data, raw = http_get_json(host, f"/api/find?wp={wp}")

        if status < 0:
            print(f"error: {raw}", file=sys.stderr)
            if hosts_to_try:
                continue
            return None

        if status >= 400 or not isinstance(data, dict):
            print(f"error: HTTP {status} from {host}: {raw}", file=sys.stderr)
            if hosts_to_try:
                continue
            return None

        if "servers" in data and isinstance(data["servers"], list):
            if not data["servers"]:
                print(f"error: empty servers list from {host}", file=sys.stderr)
                return None
            print(f"servers from {host}:")
            print(json.dumps({"servers": data["servers"]}, indent=2))
            return data["servers"]

        if "referral" in data and isinstance(data["referral"], list):
            referrals_seen += 1
            if referrals_seen > MAX_REFERRALS:
                print(
                    f"error: referred more than {MAX_REFERRALS} times; giving up",
                    file=sys.stderr,
                )
                return None
            refs = [str(h).strip() for h in data["referral"] if str(h).strip()]
            print(f"referral ({referrals_seen}/{MAX_REFERRALS}) from {host}: {refs}")
            if not refs:
                print(f"error: empty referral list from {host}", file=sys.stderr)
                return None
            for r in refs:
                if r not in visited and r not in hosts_to_try:
                    hosts_to_try.append(r)
            continue

        print(f"error: unexpected find response from {host}: {raw}", file=sys.stderr)
        return None

    print("error: exhausted hosts without finding servers", file=sys.stderr)
    return None


def get_wiu(wp: str, servers: list[dict]) -> int:
    """Try /api/get on server hosts (port 4014). Return process exit code."""
    hosts: list[str] = []
    for s in servers:
        if isinstance(s, dict) and s.get("host"):
            h = str(s["host"]).strip()
            if h and h not in hosts:
                hosts.append(h)

    if not hosts:
        print("error: no host fields in servers list", file=sys.stderr)
        return 1

    last_err = "no hosts tried"
    for host in hosts:
        print(f"get:  http://{host}:{PORT}/api/get?wp={wp}")
        status, data, raw = http_get_json(host, f"/api/get?wp={wp}")
        if status < 0:
            last_err = raw
            print(f"  fail: {raw}")
            continue
        if status >= 400:
            last_err = f"HTTP {status}: {raw}"
            print(f"  fail: {last_err}")
            continue
        if isinstance(data, (dict, list)):
            print(json.dumps(data, indent=2))
        else:
            print(raw)
        return 0

    print(f"error: /api/get failed on all servers ({last_err})", file=sys.stderr)
    return 1


def main() -> int:
    if len(sys.argv) != 2:
        usage()
    wp = sys.argv[1].strip()
    if not wp.isdigit() or len(wp) != 6:
        print("error: wp must be 6 digits (rrrnnn)", file=sys.stderr)
        return 2

    servers = find_servers(wp)
    if servers is None:
        return 1

    return get_wiu(wp, servers)


if __name__ == "__main__":
    sys.exit(main())
