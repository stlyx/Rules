#!/usr/bin/env python3
"""Refresh the private airport fallback from the owner's local network.

Uses the existing private Sub-Store handoff. Never logs subscription URLs,
credentials, node parameters or certificate material. Failed candidates leave
the saved subscription untouched.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request
import urllib.error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--access-file", type=Path, default=Path.home() / ".config/topo/sub-store-access.txt")
    parser.add_argument("--snapshot-file", type=Path, help="Upload a previously fetched private snapshot without claiming a new origin download")
    args = parser.parse_args()
    urls = re.findall(r"https?://[^\s<>`]+", args.access_file.read_text())
    base = next(u.rstrip("/") for u in urls if urllib.parse.urlparse(u).hostname == "sub.stlyx.com" and len([v for v in urllib.parse.urlparse(u).path.split("/") if v]) == 1 and not urllib.parse.urlparse(u).query)

    def api(path, method="GET", data=None):
        body = json.dumps(data, ensure_ascii=False).encode() if data is not None else None
        request = urllib.request.Request(base + path, data=body, method=method, headers={"User-Agent": "Clash.Meta/1.19.33", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            error.stage = method + " " + path
            raise

    storage = api("/api/storage")
    source = next(s for s in storage["subs"] if s["name"] == "flowercloud")
    if args.snapshot_file:
        raw = args.snapshot_file.read_text(encoding="utf-8-sig")
        fetched_at = datetime.fromtimestamp(args.snapshot_file.stat().st_mtime, timezone.utc).isoformat()
    else:
        request = urllib.request.Request(source["url"], headers={"User-Agent": source.get("ua") or "Clash.Meta/1.19.33"})
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                raw = response.read().decode("utf-8-sig")
        except urllib.error.HTTPError as error:
            error.stage = "airport-origin"
            raise
        fetched_at = datetime.now(timezone.utc).isoformat()
    if len(raw) < 1000 or raw.lstrip().lower().startswith(("<html", "<!doctype")):
        raise ValueError("Airport returned an invalid resource")
    candidate = {**source, "source": "local", "content": raw}
    candidate.pop("mergeSources", None)
    if not any("topo-provenance-flowercloud-last-good-v1" in p.get("args", {}).get("content", "") for p in source.get("process", [])):
        raise ValueError("Airport provenance processor is missing")
    # Validate the actual candidate, without either last-good operator being able
    # to mask a partial/invalid origin response with an older successful result.
    candidate["process"] = [p for p in source.get("process", []) if p.get("type") != "Script Operator"]
    result = api("/api/preview/sub?target=mihomo", "POST", candidate)
    if result.get("status") != "success":
        raise ValueError("Candidate preview failed")
    nodes = [n for n in result["data"]["processed"] if not re.match(r"^(?:Traffic:|Expire:|剩余流量|套餐到期)", n["name"], re.I)]
    patterns = ["香港|Hong Kong", "美国|美國|United States", "日本|Japan", "新加坡|Singapore", "土耳其|Turkey|Türkiye"]
    if len(nodes) < 40 or any(not any(re.search(pattern, n["name"], re.I) for n in nodes) for pattern in patterns):
        raise ValueError("Candidate lacks required airport regions")
    nodes = [{**n, "name": "[花云] " + re.sub(r"^\[花云\]\s*", "", re.sub(r"^(?:[\U0001F1E6-\U0001F1FF]{2}\s*)+", "", n["name"]))} for n in nodes]
    latest = api("/api/storage")
    current = next(s for s in latest["subs"] if s["name"] == "flowercloud")
    if current["url"] != source["url"]:
        raise ValueError("Subscription URL changed during refresh")
    # Only change the fallback text. Preserve every UI edit to other fields.
    updated = api("/api/sub/flowercloud", "PATCH", {"content": raw})
    if updated.get("status") != "success":
        raise ValueError("Fallback update was rejected")
    # Update just the two airport snapshots. Otherwise a previously cached
    # remote success could continue shadowing the freshly uploaded fallback.
    code = "const nodes = " + json.dumps(nodes, ensure_ascii=False) + ";\n"
    for key in ["topo-subscription-last-good-flowercloud-v1", "topo-provenance-flowercloud-last-good-v1"]:
        code += "scriptResourceCache.set(" + json.dumps(key) + ", nodes, 365 * 24 * 60 * 60 * 1000);\n"
    code += '$content = "airport-caches-refreshed";'
    seeded = api("/api/preview/file", "POST", {"name": "topo-airport-cache-refresh", "source": "local", "sourceType": "local", "content": "", "process": [{"type": "Script Operator", "args": {"mode": "script", "content": code}}]})
    if seeded.get("status") != "success" or seeded["data"]["processed"] != "airport-caches-refreshed":
        raise ValueError("Airport cache refresh failed")
    state = {"last_success_utc": fetched_at, "last_upload_utc": datetime.now(timezone.utc).isoformat(), "source_kind": "provided_snapshot" if args.snapshot_file else "origin_download", "nodes": len(nodes), "sha256": hashlib.sha256(raw.encode()).hexdigest()}
    os.umask(0o077)
    state_file = args.access_file.parent / "flowercloud-refresh-state.json"
    state_file.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(state, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"success": False, "error_type": type(error).__name__, "http_status": getattr(error, "code", None), "stage": getattr(error, "stage", None)}, ensure_ascii=False))
        raise SystemExit(1)
