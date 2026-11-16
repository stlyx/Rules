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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--access-file", type=Path, default=Path.home() / ".config/topo/sub-store-access.txt")
    args = parser.parse_args()
    urls = re.findall(r"https?://[^\s<>`]+", args.access_file.read_text())
    base = next(u.rstrip("/") for u in urls if urllib.parse.urlparse(u).hostname == "sub.stlyx.com" and len([v for v in urllib.parse.urlparse(u).path.split("/") if v]) == 1 and not urllib.parse.urlparse(u).query)

    def api(path, method="GET", data=None):
        body = json.dumps(data, ensure_ascii=False).encode() if data is not None else None
        request = urllib.request.Request(base + path, data=body, method=method, headers={"User-Agent": "Clash.Meta/1.19.33", "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=90) as response:
            return json.load(response)

    storage = api("/api/storage")
    source = next(s for s in storage["subs"] if s["name"] == "flowercloud")
    request = urllib.request.Request(source["url"], headers={"User-Agent": "Clash.Meta/1.19.33"})
    with urllib.request.urlopen(request, timeout=45) as response:
        raw = response.read().decode("utf-8-sig")
    if len(raw) < 1000 or raw.lstrip().lower().startswith(("<html", "<!doctype")):
        raise ValueError("Airport returned an invalid resource")
    candidate = {**source, "source": "local", "content": raw}
    candidate.pop("mergeSources", None)
    candidate["process"] = [p for p in source.get("process", []) if "topo-subscription-last-good" not in p.get("args", {}).get("content", "")]
    result = api("/api/preview/sub?target=mihomo", "POST", candidate)
    if result.get("status") != "success":
        raise ValueError("Candidate preview failed")
    nodes = result["data"]["processed"]
    patterns = ["香港|Hong Kong", "美国|美國|United States", "日本|Japan", "新加坡|Singapore", "土耳其|Turkey|Türkiye"]
    if len(nodes) < 40 or any(not any(re.search(pattern, n["name"], re.I) for n in nodes) for pattern in patterns):
        raise ValueError("Candidate lacks required airport regions")
    if any("[花云]" not in n["name"] for n in nodes):
        raise ValueError("Airport provenance processor is missing")
    latest = api("/api/storage")
    current = next(s for s in latest["subs"] if s["name"] == "flowercloud")
    if current["url"] != source["url"]:
        raise ValueError("Subscription URL changed during refresh")
    # Only change the fallback text. Preserve every UI edit to other fields.
    updated = api("/api/sub/flowercloud", "PATCH", {"content": raw})
    if updated.get("status") != "success":
        raise ValueError("Fallback update was rejected")
    state = {"last_success_utc": datetime.now(timezone.utc).isoformat(), "nodes": len(nodes), "sha256": hashlib.sha256(raw.encode()).hexdigest()}
    os.umask(0o077)
    state_file = args.access_file.parent / "flowercloud-refresh-state.json"
    state_file.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(state, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"success": False, "error_type": type(error).__name__, "http_status": getattr(error, "code", None)}, ensure_ascii=False))
        raise SystemExit(1)
