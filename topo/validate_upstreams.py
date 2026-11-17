#!/usr/bin/env python3
"""Read-only upstream checks for CI/local validation. No hosted rule artifacts."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    args.cache.mkdir(parents=True, exist_ok=True)
    sources = {}
    for p in manifest["upstream_providers"]:
        sources[p["url"]] = None
        sources[p["qx"]["url"]] = None
    parser_url = manifest["policy"]["qx"]["resource_parser_url"]
    sources[parser_url] = None

    def fetch(url):
        req = urllib.request.Request(url, headers={"User-Agent": "Quantumult X"})
        with urllib.request.urlopen(req, timeout=60) as response:
            data = response.read()
        text = data.decode("utf-8-sig")
        if len(data) < 30 or text.lstrip().lower().startswith(("<!doctype", "<html")):
            raise ValueError("Invalid upstream resource: " + url)
        return url, data

    with ThreadPoolExecutor(max_workers=6) as pool:
        sources = dict(pool.map(fetch, sources))
    for p in manifest["upstream_providers"]:
        (args.cache / (p["source_key"] + ".source")).write_bytes(sources[p["url"]])
        (args.cache / (p["source_key"] + ".qx.source")).write_bytes(sources[p["qx"]["url"]])
    (args.cache / "resource-parser.js").write_bytes(sources[parser_url])
    report = {"source_urls": len(sources), "providers": len(manifest["upstream_providers"]),
              "sha256": {url: hashlib.sha256(data).hexdigest() for url, data in sources.items()},
              "rule_contents_served": False}
    (args.cache / "validation.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps({"source_urls": len(sources), "providers": report["providers"], "rule_contents_served": False}))


if __name__ == "__main__":
    main()
