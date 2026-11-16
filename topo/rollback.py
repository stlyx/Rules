#!/usr/bin/env python3
"""Restore only this rollout's original Sub-Store sources, collection and files.

Reads a private rollout directory created during installation. The caller must
review later UI edits before running a historical rollback. Existing unrelated
resources and original share tokens are not imported or deleted.
"""
import argparse
import json
from pathlib import Path
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    before = json.loads((args.state_dir / "storage.before.json").read_text())
    base = (args.state_dir / "backend.private.txt").read_text().strip()

    def patch(path, body):
        request = urllib.request.Request(base + path, data=json.dumps(body, ensure_ascii=False).encode(), method="PATCH", headers={"User-Agent": "Clash.Meta/1.19.33", "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=90) as response:
            result = json.load(response)
        if result.get("status") != "success":
            raise RuntimeError("Resource restoration rejected")

    # The old profile works again after all source names and membership are restored.
    for source in before["subs"]:
        patch("/api/sub/" + source["name"], source)
    for collection in before["collections"]:
        if collection["name"] == "all":
            patch("/api/collection/all", collection)
    for file in before["files"]:
        if file["name"] in ["withlow-mihomo", "qx-diy"]:
            patch("/api/file/" + file["name"], file)
    print("Original sources, all collection and original full profiles restored; share tokens preserved.")


if __name__ == "__main__":
    main()
