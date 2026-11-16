#!/usr/bin/env python3
"""Validate upstream public rules and atomically replace the server snapshot.

Runs on the Sub-Store host using only the standard library and installed
validation tools. No subscriptions, API credentials or private certificates
are read. A failed build leaves the current snapshot and clients untouched.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--container", default="sub-store")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    data = args.data_dir.resolve()
    data.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    with (data / "refresh.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        releases = data / "releases"
        releases.mkdir(exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix="snapshot-", dir=releases))
        (stage / ".topo-public-rules").touch()
        actions = [
            [sys.executable, str(root / "build.py"), "--policy", str(args.policy), "--output", str(stage), "--cache", str(data / "source-cache")],
            ["docker", "exec", args.container, "node", "/opt/app/data/topo-rules-code/check-runtime.js", "/opt/app/data/topo-rules/releases/" + stage.name + "/manifest.json"],
            [sys.executable, str(root / "audit_rules.py"), "--rules", str(stage), "--output", str(stage / "audit.json"), "--quiet"],
            [sys.executable, str(root / "check_core.py"), "--rules", str(stage), "--core", str(args.core), "--upstream", "--source-cache", str(data / "source-cache")],
        ]
        try:
            for command in actions:
                subprocess.run(command, check=True, timeout=300)
        except Exception:
            shutil.rmtree(stage)
            raise
        manifest = json.loads((stage / "manifest.json").read_text())
        pointer = data / ("current.next-" + str(os.getpid()))
        pointer.symlink_to(Path("releases") / stage.name)
        os.replace(pointer, data / "current")
        state = {"last_success_utc": datetime.now(timezone.utc).isoformat(), "version": manifest["version"], "source_revisions": manifest["source_revisions"], "snapshot": stage.name}
        (data / "refresh-state.json").write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n")
        old = sorted((p for p in releases.iterdir() if p.is_dir() and (p / ".topo-public-rules").exists()), key=lambda p: p.stat().st_mtime, reverse=True)
        keep = {stage, *old[:3]}
        for snapshot in old:
            if snapshot not in keep:
                shutil.rmtree(snapshot)
        print(json.dumps(state, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"success": False, "error_type": type(error).__name__, "last_good_preserved": True}), file=sys.stderr)
        raise SystemExit(1)
