#!/usr/bin/env python3
"""Emit configuration metadata only; clients download upstream rule contents."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import yaml


def load_policy(path):
    return json.loads(path.read_text()) if path.suffix == ".json" else yaml.safe_load(path.read_text())


def build(policy_file, output, cache=None):
    policy = load_policy(policy_file)
    groups = {key: value["name"] for key, value in policy["business_groups"].items()}
    groups.update({"DIRECT": "DIRECT", "ads": "🛡️ 广告控制"})
    providers = []
    for item in policy["rule_sets"]:
        target = item["target"]
        native = item["mihomo"]
        qx = item["qx"]
        providers.append({"id": item["id"], "source_key": item["id"], "category": item["category"],
                          "policy": groups[target], **native,
                          "qx": {**qx, "policy": "reject" if target == "ads" else "direct" if target == "DIRECT" else groups[target],
                                 "tag": {"ads-anti-ad": "广告 · anti-AD", "ads-awavenue": "广告 · 秋风"}.get(item["id"],
                                          "直连 · 花云" if item["id"] == "flowercloud-direct" else "直连 · Oracle" if item["id"] == "oracle" else
                                          "国内域名" if item["id"] == "cn-domains" else "国内 IP" if item["id"] == "cn-ip" else groups[target])}})
    assert len(providers) == len({p["id"] for p in providers})
    checks = {
        "gemini.google.com": groups["ai"], "generativelanguage.googleapis.com": groups["ai"],
        "copilot.microsoft.com": groups["ai"], "chatgpt.com": groups["ai"], "claude.ai": groups["ai"],
        "www.googleapis.com": groups["google"], "drive.google.com": groups["google"], "www.youtube.com": groups["google"],
        "api.telegram.org": groups["telegram"], "www.binance.com": groups["crypto"], "www.okx.com": groups["crypto"],
        "onedrive.live.com": groups["onedrive"], "api.onedrive.com": groups["onedrive"],
        "outlook.office365.com": groups["microsoft"], "www.apple.com": groups["apple"],
        "www.baidu.com": "DIRECT", "api.deepseek.com": "DIRECT", "kimi.com": "DIRECT",
        "oraclecloud.com": "DIRECT", "www.oracle.com": "DIRECT", "api-flowercloud.com": "DIRECT", "sub.xmancdn.com": "DIRECT",
        "sub.stlyx.com": "DIRECT", "example.org": policy["selectors"]["main"]["name"],
    }
    fingerprint = hashlib.sha256(policy_file.read_bytes() + Path(__file__).with_name("runtime.js").read_bytes()).hexdigest()[:16]
    manifest = {"schema": 3, "version": "native-" + fingerprint, "policy": policy,
                "upstream_providers": providers, "checks": checks, "rule_contents_hosted": False}
    output.mkdir(parents=True, exist_ok=True)
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"version": manifest["version"], "providers": len(providers), "rule_contents_hosted": False}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=Path(__file__).with_name("policy.yaml"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.policy, args.output)
