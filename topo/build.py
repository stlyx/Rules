#!/usr/bin/env python3
"""Build public Mihomo/QX routing resources from one pinned source snapshot.

No subscriptions, node credentials, certificate keys or management URLs belong
in this directory. Private full profiles are assembled by Sub-Store.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request

import yaml

META = "MetaCubeX/meta-rules-dat"
ANTI = "privacy-protection-tools/anti-AD"
AWA = "TG-Twilight/AWAvenue-Ads-Rule"


@dataclass(frozen=True)
class Rule:
    kind: str
    value: str


def download(url: str, token: str = "") -> bytes:
    # The author's domain serves a browser index to non-QX user agents.
    # Request the actual client resource, then reject HTML instead of publishing it.
    headers = {"User-Agent": "Quantumult X" if url.startswith("https://ddgksf2013.top/") else "topo-unified-policy/1", "Accept": "application/vnd.github+json"}
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def domain(value: str) -> str:
    value = value.rstrip(".").lower()
    if not value or not re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*", value):
        raise ValueError("Unsupported domain syntax: " + value[:100])
    return value


def domains(text: str, *, plain_suffix: bool = False) -> list[Rule]:
    rules = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "!", "//")):
            continue
        suffix = line.startswith("+.")
        rules.append(Rule("DOMAIN-SUFFIX" if suffix or plain_suffix else "DOMAIN", domain(line[2:] if suffix else line)))
    return rules


def suffixes(value: str):
    parts = value.split(".")
    return (".".join(parts[i:]) for i in range(len(parts)))


def minimize(rules: list[Rule]) -> list[Rule]:
    roots = {r.value for r in rules if r.kind == "DOMAIN-SUFFIX"}
    roots = {v for v in roots if not any(s in roots for s in list(suffixes(v))[1:])}
    exact = {r.value for r in rules if r.kind == "DOMAIN" and not any(s in roots for s in suffixes(r.value))}
    other = {r for r in rules if r.kind not in {"DOMAIN", "DOMAIN-SUFFIX"}}
    return sorted([*(Rule("DOMAIN-SUFFIX", v) for v in roots), *(Rule("DOMAIN", v) for v in exact), *other], key=lambda r: (r.kind, r.value))


def addresses(text: str) -> list[Rule]:
    result = []
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            network = ipaddress.ip_network(line, strict=True)
            result.append(Rule("IP-CIDR6" if network.version == 6 else "IP-CIDR", str(network)))
    return result


def qx_disjoint(categories):
    """Remove lower-priority exact/suffix entries covered by an earlier suffix.

    QX gives exact hosts/specific suffixes precedence in ways that differ from
    ordered Mihomo rules. Fully shadowed later entries must not override an
    earlier, broader rule. Both enabled and paused lists are compiled separately.
    """
    high_exact, high_suffix, keywords = set(), set(), []
    networks = {4: [], 6: []}
    result = []
    for category in categories:
        kept = []
        for rule in category["rules"]:
            if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
                if any(v in high_suffix for v in suffixes(rule.value)) or any(k in rule.value for k in keywords):
                    continue
                if rule.kind == "DOMAIN" and rule.value in high_exact:
                    continue
                kept.append(rule)
            elif rule.kind.startswith("IP-CIDR"):
                net = ipaddress.ip_network(rule.value)
                if not any(net.subnet_of(n) for n in networks[net.version]):
                    kept.append(rule)
            else:
                kept.append(rule)
        for rule in kept:
            if rule.kind == "DOMAIN":
                high_exact.add(rule.value)
            elif rule.kind == "DOMAIN-SUFFIX":
                high_suffix.add(rule.value)
            elif rule.kind == "DOMAIN-KEYWORD":
                keywords.append(rule.value)
            elif rule.kind.startswith("IP-CIDR"):
                net = ipaddress.ip_network(rule.value)
                networks[net.version].append(net)
        result.append({**category, "rules": kept})
    return result


def qx_text(categories, version):
    kinds = {"DOMAIN": "host", "DOMAIN-SUFFIX": "host-suffix", "DOMAIN-KEYWORD": "host-keyword", "IP-CIDR": "ip-cidr", "IP-CIDR6": "ip6-cidr"}
    lines = [f"# topo unified policy {version}", "# Generated from one snapshot; preserve per-rule policies."]
    for category in qx_disjoint(categories):
        policy = category["policy"]
        policy = {"DIRECT": "direct", "REJECT": "reject"}.get(policy, policy)
        lines.append("# " + category["id"])
        lines.extend(f"{kinds[r.kind]},{r.value},{policy}" for r in category["rules"])
    return "\n".join(lines) + "\n"


def classify(host, categories, *, qx=False):
    matches = []
    for order, category in enumerate(categories):
        for rule in category["rules"]:
            score = None
            if rule.kind == "DOMAIN" and rule.value == host:
                score = (3, len(rule.value))
            elif rule.kind == "DOMAIN-SUFFIX" and (rule.value == host or host.endswith("." + rule.value)):
                score = (2, len(rule.value))
            elif rule.kind == "DOMAIN-KEYWORD" and rule.value in host:
                score = (1, len(rule.value))
            if score:
                if not qx:
                    return category["policy"]
                matches.append((score, -order, category["policy"]))
    return max(matches)[2] if matches else "🚀 主力出口"


def check(categories):
    cases = {
        "gemini.google.com": "🤖 AI 服务", "generativelanguage.googleapis.com": "🤖 AI 服务",
        "copilot.microsoft.com": "🤖 AI 服务", "chatgpt.com": "🤖 AI 服务", "claude.ai": "🤖 AI 服务",
        "www.googleapis.com": "🌐 谷歌服务", "drive.google.com": "🌐 谷歌服务", "www.youtube.com": "🌐 谷歌服务",
        "api.telegram.org": "📨 电报", "www.binance.com": "₿ 加密货币", "www.okx.com": "₿ 加密货币",
        "onedrive.live.com": "☁️ 微软云盘", "api.onedrive.com": "☁️ 微软云盘",
        "outlook.office365.com": "Ⓜ️ 微软服务", "www.apple.com": "🍎 苹果服务", "www.baidu.com": "DIRECT",
        "api.deepseek.com": "DIRECT", "kimi.com": "DIRECT", "oraclecloud.com": "DIRECT",
        "sub.stlyx.com": "DIRECT", "example.org": "🚀 主力出口",
    }
    normal = qx_disjoint(categories)
    paused = [c for c in categories if c["id"] != "ads"]
    paused_qx = qx_disjoint(paused)
    results = {}
    for host, expected in cases.items():
        values = [classify(host, categories), classify(host, normal, qx=True), classify(host, paused), classify(host, paused_qx, qx=True)]
        if any(value != expected for value in values):
            raise ValueError(f"Routing regression for {host}: {values}; expected {expected}")
        results[host] = expected
    # Synthetic overlapping suffix/exact case, including restoration after pause.
    sample = [
        {"id": "ads", "policy": "REJECT", "rules": [Rule("DOMAIN-SUFFIX", "ads.example.com")]},
        {"id": "business", "policy": "business", "rules": [Rule("DOMAIN", "api.ads.example.com"), Rule("DOMAIN-SUFFIX", "example.com")]},
    ]
    assert classify("api.ads.example.com", qx_disjoint(sample), qx=True) == "REJECT"
    assert classify("api.ads.example.com", qx_disjoint(sample[1:]), qx=True) == "business"
    return results


def build(policy_file: Path, output: Path, cache: Path):
    policy = yaml.safe_load(policy_file.read_text())
    cache.mkdir(parents=True, exist_ok=True)
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        auth = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
        token = auth.stdout.strip() if auth.returncode == 0 else ""
    repos = {META: "meta", ANTI: "master", AWA: "main"}

    def revision(item):
        repo, branch = item
        data = json.loads(download(f"https://api.github.com/repos/{repo}/commits/{branch}", token))
        return repo, data["sha"]

    with ThreadPoolExecutor(max_workers=3) as pool:
        revisions = dict(pool.map(revision, repos.items()))
    specs = []
    for key, path in policy["rule_inputs"].items():
        if key in {"base", "snapshot_consistency", "unknown_syntax"}:
            continue
        specs.append((key, META, path))
    specs.extend([("anti_ad", ANTI, "anti-ad-clash.yaml"), ("awavenue", AWA, "Filters/AWAvenue-Ads-Rule-Clash.yaml")])

    def get(spec):
        key, repo, path = spec
        url = f"https://raw.githubusercontent.com/{repo}/{revisions[repo]}/{path}"
        data = download(url)
        (cache / (key + ".source")).write_bytes(data)
        return key, data

    with ThreadPoolExecutor(max_workers=6) as pool:
        inputs = dict(pool.map(get, specs))
    if len(inputs["cn_domains"]) < 100000 or len(inputs["anti_ad"]) < 100000:
        raise ValueError("Unexpectedly empty major rule source")

    def parsed(key):
        return domains(inputs[key].decode("utf-8-sig"))

    groups = policy["business_groups"]
    boot = [Rule(r[0], r[1]) for r in policy["bootstrap_rules"]]
    categories = [{"id": "bootstrap", "policy": "DIRECT", "rules": minimize(boot)}]
    categories.append({"id": "domestic-ai", "policy": "DIRECT", "rules": minimize(parsed("domestic_ai"))})
    ad_rules = []
    for key in ["anti_ad", "awavenue"]:
        data = yaml.safe_load(inputs[key])
        payload = data["payload"]
        ad_rules.extend(domains("\n".join(payload)))
    categories.append({"id": "ads", "policy": "REJECT", "rules": minimize(ad_rules)})
    for name, key in [("ai", "ai"), ("telegram", "telegram_domains"), ("crypto", "crypto"), ("onedrive", "onedrive"), ("microsoft", "microsoft"), ("apple", "apple"), ("google", "google")]:
        categories.append({"id": name, "policy": groups[name]["name"], "rules": minimize(parsed(key))})
        if name == "telegram":
            categories.append({"id": "telegram-ip", "policy": groups[name]["name"], "rules": addresses(inputs["telegram_ip"].decode())})
    categories.append({"id": "cn-domains", "policy": "DIRECT", "rules": minimize(parsed("cn_domains"))})
    categories.append({"id": "cn-ip", "policy": "DIRECT", "rules": addresses(inputs["cn_ip"].decode())})
    checks = check(categories)
    startup = download("https://ddgksf2013.top/rewrite/StartUpAds.conf").decode("utf-8-sig")
    if startup.lstrip().lower().startswith(("<!doctype", "<html")):
        raise ValueError("Startup source returned HTML")
    fingerprint = hashlib.sha256(policy_file.read_bytes() + Path(__file__).read_bytes() + Path(__file__).with_name("runtime.js").read_bytes() + startup.encode() + json.dumps(revisions, sort_keys=True).encode()).hexdigest()[:16]
    version = "v1-" + fingerprint
    output.mkdir(parents=True, exist_ok=True)
    descriptors = []
    for category in categories:
        domain_rules = [r for r in category["rules"] if r.kind in {"DOMAIN", "DOMAIN-SUFFIX"}]
        classical = [r for r in category["rules"] if r.kind not in {"DOMAIN", "DOMAIN-SUFFIX"}]
        for kind, rules in [("domain", domain_rules), ("classical", classical)]:
            if not rules:
                continue
            name = category["id"] + ("-ip" if kind == "classical" else "")
            relative = "mihomo/" + name + ".list"
            target = output / relative
            target.parent.mkdir(exist_ok=True)
            if kind == "domain":
                text = "\n".join(("+." if r.kind == "DOMAIN-SUFFIX" else "") + r.value for r in rules) + "\n"
            else:
                text = "\n".join(r.kind + "," + r.value + (",no-resolve" if category["id"] != "cn-ip" and r.kind.startswith("IP-CIDR") else "") for r in rules) + "\n"
            target.write_text(text)
            descriptors.append({"id": name, "category": category["id"], "policy": "🛡️ 广告控制" if category["id"] == "ads" else category["policy"], "behavior": kind, "path": relative, "count": len(rules)})
    (output / "qx-on.list").write_text(qx_text(categories, version))
    (output / "qx-off.list").write_text(qx_text([c for c in categories if c["id"] != "ads"], version))
    # Dedicated app modules own these endpoints. Keep the generic startup list
    # for other applications rather than running two response modifiers there.
    excluded = ("bilibili", "biliapi", "amap", "baidu", "weibo", "umetrip", "youtube", "googlevideo", "weixin", "wechat")
    curated, removed = [], 0
    for line in startup.splitlines():
        stripped = line.strip()
        if " url " in stripped and not stripped.startswith(("#", ";", "//")):
            pattern = stripped.split(" url ", 1)[0]
            normalized = re.sub(r"[^a-z0-9]", "", pattern.lower())
            if any(marker in normalized for marker in excluded):
                removed += 1
                continue
        curated.append(line)
    if sum(" url " in line and not line.lstrip().startswith(("#", ";", "//")) for line in curated) < 50:
        raise ValueError("Generic startup source unexpectedly empty")
    (output / "rewrites").mkdir(exist_ok=True)
    (output / "rewrites/startup.conf").write_text("# Curated from ddgksf2013 StartUpAds; dedicated app endpoints excluded.\n" + "\n".join(curated) + "\n")
    manifest = {"schema": 1, "version": version, "built_at": datetime.now(timezone.utc).isoformat(), "source_revisions": revisions, "source_hashes": {k: hashlib.sha256(v).hexdigest() for k, v in inputs.items()}, "providers": descriptors, "policy": policy, "qx_on": "qx-on.list", "qx_off": "qx-off.list", "checks": checks, "startup_source_sha256": hashlib.sha256(startup.encode()).hexdigest(), "startup_dedicated_rules_removed": removed}
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    (output / "validation.json").write_text(json.dumps({"version": version, "domain_cases": checks, "overlapping_ad_pause_case": True, "provider_counts": {p["id"]: p["count"] for p in descriptors}}, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"version": version, "providers": len(descriptors), "ad_rules": len(next(c for c in categories if c["id"] == "ads")["rules"]), "checked_domains": len(checks)}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=Path(__file__).with_name("policy.yaml"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    args = parser.parse_args()
    build(args.policy, args.output, args.cache)
