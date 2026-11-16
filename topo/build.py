#!/usr/bin/env python3
"""Build public Mihomo/QX routing resources from one audited build snapshot and track upstream branches in clients.

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
import shutil
import subprocess
import urllib.request

try:
    import yaml
except ImportError:
    yaml = None  # The server updater uses JSON policy and generated domain YAML.

META = "MetaCubeX/meta-rules-dat"
ANTI = "privacy-protection-tools/anti-AD"
AWA = "TG-Twilight/AWAvenue-Ads-Rule"
CATS = "Cats-Team/AdRules"


def load_policy(path: Path):
    if path.suffix == ".json":
        return json.loads(path.read_text())
    if yaml is None:
        raise RuntimeError("Use the installed JSON policy when PyYAML is unavailable")
    return yaml.safe_load(path.read_text())


def domain_payload(data: bytes) -> list[str]:
    """Read the deliberately narrow generated domain payload used upstream.

    Reject other YAML constructs rather than guessing their meaning. This
    keeps the scheduled JSON-policy build free of third-party dependencies.
    """
    result, header = [], False
    for raw in data.decode("utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "payload:" and not header:
            header = True
            continue
        match = re.fullmatch(r"-\s+(?:'([a-zA-Z0-9_+.\-]+)'|\"([a-zA-Z0-9_+.\-]+)\"|([a-zA-Z0-9_+.\-]+))", line)
        if not header or not match:
            raise ValueError("Unsupported generated domain payload syntax")
        result.append(next(group for group in match.groups() if group is not None))
    if not header or not result:
        raise ValueError("Empty generated domain payload")
    return result


@dataclass(frozen=True)
class Rule:
    kind: str
    value: str


def download(url: str, token: str = "") -> bytes:
    headers = {"User-Agent": "topo-unified-policy/1", "Accept": "application/vnd.github+json"}
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


def classical_domains(text: str) -> list[Rule]:
    result = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "!", "//")):
            continue
        parts = line.split(",")
        if len(parts) != 2 or parts[0] not in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
            raise ValueError("Unsupported external domain rule syntax")
        result.append(Rule(parts[0], domain(parts[1])))
    if not result:
        raise ValueError("Empty external domain rule source")
    return result


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


def qx_manual_feeds(categories):
    """Keep complete business routes while making the ad feed optional.

    QX chooses exact/more-specific hosts before broader suffixes across files.
    Copy business rules hidden by ads into the ad resource as REJECT rules,
    preserving both ad priority and the business route when that resource is off.
    """
    normal = qx_disjoint(categories)
    business = qx_disjoint([c for c in categories if c["id"] != "ads"])
    kept = {r for c in normal if c["id"] != "ads" for r in c["rules"]}
    ads = next(c for c in normal if c["id"] == "ads")
    covered = [r for c in business for r in c["rules"] if r not in kept]
    rules = list(dict.fromkeys([*ads["rules"], *covered]))
    return business, [{**ads, "rules": rules}], len(rules) - len(ads["rules"])


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
        "www.oracle.com": "DIRECT", "api-flowercloud.com": "DIRECT", "sub.xmancdn.com": "DIRECT",
        "sub.stlyx.com": "DIRECT", "example.org": "🚀 主力出口",
    }
    normal = qx_disjoint(categories)
    paused = [c for c in categories if c["id"] != "ads"]
    paused_qx = qx_disjoint(paused)
    business_feed, ad_feed, _ = qx_manual_feeds(categories)
    manual = [*ad_feed, *business_feed]
    results = {}
    for host, expected in cases.items():
        values = [classify(host, categories), classify(host, normal, qx=True), classify(host, paused), classify(host, paused_qx, qx=True), classify(host, manual, qx=True), classify(host, business_feed, qx=True)]
        if any(value != expected for value in values):
            raise ValueError(f"Routing regression for {host}: {values}; expected {expected}")
        results[host] = expected
    if any(c["id"] == "oracle" for c in categories):
        overlap = "addthis.com"
        values = [classify(overlap, categories), classify(overlap, normal, qx=True), classify(overlap, paused), classify(overlap, paused_qx, qx=True)]
        if values != ["REJECT", "REJECT", "DIRECT", "DIRECT"]:
            raise ValueError("Oracle source must remain below advertising rules: " + str(values))
    for host, target in [("ad.mi.com", "DIRECT"), ("googleads.g.doubleclick.net", "🌐 谷歌服务"), ("addthis.com", "DIRECT")]:
        assert classify(host, manual, qx=True) == "REJECT"
        assert classify(host, business_feed, qx=True) == target
    # Synthetic overlapping suffix/exact case, including restoration after pause.
    sample = [
        {"id": "ads", "policy": "REJECT", "rules": [Rule("DOMAIN-SUFFIX", "ads.example.com")]},
        {"id": "business", "policy": "business", "rules": [Rule("DOMAIN", "api.ads.example.com"), Rule("DOMAIN-SUFFIX", "example.com")]},
    ]
    assert classify("api.ads.example.com", qx_disjoint(sample), qx=True) == "REJECT"
    assert classify("api.ads.example.com", qx_disjoint(sample[1:]), qx=True) == "business"
    business_sample, ads_sample, _ = qx_manual_feeds(sample)
    assert classify("api.ads.example.com", [*ads_sample, *business_sample], qx=True) == "REJECT"
    assert classify("api.ads.example.com", business_sample, qx=True) == "business"
    return results


def build(policy_file: Path, output: Path, cache: Path):
    policy = load_policy(policy_file)
    cache.mkdir(parents=True, exist_ok=True)
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token and shutil.which("gh"):
        auth = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
        token = auth.stdout.strip() if auth.returncode == 0 else ""
    ad_choices = {
        "anti-AD": ("anti_ad", ANTI, "master", "anti-ad-clash.yaml"),
        "AWAvenue": ("awavenue", AWA, "main", "Filters/AWAvenue-Ads-Rule-Clash.yaml"),
        "AdRules": ("ad_rules", CATS, "main", "adrules_domainset.txt"),
    }
    selected_ads = policy["ads"]["default_sources"]
    if not selected_ads or any(name not in ad_choices for name in selected_ads):
        raise ValueError("Unknown or empty advertising source selection")
    repos = {META: "meta", **{ad_choices[name][1]: ad_choices[name][2] for name in selected_ads}}

    external = policy.get("external_rule_inputs", {})
    for item in external.values():
        if item["behavior"] != "classical" or item["format"] != "text":
            raise ValueError("Unsupported external domain source format")
        if item["repo"] in repos and repos[item["repo"]] != item["branch"]:
            raise ValueError("Conflicting branches for one repository")
        repos[item["repo"]] = item["branch"]

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
    specs.extend((key, repo, path) for key, repo, _, path in (ad_choices[name] for name in selected_ads))

    specs.extend((key, item["repo"], item["path"]) for key, item in external.items())

    def get(spec):
        key, repo, path = spec
        url = f"https://raw.githubusercontent.com/{repo}/{revisions[repo]}/{path}"
        data = download(url)
        (cache / (key + ".source")).write_bytes(data)
        return key, data

    with ThreadPoolExecutor(max_workers=6) as pool:
        inputs = dict(pool.map(get, specs))
    if len(inputs["cn_domains"]) < 100000 or any(len(inputs[ad_choices[name][0]]) < (10000 if name == "AWAvenue" else 100000) for name in selected_ads):
        raise ValueError("Unexpectedly empty major rule source")

    def parsed(key):
        return domains(inputs[key].decode("utf-8-sig"))

    groups = policy["business_groups"]
    boot = [Rule(r[0], r[1]) for r in policy["bootstrap_rules"]]
    categories = [{"id": "bootstrap", "policy": "DIRECT", "rules": minimize(boot)}]
    categories.append({"id": "domestic-ai", "policy": "DIRECT", "rules": minimize(parsed("domestic_ai"))})
    ad_rules = []
    for name in selected_ads:
        key = ad_choices[name][0]
        if key == "ad_rules":
            ad_rules.extend(domains(inputs[key].decode("utf-8-sig")))
        else:
            payload = domain_payload(inputs[key])
            ad_rules.extend(domains("\n".join(payload)))
    categories.append({"id": "ads", "policy": "REJECT", "rules": minimize(ad_rules)})
    for name, key in [("ai", "ai"), ("telegram", "telegram_domains"), ("crypto", "crypto"), ("onedrive", "onedrive"), ("microsoft", "microsoft"), ("apple", "apple"), ("google", "google")]:
        categories.append({"id": name, "policy": groups[name]["name"], "rules": minimize(parsed(key))})
        if name == "telegram":
            categories.append({"id": "telegram-ip", "policy": groups[name]["name"], "rules": addresses(inputs["telegram_ip"].decode())})
    categories.append({"id": "cn-domains", "policy": "DIRECT", "rules": minimize(parsed("cn_domains"))})
    categories.append({"id": "cn-ip", "policy": "DIRECT", "rules": addresses(inputs["cn_ip"].decode())})
    categories.extend({"id": key, "policy": item["policy"], "rules": minimize(classical_domains(inputs[key].decode("utf-8-sig")))} for key, item in external.items())
    category_by_id = {c["id"]: c for c in categories}
    order = policy["routing"]["order"]
    if not order or order[-1] != "final" or len(order) != len(set(order)) or set(order[:-1]) != set(category_by_id):
        raise ValueError("Routing order must list each supported category once, followed by final")
    categories = [category_by_id[name] for name in order[:-1]]
    checks = check(categories)
    fingerprint = hashlib.sha256(policy_file.read_bytes() + Path(__file__).read_bytes() + Path(__file__).with_name("runtime.js").read_bytes() + json.dumps(revisions, sort_keys=True).encode()).hexdigest()[:16]
    version = "v1-" + fingerprint
    output.mkdir(parents=True, exist_ok=True)
    descriptors = []
    upstream = []
    input_keys = {"domestic-ai": "domestic_ai", "telegram": "telegram_domains", "telegram-ip": "telegram_ip", "cn-domains": "cn_domains", "cn-ip": "cn_ip"}
    for category in categories:
        if category["id"] == "ads":
            for name in selected_ads:
                key, repo, _, path = ad_choices[name]
                upstream.append({"id": "ads-" + key.replace("_", "-"), "source_key": key, "category": "ads", "policy": "🛡️ 广告控制", "behavior": "domain", "format": "text" if key == "ad_rules" else "yaml", "url": f"https://raw.githubusercontent.com/{repo}/{repos[repo]}/{path}"})
        elif category["id"] in external:
            key = category["id"]
            item = external[key]
            upstream.append({"id": key, "source_key": key, "category": key, "policy": item["policy"], "behavior": item["behavior"], "format": item["format"], "url": f"https://raw.githubusercontent.com/{item['repo']}/{item['branch']}/{item['path']}"})
        elif category["id"] != "bootstrap":
            key = input_keys.get(category["id"], category["id"])
            upstream.append({"id": category["id"], "source_key": key, "category": category["id"], "policy": category["policy"], "behavior": "ipcidr" if category["id"] in {"telegram-ip", "cn-ip"} else "domain", "format": "text", "url": f"https://raw.githubusercontent.com/{META}/{repos[META]}/{policy['rule_inputs'][key]}"})
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
    _, ad_feed, shadow_count = qx_manual_feeds(categories)
    (output / "qx-ads.list").write_text(qx_text(ad_feed, version))
    manifest = {"qx_business": "qx-off.list", "qx_ads": "qx-ads.list", "qx_ad_priority_copies": shadow_count, "schema": 2, "version": version, "built_at": datetime.now(timezone.utc).isoformat(), "source_revisions": revisions, "source_hashes": {k: hashlib.sha256(v).hexdigest() for k, v in inputs.items()}, "providers": descriptors, "upstream_providers": upstream, "policy": policy, "qx_on": "qx-on.list", "qx_off": "qx-off.list", "checks": checks}
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
