#!/usr/bin/env python3
"""Compare published Mihomo/QX routing artifacts without private profiles.

This is a static comparison under the priority model used by build.py. It does
not execute Quantumult X or verify DNS, rewrites, or device-selected policies.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path


KINDS = {
    "host": "DOMAIN", "host-suffix": "DOMAIN-SUFFIX",
    "host-keyword": "DOMAIN-KEYWORD", "ip-cidr": "IP-CIDR",
    "ip6-cidr": "IP-CIDR6",
}


def policy_name(value):
    return {"direct": "DIRECT", "reject": "REJECT"}.get(value, value)


def mihomo_rules(folder, manifest):
    rules = []
    for order, provider in enumerate(manifest["providers"]):
        policy = "REJECT" if provider["category"] == "ads" else provider["policy"]
        count = 0
        for line in (folder / provider["path"]).read_text().splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if provider["behavior"] == "domain":
                kind = "DOMAIN-SUFFIX" if line.startswith("+.") else "DOMAIN"
                value = line.removeprefix("+.")
            elif provider["behavior"] == "classical":
                kind, value, *_ = line.split(",")
            else:
                raise ValueError("Unsupported provider behavior")
            if kind not in KINDS.values():
                raise ValueError("Unsupported Mihomo rule: " + kind)
            rules.append((order, kind, value, policy, provider["category"]))
            count += 1
        if count != provider["count"]:
            raise ValueError("Provider count differs from manifest: " + provider["id"])
    return rules


def qx_rules(path):
    rules = []
    category = None
    for line in path.read_text().splitlines():
        if line.startswith("# "):
            category = line[2:]
        elif line.strip() and not line.startswith("#"):
            fields = line.split(",")
            if len(fields) != 3 or fields[0] not in KINDS:
                raise ValueError("Unsupported QX rule")
            rules.append((len(rules), KINDS[fields[0]], fields[1], policy_name(fields[2]), category))
    return rules


class Index:
    def __init__(self, rules, fallback):
        self.exact, self.suffix, self.keywords = {}, {}, []
        self.networks = {4: {}, 6: {}}
        self.fallback = fallback
        for order, kind, value, policy, _ in rules:
            action = (order, policy)
            if kind == "DOMAIN":
                self.exact.setdefault(value, action)
            elif kind == "DOMAIN-SUFFIX":
                self.suffix.setdefault(value, action)
            elif kind == "DOMAIN-KEYWORD":
                self.keywords.append((value, action))
            else:
                net = ipaddress.ip_network(value)
                self.networks[net.version].setdefault(net.prefixlen, {}).setdefault(int(net.network_address), action)

    def domain(self, host, qx=False):
        exact = self.exact.get(host)
        labels = host.split(".")
        suffix = [self.suffix[key] for i in range(len(labels)) if (key := ".".join(labels[i:])) in self.suffix]
        keywords = [action for word, action in self.keywords if word in host]
        if qx:
            return (exact or next(iter(suffix), None) or next(iter(keywords), None) or (10**9, self.fallback))[1]
        return min(([exact] if exact else []) + suffix + keywords + [(10**9, self.fallback)])[1]

    def address(self, address, qx=False):
        matches = []
        for prefix, networks in sorted(self.networks[address.version].items(), reverse=True):
            width = address.max_prefixlen - prefix
            network = (int(address) >> width) << width
            if network in networks:
                if qx:
                    return networks[network][1]
                matches.append(networks[network])
        return min(matches + [(10**9, self.fallback)])[1]


def compare(values, left, right):
    mismatches = []
    count = 0
    for value in values:
        count += 1
        a, b = left(value), right(value)
        if a != b:
            mismatches.append({"input": str(value), "mihomo": a, "qx_model": b})
    return {"probes": count, "mismatches": len(mismatches), "examples": mismatches[:20]}


def audit(folder):
    manifest = json.loads((folder / "manifest.json").read_text())
    rules = mihomo_rules(folder, manifest)
    final_id = manifest["policy"]["routing"]["final"]
    fallback = manifest["policy"]["selectors"][final_id]["name"]
    hosts = {value for _, kind, value, _, _ in rules if kind in {"DOMAIN", "DOMAIN-SUFFIX"}}
    hosts.update("probe." + value for _, kind, value, _, _ in rules if kind == "DOMAIN-SUFFIX")
    addresses = set()
    for _, kind, value, _, _ in rules:
        if kind in {"IP-CIDR", "IP-CIDR6"}:
            net = ipaddress.ip_network(value)
            constructor = ipaddress.IPv4Address if net.version == 4 else ipaddress.IPv6Address
            for number in [int(net.network_address) - 1, int(net.network_address), int(net.broadcast_address), int(net.broadcast_address) + 1]:
                if 0 <= number < 2**net.max_prefixlen:
                    addresses.add(constructor(number))
    report = {
        "verified_utc": datetime.now(timezone.utc).isoformat(),
        "version": manifest["version"],
        "scope": "Published rule artifacts; static priority model, not a QX device test",
        "qx_model": "Exact host, longest suffix, keyword; longest IP prefix; first equal-priority entry wins",
        "source_revisions": manifest["source_revisions"],
        "modes": {},
    }
    for mode in ["on", "off"]:
        reference = [rule for rule in rules if mode == "on" or rule[4] != "ads"]
        paths = ([folder / manifest["qx_ads"], folder / manifest["qx_business"]] if mode == "on" else [folder / manifest["qx_business"]]) if manifest.get("qx_ads") else [folder / manifest["qx_" + mode]]
        compiled = []
        for path in paths:
            compiled.extend(qx_rules(path))
            if path.read_text().splitlines()[0] != "# topo unified policy " + manifest["version"]:
                raise ValueError("QX artifact version differs from manifest")
        left, right = Index(reference, fallback), Index(compiled, fallback)
        edge_hosts = [word + "." + suffix for word, _ in left.keywords for suffix in ["google.com", "microsoft.com", "example.org"]]
        report["modes"][mode] = {
            "qx_rules": len(compiled),
            "qx_files": [p.name for p in paths],
            "qx_sha256": hashlib.sha256(b"\n".join(p.read_bytes() for p in paths)).hexdigest(),
            "source_domain_cases": compare(sorted(hosts), left.domain, lambda host: right.domain(host, qx=True)),
            "ip_boundaries": compare(sorted(addresses, key=lambda ip: (ip.version, int(ip))), left.address, lambda ip: right.address(ip, qx=True)),
            "keyword_cross_category_cases": compare(edge_hosts, left.domain, lambda host: right.domain(host, qx=True)),
            "ad_examples": {host: {"mihomo": left.domain(host), "qx_model": right.domain(host, qx=True)} for host in ["ad.mi.com", "googleads.g.doubleclick.net"]},
        }
    report["source_cases_pass"] = all(not result[key]["mismatches"] for result in report["modes"].values() for key in ["source_domain_cases", "ip_boundaries"])
    report["all_probes_match"] = report["source_cases_pass"] and all(not result["keyword_cross_category_cases"]["mismatches"] for result in report["modes"].values())
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    result = audit(args.rules)
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(json.dumps({"version": result["version"], "all_probes_match": result["all_probes_match"]}) if args.quiet else rendered, end="\n" if args.quiet else "")
    raise SystemExit(0 if result["all_probes_match"] else 1)
