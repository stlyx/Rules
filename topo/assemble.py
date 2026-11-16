#!/usr/bin/env python3
"""Assemble private Sub-Store resource candidates; never publish this output.

Inputs include a private storage snapshot and native per-source node exports.
This command does not modify the live backend.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import secrets
import urllib.parse

import yaml

ROOT = Path(__file__).parent


def span(lines, section):
    start = next(i for i, line in enumerate(lines) if line.strip() == "[" + section + "]")
    end = next((i for i in range(start + 1, len(lines)) if re.fullmatch(r"\s*\[[^]]+\]\s*", lines[i])), len(lines))
    return start, end


def section(text, name):
    lines = text.splitlines()
    try:
        start, end = span(lines, name)
    except StopIteration:
        return []
    return lines[start + 1:end]


def replace(text, name, values):
    lines = text.splitlines()
    try:
        start, end = span(lines, name)
    except StopIteration:
        return text.rstrip() + "\n\n[" + name + "]\n" + "\n".join(values) + "\n"
    lines[start + 1:end] = values + [""]
    return "\n".join(lines) + "\n"


def active(line):
    return bool(line.strip()) and not line.lstrip().startswith(("#", ";"))


def tag(line):
    match = re.search(r"\btag\s*=\s*([^,]+)", line)
    return match.group(1).strip() if match else ""


def rewrite_module(line, policy):
    label = tag(line)
    return next(((key, item) for key, item in policy["qx"]["rewrite_modules"].items()
                 if label == item["tag"] or label in item.get("legacy_tags", [])), (None, None))


def normalize_rewrite(line, policy):
    _, module = rewrite_module(line, policy)
    if module is None or not active(line):
        return line
    line = re.sub(r"(,\s*tag\s*=\s*)[^,]+", lambda m: m[1] + module["tag"], line)
    if module.get("url"):
        line = re.sub(r"^[^,\s]+(?=\s*,)", lambda _: module["url"], line)
    options = {"opt-parser": str(module["opt_parser"]).lower() if "opt_parser" in module else None,
               "update-interval": module.get("update_interval"), "img-url": module.get("img_url")}
    for key, value in options.items():
        if value is None:
            continue
        pattern = r"(^|,)(\s*" + key + r"\s*=\s*)[^,]+"
        line = re.sub(pattern, lambda m: m[1] + m[2] + str(value), line) if re.search(pattern, line) else line + ", " + key + "=" + str(value)
    return line


def rewrite_resource(module):
    fields = [module["url"], "tag=" + module["tag"]]
    if module.get("img_url"):
        fields.append("img-url=" + module["img_url"])
    fields += ["update-interval=" + str(module.get("update_interval", 86400)),
               "opt-parser=" + str(module.get("opt_parser", False)).lower(),
               "enabled=" + str(module.get("enabled", True)).lower()]
    return ", ".join(fields)


def enabled(line):
    return not bool(re.search(r"\benabled\s*=\s*false\b", line, re.I))


def share(name, token):
    return "https://sub.stlyx.com/share/file/" + name + "?" + urllib.parse.urlencode({"token": token})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    args = parser.parse_args()
    folder = args.state_dir
    os.umask(0o077)
    storage = json.loads((folder / "storage.before.json").read_text())
    original_files = {x["name"]: x for x in storage["files"]}
    manifest = json.loads((folder / "generated/manifest.json").read_text())
    policy = manifest["policy"]
    tokens = {x["name"]: x["token"] for x in storage["tokens"]}
    nodes_url = "https://sub.stlyx.com/share/col/all?" + urllib.parse.urlencode({"token": tokens["all"], "target": "QX"})
    allocations = folder / "new-tokens.private.json"
    allocated = json.loads(allocations.read_text()) if allocations.exists() else {}
    new_tokens = {name: tokens.get(name) or allocated.get(name) or secrets.token_urlsafe(24) for name in ["qx-routing", "qx-ads"]}
    allocations.write_text(json.dumps(new_tokens))
    rule_links = {"rules": share("qx-routing", new_tokens["qx-routing"]), "ads": share("qx-ads", new_tokens["qx-ads"])}
    rule_files = []
    for name, label, path in [("qx-routing", "业务分流", manifest["qx_business"]), ("qx-ads", "广告拦截", manifest["qx_ads"])]:
        code = '$content = require("fs").readFileSync(' + json.dumps("/opt/app/data/topo-rules/current/" + path) + ', "utf8");\n$options ||= {}; $options._res = { headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } };'
        rule_files.append({"name": name, "displayName": "QX · " + label, "source": "local", "sourceType": "local", "content": "", "noCache": True, "process": [{"type": "Script Operator", "args": {"mode": "script", "content": code}}]})

    text = original_files["qx-diy"]["content"]
    original_rewrites = [line for line in section(text, "rewrite_remote") if active(line)]
    travel = [line for line in original_rewrites if "旅行串串" in tag(line)]
    if len(travel) != 4:
        raise ValueError("Expected all four owner travel resources")
    new_rewrites, categories, seen = [], {}, set()
    for old in original_rewrites:
        key, module = rewrite_module(old, policy)
        if key is None:
            continue
        if key in seen:
            raise ValueError("Duplicate preserved rewrite module: " + key)
        seen.add(key)
        line = normalize_rewrite(old, policy)
        new_rewrites.append(line)
        categories[tag(line)] = module["category"]
    for key, module in policy["qx"]["rewrite_modules"].items():
        if key not in seen and module.get("url"):
            new_rewrites.append(rewrite_resource(module))
            categories[module["tag"]] = module["category"]
            seen.add(key)
    if seen != set(policy["qx"]["rewrite_modules"]):
        raise ValueError("Preserved rewrite inventory mismatch")
    base = replace(text, "rewrite_remote", new_rewrites)
    base = replace(base, "filter_remote", [rule_links[key] + ", tag=" + label + ", update-interval=86400, opt-parser=false, inserted-resource=true, enabled=true" for key, label in [("ads", "广告拦截"), ("rules", "业务分流")]])
    base = replace(base, "task_local", [line for line in section(base, "task_local") if "qx-ad-control-task" not in line])
    runtime = (ROOT / "runtime.js").read_text()
    qx = copy.deepcopy(original_files["qx-diy"])
    qx["displayName"] = "Quantumult X · 统一配置"
    qx["content"] = base
    bindings = {"nodes": nodes_url, **rule_links}
    code = runtime + "\nconst TOPO_SEED = " + json.dumps(manifest, ensure_ascii=False) + ";\nconst TOPO_BINDINGS = " + json.dumps(bindings, ensure_ascii=False) + ";\n$content = topoQxConfig($content, await topoManifest(TOPO_SEED), TOPO_BINDINGS);\n"
    qx["process"] = [{"type": "Script Operator", "args": {"mode": "script", "content": code}}]

    mihomo = copy.deepcopy(original_files["withlow-mihomo"])
    template = yaml.safe_load(mihomo["content"])
    for key in list(template):
        if key.startswith("x-topo-"):
            del template[key]
    legacy = {}
    for source in ["bwh", "ora", "flowercloud", "pages"]:
        before = yaml.safe_load((folder / (source + ".before.yaml")).read_text())["proxies"]
        projection = json.loads((folder / (source + ".mihomo.preview.private.json")).read_text())["data"]["processed"]
        strips = lambda name: re.sub(r"^(?:(?:[\U0001F1E6-\U0001F1FF]{2}|🏴‍☠️|🏳️‍🌈)\s*)+", "", name)
        by_core = {strips(p["name"]).split("] ", 1)[-1]: p["name"] for p in projection}
        for node in before:
            core = strips(node["name"])
            if core in by_core:
                legacy[core] = by_core[core]
    template["x-topo-policy-seed"] = manifest
    template["x-topo-legacy-provenance"] = legacy
    mihomo["content"] = yaml.safe_dump(template, allow_unicode=True, sort_keys=False)
    mihomo["displayName"] = "统一 Mihomo · 花云主力与独立业务"
    mihomo["process"] = [p for p in mihomo.get("process", []) if p.get("type") == "Add Proxies From Subscription Operator"]
    if len(mihomo["process"]) != 1:
        raise ValueError("Missing native node collection operator")
    code = runtime + "\nasync function main(config) { return topoMihomo(config, await topoManifest(config['x-topo-policy-seed'])); }\n"
    mihomo["process"].append({"type": "Script Operator", "args": {"mode": "script", "content": code}})
    definitions = [mihomo, qx, *rule_files]
    (folder / "files.next.private.json").write_text(json.dumps(definitions, ensure_ascii=False, indent=2))
    assert [line for line in new_rewrites if "旅行串串" in tag(line)] == [normalize_rewrite(line, policy) for line in travel]
    assert section(base, "mitm") == section(text, "mitm")
    print(json.dumps({"files": [x["name"] for x in definitions], "travel_preserved": len(travel), "rewrite_resources": len(new_rewrites), "node_resource_count": 1, "new_scoped_tokens": len(new_tokens), "manual_ad_control": True}, ensure_ascii=False))



if __name__ == "__main__":
    main()
