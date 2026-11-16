#!/usr/bin/env python3
"""Load generated providers in a real Mihomo core and check routing/ads PASS.

All test connections are rejected locally. No private subscriptions or actual
proxy credentials are used, and no target website connection is established.
"""
import argparse
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

try:
    import yaml
except ImportError:
    yaml = None


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--upstream", action="store_true", help="Validate the native formats downloaded from upstream")
    parser.add_argument("--source-cache", type=Path)
    args = parser.parse_args()
    manifest = json.loads((args.rules / "manifest.json").read_text())
    proxy_port, controller = port(), port()
    with tempfile.TemporaryDirectory(prefix="topo-core-check-") as tmp:
        home = Path(tmp)
        descriptors = manifest["upstream_providers"] if args.upstream else manifest["providers"]
        if args.upstream and not args.source_cache:
            raise ValueError("Upstream validation requires --source-cache")
        policies = {p["policy"] for p in descriptors} | {"🚀 主力出口"}
        groups = [{"name": p, "type": "select", "proxies": ["REJECT", "PASS"] if p == "🛡️ 广告控制" else ["REJECT"]} for p in sorted(policies - {"DIRECT"})]
        groups.append({"name": "🧪 直连", "type": "select", "proxies": ["REJECT"]})
        providers, rules = {}, []
        if args.upstream:
            rules = [kind + "," + value + ",🧪 直连" + (",no-resolve" if kind.startswith("IP-CIDR") else "") for kind, value in manifest["policy"]["bootstrap_rules"]]
        for provider in descriptors:
            name = provider["id"]
            file = home / (name + ".list")
            shutil.copyfile(args.source_cache / (provider["source_key"] + ".source") if args.upstream else args.rules / provider["path"], file)
            providers[name] = {"type": "file", "behavior": provider["behavior"], "format": provider["format"] if args.upstream else "text", "path": file.name}
            policy = "🧪 直连" if provider["policy"] == "DIRECT" else provider["policy"]
            rules.append(f"RULE-SET,{name},{policy}" + (",no-resolve" if args.upstream and provider["category"] == "telegram-ip" else ""))
        rules.append("MATCH,🚀 主力出口")
        config = {"mixed-port": proxy_port, "bind-address": "127.0.0.1", "external-controller": f"127.0.0.1:{controller}", "allow-lan": False, "mode": "rule", "log-level": "info", "find-process-mode": "off", "dns": {"enable": False}, "proxies": [], "proxy-groups": groups, "rule-providers": providers, "rules": rules}
        (home / "config.yaml").write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False) if yaml else json.dumps(config, ensure_ascii=False))
        with (home / "core.log").open("w") as log:
            process = subprocess.Popen([str(args.core.resolve()), "-d", str(home), "-f", str(home / "config.yaml")], stdout=log, stderr=subprocess.STDOUT)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError("Validation core exited; generated rule syntax failed")
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{controller}/providers/rules", timeout=1) as response:
                            state = json.load(response)
                        loaded = state.get("providers") or {}
                        if len(loaded) == len(providers) and all(p.get("ruleCount", 0) > 0 for p in loaded.values()):
                            break
                    except OSError:
                        pass
                    time.sleep(.1)
                else:
                    raise RuntimeError("Generated providers did not load")

                def connection(host, expected):
                    with socket.create_connection(("127.0.0.1", proxy_port), timeout=4) as conn:
                        conn.settimeout(8)
                        conn.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
                        conn.recv(4096)
                    for _ in range(20):
                        text = (home / "core.log").read_text(errors="replace")
                        lines = [l for l in text.splitlines() if " --> " + host + ":443 " in l]
                        if lines and "using " + expected + "[" in lines[-1]:
                            return
                        time.sleep(.05)
                    raise AssertionError("Unexpected core classification for " + host + "; expected " + expected)

                checked = 0
                for host, expected in manifest["checks"].items():
                    if host == "example.org":
                        continue  # The pure fallback case is covered without DNS in build.py.
                    connection(host, "🧪 直连" if expected == "DIRECT" else expected)
                    checked += 1
                for host in ["ad.mi.com", "googleads.g.doubleclick.net"]:
                    connection(host, "🛡️ 广告控制")
                request = urllib.request.Request(f"http://127.0.0.1:{controller}/proxies/" + urllib.parse.quote("🛡️ 广告控制"), data=json.dumps({"name": "PASS"}).encode(), method="PUT", headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(request, timeout=3) as response:
                    assert response.status in {200, 204}
                connection("ad.mi.com", "🧪 直连")
                connection("googleads.g.doubleclick.net", "🌐 谷歌服务")
                print(json.dumps({"core_provider_load": True, "business_cases": checked, "ad_block_and_pass_cases": 4, "pass_restores_domestic_and_google_routing": True}, ensure_ascii=False))
            finally:
                process.terminate()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
