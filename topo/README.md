# Unified routing resources

`policy.yaml` is the shared policy for Mihomo and Quantumult X. `build.py`
downloads one immutable revision of each public upstream and emits the routing
resources. `runtime.js` assembles platform-specific groups in private Sub-Store
profiles. This directory must never contain subscriptions, proxy credentials,
personal rewrite URLs or MITM private keys.

The GitHub workflow refreshes daily and retains the last published snapshot on
download, syntax or classification failure. Mihomo profiles follow `latest.json`
and pin all provider URLs to its immutable commit. QX reads one complete routing
file per mode (`qx-on.list` or `qx-off.list`), so categories update together.

QX shadowed exact/suffix rules are removed to preserve the ordered policy;
paused resources are compiled separately to restore the normal business route.
Mihomo keeps the ordinary business providers after the ad provider so `PASS`
continues routing when ad interception is paused.

Regions contain only FlowerCloud nodes. Same-region fallback prefers the
experimental nodes. CF and residential OpenVPN chains are explicit choices;
the latter are Mihomo-only and must retain their CF dialer group.

Private installation and verification records are maintained in `/opt/topo`
on the owner's workstation, not in this public repository.
