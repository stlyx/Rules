# Unified routing resources

`policy.yaml` is the shared policy for Mihomo and Quantumult X. `build.py`
downloads one immutable revision of each public upstream and emits the routing
resources. `runtime.js` assembles platform-specific groups in private Sub-Store
profiles. This directory must never contain subscriptions, proxy credentials,
personal rewrite URLs or MITM private keys.

Active profiles do not fetch routing files or manifests from this repository.
Mihomo references the original MetaCubeX, anti-AD and AWAvenue GitHub URLs,
pinned to one validated revision per upstream. QX uses two scoped Sub-Store
resources backed by the same source snapshot; conversion preserves the shared
priority rules. The generated lists live on the server's persisted filesystem,
outside Sub-Store's configuration database.

`refresh_rules.py` runs daily on the Sub-Store host. It builds a candidate,
checks the shared runtime and native upstream formats with Mihomo, then
atomically advances a local snapshot symlink. Failures retain the last good
snapshot. The installed JSON policy and strict upstream domain-payload reader
allow the host job to use Python's standard library. No management keys or
subscriptions are needed by the refresh job. GitHub Actions validates source
changes and no longer publishes routing artifacts.

QX shadowed exact/suffix rules are removed to preserve the ordered policy;
paused resources are compiled separately to restore the normal business route.
Mihomo keeps the ordinary business providers after the ad provider so `PASS`
continues routing when ad interception is paused.

Regions contain only FlowerCloud nodes and use manual selection, with
experimental nodes listed first. Failover groups are omitted. The main group
defaults to the low-cost airport selector. Mapping order in `policy.yaml`
places the main, low-cost, self-hosted and other node selectors before the
service selectors; Telegram and cryptocurrency are last in both clients.
CF and residential OpenVPN chains are explicit choices; the latter are
Mihomo-only. Their dialer selector offers the low-cost airport, self-hosted,
all-airport and CF selectors, with CF selected by default. The main and
residential selectors are excluded to prevent recursive chains. All group and
dialer dependencies are checked for cycles before returning a profile.
The residential dialer is named `⚡ CF 前置`. QX policy icons use the upstream
Qure icon set through each policy's native `img-url` option.

CMFA 2.11.28.Meta receives a legacy-compatible subset from the same full share:
OpenVPN ciphers unsupported by Mihomo 1.19.25 are omitted, and unused residential
fronts/groups are removed. Desktop clients keep the full residential output.
Responses vary by User-Agent and are not cached. Missing `tls-crypt` fields are
emitted as empty strings for old decoders; supplied keys and ciphers are kept.

Private installation and verification records are maintained in `/opt/topo`
on the owner's workstation, not in this public repository.

`audit_rules.py --rules <snapshot-directory> --output <report.json>` compares
the actual generated Mihomo providers with both QX routing files. It checks
source domains, representative subdomains, IP prefix boundaries, ad pause and
keyword overlaps using a static priority model. Exit status 1 means at least
one modeled probe differs; it must not be described as QX device validation.

Two consistency boundaries require separate attention: the inherited
`oraclecloud` keyword can intersect a lower-priority suffix differently in QX,
and QX refreshes its complete normalized feed while Mihomo pins providers until
its full profile is refreshed. Matching source snapshots do not synchronize
device refresh times or the policies manually selected on each device.
