# Unified routing resources

`policy.yaml` is the shared policy for Mihomo and Quantumult X. `build.py`
downloads one immutable revision of each public upstream and emits the routing
resources. `runtime.js` assembles platform-specific groups in private Sub-Store
profiles. This directory must never contain subscriptions, proxy credentials,
personal rewrite URLs or MITM private keys.

Mihomo tracks the upstream branches of MetaCubeX, anti-AD, AWAvenue and
blackmatrix7 Oracle. Only the small FlowerCloud direct-domain list is hosted
in this repository (`FlowerCloudDirect.list`); profiles do not fetch generated
catalogs or manifests from it. QX uses two scoped Sub-Store
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
Oracle uses the public blackmatrix7 list, below both ad providers. This includes
Oracle corporate domains as maintained upstream; overlapping ad/tracker domains
remain blocked while ads are enabled. FlowerCloud bootstrap domains precede ads.
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

QX rewrite resource labels use `Application · Function`, with aliases recorded
in the shared policy. URLs, order, enable flags and other options are retained;
Baidu Maps explicitly enables the configured resource parser to extract its
comment-wrapped rewrite and MITM sections. Both ad-control bundles use the same
labels/options, so switching ad mode preserves them.
YouTube subtitle translation has been removed from the maintained inventory.

Rewrite resources reference their original upstreams directly, including the full
startup-ad list. The routing builder no longer downloads, filters or publishes
startup rewrites, and no custom-host guard is applied. Upstream overlaps are
accepted. URLs, parser flags and refresh intervals for public modules live in
`policy.yaml`; private owner resources stay only in Sub-Store.

The 12306 rewrite requires `ad.12306.cn` to bypass DNS ad rejection, so QX has
one exact-host direct exception before its fallback. This is a QX rewrite
requirement; Mihomo keeps its domain ad blocking. XiaoHongShu's upstream setup
requires UDP port 443 in QX's `udp_drop_list`. The mixed cleanup modules for
XiaoHongShu and Spotify pause as a whole with ads, including their added features;
Baidu Pan speed, WeChat link unblocking and WeatherKit remain in functional mode.

QX syncs existing remote resources automatically (nodes every 6 hours; routing
and default rewrite resources every 24 hours). Changes to `[policy]` require
updating the complete profile. Resource additions/removals can instead be
applied through the current ad-control page's resource bundle, using the button
for the desired ad mode. These bundles replace all three remote inventories;
they do not replace groups, DNS or MITM settings. The old official remote-managed
configuration documentation is marked `Removed`; no whole-profile background
replacement is configured here.

Private installation and verification records are maintained in `/opt/topo`
on the owner's workstation, not in this public repository.

`audit_rules.py --rules <snapshot-directory> --output <report.json>` compares
the actual generated Mihomo providers with both QX routing files. It checks
source domains, representative subdomains, IP prefix boundaries, ad pause and
keyword overlaps using a static priority model. Exit status 1 means at least
one modeled probe differs; it must not be described as QX device validation.

Each QX build downloads one resolved revision per repository and records SHA
and content hashes for auditing. Mihomo clients fetch branch URLs daily, while
QX receives the server's daily normalized build. Their independent refresh times
can temporarily produce different upstream versions. Device selections are
also independent. The inherited Oracle keyword exception has been removed in
favor of the public list; local/private-network bootstrap rules remain inline.
