# Shared groups and direct upstream rule URLs

`policy.yaml` owns the group layout, business defaults, public upstream URLs and
QX rewrite inventory. `build.py` emits URL metadata only: it never downloads,
converts, merges or publishes rule contents. `runtime.js` builds the two private
Sub-Store profiles from that embedded metadata; it does not read a disk manifest.

Mihomo and QX download their rule resources directly from the same upstream
families. Business categories use blackmatrix7's respective Clash/QX formats;
AI uses ACL4SSR's aggregate list; ads use anti-AD and AWAvenue. The two small
FlowerCloud bootstrap exceptions remain in `FlowerCloudDirect.list`, as agreed.
Oracle stays below ads. Every URL follows its upstream branch.

QX uses native QX lists where available. ACL4SSR AI, FlowerCloud's classical list
and AWAvenue's list use the already configured KOP-XIAO resource parser on the
client. No Sub-Store conversion or rule-file shares are involved. Each resource
sets `force-policy` to the existing business group, DIRECT or REJECT. Users toggle
ad resources and rewrites in QX; there are no ad-control pages or tasks.

Upstream lists and native client matchers differ: some native formats include
process, user-agent, ASN or wildcard entries. Those contents are used as published;
this project no longer normalizes every overlap between clients. Group names,
defaults and category order remain shared. Representative route and ad priority
checks validate both clients' intended groups; they do not assert identical
classification for every possible hostname or replace QX device testing.

Sub-Store retains only `withlow-mihomo` and `qx-diy`. Nodes still come from the
owner's `all` collection. There is no daily server rule downloader, normalization
job, rule directory or hosted QX routing/ads file. Clients handle their own updates.

QX has 22 upstream rewrite resources, preserving the four private owner travel
entries. Startup ads use the complete upstream without overlap filtering or
custom-host protection. Baidu Maps, Baidu Pan scripts and 12306 use the resource
parser as required. QX keeps UDP 443 disabled for XiaoHongShu's rewrite and one
exact 12306 direct exception for its response replacement. Location and YouTube
subtitle translation are omitted.

Source changes run read-only checks: `validate_upstreams.py` downloads sources to
a temporary CI/local cache, `check-direct-qx.js` checks native QX and client parser
output, and `check_core.py` loads the upstream formats in a real Mihomo core.
No rules are uploaded or served by these checks.

Selectors remain manual, with source selectors before services and Telegram/
cryptocurrency last. Regions contain only FlowerCloud nodes. NanoCloud is a
separate manual secondary airport selector, selectable from the main/Google/
Telegram/crypto groups. It stays outside FlowerCloud regions and the four CF
front choices. Upstream fetching uses a fixed Mihomo user-agent. Mihomo exports
VLESS and TUIC; QX exports compatible VLESS nodes and omits unsupported TUIC nodes.
CF residential fronts remain explicit and cycle checked. CMFA 2.11.28.Meta receives
the legacy-compatible subset from the same original share; desktop retains
residential OpenVPN support. Missing `tls-crypt` fields are emitted as empty
strings; supplied keys are kept.

The `all` collection runs `flag-operator.js` after the native Flag Operator. It
uses Sub-Store's country database, adds 香江→香港 and 西美→美国 as matching aliases,
and excludes the parenthesized 流量 usage label from country detection. Display
labels and connection fields are preserved. This prevents traffic variants from
being displayed with a rainbow flag.

Never commit subscriptions, proxy credentials, personal rewrite URLs, MITM keys or
management URLs. Private deployment records stay in `/opt/topo` on the workstation.
