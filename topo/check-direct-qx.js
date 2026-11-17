// Validate direct upstream QX resources and client parser output without hosting them.
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm'), assert = require('node:assert/strict');
const manifest = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const cache = process.argv[3];
const parser = fs.readFileSync(path.join(cache, 'resource-parser.js'), 'utf8');
const resources = [];
for (const provider of manifest.upstream_providers) {
  let text = fs.readFileSync(path.join(cache, provider.source_key + '.qx.source'), 'utf8');
  if (provider.qx.opt_parser) {
    let result;
    const context = { $resource: { type: 'filter', link: provider.qx.url, content: text, tag: provider.qx.tag },
      $environment: { version: '1.5.6 build951' }, $notify() {}, $done(value) { result = value; },
      console: { log() {} }, URL, TextEncoder, TextDecoder, atob, btoa };
    vm.createContext(context); vm.runInContext(parser, context, { timeout: 15000 });
    text = typeof result === 'string' ? result : result?.content;
    assert(text, 'Parser returned no rules: ' + provider.id);
  }
  const rules = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || /^\s*[#;]/.test(line)) continue;
    const parts = line.split(',').map(value => value.trim());
    const kind = parts[0].toLowerCase();
    assert(['host', 'host-suffix', 'host-keyword', 'host-wildcard', 'user-agent', 'ip-cidr', 'ip6-cidr', 'ip-asn', 'geoip'].includes(kind), 'Unexpected upstream QX kind: ' + kind);
    assert(parts.length >= 3 && parts[1], 'Invalid QX resource row: ' + provider.id);
    rules.push({ kind, value: parts[1], policy: provider.qx.policy, id: provider.id, category: provider.category });
  }
  assert(rules.length > 0, 'Empty resource: ' + provider.id);
  resources.push(...rules);
}
for (const [kind, value] of manifest.policy.bootstrap_rules) {
  if (kind === 'DOMAIN-SUFFIX') resources.unshift({ kind: 'host-suffix', value, policy: 'direct', category: 'bootstrap' });
}
function suffixes(value) { const labels = value.split('.'); return labels.map((_, index) => labels.slice(index).join('.')); }
function classify(host, ads) {
  const rows = resources.filter(r => ads || r.category !== 'ads');
  let best;
  for (let index = 0; index < rows.length; index++) {
    const row = rows[index]; let rank = 0;
    if (row.kind === 'host' && row.value === host) rank = 3e5;
    else if (row.kind === 'host-suffix' && suffixes(host).includes(row.value)) rank = 2e5 + row.value.length;
    else if (row.kind === 'host-keyword' && host.includes(row.value)) rank = 1e5;
    if (rank && (!best || rank > best.rank)) best = { rank, policy: row.policy };
  }
  return best?.policy || manifest.policy.selectors.main.name;
}
for (const [host, expected] of Object.entries(manifest.checks)) {
  const policy = expected === 'DIRECT' ? 'direct' : expected;
  assert.equal(classify(host, true), policy, 'Normal route: ' + host);
  assert.equal(classify(host, false), policy, 'Ads disabled route: ' + host);
}
for (const [host, normal] of [['ad.mi.com', 'direct'], ['googleads.g.doubleclick.net', manifest.policy.business_groups.google.name], ['addthis.com', 'direct']]) {
  assert.equal(classify(host, true), 'reject', 'Ad route: ' + host);
  assert.equal(classify(host, false), normal, 'Restored route: ' + host);
}
console.log(JSON.stringify({ providers: manifest.upstream_providers.length, upstream_qx_rules: resources.length, hostname_cases: Object.keys(manifest.checks).length, ad_toggle_cases: 6, client_parser_checked: true }));
