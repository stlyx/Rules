// Shared Sub-Store runtime. The same policy IDs drive Mihomo and QX groups.
// The installer appends either a main(config) wrapper or a QX file wrapper.
const TOPO_RULES_ROOT = '/opt/app/data/topo-rules/current';
const TOPO_COUNTRIES = {
  US: { name: '🇺🇸 美国', pattern: '(?:美国|美國|United States|\\bUS\\b)' },
  HK: { name: '🇭🇰 香港', pattern: '(?:香港|Hong Kong|\\bHK\\b)' },
  JP: { name: '🇯🇵 日本', pattern: '(?:日本|Japan|\\bJP\\b)' },
  SG: { name: '🇸🇬 新加坡', pattern: '(?:新加坡|狮城|Singapore|\\bSG\\b)' },
  TR: { name: '🇹🇷 土耳其', pattern: '(?:土耳其|Turkey|Türkiye|\\bTR\\b)' },
  TW: { name: '🇹🇼 台湾', pattern: '(?:台湾|台灣|Taiwan|\\bTW\\b)' },
  KR: { name: '🇰🇷 韩国', pattern: '(?:韩国|韓國|Korea|\\bKR\\b)' },
};

async function topoManifest(seed) {
  try {
    const manifest = JSON.parse(require('fs').readFileSync(TOPO_RULES_ROOT + '/manifest.json', 'utf8'));
    if (manifest.schema !== 2 || !manifest.upstream_providers?.length || !manifest.policy?.business_groups || manifest.policy.layout !== seed.policy.layout) {
      throw new Error('Incomplete unified policy');
    }
    return manifest;
  } catch (error) {
    if (seed?.schema !== 2 || !seed.upstream_providers?.length) throw error;
    $substore.error('Using the last valid unified policy snapshot');
    return seed;
  }
}

function topoNames(policy) {
  const names = Object.fromEntries(Object.entries(policy.selectors).map(([id, s]) => [id, s.name]));
  for (const [country, item] of Object.entries(TOPO_COUNTRIES)) names['region-' + country] = item.name;
  return names;
}

function topoRegionRegex(country) {
  return `^(?=[^\\[]*\\[花云\\])(?=.*${TOPO_COUNTRIES[country].pattern}).*$`;
}

function topoRank(nodes) {
  return nodes.map((node, index) => ({ node, index })).sort((a, b) =>
    Number(!/实验/.test(a.node.name)) - Number(!/实验/.test(b.node.name)) || a.index - b.index,
  ).map(item => item.node.name);
}

function topoOrderGroups(groups, policy) {
  const order = [
    ...Object.values(policy.selectors).map(item => item.name),
    policy.chain_front.name,
    ...[...policy.regions.required, ...policy.regions.optional].map(country => TOPO_COUNTRIES[country].name),
    '♻️ 花云自动', '♻️ CF 自动', '🛡️ 广告控制',
    ...Object.values(policy.business_groups).map(item => item.name),
  ];
  const ranks = new Map(order.map((name, index) => [name, index]));
  for (const group of groups) if (!ranks.has(group.name)) throw new Error('Missing display order: ' + group.name);
  return [...groups].sort((a, b) => ranks.get(a.name) - ranks.get(b.name));
}

function topoMihomo(config, manifest) {
  const policy = manifest.policy;
  const requestOptions = typeof $options === 'object' ? $options : null;
  const userAgent = String(requestOptions?._req?.headers?.['user-agent'] || '');
  const androidLegacy = config['x-topo-compatibility'] === 'android-legacy' || /^ClashMetaForAndroid\/2\.11\.28\.Meta(?:\s|$)/i.test(userAgent);
  if (requestOptions) {
    requestOptions._res ||= {};
    requestOptions._res.headers = { ...requestOptions._res.headers, vary: 'User-Agent', 'cache-control': 'no-store' };
  }
  // A private migration map keeps the existing share usable while individual
  // source processors are patched. Already tagged nodes bypass this map.
  const legacy = config['x-topo-legacy-provenance'] || {};
  const leadingFlag = /^(?:(?:\p{Regional_Indicator}{2}|🏴‍☠️|🏳️‍🌈)\s*)+/u;
  let nodes = (config.proxies || []).filter(p => !/^(?:Traffic:|Expire:|剩余流量|套餐到期)/i.test(p.name.replace(leadingFlag, ''))).map(p => {
    if (/\[(?:花云|CF|家宽|家宽前置|自建\/bwh|自建\/ora)\]/.test(p.name)) return p;
    const mapped = legacy[p.name.replace(leadingFlag, '')];
    if (!mapped) return p;
    return { ...p, name: leadingFlag.test(mapped) ? mapped : (p.name.match(leadingFlag)?.[0] || '') + mapped };
  }).map(p => p['dialer-proxy'] === '⚡ CF前置' ? { ...p, 'dialer-proxy': policy.chain_front.name } : p)
    // Mihomo 1.19.25 requires the key even when TLS-Crypt is unused.
    .map(p => p.type === 'openvpn' && p['tls-crypt'] == null ? { ...p, 'tls-crypt': '' } : p);
  const origin = p => p.name.replace(leadingFlag, '').match(/^\[([^\]]+)\]\s/)?.[1];
  if (androidLegacy) {
    const supported = new Set(['AES-128-GCM', 'AES-256-GCM']);
    nodes = nodes.filter(p => p.type !== 'openvpn' || supported.has(String(p.cipher || '').toUpperCase()));
    if (!nodes.some(p => p.type === 'openvpn')) nodes = nodes.filter(p => origin(p) !== '家宽前置');
  }
  config.proxies = nodes;
  const airport = nodes.filter(p => origin(p) === '花云');
  const self = nodes.filter(p => /^(?:自建\/bwh|自建\/ora)$/.test(origin(p) || ''));
  const cf = nodes.filter(p => origin(p) === 'CF');
  const home = nodes.filter(p => origin(p) === '家宽' && p.type === 'openvpn');
  if (!airport.length || !self.length || !cf.length) throw new Error('Missing required node source');
  const names = topoNames(policy);
  const groups = [];
  const options = { url: 'https://www.gstatic.com/generate_204', interval: 300, lazy: true, timeout: 5000, 'expected-status': 204 };
  function group(name, type, members, extra = {}) {
    if (!members.length) throw new Error('Empty group: ' + name);
    groups.push({ name, type, proxies: [...new Set(members)], ...(type === 'select' ? {} : options), ...extra });
  }
  const regionIds = [];
  for (const country of [...policy.regions.required, ...policy.regions.optional]) {
    const found = airport.filter(p => new RegExp(TOPO_COUNTRIES[country].pattern, 'i').test(p.name));
    if (!found.length) {
      if (policy.regions.required.includes(country)) throw new Error('Missing airport region: ' + country);
      continue;
    }
    regionIds.push('region-' + country);
    const sorted = topoRank(found);
    const label = TOPO_COUNTRIES[country].name;
    group(label, 'select', sorted);
  }
  group(names['airport-low'], 'select', topoRank(airport.filter(p => /实验/.test(p.name))));
  group('♻️ 花云自动', 'url-test', topoRank(airport), { interval: 600, tolerance: 80 });
  group(names['airport-all'], 'select', ['♻️ 花云自动', ...topoRank(airport)]);
  const orderedSelf = [...self].sort((a, b) => Number(!/\[自建\/bwh\].*reality\+vision/.test(a.name)) - Number(!/\[自建\/bwh\].*reality\+vision/.test(b.name))).map(p => p.name);
  group(names['self-hosted'], 'select', orderedSelf);
  group('♻️ CF 自动', 'url-test', cf.map(p => p.name), { interval: 600, tolerance: 80 });
  group(names['cf-backup'], 'select', ['♻️ CF 自动', ...cf.map(p => p.name)]);
  if (home.length) {
    const front = policy.chain_front;
    const frontIds = [front.default, ...front.choices.filter(id => id !== front.default)];
    const allowed = new Set(['airport-low', 'self-hosted', 'airport-all', 'cf-backup']);
    if (frontIds.some(id => !allowed.has(id))) throw new Error('Unsupported residential front choice');
    group(front.name, 'select', frontIds.map(id => names[id]));
    const preferred = [...home].sort((a, b) => Number(!/HK-家宽/.test(a.name)) - Number(!/HK-家宽/.test(b.name)));
    group(names['home-chain'], 'select', preferred.map(p => p.name));
  }
  const validIds = new Set(['DIRECT', ...Object.keys(policy.selectors).filter(id => id !== 'home-chain' || home.length), ...regionIds]);
  function candidates(items) { return items.filter(id => validIds.has(id)).map(id => names[id] || id); }
  group(names.main, 'select', candidates([policy.selectors.main.default, ...policy.selectors.main.choices.filter(id => id !== policy.selectors.main.default)]));
  const business = [];
  for (const [id, definition] of Object.entries(policy.business_groups)) {
    const choices = [definition.default, ...definition.choices.filter(v => v !== definition.default)];
    const members = candidates(choices);
    business.push({ name: definition.name, type: 'select', proxies: [...new Set(members)] });
  }
  group('🛡️ 广告控制', 'select', ['REJECT', 'PASS']);
  config['proxy-groups'] = topoOrderGroups([...groups, ...business], policy);
  config['rule-providers'] = {};
  config.rules = policy.bootstrap_rules.map(([kind, value]) => kind + ',' + value + ',DIRECT' + (kind.startsWith('IP-CIDR') ? ',no-resolve' : ''));
  for (const provider of manifest.upstream_providers) {
    const id = 'topo-' + provider.id;
    const revision = provider.url.split('/')[5];
    if (!/^https:\/\/raw\.githubusercontent\.com\/[^/]+\/[^/]+\/[a-zA-Z0-9._-]+\/.+/.test(provider.url) || !/^[a-zA-Z0-9._-]+$/.test(revision)) throw new Error('Invalid upstream provider URL');
    config['rule-providers'][id] = { type: 'http', behavior: provider.behavior, format: provider.format, url: provider.url, path: './rule-providers/' + id + '-' + (revision.length === 40 ? revision.slice(0, 12) : revision) + (provider.format === 'yaml' ? '.yaml' : '.list'), interval: 86400, proxy: names.main };
    config.rules.push(`RULE-SET,${id},${provider.policy}` + (provider.category === 'telegram-ip' ? ',no-resolve' : ''));
  }
  config.rules.push('MATCH,' + names.main);
  const known = new Set([...nodes.map(p => p.name), ...config['proxy-groups'].map(g => g.name), 'DIRECT', 'REJECT', 'PASS']);
  for (const g of config['proxy-groups']) for (const n of g.proxies) if (!known.has(n)) throw new Error('Unresolved group member: ' + n);
  for (const p of nodes) if (p['dialer-proxy'] && !known.has(p['dialer-proxy'])) throw new Error('Unresolved chain front');
  const dependencies = new Map(config['proxy-groups'].map(g => [g.name, g.proxies]));
  for (const p of nodes) if (p['dialer-proxy']) dependencies.set(p.name, [p['dialer-proxy']]);
  const visiting = new Set(), visited = new Set();
  function visit(name) {
    if (visiting.has(name)) throw new Error('Proxy dependency cycle: ' + name);
    if (visited.has(name)) return;
    visiting.add(name);
    for (const member of dependencies.get(name) || []) visit(member);
    visiting.delete(name);
    visited.add(name);
  }
  for (const name of dependencies.keys()) visit(name);
  for (const key of Object.keys(config)) if (key.startsWith('x-topo-')) delete config[key];
  return config;
}

function topoQxPolicies(policy) {
  const names = topoNames(policy);
  const lines = [];
  const regions = [...policy.regions.required, ...policy.regions.optional];
  const valid = new Set(['DIRECT', ...Object.keys(policy.selectors).filter(id => id !== 'home-chain'), ...regions.map(c => 'region-' + c)]);
  const get = id => id === 'DIRECT' ? 'direct' : names[id];
  function select(name, ids) { lines.push('static=' + name + ', ' + [...new Set(ids.filter(id => valid.has(id)).map(get))].join(', ')); }
  select(names.main, [policy.selectors.main.default, ...policy.selectors.main.choices.filter(id => id !== policy.selectors.main.default)]);
  for (const definition of Object.values(policy.business_groups)) select(definition.name, [definition.default, ...definition.choices.filter(v => v !== definition.default)]);
  lines.push(`static=${names['airport-low']}, server-tag-regex=^(?=[^\\[]*\\[花云\\])(?=.*实验).*$`);
  lines.push('url-latency-benchmark=♻️ 花云自动, server-tag-regex=^[^\\[]*\\[花云\\], check-interval=600, tolerance=80, alive-checking=false');
  lines.push(`static=${names['airport-all']}, ♻️ 花云自动, server-tag-regex=^[^\\[]*\\[花云\\]`);
  lines.push(`static=${names['self-hosted']}, server-tag-regex=^[^\\[]*\\[自建/(?:bwh|ora)\\]`);
  lines.push('url-latency-benchmark=♻️ CF 自动, server-tag-regex=^[^\\[]*\\[CF\\], check-interval=600, tolerance=80, alive-checking=false');
  lines.push(`static=${names['cf-backup']}, ♻️ CF 自动, server-tag-regex=^[^\\[]*\\[CF\\]`);
  for (const country of regions) {
    const label = TOPO_COUNTRIES[country].name;
    lines.push(`static=${label}, server-tag-regex=${topoRegionRegex(country)}`);
  }
  const groups = lines.map(line => ({ name: line.split(',')[0].split('=')[1], line }));
  const ids = new Map([
    ...Object.entries(policy.selectors).map(([id, item]) => [item.name, id]),
    ...Object.entries(policy.business_groups).map(([id, item]) => [item.name, id]),
    ...regions.map(country => [TOPO_COUNTRIES[country].name, 'region-' + country]),
    ['♻️ 花云自动', 'airport-auto'], ['♻️ CF 自动', 'cf-auto'],
  ]);
  return topoOrderGroups(groups, policy).map(group => {
    const icon = policy.qx.policy_icons[ids.get(group.name)];
    if (!icon) throw new Error('Missing QX policy icon: ' + group.name);
    return group.line + ', img-url=' + policy.qx.policy_icon_base + icon;
  }).join('\n') + '\n';
}

function topoReplaceSection(text, section, content) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex(line => line.trim() === '[' + section + ']');
  if (start < 0) return text.trimEnd() + '\n\n[' + section + ']\n' + content + '\n';
  let end = lines.findIndex((line, i) => i > start && /^\s*\[[^\]]+\]\s*$/.test(line));
  if (end < 0) end = lines.length;
  lines.splice(start + 1, end - start - 1, ...content.trimEnd().split('\n'), '');
  return lines.join('\n');
}

function topoQxRewriteLine(line, policy) {
  const match = line.match(/(?:^|,)\s*tag\s*=\s*([^,]+)/);
  if (!match || /^\s*[#;]/.test(line)) return line;
  const tag = match[1].trim();
  const module = Object.values(policy.qx.rewrite_modules).find(item => item.tag === tag || (item.legacy_tags || []).includes(tag));
  if (!module) return line;
  line = line.replace(/(,\s*tag\s*=\s*)[^,]+/, '$1' + module.tag);
  if (typeof module.opt_parser === 'boolean') {
    const value = 'opt-parser=' + module.opt_parser;
    line = /(?:^|,)\s*opt-parser\s*=/.test(line)
      ? line.replace(/opt-parser\s*=\s*[^,]+/, value)
      : line + ', ' + value;
  }
  return line;
}

function topoQxConfig(text, manifest, bindings) {
  text = topoReplaceSection(text, 'policy', topoQxPolicies(manifest.policy));
  text = topoReplaceSection(text, 'server_remote', bindings.nodes + ', tag=pnodes, update-interval=21600, opt-parser=false, enabled=true');
  text = topoReplaceSection(text, 'server_local', '');
  if (!bindings.rules) throw new Error('Missing upstream QX routing feed');
  text = topoReplaceSection(text, 'filter_remote', bindings.rules + ', tag=统一分流 · 上游同步, update-interval=86400, opt-parser=false, inserted-resource=true, enabled=true');
  text = topoReplaceSection(text, 'filter_local', 'final,🚀 主力出口');
  let section = '';
  text = text.split('\n').map(line => {
    const header = line.trim().match(/^\[([^\]]+)\]$/);
    if (header) section = header[1];
    return section === 'rewrite_remote' ? topoQxRewriteLine(line, manifest.policy) : line;
  }).join('\n');
  // QX rejects an HTTPS server_check_url when importing this configuration.
  text = text.replace(/^\s*server_check_url\s*=.*$/m, 'server_check_url=http://www.gstatic.com/generate_204');
  return text.trimEnd() + '\n';
}

if (typeof module !== 'undefined') module.exports = { topoMihomo, topoQxPolicies, topoQxConfig, topoRegionRegex, topoRank, topoReplaceSection, topoQxRewriteLine };
