// Shared Sub-Store runtime. The same policy IDs drive Mihomo and QX groups.
// The installer appends either a main(config) wrapper or a QX file wrapper.
const TOPO_LATEST = 'https://raw.githubusercontent.com/stlyx/Rules/master/topo/latest.json';
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
  const key = 'topo-unified-manifest-v1';
  const fresh = scriptResourceCache.get(key + '-fresh');
  if (fresh) return fresh;
  try {
    const response = await $substore.http.get({ url: TOPO_LATEST, timeout: 15000 });
    if (response.statusCode !== 200) throw new Error('Policy pointer unavailable');
    const pointer = JSON.parse(response.body);
    if (!/^[0-9a-f]{40}$/.test(pointer.revision)) throw new Error('Invalid policy revision');
    const base = `https://raw.githubusercontent.com/stlyx/Rules/${pointer.revision}/topo/generated/current/`;
    const body = await $substore.http.get({ url: base + 'manifest.json', timeout: 15000 });
    if (body.statusCode !== 200) throw new Error('Policy manifest unavailable');
    const manifest = { ...JSON.parse(body.body), base };
    if (manifest.schema !== 1 || !manifest.providers?.length || !manifest.policy?.business_groups) {
      throw new Error('Incomplete unified policy');
    }
    scriptResourceCache.set(key + '-fresh', manifest, 5 * 60 * 1000);
    scriptResourceCache.set(key + '-saved', manifest, 30 * 24 * 60 * 60 * 1000);
    return manifest;
  } catch (error) {
    const saved = scriptResourceCache.get(key + '-saved') || seed;
    if (!saved?.providers?.length || !saved.base) throw error;
    $substore.error('Using the last valid unified policy snapshot');
    return saved;
  }
}

function topoNames(policy) {
  const names = Object.fromEntries(Object.entries(policy.selectors).map(([id, s]) => [id, s.name]));
  for (const [country, item] of Object.entries(TOPO_COUNTRIES)) names['region-' + country] = item.name;
  return names;
}

function topoRegionRegex(country) {
  return `^(?=.*\\[花云\\])(?=.*${TOPO_COUNTRIES[country].pattern}).*$`;
}

function topoRank(nodes) {
  return nodes.map((node, index) => ({ node, index })).sort((a, b) =>
    Number(!/实验/.test(a.node.name)) - Number(!/实验/.test(b.node.name)) || a.index - b.index,
  ).map(item => item.node.name);
}

function topoMihomo(config, manifest) {
  const policy = manifest.policy;
  // A private migration map keeps the existing share usable while individual
  // source processors are patched. Already tagged nodes bypass this map.
  const legacy = config['x-topo-legacy-provenance'] || {};
  const leadingFlag = /^(?:(?:\p{Regional_Indicator}{2}|🏴‍☠️|🏳️‍🌈)\s*)+/u;
  const nodes = (config.proxies || []).filter(p => !/^(?:Traffic:|Expire:|剩余流量|套餐到期)/i.test(p.name.replace(leadingFlag, ''))).map(p => {
    if (/\[(?:花云|CF|家宽|家宽前置|自建\/bwh|自建\/ora)\]/.test(p.name)) return p;
    const mapped = legacy[p.name.replace(leadingFlag, '')];
    if (!mapped) return p;
    return { ...p, name: leadingFlag.test(mapped) ? mapped : (p.name.match(leadingFlag)?.[0] || '') + mapped };
  });
  config.proxies = nodes;
  const airport = nodes.filter(p => p.name.includes('[花云]'));
  const self = nodes.filter(p => /\[自建\/(bwh|ora)\]/.test(p.name));
  const cf = nodes.filter(p => p.name.includes('[CF]'));
  const home = nodes.filter(p => p.name.includes('[家宽]') && p.type === 'openvpn');
  const fronts = nodes.filter(p => p.name.includes('[家宽前置]'));
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
    const fallback = '🛟 ' + label.replace(/^\S+\s*/, '') + '容灾';
    group(fallback, 'fallback', sorted);
    group(label, 'select', [fallback, ...sorted]);
  }
  const hk = airport.filter(p => new RegExp(TOPO_COUNTRIES.HK.pattern, 'i').test(p.name));
  group(names['airport-failover'], 'fallback', topoRank(hk));
  group(names['airport-low'], 'select', topoRank(airport.filter(p => /实验/.test(p.name))));
  group('♻️ 花云自动', 'url-test', topoRank(airport), { interval: 600, tolerance: 80 });
  group(names['airport-all'], 'select', ['♻️ 花云自动', ...topoRank(airport)]);
  const orderedSelf = [...self].sort((a, b) => Number(!/\[自建\/bwh\].*reality\+vision/.test(a.name)) - Number(!/\[自建\/bwh\].*reality\+vision/.test(b.name))).map(p => p.name);
  group(names['self-hosted'], 'select', orderedSelf);
  group('🏠 自建容灾', 'fallback', orderedSelf);
  group('♻️ CF 自动', 'url-test', cf.map(p => p.name), { interval: 600, tolerance: 80 });
  group(names['cf-backup'], 'select', ['♻️ CF 自动', ...cf.map(p => p.name)]);
  if (home.length) {
    group('⚡ CF前置', 'url-test', fronts.map(p => p.name), { interval: 600, tolerance: 80 });
    const preferred = [...home].sort((a, b) => Number(!/HK-家宽/.test(a.name)) - Number(!/HK-家宽/.test(b.name)));
    group(names['home-chain'], 'select', preferred.map(p => p.name));
  }
  const validIds = new Set(['DIRECT', ...Object.keys(policy.selectors).filter(id => id !== 'home-chain' || home.length), ...regionIds]);
  function candidates(items) { return items.filter(id => validIds.has(id)).map(id => names[id] || id); }
  group(names.main, 'select', candidates(policy.selectors.main.choices));
  const business = [];
  for (const [id, definition] of Object.entries(policy.business_groups)) {
    const choices = [definition.default, ...definition.choices.filter(v => v !== definition.default)];
    const members = candidates(choices);
    business.push({ name: definition.name, type: 'select', proxies: [...new Set(members)] });
  }
  group('🛡️ 广告控制', 'select', ['REJECT', 'PASS']);
  const main = groups.find(g => g.name === names.main);
  config['proxy-groups'] = [main, ...business, ...groups.filter(g => g !== main)];
  config['rule-providers'] = {};
  config.rules = [];
  for (const provider of manifest.providers) {
    const id = 'topo-' + provider.id;
    config['rule-providers'][id] = { type: 'http', behavior: provider.behavior, format: 'text', url: manifest.base + provider.path, path: './rule-providers/' + id + '.list', interval: 86400, proxy: names.main };
    config.rules.push(`RULE-SET,${id},${provider.policy}`);
  }
  config.rules.push('MATCH,' + names.main);
  const known = new Set([...nodes.map(p => p.name), ...config['proxy-groups'].map(g => g.name), 'DIRECT', 'REJECT', 'PASS']);
  for (const g of config['proxy-groups']) for (const n of g.proxies) if (!known.has(n)) throw new Error('Unresolved group member: ' + n);
  for (const p of nodes) if (p['dialer-proxy'] && !known.has(p['dialer-proxy'])) throw new Error('Unresolved chain front');
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
  select(names.main, policy.selectors.main.choices);
  for (const definition of Object.values(policy.business_groups)) select(definition.name, [definition.default, ...definition.choices.filter(v => v !== definition.default)]);
  lines.push(`available=${names['airport-failover']}, server-tag-regex=${topoRegionRegex('HK')}`);
  lines.push(`static=${names['airport-low']}, server-tag-regex=^(?=.*\\[花云\\])(?=.*实验).*$`);
  lines.push('url-latency-benchmark=♻️ 花云自动, server-tag-regex=\\[花云\\], check-interval=600, tolerance=80, alive-checking=false');
  lines.push(`static=${names['airport-all']}, ♻️ 花云自动, server-tag-regex=\\[花云\\]`);
  lines.push(`static=${names['self-hosted']}, server-tag-regex=\\[自建/(?:bwh|ora)\\]`);
  lines.push('available=🏠 自建容灾, server-tag-regex=\\[自建/(?:bwh|ora)\\]');
  lines.push('url-latency-benchmark=♻️ CF 自动, server-tag-regex=\\[CF\\], check-interval=600, tolerance=80, alive-checking=false');
  lines.push(`static=${names['cf-backup']}, ♻️ CF 自动, server-tag-regex=\\[CF\\]`);
  for (const country of regions) {
    const label = TOPO_COUNTRIES[country].name;
    const fallback = '🛟 ' + label.replace(/^\S+\s*/, '') + '容灾';
    lines.push(`available=${fallback}, server-tag-regex=${topoRegionRegex(country)}`);
    lines.push(`static=${label}, ${fallback}, server-tag-regex=${topoRegionRegex(country)}`);
  }
  return lines.join('\n') + '\n';
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

function topoQxConfig(text, manifest, bindings) {
  text = topoReplaceSection(text, 'policy', topoQxPolicies(manifest.policy));
  text = topoReplaceSection(text, 'server_remote', bindings.nodes + ', tag=pnodes, update-interval=21600, opt-parser=false, enabled=true');
  text = topoReplaceSection(text, 'server_local', '');
  const filter = 'https://raw.githubusercontent.com/stlyx/Rules/master/topo/generated/current/qx-' + (bindings.adsMode === 'off' ? 'off' : 'on') + '.list';
  text = topoReplaceSection(text, 'filter_remote', filter + ', tag=统一分流, update-interval=86400, opt-parser=false, inserted-resource=true, enabled=true');
  text = topoReplaceSection(text, 'filter_local', 'final,🚀 主力出口');
  text = text.replace(/^\s*server_check_url\s*=.*$/m, 'server_check_url=https://www.gstatic.com/generate_204');
  return text.trimEnd() + '\n';
}

if (typeof module !== 'undefined') module.exports = { topoMihomo, topoQxPolicies, topoQxConfig, topoRegionRegex, topoRank, topoReplaceSection };
