// Behavioral checks with synthetic credentials-free nodes.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { topoMihomo, topoQxConfig, topoQxRewriteLine, topoRegionRegex } = require('./runtime.js');
const file = process.argv[2];
if (!file) throw new Error('Pass the generated manifest path');
const manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
manifest.base = 'https://example.org/immutable-snapshot/';
const countries = { HK: '香港', US: '美国', JP: '日本', SG: '新加坡', TR: '土耳其', TW: '台湾', KR: '韩国' };
const airport = Object.values(countries).flatMap(label => [
  { name: `[花云] ${label}实验性 1`, type: 'trojan', server: 'example.org' },
  { name: `[花云] ${label}标准 1`, type: 'trojan', server: 'example.org' },
]);
const nodes = [...airport,
  { name: '🇺🇸 [自建/bwh] reality+vision 直连', type: 'vless', server: 'example.org' },
  { name: '[自建/ora] oracle', type: 'vless', server: 'example.org' },
  { name: '[CF] 美国假标签', type: 'vless', server: 'example.org' },
  { name: '[CF] [花云] 美国实验性伪标签', type: 'vless', server: 'example.org' },
  { name: '[家宽前置] front', type: 'vless', server: 'example.org' },
  { name: '[家宽] HK-家宽-01', type: 'openvpn', server: 'example.org', 'dialer-proxy': '⚡ CF 前置' },
];
const config = topoMihomo({ proxies: nodes }, manifest);
const groups = Object.fromEntries(config['proxy-groups'].map(g => [g.name, g]));
assert.equal(groups['🚀 主力出口'].proxies[0], '🌸 花云低倍');
assert.deepEqual(groups['🇺🇸 美国'].proxies, ['[花云] 美国实验性 1', '[花云] 美国标准 1']);
assert(config['proxy-groups'].every(group => group.type !== 'fallback' && !group.name.includes('容灾')));
assert.deepEqual(config['proxy-groups'].slice(0, 6).map(group => group.name), [
  '🚀 主力出口', '🌸 花云低倍', '🏠 自建节点', '🌸 花云全量', '☁️ CF 备用', '🏡 家宽链式',
]);
assert.deepEqual(config['proxy-groups'].slice(-2).map(group => group.name), ['📨 电报', '₿ 加密货币']);
assert(config['proxy-groups'].findIndex(group => group.name === '🇰🇷 韩国') < config['proxy-groups'].findIndex(group => group.name === '🤖 AI 服务'));
assert(new RegExp(topoRegionRegex('US')).test('🇺🇸 [花云] 美国实验性 1'));
assert(!new RegExp(topoRegionRegex('US')).test('[CF] [花云] 美国实验性伪标签'));
assert.equal(groups['🤖 AI 服务'].proxies[0], '🇺🇸 美国');
assert.equal(groups['Ⓜ️ 微软服务'].proxies[0], 'DIRECT');
assert.equal(groups['☁️ 微软云盘'].proxies[0], 'DIRECT');
assert.equal(groups['🍎 苹果服务'].proxies[0], 'DIRECT');
assert.deepEqual(groups['🛡️ 广告控制'].proxies, ['REJECT', 'PASS']);
assert(groups['🚀 主力出口'].proxies.includes('🏡 家宽链式'));
assert.equal(groups['⚡ CF 前置'].type, 'select');
assert.deepEqual(groups['⚡ CF 前置'].proxies, ['☁️ CF 备用', '🌸 花云低倍', '🏠 自建节点', '🌸 花云全量']);
assert(config['proxy-groups'].findIndex(group => group.name === '⚡ CF 前置') < config['proxy-groups'].findIndex(group => group.name === '🇺🇸 美国'));
const badFront = structuredClone(manifest);
badFront.policy.chain_front.choices.push('main');
assert.throws(() => topoMihomo({ proxies: nodes }, badFront), /Unsupported residential front choice/);
const recursiveNodes = structuredClone(nodes);
recursiveNodes.find(node => node.name.includes('[自建/bwh]'))['dialer-proxy'] = '⚡ CF 前置';
assert.throws(() => topoMihomo({ proxies: recursiveNodes }, manifest), /Proxy dependency cycle/);
assert.throws(() => topoMihomo({ proxies: nodes.filter(n => !n.name.includes('[花云] 美国')) }, manifest), /Missing airport region/);

const text = '[general]\nserver_check_url=https://example.org\n[policy]\nstatic=legacy,direct\n[server_remote]\nhttps://example.org/old\n[server_local]\nlegacy-node\n[filter_remote]\nhttps://example.org/old-rules\n[filter_local]\nfinal,direct\n[mitm]\npassphrase=PRIVATE-PLACEHOLDER\n';
const qx = topoQxConfig(text, manifest, { nodes: 'https://example.org/new-nodes', rules: 'https://example.org/upstream-routing' });
assert(!qx.includes('legacy-node'));
assert(!qx.includes('🏡 家宽链式'));
assert(qx.includes('static=🤖 AI 服务, 🇺🇸 美国'));
assert(!qx.includes('available='));
assert(!qx.includes('容灾'));
const qxGroups = qx.split('[policy]\n')[1].split('\n[')[0].trim().split('\n').map(line => line.split(',')[0].split('=')[1]);
const mihomoOnly = new Set(['🏡 家宽链式', '⚡ CF 前置', '🛡️ 广告控制']);
assert.deepEqual(qxGroups, config['proxy-groups'].map(group => group.name).filter(name => !mihomoOnly.has(name)));
assert(qx.includes('passphrase=PRIVATE-PLACEHOLDER'));
assert(Object.values(config['rule-providers']).every(provider => provider.url.startsWith('https://raw.githubusercontent.com/')));
assert(qx.includes('https://example.org/upstream-routing, tag=统一分流'));

const baidu = 'https://example.org/baidu, tag=百度地图, enabled=false, opt-parser=false, update-interval=123';
const baiduNext = topoQxRewriteLine(baidu, manifest.policy);
assert.equal(baiduNext, 'https://example.org/baidu, tag=百度地图 · 去广告, enabled=false, opt-parser=true, update-interval=123');
assert.equal(topoQxRewriteLine(baiduNext, manifest.policy), baiduNext);
assert.equal(topoQxRewriteLine('https://example.org/private, tag=旅行串串下载修改, opt-parser=false, enabled=true', manifest.policy),
  'https://example.org/private, tag=旅行串串 · 下载修改, opt-parser=false, enabled=true');
assert(Object.values(config['rule-providers']).every(provider => ['meta', 'master', 'main'].includes(provider.url.split('/')[5])));
assert.deepEqual(Object.entries(config['rule-providers']).filter(([, provider]) => provider.url.includes('/stlyx/')).map(([id]) => id), ['topo-flowercloud-direct']);
const oracleRule = config.rules.indexOf('RULE-SET,topo-oracle,DIRECT');
assert(oracleRule > 0 && config.rules.every((rule, index) => !rule.startsWith('RULE-SET,topo-ads-') || index < oracleRule));


const operatorCode = fs.readFileSync(require.resolve('./source-operator.js'), 'utf8');
function project(source, target, values) {
  const context = { TOPO_SOURCE: source, scriptResourceCache: { get() {}, set() {} }, $substore: { error() {} } };
  vm.createContext(context);
  vm.runInContext(operatorCode, context);
  return context.operator(values, target, {});
}
assert.equal(project({ id: 'pages-copy8708', role: 'residential-chain' }, 'QX', nodes).length, 0);
const original = [{ name: '🇺🇸 vision', type: 'vless', uuid: 'test-placeholder', 'reality-opts': { 'public-key': 'test-placeholder' } }];
const before = JSON.stringify(original);
const tagged = project({ id: 'bwh', role: 'self-hosted' }, 'mihomo', original);
assert.equal(tagged[0].name, '🇺🇸 [自建/bwh] vision');
assert.equal(tagged[0].uuid, original[0].uuid);
assert.deepEqual(JSON.stringify(tagged[0]['reality-opts']), JSON.stringify(original[0]['reality-opts']));
assert.equal(JSON.stringify(original), before);
console.log('Runtime checks passed: manual selectors first, no failover, shared display order, source/country isolation, business defaults, QX capabilities and credential preservation.');
