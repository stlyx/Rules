// The private installer prepends const TOPO_SOURCE = { id, role }.
// Subscription URLs and node credentials are never embedded in this script.
function operator(proxies, targetPlatform, context) {
  const source = TOPO_SOURCE;
  const platform = String(targetPlatform || '').toLowerCase();
  if (source.role === 'residential-chain' && !['json', 'mihomo', 'clashmeta', 'clash'].includes(platform)) return [];
  const flag = /^(?:(?:\p{Regional_Indicator}{2}|🏴‍☠️|🏳️‍🌈)\s*)+/u;
  const ownPrefix = /^\[(?:花云|CF|家宽|家宽前置|自建\/bwh|自建\/ora)\]\s*/;
  let result = proxies.filter(proxy => !/^(?:Traffic:|Expire:|剩余流量|套餐到期|到期时间)/i.test(proxy.name.trim())).map(proxy => {
    let name = proxy.name.replace(flag, '').replace(ownPrefix, '');
    let prefix;
    if (source.id === 'bwh') prefix = '🇺🇸 [自建/bwh] ';
    else if (source.id === 'ora') prefix = '🇸🇬 [自建/ora] ';
    else if (source.role === 'primary') prefix = '[花云] ';
    else if (source.role === 'residential-chain') prefix = proxy.type === 'openvpn' ? '[家宽] ' : '[家宽前置] ';
    else prefix = '[CF] ';
    return { ...proxy, name: prefix + name };
  });
  if (source.role === 'primary') {
    const required = [/香港|Hong Kong/i, /日本|Japan/i, /新加坡|Singapore/i, /美国|美國|United States/i, /土耳其|Turkey|Türkiye/i];
    const key = 'topo-provenance-flowercloud-last-good-v1';
    if (required.some(pattern => !result.some(proxy => pattern.test(proxy.name)))) {
      const saved = scriptResourceCache.get(key);
      if (!saved?.length) throw new Error('Airport update lacks a required region');
      $substore.error('Incomplete airport update; retaining the last complete regional snapshot');
      return saved;
    }
    result = result.map((proxy, index) => ({ proxy, index })).sort((a, b) =>
      Number(!/实验/.test(a.proxy.name)) - Number(!/实验/.test(b.proxy.name)) || a.index - b.index,
    ).map(item => item.proxy);
    scriptResourceCache.set(key, result, 365 * 24 * 60 * 60 * 1000);
  }
  return result;
}
