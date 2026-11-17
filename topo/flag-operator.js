// Correct aliases and usage labels after Sub-Store's native Flag Operator.
// Keep its country database; aliases below are used only for matching.
function operator(proxies) {
  const leading = /^(?:(?:\p{Regional_Indicator}{2}|🏴‍☠️|🏳️‍🌈)\s*)+/u;
  return proxies.map(proxy => {
    const name = proxy.name.replace(leading, '');
    const label = name.replace(/^\[[^\]]+\]\s*/, '');
    const lookup = label.replace(/香江/g, '香港').replace(/西美/g, '美国')
      .replace(/[（(]\s*流量\s*[)）]/g, '');
    if (lookup === label) return proxy;
    // Retain an explicit country as a fallback; discard non-country flags.
    const existing = proxy.name.match(/^\p{Regional_Indicator}{2}/u)?.[0] || '';
    const flag = ProxyUtils.getFlag(existing + ' ' + lookup);
    return { ...proxy, name: flag + ' ' + name };
  });
}
