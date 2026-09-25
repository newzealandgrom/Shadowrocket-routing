/*
 * Проверка сервисов для Shadowrocket: страница http://sr.test/ из модуля modules/Service-Check-RU.module.
 *
 *   http://sr.test/          страница с проверками; ?q=адрес сразу проверяет этот адрес;
 *   http://sr.test/route     IP напрямую (Яндекс) и через прокси (ipinfo.io): работает ли разделение трафика;
 *   http://sr.test/sites     сайты: по какому правилу идут и отвечают ли. ?extra=[{"name":"…","url":"…"}]
 *                            добавляет свои сайты, ?nodefault=1 убирает стандартные;
 *   http://sr.test/rule      по какому правилу SR_RU.conf пойдёт адрес: ?host=&port=&scheme=&url=;
 *   http://sr.test/probe     открывается ли адрес через Shadowrocket: ?url=.
 *
 * Адреса https:// работают так же, если включена HTTPS-расшифровка.
 *
 * Как /rule выбирает правило. Скрипт читает [Rule] из SR_RU.conf в репозитории и проходит правила в порядке,
 * который описывает руководство Shadowrocket: сверху вниз, но сначала доменные и другие точные правила,
 * затем IP-CIDR, затем правила по базам (IP-ASN, GEOIP), последним FINAL. Правила с no-resolve для домена
 * пропускаются, для остальных IP-правил домен разрешается через DNS. Списки RULE-SET берутся из индекса
 * Script/rule-index/, его собирает github_actions/build_rule_index.py: reject.list и domains_refilter.list
 * целиком не помещаются в лимит памяти сетевого расширения iOS. Правила модулей и правила, добавленные на
 * телефоне вручную, скрипт не видит.
 *
 * Проверки сервисов (YouTube, ChatGPT, Netflix и т.д.) выполняют скрипты huskydsb/Shadowrocket, их
 * подключает модуль. Все запросы идут по правилам текущего конфига, поэтому результаты показывают
 * реальную маршрутизацию.
 */

const UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1';
const REQUEST_LIMIT_MS = 9000;

const REPO_RAW = 'https://raw.githubusercontent.com/newzealandgrom/Shadowrocket-routing/refs/heads/master/';
const CONFIG_URL = REPO_RAW + 'SR_RU.conf';
const INDEX_URL = REPO_RAW + 'Script/rule-index/';
const LISTS_URL = REPO_RAW + 'lists/';
const LISTS_PAGE = 'https://github.com/newzealandgrom/Shadowrocket-routing/blob/master/lists/';
const INDEX_FORMAT = 1;
// Список не из индекса больше этого размера не скачивается: лимит памяти сетевого расширения iOS.
const RAW_SET_LIMIT = 1500000;
const MAX_EXTRA_SITES = 30;

const SITES = [
  { name: 'Госуслуги', url: 'https://www.gosuslugi.ru/' },
  { name: 'Сбербанк', url: 'https://www.sberbank.ru/' },
  { name: 'Яндекс', url: 'https://ya.ru/' },
  { name: 'ВКонтакте', url: 'https://vk.com/' },
  { name: 'YouTube', url: 'https://www.youtube.com/generate_204' },
  { name: 'Instagram', url: 'https://www.instagram.com/' },
  { name: 'Telegram', url: 'https://telegram.org/' },
  { name: 'Discord', url: 'https://discord.com/api/v9/experiments' },
  { name: 'ChatGPT', url: 'https://chatgpt.com/' },
  { name: 'Claude', url: 'https://claude.ai/' },
  { name: 'X (Twitter)', url: 'https://x.com/' },
  { name: 'LinkedIn', url: 'https://www.linkedin.com/' },
];

// Проверки из huskydsb/Shadowrocket: путь на sr.test и название на странице.
const SERVICES = [
  ['youtube', 'YouTube Premium'],
  ['chatgpt', 'ChatGPT'],
  ['netflix', 'Netflix'],
  ['spotify', 'Spotify'],
  ['tiktok', 'TikTok'],
  ['disney', 'Disney+'],
  ['primevideo', 'Prime Video'],
  ['steam', 'Steam'],
  ['googleplay', 'Google Play'],
  ['bing', 'Bing'],
  ['wikipedia', 'Wikipedia'],
  ['scamalytics', 'Репутация IP сервера'],
  ['dns', 'Утечка DNS'],
];

// ─── Общее ──────────────────────────────────────────────────────────────────

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function flag(cc) {
  if (!/^[A-Za-z]{2}$/.test(cc || '')) return '';
  return String.fromCodePoint(...cc.toUpperCase().split('').map((c) => 127397 + c.charCodeAt(0)));
}

function get(url, headers) {
  return new Promise((resolve) => {
    const started = Date.now();
    let finished = false;
    const finish = (result) => {
      if (finished) return;
      finished = true;
      resolve(Object.assign({ ms: Date.now() - started }, result));
    };
    if (typeof setTimeout === 'function') {
      setTimeout(() => finish({ error: 'нет ответа за ' + REQUEST_LIMIT_MS / 1000 + ' с' }), REQUEST_LIMIT_MS);
    }
    const allHeaders = Object.assign({ 'User-Agent': UA, 'Accept-Language': 'ru-RU,ru;q=0.9,en;q=0.8' }, headers || {});
    $httpClient.get({ url, headers: allHeaders, timeout: 10000 }, (error, response, body) => {
      if (error) {
        finish({ error: String((error && (error.code || error.message)) || error) });
        return;
      }
      finish({ status: response && (response.status || response.statusCode), body: body || '' });
    });
  });
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch (e) {
    return null;
  }
}

function failure(r) {
  if (r.error) return r.error;
  return r.status === 200 ? 'неожиданный ответ сервиса' : 'код ' + r.status;
}

// Промис на ключ: повторные запросы в рамках одного запуска скрипта не уходят в сеть.
function once(cache, key, make) {
  if (!Object.prototype.hasOwnProperty.call(cache, key)) cache[key] = make();
  return cache[key];
}

const textCache = {};
function fetchText(url, limit) {
  return once(textCache, url, () => get(url).then((r) => {
    if (r.error) throw new Error(r.error);
    if (r.status !== 200) throw new Error('код ' + r.status);
    if (limit && r.body.length > limit) throw new Error('файл больше ' + (limit / 1e6).toFixed(1) + ' МБ');
    return r.body;
  }));
}

function parseQuery(url) {
  const query = {};
  const start = url.indexOf('?');
  if (start < 0) return query;
  for (const part of url.slice(start + 1).split('&')) {
    if (!part) continue;
    const eq = part.indexOf('=');
    const key = eq < 0 ? part : part.slice(0, eq);
    const value = eq < 0 ? '' : part.slice(eq + 1);
    try {
      query[decodeURIComponent(key.replace(/\+/g, ' '))] = decodeURIComponent(value.replace(/\+/g, ' '));
    } catch (e) {
      // битая %-последовательность: параметр пропускаем
    }
  }
  return query;
}

// ─── IP-адреса ──────────────────────────────────────────────────────────────

function parseIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const octet = Number(m[i]);
    if (octet > 255) return null;
    n = n * 256 + octet;
  }
  return n;
}

function parseIPv6(s) {
  if (!/^[0-9a-fA-F:.]+$/.test(s) || s.indexOf(':') < 0) return null;
  const lastColon = s.lastIndexOf(':');
  const tail = s.slice(lastColon + 1);
  if (tail.indexOf('.') >= 0) {
    const v4 = parseIPv4(tail);
    if (v4 === null) return null;
    s = s.slice(0, lastColon + 1) + ((v4 >>> 16) & 0xffff).toString(16) + ':' + (v4 & 0xffff).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  if (halves.length === 1 && head.length !== 8) return null;
  if (halves.length === 2 && head.length + rest.length > 7) return null;
  const zeros = halves.length === 2 ? new Array(8 - head.length - rest.length).fill('0') : [];
  const parts = [];
  for (const group of head.concat(zeros, rest)) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    parts.push(parseInt(group, 16));
  }
  return parts.length === 8 ? parts : null;
}

function parseIp(s) {
  const v4 = parseIPv4(s);
  if (v4 !== null) return { v: 4, n: v4, text: s };
  const v6 = parseIPv6(s);
  return v6 ? { v: 6, parts: v6, text: s.toLowerCase() } : null;
}

function parseCidr(text) {
  const s = String(text).trim();
  const slash = s.indexOf('/');
  const ip = parseIp(slash < 0 ? s : s.slice(0, slash));
  if (!ip) return null;
  const max = ip.v === 4 ? 32 : 128;
  const bits = slash < 0 ? max : Number(s.slice(slash + 1));
  if (!(bits >= 0 && bits <= max) || Math.floor(bits) !== bits) return null;
  return Object.assign(ip, { bits });
}

function inCidr(ip, cidr) {
  if (ip.v !== cidr.v) return false;
  if (ip.v === 4) {
    const size = Math.pow(2, 32 - cidr.bits);
    return Math.floor(ip.n / size) === Math.floor(cidr.n / size);
  }
  let bits = cidr.bits;
  for (let i = 0; i < 8 && bits > 0; i++) {
    const take = Math.min(16, bits);
    const mask = (0xffff << (16 - take)) & 0xffff;
    if ((ip.parts[i] & mask) !== (cidr.parts[i] & mask)) return false;
    bits -= take;
  }
  return true;
}

// ─── Разбор правил ──────────────────────────────────────────────────────────

const LOGIC_TYPES = { AND: true, OR: true, NOT: true };
const RULE_OPTIONS = { 'no-resolve': true, 'pre-matching': true, 'extended-matching': true, 'force-remote-dns': true, 'dns-failed': true };
const POLICY_WORD = /^(DIRECT|PROXY|REJECT(-[A-Z0-9]+)?)$/i;

function splitLogicItems(group) {
  if (group[0] !== '(' || group[group.length - 1] !== ')') return null;
  const inner = group.slice(1, -1);
  const items = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < inner.length; i++) {
    if (inner[i] === '(') {
      if (depth === 0) start = i;
      depth++;
    } else if (inner[i] === ')') {
      depth--;
      if (depth < 0) return null;
      if (depth === 0) items.push(inner.slice(start + 1, i).trim());
    }
  }
  return depth === 0 ? items : null;
}

function makeRule(type, value, options, policy) {
  return {
    type,
    value,
    options,
    policy: policy || '',
    noResolve: options.indexOf('no-resolve') >= 0,
    text: type + (value ? ',' + value : ''),
  };
}

// inList: строка из файла списка, политику задаёт RULE-SET; иначе строка из [Rule] конфига.
function parseRule(line, inList) {
  const s = line.trim();
  if (!s || s[0] === '#' || s[0] === ';' || s.slice(0, 2) === '//') return null;
  const comma = s.indexOf(',');
  const type = (comma < 0 ? s : s.slice(0, comma)).trim().toUpperCase();
  let rest = comma < 0 ? '' : s.slice(comma + 1);
  if (type !== 'URL-REGEX' && type !== 'USER-AGENT') {
    const comment = /\s(#|\/\/)/.exec(rest);
    if (comment) rest = rest.slice(0, comment.index);
  }
  let value = '';
  let tail = [];
  if (LOGIC_TYPES[type]) {
    rest = rest.trim();
    let depth = 0;
    let end = -1;
    for (let i = 0; i < rest.length && end < 0; i++) {
      if (rest[i] === '(') depth++;
      else if (rest[i] === ')' && --depth === 0) end = i;
    }
    value = end < 0 ? rest : rest.slice(0, end + 1);
    tail = end < 0 ? [] : rest.slice(end + 1).split(',');
  } else if (type === 'FINAL') {
    tail = rest.split(',');
  } else if (type === 'URL-REGEX' || type === 'USER-AGENT') {
    // Значение может содержать запятые: с конца снимаем только известные опции и политику.
    const parts = rest.split(',');
    while (parts.length > 1 && (RULE_OPTIONS[parts[parts.length - 1].trim()] || POLICY_WORD.test(parts[parts.length - 1].trim()))) {
      tail.unshift(parts.pop());
    }
    if (!inList && parts.length > 1 && !tail.some((x) => POLICY_WORD.test(x.trim()))) tail.unshift(parts.pop());
    value = parts.join(',').trim();
  } else {
    const parts = rest.split(',');
    value = parts[0].trim();
    tail = parts.slice(1);
  }
  const options = tail.map((x) => x.trim()).filter(Boolean);
  const policy = inList ? '' : options.filter((o) => !RULE_OPTIONS[o])[0];
  const rule = makeRule(type, value, options, policy);
  if (LOGIC_TYPES[type]) {
    const items = splitLogicItems(value);
    rule.subs = items ? items.map((item) => parseRule(item, true)) : null;
  }
  return rule;
}

function parseConfig(text) {
  const rules = [];
  const general = {};
  let section = '';
  for (const raw of text.split('\n')) {
    const s = raw.trim();
    if (/^\[.+\]$/.test(s)) {
      section = s.slice(1, -1).trim().toLowerCase();
      continue;
    }
    if (section === 'general') {
      const m = /^([\w-]+)\s*=\s*(.*)$/.exec(s);
      if (m) general[m[1].toLowerCase()] = m[2];
    } else if (section === 'rule') {
      const rule = parseRule(s, false);
      if (rule) rules.push(rule);
    }
  }
  const bypass = (general['tun-excluded-routes'] || general['bypass-tun'] || '')
    .split(',').map((x) => parseCidr(x)).filter(Boolean);
  return { rules, bypass };
}

// ─── Загрузка конфига и индекса ─────────────────────────────────────────────

const loaded = {};

function loadConfig() {
  return once(loaded, 'config', () => fetchText(CONFIG_URL).then(parseConfig));
}

function loadManifest() {
  return once(loaded, 'manifest', () => fetchText(INDEX_URL + 'manifest.json').then((text) => {
    const m = JSON.parse(text);
    if (m.format !== INDEX_FORMAT) throw new Error('неизвестный формат индекса ' + m.format);
    const byUrl = {};
    m.lists.forEach((list, id) => {
      byUrl[list.url] = { id: String(id), name: list.name, cidrResolve: list.cidrResolve || 0 };
    });
    return {
      byUrl,
      shards: m.domainShards,
      splitKeys: new Set(m.splitKeys || []),
      ip4Leaves: (m.ip4Parts || []).map((part) => ({
        cidr: parseCidr(part[0]),
        count: part[1],
        file: 'ip4/' + part[0].replace('/', '_') + '.txt',
      })),
    };
  }));
}

function loadOther() {
  return once(loaded, 'other', () => fetchText(INDEX_URL + 'other.txt').then((text) => {
    const byList = {};
    for (const line of text.split('\n')) {
      const tab = line.indexOf('\t');
      if (tab < 0) continue;
      const rule = parseRule(line.slice(tab + 1), true);
      const id = line.slice(0, tab);
      if (rule) (byList[id] = byList[id] || []).push(rule);
    }
    return byList;
  }));
}

function setName(url) {
  const name = url.split('?')[0].split('/').pop() || url;
  try {
    return decodeURIComponent(name);
  } catch (e) {
    return name;
  }
}

const rawSets = {};
function loadRawSet(url, type) {
  return once(rawSets, url, () => fetchText(url, RAW_SET_LIMIT).then((text) => {
    const rules = [];
    for (const line of text.split('\n')) {
      if (type === 'DOMAIN-SET') {
        const s = line.trim().toLowerCase();
        if (!s || s[0] === '#') continue;
        rules.push(s[0] === '.' ? makeRule('DOMAIN-SUFFIX', s.slice(1), []) : makeRule('DOMAIN', s, []));
      } else {
        const rule = parseRule(line, true);
        if (rule) rules.push(rule);
      }
    }
    return { rules };
  }).catch((e) => ({ rules: [], error: String((e && e.message) || e) })));
}

// Тот же хэш и выбор части, что в github_actions/build_rule_index.py.
function fnv1a(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function domainShard(domain, manifest) {
  const labels = domain.split('.');
  let key = labels.slice(-2).join('.');
  if (manifest.splitKeys.has(key) && labels.length >= 3) key = labels.slice(-3).join('.');
  return (fnv1a(key) % manifest.shards).toString(16).padStart(2, '0');
}

// {номер списка: самое точное совпавшее правило DOMAIN/DOMAIN-SUFFIX}
function domainHits(ctx) {
  if (!ctx.domainHits) {
    ctx.domainHits = (async () => {
      const hits = {};
      if (ctx.t.ip) return hits;
      const labels = ctx.t.host.split('.');
      const suffixes = {};
      const shards = {};
      for (let i = 0; i < labels.length; i++) {
        const suffix = labels.slice(i).join('.');
        suffixes[suffix] = true;
        shards[domainShard(suffix, ctx.manifest)] = true;
      }
      const texts = await Promise.all(Object.keys(shards).map((id) => fetchText(INDEX_URL + 'd/' + id + '.txt')));
      for (const text of texts) {
        for (const line of text.split('\n')) {
          const tab = line.indexOf('\t');
          if (tab < 0) continue;
          let entry = line.slice(tab + 1);
          const exact = entry[0] === '=';
          if (exact) entry = entry.slice(1);
          if (exact ? entry !== ctx.t.host : !suffixes[entry]) continue;
          const id = line.slice(0, tab);
          if (!hits[id] || entry.length > hits[id].value.length) {
            hits[id] = { type: exact ? 'DOMAIN' : 'DOMAIN-SUFFIX', value: entry };
          }
        }
      }
      return hits;
    })();
  }
  return ctx.domainHits;
}

// {номер списка: [{value, noResolve}]} для подсетей из индекса, в которые попадает адрес.
const ipHitsCache = {};
function ipHits(ip, manifest) {
  return once(ipHitsCache, ip.text, async () => {
    let file = 'ip6.txt';
    if (ip.v === 4) {
      const leaf = manifest.ip4Leaves.filter((l) => l.cidr && inCidr(ip, l.cidr))[0];
      file = leaf && leaf.count ? leaf.file : '';
    }
    const hits = {};
    if (!file) return hits;
    const text = await fetchText(INDEX_URL + file);
    for (const line of text.split('\n')) {
      const parts = line.split('\t');
      if (parts.length < 2) continue;
      const cidr = parseCidr(parts[1]);
      if (cidr && inCidr(ip, cidr)) (hits[parts[0]] = hits[parts[0]] || []).push({ value: parts[1], noResolve: parts[2] === 'n' });
    }
    return hits;
  });
}

// ─── DNS, страна и ASN ──────────────────────────────────────────────────────

// Подсеть /24 прямого IP: Google DNS отвечает так, как ответил бы в сети провайдера.
function directSubnet() {
  return once(loaded, 'subnet', () => get('https://ipv4-internet.yandex.net/api/v0/ip').then((r) => {
    const n = r.status === 200 ? parseIPv4(r.body.replace(/["\s]/g, '')) : null;
    return n === null ? '' : [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, 0].join('.') + '/24';
  }));
}

const dnsCache = {};
function resolveHost(host) {
  return once(dnsCache, host, async () => {
    const subnet = await directSubnet();
    const google = await get('https://dns.google/resolve?name=' + encodeURIComponent(host) + '&type=A' +
      (subnet ? '&edns_client_subnet=' + subnet : ''));
    let data = google.status === 200 ? parseJson(google.body) : null;
    let via = subnet ? 'Google DNS для вашей сети' : 'Google DNS';
    if (!data || typeof data.Status !== 'number') {
      const cloudflare = await get('https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(host) + '&type=A',
        { Accept: 'application/dns-json' });
      data = cloudflare.status === 200 ? parseJson(cloudflare.body) : null;
      via = 'Cloudflare DNS';
    }
    if (!data || typeof data.Status !== 'number') return { ips: [], via, error: 'DNS не ответил' };
    const ips = (Array.isArray(data.Answer) ? data.Answer : [])
      .filter((a) => a && a.type === 1)
      .map((a) => parseIp(String(a.data)))
      .filter(Boolean);
    return { ips, via, error: ips.length ? '' : data.Status === 3 ? 'такого домена нет' : 'у домена нет IPv4-адреса' };
  });
}

const geoCache = {};
function countryOf(ip) {
  return once(geoCache, ip.text, async () => {
    if (typeof $utils !== 'undefined' && $utils && typeof $utils.geoip === 'function') {
      try {
        const cc = $utils.geoip(ip.text);
        if (cc) return { cc: String(cc).toUpperCase(), via: 'базе GeoIP Shadowrocket' };
      } catch (e) {
        // нет встроенной базы: спрашиваем ipinfo.io
      }
    }
    const r = await get('https://ipinfo.io/' + encodeURIComponent(ip.text) + '/country');
    const cc = r.status === 200 ? r.body.trim().toUpperCase() : '';
    return /^[A-Z]{2}$/.test(cc) ? { cc, via: 'ipinfo.io' } : { cc: '', via: 'ipinfo.io', error: failure(r) };
  });
}

const asnCache = {};
function asnOf(ip) {
  return once(asnCache, ip.text, async () => {
    if (typeof $utils !== 'undefined' && $utils && typeof $utils.ipasn === 'function') {
      try {
        const asn = $utils.ipasn(ip.text);
        if (asn) return { asn: String(asn).replace(/^AS/i, ''), via: 'базе ASN Shadowrocket' };
      } catch (e) {
        // нет встроенной базы: спрашиваем ipinfo.io
      }
    }
    const r = await get('https://ipinfo.io/' + encodeURIComponent(ip.text) + '/org');
    const m = r.status === 200 ? /^AS(\d+)/i.exec(r.body.trim()) : null;
    return m ? { asn: m[1], via: 'ipinfo.io' } : { asn: '', via: 'ipinfo.io', error: failure(r) };
  });
}

// ─── Сопоставление ──────────────────────────────────────────────────────────

// Порядок из руководства Shadowrocket: доменные и прочие точные правила, затем IP-CIDR, затем правила по
// базам (GEOIP, IP-ASN). Внутри каждого этапа правила идут в порядке конфига.
const PHASES = { 'IP-CIDR': 2, 'IP-CIDR6': 2, 'SRC-IP-CIDR': 2, 'IP-ASN': 3, 'GEOIP': 3 };

function phaseOf(rule) {
  if (rule.subs) return rule.subs.reduce((phase, sub) => Math.max(phase, sub ? phaseOf(sub) : 1), 1);
  return PHASES[rule.type] || 1;
}

function makeTarget(host, port, scheme, url) {
  host = String(host || '').trim().toLowerCase().replace(/^\[/, '').replace(/\]$/, '').replace(/\.$/, '');
  const ip = parseIp(host);
  if (!ip && !(host.length <= 253 && /^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/.test(host))) return null;
  scheme = scheme === 'http' ? 'http' : 'https';
  const defaultPort = scheme === 'http' ? 80 : 443;
  port = port ? Number(port) : defaultPort;
  if (!(port >= 1 && port <= 65535) || Math.floor(port) !== port) return null;
  if (!url || url.length > 2000 || !/^https?:\/\/\S+$/i.test(url)) {
    url = scheme + '://' + (ip && ip.v === 6 ? '[' + host + ']' : host) + (port === defaultPort ? '' : ':' + port) + '/';
  }
  return { host, ip, port, scheme, url };
}

function targetFromUrl(url) {
  const m = /^(https?):\/\/(\[[0-9a-fA-F:.]+\]|[^/:?#\s]+)(?::(\d+))?/i.exec(url || '');
  return m ? makeTarget(m[2], m[3], m[1].toLowerCase(), url) : null;
}

async function targetIps(ctx, noResolve) {
  if (ctx.t.ip) return [ctx.t.ip];
  if (noResolve) return null;
  if (!ctx.dns) ctx.dns = resolveHost(ctx.t.host);
  const r = await ctx.dns;
  return r.ips.length ? r.ips : null;
}

function wildcardRegExp(pattern) {
  const body = pattern.toLowerCase().replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp('^' + body + '$');
}

function portMatches(value, port) {
  const m = /^(\d+)(?:-(\d+))?$/.exec(String(value).trim());
  if (!m) return null;
  return port >= Number(m[1]) && port <= Number(m[2] || m[1]);
}

function protocolMatches(value, t) {
  const p = value.toUpperCase();
  if (p === 'TCP') return true;
  if (p === 'HTTPS') return t.scheme === 'https';
  if (p === 'HTTP') return t.scheme === 'http';
  if (p === 'UDP' || p === 'QUIC' || p === 'ICMP') return false;
  return null;
}

// true, false или null, если правило нельзя проверить по одному адресу (USER-AGENT и т.п.).
async function matchRule(rule, ctx) {
  const t = ctx.t;
  const v = rule.value;
  switch (rule.type) {
    case 'DOMAIN':
      return !t.ip && t.host === v.toLowerCase();
    case 'DOMAIN-SUFFIX': {
      const suffix = v.toLowerCase().replace(/^\./, '');
      return !t.ip && (t.host === suffix || t.host.slice(-suffix.length - 1) === '.' + suffix);
    }
    case 'DOMAIN-KEYWORD':
      return !t.ip && t.host.indexOf(v.toLowerCase()) >= 0;
    case 'DOMAIN-WILDCARD':
      return !t.ip && wildcardRegExp(v).test(t.host);
    case 'URL-REGEX':
      try {
        return new RegExp(v).test(t.url);
      } catch (e) {
        return null;
      }
    case 'DST-PORT':
      return portMatches(v, t.port);
    case 'PROTOCOL':
      return protocolMatches(v, t);
    case 'IP-CIDR':
    case 'IP-CIDR6': {
      const cidr = parseCidr(v);
      if (!cidr) return null;
      const ips = await targetIps(ctx, rule.noResolve);
      return !!ips && ips.some((ip) => inCidr(ip, cidr));
    }
    case 'IP-ASN': {
      const ips = await targetIps(ctx, rule.noResolve);
      if (!ips) return false;
      ctx.asn = await asnOf(ips[0]);
      return !!ctx.asn.asn && ctx.asn.asn === v.replace(/^AS/i, '');
    }
    case 'GEOIP': {
      const ips = await targetIps(ctx, rule.noResolve);
      if (!ips) return false;
      ctx.geo = await countryOf(ips[0]);
      return !!ctx.geo.cc && ctx.geo.cc === v.toUpperCase();
    }
    case 'AND':
    case 'OR':
    case 'NOT': {
      if (!rule.subs || rule.subs.some((sub) => !sub)) return null;
      const results = [];
      for (const sub of rule.subs) {
        const r = await matchRule(sub, ctx);
        if (rule.type === 'AND' && r === false) return false;
        if (rule.type === 'OR' && r === true) return true;
        results.push(r);
      }
      if (results.indexOf(null) >= 0) return null;
      return rule.type === 'NOT' ? !results[0] : rule.type === 'AND';
    }
    default:
      return null;
  }
}

async function matchRules(rules, phase, ctx, list, url) {
  for (const rule of rules) {
    if (phaseOf(rule) !== phase) continue;
    const m = await matchRule(rule, ctx);
    if (m === null) ctx.skipped[rule.type] = (ctx.skipped[rule.type] || 0) + 1;
    if (m === true) return { text: rule.text, list, url };
  }
  return null;
}

async function matchSet(rule, phase, ctx) {
  const info = ctx.manifest && ctx.manifest.byUrl[rule.value];
  if (!info) {
    const name = setName(rule.value);
    const set = await loadRawSet(rule.value, rule.type);
    if (set.error) {
      ctx.unchecked[name] = set.error;
      return null;
    }
    return matchRules(set.rules, phase, ctx, name, rule.value);
  }
  if (phase === 1) {
    const hit = (await domainHits(ctx))[info.id];
    if (hit) return { text: hit.type + ',' + hit.value, list: info.name, url: rule.value };
  }
  if (phase === 2) {
    // Для домена подсети с no-resolve пропускаются; остальные проверяются по адресу из DNS.
    const isDomain = !ctx.t.ip;
    const ips = isDomain ? (info.cidrResolve ? await targetIps(ctx, false) : null) : [ctx.t.ip];
    for (const ip of ips || []) {
      const entry = ((await ipHits(ip, ctx.manifest))[info.id] || []).filter((e) => !(isDomain && e.noResolve))[0];
      if (entry) return { text: (ip.v === 6 ? 'IP-CIDR6,' : 'IP-CIDR,') + entry.value, list: info.name, url: rule.value };
    }
  }
  return matchRules(ctx.other[info.id] || [], phase, ctx, info.name, rule.value);
}

async function checkTarget(t) {
  const [conf, manifest, other] = await Promise.all([
    loadConfig(),
    loadManifest().catch(() => null),
    loadOther().catch(() => null),
  ]);
  const ctx = {
    t,
    manifest: manifest && other ? manifest : null,
    other: other || {},
    skipped: {},
    unchecked: {},
    dns: null,
    geo: null,
    asn: null,
  };
  let hit = null;
  let policy = '';
  for (const phase of [1, 2, 3]) {
    for (const rule of conf.rules) {
      if (rule.type === 'FINAL') continue;
      if (rule.type === 'RULE-SET' || rule.type === 'DOMAIN-SET') {
        hit = await matchSet(rule, phase, ctx);
      } else if (phaseOf(rule) === phase) {
        const m = await matchRule(rule, ctx);
        if (m === null) ctx.skipped[rule.type] = (ctx.skipped[rule.type] || 0) + 1;
        hit = m === true ? { text: rule.text, list: '', url: '' } : null;
      }
      if (hit) {
        policy = rule.policy;
        break;
      }
    }
    if (hit) break;
  }
  if (!hit) {
    const final = conf.rules.filter((r) => r.type === 'FINAL')[0];
    policy = final ? final.policy : '';
    hit = { text: final ? 'FINAL,' + policy : 'FINAL', list: '', url: '', final: true };
  }
  const dns = ctx.dns ? await ctx.dns : null;
  const ips = t.ip ? [t.ip] : dns ? dns.ips : [];
  return {
    t,
    ctx,
    dns,
    hit,
    policy: policy || 'DIRECT',
    indexMissing: !ctx.manifest,
    bypass: ips.some((ip) => conf.bypass.some((cidr) => inCidr(ip, cidr))),
  };
}

// ─── Отчёты ─────────────────────────────────────────────────────────────────

function verdictOf(policy) {
  const p = String(policy).toUpperCase();
  if (p === 'DIRECT') return { cls: 'direct', icon: '✅', text: 'Напрямую' };
  if (p.indexOf('REJECT') === 0) return { cls: 'reject', icon: '⛔', text: 'Блокируется' };
  return { cls: 'proxy', icon: '🌐', text: 'Через прокси' };
}

function listLink(hit) {
  const name = escapeHtml(hit.list);
  if (hit.url && hit.url.indexOf(LISTS_URL) === 0) {
    return '<a href="' + escapeHtml(LISTS_PAGE + hit.url.slice(LISTS_URL.length)) + '">' + name + '</a>';
  }
  return name;
}

function ruleReport(res) {
  const v = verdictOf(res.policy);
  const lines = ['<div class="verdict ' + v.cls + '">' + v.icon + ' ' + v.text + ' <code>' + escapeHtml(res.policy) + '</code></div>'];
  if (res.hit.final) {
    lines.push('Ни одно правило не подошло, сработал <code>' + escapeHtml(res.hit.text) + '</code>.');
  } else {
    lines.push('Правило <code>' + escapeHtml(res.hit.text) + '</code> ' + (res.hit.list ? 'из списка ' + listLink(res.hit) : 'из SR_RU.conf') + '.');
  }
  const geo = res.ctx.geo && res.ctx.geo.cc ? res.ctx.geo : null;
  if (res.dns && res.dns.ips.length) {
    lines.push('<span class="muted">IP ' + escapeHtml(res.dns.ips[0].text) + (geo ? ' · ' + flag(geo.cc) + ' ' + geo.cc : '') +
      ': адрес от ' + escapeHtml(res.dns.via) + (geo ? ', страна по ' + escapeHtml(geo.via) : '') + '.</span>');
  } else if (res.dns) {
    lines.push('<span class="muted">DNS: ' + escapeHtml(res.dns.error) + ' (' + escapeHtml(res.dns.via) + '), поэтому правила по IP не сработали.</span>');
  } else if (geo) {
    lines.push('<span class="muted">Страна адреса: ' + flag(geo.cc) + ' ' + geo.cc + ' по ' + escapeHtml(geo.via) + '.</span>');
  }
  if (res.bypass) {
    lines.push('⚠️ Адрес входит в bypass-tun: через интерфейс TUN такие подключения идут мимо Shadowrocket, и правила к ним не применяются.');
  }
  if (res.indexMissing) {
    lines.push('⚠️ Индекс правил не загрузился, большие списки проверить не удалось.');
  }
  const unchecked = Object.keys(res.ctx.unchecked);
  if (unchecked.length) {
    lines.push('⚠️ Не удалось проверить списки: ' + unchecked.map((k) => escapeHtml(k) + ' (' + escapeHtml(res.ctx.unchecked[k]) + ')').join(', ') + '.');
  }
  const skipped = Object.keys(res.ctx.skipped);
  if (skipped.length) {
    lines.push('<span class="muted small">Правила ' + skipped.map((k) => escapeHtml(k) + ' (' + res.ctx.skipped[k] + ')').join(', ') +
      ' зависят от приложения или запроса и здесь не проверялись.</span>');
  }
  lines.push('<span class="muted small">Учтены правила SR_RU.conf из репозитория. Правила модулей и добавленные на телефоне вручную не учитываются.</span>');
  return lines.join('<br>');
}

async function probe(url) {
  const r = await get(url);
  let state;
  if (r.error) {
    state = '❌ Не открылся: ' + escapeHtml(r.error) + ' · ' + r.ms + ' мс';
  } else if (r.status >= 200 && r.status < 400) {
    state = '✅ Открылся: код ' + r.status + ' · ' + r.ms + ' мс';
  } else if (r.status >= 400 && r.status < 500) {
    state = '⚠️ Код ' + r.status + ' · ' + r.ms + ' мс: сайт отвечает, но просит вход или проверку либо ограничивает регион';
  } else {
    state = '❌ Код ' + r.status + ' · ' + r.ms + ' мс';
  }
  return state + '<br><span class="muted small">Запрос прошёл через Shadowrocket со всеми правилами, включая модули.</span>';
}

async function checkRoute() {
  const [direct, proxy] = await Promise.all([
    get('https://ipv4-internet.yandex.net/api/v0/ip'),
    get('https://ipinfo.io/json'),
  ]);

  let directIp = direct.status === 200 ? direct.body.replace(/["\s]/g, '') : '';
  if (!/^[0-9a-fA-F:.]{3,45}$/.test(directIp)) directIp = '';
  const proxyInfo = proxy.status === 200 ? parseJson(proxy.body) : null;
  const proxyIp = proxyInfo && proxyInfo.ip ? proxyInfo.ip : '';
  let directInfo = null;
  if (directIp) {
    const lookup = await get('https://ipinfo.io/' + encodeURIComponent(directIp) + '/json');
    directInfo = lookup.status === 200 ? parseJson(lookup.body) : null;
  }

  const describeIp = (ip, info) => {
    const parts = [escapeHtml(ip)];
    if (info && info.country) parts.push(flag(info.country) + ' ' + escapeHtml(info.country));
    if (info && info.city) parts.push(escapeHtml(info.city));
    if (info && info.org) parts.push(escapeHtml(info.org));
    return parts.join(' · ');
  };
  const lines = [
    '<b>Напрямую</b> (Яндекс): ' + (directIp ? describeIp(directIp, directInfo) : 'ошибка: ' + escapeHtml(failure(direct))),
    '<b>Через прокси</b> (ipinfo.io): ' + (proxyIp ? describeIp(proxyIp, proxyInfo) : 'ошибка: ' + escapeHtml(failure(proxy))),
  ];

  let verdict;
  if (!directIp || !proxyIp) {
    verdict = '⚠️ Один из адресов не определился. Проверьте, что подключение включено, и повторите проверку.';
  } else if (directIp === proxyIp) {
    verdict = '❌ Адреса совпадают: весь трафик идёт одним путём. Проверьте, что в «Глобальной маршрутизации» выбрано «Конфигурация».';
  } else if (proxyInfo && proxyInfo.country === 'RU') {
    verdict = '⚠️ IP через прокси российский: сервер находится в России, и заблокированные сайты могут не открываться.';
  } else {
    verdict = '✅ Разделение работает: российские сайты идут напрямую, зарубежные через прокси.';
  }
  lines.push(verdict);
  return lines.join('<br>');
}

function parseExtraSites(json) {
  const items = parseJson(json || '[]');
  if (!Array.isArray(items)) return [];
  return items.slice(0, MAX_EXTRA_SITES).map((item) => {
    const url = typeof item === 'string' ? item : item && item.url;
    const t = targetFromUrl(String(url || ''));
    if (!t) return null;
    const name = item && typeof item === 'object' && item.name ? String(item.name).slice(0, 60) : t.host;
    return { name, url: t.url };
  }).filter(Boolean);
}

async function checkSites(query) {
  const sites = (query.nodefault === '1' ? [] : SITES).concat(parseExtraSites(query.extra));
  if (!sites.length) return 'Список пуст: добавьте свои сайты в настройках страницы (⚙️ вверху).';
  const rows = await Promise.all(sites.map(async (site) => {
    const t = targetFromUrl(site.url);
    const [r, rule] = await Promise.all([get(site.url), t ? checkTarget(t).catch(() => null) : null]);
    let state;
    if (r.error) {
      state = '❌ ' + escapeHtml(r.error);
    } else if (r.status >= 200 && r.status < 400) {
      state = '✅ код ' + r.status + ' · ' + r.ms + ' мс';
    } else if (r.status >= 400 && r.status < 500) {
      state = '⚠️ код ' + r.status + ' · ' + r.ms + ' мс: сайт отвечает, но просит проверку или ограничивает регион';
    } else {
      state = '❌ код ' + r.status + ' · ' + r.ms + ' мс';
    }
    let route = '';
    if (rule) {
      const v = verdictOf(rule.policy);
      const source = rule.hit.list ? listLink(rule.hit) : '<code>' + escapeHtml(rule.hit.text) + '</code>';
      route = '<br><span class="muted">' + v.icon + ' ' + v.text.toLowerCase() + ' · ' + source + '</span>';
    }
    return '<div class="row"><b>' + escapeHtml(site.name) + '</b>: ' + state + route + '</div>';
  }));
  return rows.join('');
}

// ─── Страница ───────────────────────────────────────────────────────────────

const CSS = `
:root{--bg:#f5f5f7;--card:#fff;--text:#1d1d1f;--muted:#6e6e73;--accent:#0a64d8;--solid:#0a64d8;--line:#e3e3e8;--chip:#eef0f4;
--ok:#1a7f37;--ok-bg:#e6f4ea;--proxy:#0a58c2;--proxy-bg:#e7effb;--bad:#c62828;--bad-bg:#fdecec;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#000;--card:#1c1c1e;--text:#f5f5f7;--muted:#a1a1a6;
--accent:#4c9dff;--line:#2c2c2e;--chip:#2c2c2e;--ok:#5fd07c;--ok-bg:#15311d;--proxy:#7ab4ff;--proxy-bg:#132842;
--bad:#ff7b7b;--bad-bg:#3b1616;color-scheme:dark}}
:root[data-theme=dark]{--bg:#000;--card:#1c1c1e;--text:#f5f5f7;--muted:#a1a1a6;--accent:#4c9dff;--line:#2c2c2e;--chip:#2c2c2e;
--ok:#5fd07c;--ok-bg:#15311d;--proxy:#7ab4ff;--proxy-bg:#132842;--bad:#ff7b7b;--bad-bg:#3b1616;color-scheme:dark}
[hidden]{display:none!important}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.45 -apple-system,system-ui,sans-serif;padding:16px}
main{max-width:720px;margin:0 auto}
a{color:var(--accent)}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px}
h1{font-size:24px;margin:8px 0 4px}
.gear{border:0;background:transparent;font-size:24px;line-height:1;padding:6px;border-radius:10px;color:var(--text)}
p.lead{color:var(--muted);margin:0 0 16px}
.all{width:100%;padding:12px;border:0;border-radius:12px;background:var(--solid);color:#fff;font-size:17px;font-weight:600;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px 14px;margin-bottom:10px}
.card header{display:flex;align-items:center;justify-content:space-between;gap:12px}
.card h2{font-size:17px;margin:0}
.card h3{font-size:15px;margin:16px 0 6px}
.btn{border:1px solid var(--accent);background:transparent;color:var(--accent);border-radius:10px;padding:6px 12px;font-size:15px}
.btn.solid{background:var(--solid);border-color:var(--solid);color:#fff}
.out{font-size:15px;margin-top:8px;word-break:break-word}
.out:empty{display:none}
.muted{color:var(--muted)}
.small{font-size:13px}
.lookup{display:flex;gap:8px;margin-top:10px}
.lookup input{flex:1;min-width:0;font-size:16px;padding:9px 12px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--text)}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.chips:empty{display:none}
.chip{border:0;background:var(--chip);color:var(--text);border-radius:999px;padding:4px 10px;font-size:14px;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chip.clear{background:transparent;color:var(--muted)}
.verdict{display:inline-block;font-weight:600;border-radius:10px;padding:4px 10px;margin-bottom:4px}
.verdict.direct{color:var(--ok);background:var(--ok-bg)}
.verdict.proxy{color:var(--proxy);background:var(--proxy-bg)}
.verdict.reject{color:var(--bad);background:var(--bad-bg)}
code{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--chip);border-radius:6px;padding:1px 5px;word-break:break-all}
.row{padding:7px 0;border-top:1px solid var(--line)}
.row:first-child{border-top:0;padding-top:0}
.probe{margin-top:10px;padding-top:10px;border-top:1px solid var(--line)}
.checks{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:2px 12px}
.check{display:flex;align-items:center;gap:8px;padding:5px 0;font-size:15px}
.check input{width:18px;height:18px;flex:none}
textarea,select{width:100%;font:16px/1.4 -apple-system,system-ui,sans-serif;padding:8px 10px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--text)}
.note{font-size:13px;margin-top:4px}
.foot{font-size:13px;margin-top:16px}
`;

// Код страницы в Safari. Отдаётся как исходный текст функции, поэтому не использует ничего снаружи неё.
function clientMain(DATA) {
  const SETTINGS_KEY = 'sr-check-settings';
  const HISTORY_KEY = 'sr-check-history';
  const DEFAULTS = { hidden: [], sites: '', onlyMine: false, autorun: false, keepHistory: true, theme: 'auto' };
  const RU = { '网络连接失败': 'нет соединения', '检测失败': 'проверка не удалась', '请求失败': 'запрос не удался', '未知': 'неизвестно', '超时': 'таймаут' };
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.prototype.slice.call(document.querySelectorAll(sel));

  function readStore(key, fallback) {
    try {
      const value = window.localStorage.getItem(key);
      return value ? JSON.parse(value) : fallback;
    } catch (e) {
      return fallback;
    }
  }
  function writeStore(key, value) {
    try {
      window.localStorage.setItem(key, JSON.stringify(value));
    } catch (e) {
      // приватный режим Safari: настройки живут до закрытия вкладки
    }
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function translate(html) {
    let s = String(html);
    Object.keys(RU).forEach((k) => { s = s.split(k).join(RU[k]); });
    return s;
  }
  function errorText(e) {
    return e && e.message ? e.message : String(e);
  }

  let settings = Object.assign({}, DEFAULTS, readStore(SETTINGS_KEY, {}));
  if (!Array.isArray(settings.hidden)) settings.hidden = [];
  let recent = readStore(HISTORY_KEY, []);
  if (!Array.isArray(recent)) recent = [];
  const saveSettings = () => writeStore(SETTINGS_KEY, settings);

  // Домен, ссылка или IP: Safari сам переводит кириллические домены в punycode.
  function parseTarget(raw) {
    let s = String(raw || '').trim();
    if (!s) return null;
    const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s);
    if (!hasScheme && s[0] !== '[' && s.indexOf(':') !== s.lastIndexOf(':')) s = '[' + s + ']';
    let u;
    try {
      u = new URL(hasScheme ? s : 'https://' + s);
    } catch (e) {
      return null;
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    const host = u.hostname.replace(/^\[/, '').replace(/\]$/, '').replace(/\.$/, '').toLowerCase();
    // Некоторые браузеры кодируют пробелы и прочие символы в имени хоста вместо ошибки.
    const isIPv6 = host.indexOf(':') >= 0 && /^[0-9a-f:.]+$/.test(host);
    if (!isIPv6 && !(host.length <= 253 && /^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/.test(host))) return null;
    const scheme = u.protocol.slice(0, -1);
    const port = u.port ? Number(u.port) : scheme === 'http' ? 80 : 443;
    return { host, port, scheme, url: u.href, probe: hasScheme || port === 80 || port === 443 };
  }

  function mySites() {
    const sites = [];
    const bad = [];
    String(settings.sites || '').split('\n').map((line) => line.trim()).filter(Boolean).forEach((line) => {
      const bar = line.indexOf('|');
      const name = bar >= 0 ? line.slice(0, bar).trim() : '';
      const t = parseTarget(bar >= 0 ? line.slice(bar + 1) : line);
      if (t) sites.push({ name: name || t.host, url: t.url });
      else bad.push(line);
    });
    return { sites, bad };
  }

  async function getJson(path) {
    const r = await fetch(path, { cache: 'no-store' });
    let data = null;
    try {
      data = await r.json();
    } catch (e) {
      data = null;
    }
    if (!data || !data.message) throw new Error('пустой ответ, код ' + r.status);
    return data;
  }

  function applyTheme() {
    if (settings.theme === 'light' || settings.theme === 'dark') document.documentElement.setAttribute('data-theme', settings.theme);
    else document.documentElement.removeAttribute('data-theme');
  }

  function applyVisibility() {
    $$('.card[data-id]').forEach((card) => { card.hidden = settings.hidden.indexOf(card.dataset.id) >= 0; });
    $('#all').hidden = !$$('.card[data-runnable]').some((card) => !card.hidden);
  }

  async function run(id) {
    const out = $('.card[data-id="' + id + '"] .out');
    out.innerHTML = '<span class="muted">проверяю…</span>';
    let path = '/' + id;
    if (id === 'sites') {
      const params = [];
      const mine = mySites().sites;
      if (mine.length) params.push('extra=' + encodeURIComponent(JSON.stringify(mine)));
      if (settings.onlyMine) params.push('nodefault=1');
      if (params.length) path += '?' + params.join('&');
    }
    try {
      out.innerHTML = translate((await getJson(path)).message);
    } catch (e) {
      out.textContent = '❌ проверка не выполнилась: ' + errorText(e);
    }
  }

  async function runAll() {
    const queue = $$('.card[data-runnable]').filter((card) => !card.hidden).map((card) => card.dataset.id);
    const worker = async () => {
      while (queue.length) await run(queue.shift());
    };
    await Promise.all([worker(), worker(), worker()]);
  }

  function renderHistory() {
    const box = $('#history');
    if (!settings.keepHistory || !recent.length) {
      box.innerHTML = '';
      return;
    }
    box.innerHTML = recent.map((item, i) => '<button type="button" class="chip" data-recent="' + i + '">' + esc(item) + '</button>').join('') +
      '<button type="button" class="chip clear" data-clear>Очистить</button>';
  }

  function remember(raw) {
    if (!settings.keepHistory) return;
    recent = [raw].concat(recent.filter((item) => item !== raw)).slice(0, 10);
    writeStore(HISTORY_KEY, recent);
    renderHistory();
  }

  async function lookup(raw) {
    const out = $('#lookup-out');
    const text = String(raw || '').trim();
    const t = parseTarget(text);
    if (!t) {
      out.innerHTML = '❌ Не похоже на адрес. Введите домен, ссылку или IP, например <b>youtube.com</b> или <b>1.1.1.1</b>.';
      return;
    }
    remember(text);
    try {
      window.history.replaceState(null, '', '/?q=' + encodeURIComponent(text));
    } catch (e) {
      // адресная строка не обновится, проверка всё равно идёт
    }
    out.innerHTML = '<span class="muted">проверяю правила…</span>';
    const query = 'host=' + encodeURIComponent(t.host) + '&port=' + t.port + '&scheme=' + t.scheme + '&url=' + encodeURIComponent(t.url);
    try {
      out.innerHTML = '<div>' + (await getJson('/rule?' + query)).message + '</div><div class="probe"></div>';
    } catch (e) {
      out.textContent = '❌ проверка не выполнилась: ' + errorText(e);
      return;
    }
    const probeBox = out.querySelector('.probe');
    if (!t.probe) {
      probeBox.innerHTML = '<span class="muted">Соединение не проверялось: порт ' + t.port + ' не относится к сайтам.</span>';
      return;
    }
    probeBox.innerHTML = '<span class="muted">проверяю соединение…</span>';
    try {
      probeBox.innerHTML = translate((await getJson('/probe?url=' + encodeURIComponent(t.url))).message);
    } catch (e) {
      probeBox.textContent = '❌ проверка соединения не выполнилась: ' + errorText(e);
    }
  }

  function showSitesStatus() {
    const parsed = mySites();
    const status = $('#sites-status');
    if (parsed.bad.length) {
      status.textContent = '⚠️ Не похоже на адрес: ' + parsed.bad.slice(0, 3).join(', ') + (parsed.bad.length > 3 ? ' и ещё ' + (parsed.bad.length - 3) : '');
    } else {
      status.textContent = parsed.sites.length ? 'Сохранено сайтов: ' + parsed.sites.length + (parsed.sites.length > DATA.maxExtraSites ? ', проверяются первые ' + DATA.maxExtraSites : '') : '';
    }
  }

  function fillSettings() {
    $$('[data-card]').forEach((box) => { box.checked = settings.hidden.indexOf(box.dataset.card) < 0; });
    $('#my-sites').value = settings.sites || '';
    $('#only-mine').checked = !!settings.onlyMine;
    $('#autorun').checked = !!settings.autorun;
    $('#keep-history').checked = !!settings.keepHistory;
    $('#theme').value = settings.theme;
    showSitesStatus();
  }

  $('#gear').addEventListener('click', () => {
    const panel = $('#settings');
    panel.hidden = !panel.hidden;
    if (!panel.hidden) {
      fillSettings();
      panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
  $('#settings-close').addEventListener('click', () => { $('#settings').hidden = true; });
  $('#settings').addEventListener('change', (e) => {
    const el = e.target;
    if (el.dataset.card) {
      settings.hidden = settings.hidden.filter((id) => id !== el.dataset.card);
      if (!el.checked) settings.hidden.push(el.dataset.card);
      applyVisibility();
    } else if (el.id === 'only-mine') {
      settings.onlyMine = el.checked;
    } else if (el.id === 'autorun') {
      settings.autorun = el.checked;
    } else if (el.id === 'keep-history') {
      settings.keepHistory = el.checked;
      if (!el.checked) {
        recent = [];
        writeStore(HISTORY_KEY, recent);
      }
      renderHistory();
    } else if (el.id === 'theme') {
      settings.theme = el.value;
      applyTheme();
    }
    saveSettings();
  });
  $('#my-sites').addEventListener('input', () => {
    settings.sites = $('#my-sites').value;
    saveSettings();
    showSitesStatus();
  });
  $('#reset').addEventListener('click', () => {
    if (!window.confirm('Вернуть настройки страницы по умолчанию? История адресов останется.')) return;
    settings = Object.assign({}, DEFAULTS);
    saveSettings();
    fillSettings();
    applyTheme();
    applyVisibility();
    renderHistory();
  });

  $('#lookup-form').addEventListener('submit', (e) => {
    e.preventDefault();
    $('#q').blur();
    lookup($('#q').value);
  });
  $('#history').addEventListener('click', (e) => {
    const el = e.target.closest('button');
    if (!el) return;
    if (el.hasAttribute('data-clear')) {
      recent = [];
      writeStore(HISTORY_KEY, recent);
      renderHistory();
      return;
    }
    const item = recent[Number(el.dataset.recent)];
    if (item) {
      $('#q').value = item;
      lookup(item);
    }
  });
  $$('[data-run]').forEach((button) => button.addEventListener('click', () => run(button.dataset.run)));
  $('#all').addEventListener('click', runAll);

  applyTheme();
  applyVisibility();
  renderHistory();
  const initial = new URLSearchParams(window.location.search).get('q');
  if (initial) {
    $('#q').value = initial;
    lookup(initial);
  }
  if (settings.autorun) runAll();
}

function page() {
  const runnable = [['route', 'Маршрут и IP'], ['sites', 'Сайты']].concat(SERVICES);
  const cards = runnable.map(([id, name]) =>
    '<section class="card" data-id="' + id + '" data-runnable><header><h2>' + escapeHtml(name) + '</h2>' +
    '<button type="button" class="btn" data-run="' + id + '">Проверить</button></header><div class="out"></div></section>').join('');
  const checks = [['lookup', 'Проверить адрес']].concat(runnable).map(([id, name]) =>
    '<label class="check"><input type="checkbox" data-card="' + id + '"> ' + escapeHtml(name) + '</label>').join('');
  const data = JSON.stringify({ maxExtraSites: MAX_EXTRA_SITES }).replace(/</g, '\\u003c');
  return `<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Проверка сервисов</title>
<script>try{var s=JSON.parse(localStorage.getItem('sr-check-settings')||'{}');if(s.theme==='light'||s.theme==='dark')document.documentElement.setAttribute('data-theme',s.theme)}catch(e){}</script>
<style>${CSS}</style></head><body><main>
<div class="top"><h1>Проверка сервисов</h1><button type="button" class="gear" id="gear" aria-label="Настройки страницы">⚙️</button></div>
<p class="lead">Все проверки идут по правилам вашего конфига: видно, что открывается напрямую, что через прокси, а что блокируется.</p>
<section class="card" id="settings" hidden>
<header><h2>Настройки страницы</h2><button type="button" class="btn solid" id="settings-close">Готово</button></header>
<p class="muted note">Настройки сохраняются в Safari на этом устройстве.</p>
<h3>Блоки на странице</h3>
<div class="checks">${checks}</div>
<h3>Свои сайты</h3>
<p class="muted note">По одному в строке: адрес или «Название | адрес». Они проверяются в блоке «Сайты» вместе со стандартными.</p>
<textarea id="my-sites" rows="5" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="habr.com&#10;Мой сервер | https://example.com"></textarea>
<p class="muted note" id="sites-status"></p>
<label class="check"><input type="checkbox" id="only-mine"> Проверять только свои сайты</label>
<h3>Поведение</h3>
<label class="check"><input type="checkbox" id="autorun"> Запускать все проверки при открытии</label>
<label class="check"><input type="checkbox" id="keep-history"> Запоминать проверенные адреса</label>
<h3>Тема</h3>
<select id="theme"><option value="auto">Как в системе</option><option value="light">Светлая</option><option value="dark">Тёмная</option></select>
<h3>Сброс</h3>
<button type="button" class="btn" id="reset">Вернуть настройки по умолчанию</button>
</section>
<section class="card" data-id="lookup"><header><h2>Проверить адрес</h2></header>
<p class="muted note">Домен, ссылка или IP: покажу, по какому правилу он пойдёт, и проверю, открывается ли он.</p>
<form class="lookup" id="lookup-form"><input id="q" type="text" inputmode="url" enterkeyhint="go" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="youtube.com, 1.1.1.1 или ссылка"><button type="submit" class="btn solid">Проверить</button></form>
<div class="chips" id="history"></div>
<div class="out" id="lookup-out"></div>
</section>
<button type="button" class="all" id="all">Проверить всё</button>
${cards}
<p class="muted foot">Проверки сервисов: скрипты huskydsb/Shadowrocket. Модуль и правила: newzealandgrom/Shadowrocket-routing.</p>
</main>
<script>(${clientMain.toString()})(${data});</script>
</body></html>`;
}

// ─── Ответ ──────────────────────────────────────────────────────────────────

function respond(status, contentType, body) {
  $done({ response: { status, headers: { 'Content-Type': contentType, 'Cache-Control': 'no-store' }, body } });
}

function respondJson(value, status) {
  respond(status || 200, 'application/json; charset=utf-8', JSON.stringify(value));
}

(async () => {
  const url = ($request && $request.url) || '';
  const path = url.replace(/^https?:\/\/[^/]+/, '').split('?')[0].replace(/\/+$/, '');
  const query = parseQuery(url);
  try {
    if (path === '/route') {
      respondJson({ message: await checkRoute() });
    } else if (path === '/sites') {
      respondJson({ message: await checkSites(query) });
    } else if (path === '/rule') {
      const t = makeTarget(query.host, query.port, query.scheme, query.url);
      if (!t) {
        respondJson({ message: '❌ Не похоже на домен или IP-адрес.' });
      } else {
        const res = await checkTarget(t);
        respondJson({ message: ruleReport(res), policy: res.policy, verdict: verdictOf(res.policy).cls });
      }
    } else if (path === '/probe') {
      const target = query.url && query.url.length <= 2000 ? targetFromUrl(query.url) : null;
      respondJson({ message: target ? await probe(target.url) : '❌ Нужна ссылка http:// или https://.' });
    } else {
      respond(200, 'text/html; charset=utf-8', page());
    }
  } catch (e) {
    respondJson({ message: '❌ ошибка скрипта: ' + escapeHtml(e && e.message ? e.message : e) }, 500);
  }
})();
