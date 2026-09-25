/*
 * Проверка сервисов для Shadowrocket: страница http://sr.test/ из модуля modules/Service-Check-RU.module.
 *
 *   http://sr.test/        — страница с кнопками проверок (https:// тоже, если включена HTTPS-расшифровка);
 *   http://sr.test/route   — IP напрямую (Яндекс) и через прокси (ipinfo.io): работает ли разделение трафика;
 *   http://sr.test/sites   — отвечают ли ключевые сайты: российские напрямую, зарубежные через прокси.
 *
 * Остальные проверки на странице (YouTube, ChatGPT, Netflix и т.д.) выполняют скрипты
 * huskydsb/Shadowrocket, их подключает модуль. Все запросы идут по правилам текущего конфига,
 * поэтому результаты показывают реальную маршрутизацию.
 */

const UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1';
const REQUEST_LIMIT_MS = 9000;

const SITES = [
  { name: 'Госуслуги', url: 'https://www.gosuslugi.ru/', route: 'напрямую' },
  { name: 'Сбербанк', url: 'https://www.sberbank.ru/', route: 'напрямую' },
  { name: 'Яндекс', url: 'https://ya.ru/', route: 'напрямую' },
  { name: 'ВКонтакте', url: 'https://vk.com/', route: 'напрямую' },
  { name: 'YouTube', url: 'https://www.youtube.com/generate_204', route: 'через прокси' },
  { name: 'Instagram', url: 'https://www.instagram.com/', route: 'через прокси' },
  { name: 'Telegram', url: 'https://telegram.org/', route: 'через прокси' },
  { name: 'Discord', url: 'https://discord.com/api/v9/experiments', route: 'через прокси' },
  { name: 'ChatGPT', url: 'https://chatgpt.com/', route: 'через прокси' },
  { name: 'Claude', url: 'https://claude.ai/', route: 'через прокси' },
  { name: 'X (Twitter)', url: 'https://x.com/', route: 'через прокси' },
  { name: 'LinkedIn', url: 'https://www.linkedin.com/', route: 'через прокси' },
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

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function flag(cc) {
  if (!/^[A-Za-z]{2}$/.test(cc || '')) return '';
  return String.fromCodePoint(...cc.toUpperCase().split('').map((c) => 127397 + c.charCodeAt(0)));
}

function get(url) {
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
    $httpClient.get({ url, headers: { 'User-Agent': UA, 'Accept-Language': 'ru-RU,ru;q=0.9,en;q=0.8' }, timeout: 10000 },
      (error, response, body) => {
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

function describeIp(ip, info) {
  if (!ip) return 'не удалось определить';
  const parts = [escapeHtml(ip)];
  if (info && info.country) parts.push(flag(info.country) + ' ' + escapeHtml(info.country));
  if (info && info.city) parts.push(escapeHtml(info.city));
  if (info && info.org) parts.push(escapeHtml(info.org));
  return parts.join(' · ');
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

async function checkSites() {
  const results = await Promise.all(SITES.map((site) => get(site.url).then((r) => ({ site, r }))));
  return results.map(({ site, r }) => {
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
    return '<b>' + escapeHtml(site.name) + '</b> (' + site.route + '): ' + state;
  }).join('<br>');
}

function page() {
  const cards = [['route', 'Маршрут и IP'], ['sites', 'Доступность сайтов']].concat(SERVICES);
  const items = cards.map(([id, name]) =>
    '<section class="card" data-id="' + id + '"><header><h2>' + escapeHtml(name) + '</h2>' +
    '<button type="button" data-run="' + id + '">Проверить</button></header><div class="out"></div></section>').join('');
  return `<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Проверка сервисов</title>
<style>
:root{--bg:#f5f5f7;--card:#fff;--text:#1d1d1f;--muted:#6e6e73;--accent:#0a64d8;--line:#e3e3e8}
@media (prefers-color-scheme:dark){:root{--bg:#000;--card:#1c1c1e;--text:#f5f5f7;--muted:#a1a1a6;--accent:#4c9dff;--line:#2c2c2e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.45 -apple-system,system-ui,sans-serif;padding:16px}
main{max-width:720px;margin:0 auto}h1{font-size:24px;margin:8px 0 4px}p.lead{color:var(--muted);margin:0 0 16px}
.all{width:100%;padding:12px;border:0;border-radius:12px;background:var(--accent);color:#fff;font-size:17px;font-weight:600;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px 14px;margin-bottom:10px}
.card header{display:flex;align-items:center;justify-content:space-between;gap:12px}
.card h2{font-size:17px;margin:0}.card button{border:1px solid var(--accent);background:transparent;color:var(--accent);border-radius:10px;padding:6px 12px;font-size:15px}
.out{color:var(--text);font-size:15px;margin-top:6px;word-break:break-word}.out:empty{display:none}.muted{color:var(--muted)}
</style></head><body><main>
<h1>Проверка сервисов</h1>
<p class="lead">Все проверки идут по правилам вашего конфига: так видно, что открывается напрямую, а что через прокси.</p>
<button type="button" class="all" id="all">Проверить всё</button>
${items}
<p class="muted">Проверки сервисов: скрипты huskydsb/Shadowrocket. Модуль: newzealandgrom/Shadowrocket-routing.</p>
</main>
<script>
const RU = { '网络连接失败': 'нет соединения', '检测失败': 'проверка не удалась', '请求失败': 'запрос не удался', '未知': 'неизвестно', '超时': 'таймаут' };
function translate(html) { let s = String(html); for (const k in RU) s = s.split(k).join(RU[k]); return s; }
async function run(id) {
  const out = document.querySelector('.card[data-id="' + id + '"] .out');
  out.innerHTML = '<span class="muted">проверяю…</span>';
  try {
    const r = await fetch('/' + id, { cache: 'no-store' });
    const data = await r.json().catch(() => ({}));
    out.innerHTML = data && data.message ? translate(data.message) : '❌ пустой ответ, код ' + r.status;
  } catch (e) {
    out.textContent = '❌ проверка не выполнилась: ' + e;
  }
}
document.querySelectorAll('[data-run]').forEach((b) => b.addEventListener('click', () => run(b.dataset.run)));
document.getElementById('all').addEventListener('click', async () => {
  const ids = Array.from(document.querySelectorAll('.card')).map((c) => c.dataset.id);
  const queue = ids.slice();
  const worker = async () => { while (queue.length) await run(queue.shift()); };
  await Promise.all([worker(), worker(), worker()]);
});
</script></body></html>`;
}

function respond(status, contentType, body) {
  $done({ response: { status, headers: { 'Content-Type': contentType, 'Cache-Control': 'no-store' }, body } });
}

(async () => {
  const path = (($request && $request.url) || '').replace(/^https?:\/\/[^/]+/, '').split('?')[0].replace(/\/+$/, '');
  try {
    if (path === '/route') {
      respond(200, 'application/json; charset=utf-8', JSON.stringify({ message: await checkRoute() }));
    } else if (path === '/sites') {
      respond(200, 'application/json; charset=utf-8', JSON.stringify({ message: await checkSites() }));
    } else {
      respond(200, 'text/html; charset=utf-8', page());
    }
  } catch (e) {
    respond(500, 'application/json; charset=utf-8', JSON.stringify({ message: '❌ ошибка скрипта: ' + escapeHtml(e && e.message ? e.message : e) }));
  }
})();
