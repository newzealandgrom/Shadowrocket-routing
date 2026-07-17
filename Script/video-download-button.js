// video-download-button.js
// ВАЖНО: этот код выполняется в песочнице Shadowrocket (НЕ в браузере).
// Здесь нет document/window — только $request/$response/$done.
// Скрипт вставляет браузерный код кнопки внутрь HTML-ответа как строку.

let headers = $response.headers || {};
let contentType = '';
for (const key of Object.keys(headers)) {
  if (key.toLowerCase() === 'content-type') {
    contentType = String(headers[key]);
    break;
  }
}

// Трогаем только HTML-страницы — иначе можно сломать JSON/картинки/шрифты сайта
if (!contentType || contentType.toLowerCase().indexOf('text/html') === -1) {
  $done({});
} else {
  let body = $response.body || '';

  // Снимаем CSP-заголовок (иначе браузер молча заблокирует наш инлайн-скрипт)
  const newHeaders = {};
  for (const key of Object.keys(headers)) {
    const lower = key.toLowerCase();
    if (lower === 'content-security-policy' || lower === 'content-security-policy-report-only') {
      continue;
    }
    newHeaders[key] = headers[key];
  }

  // Снимаем CSP, если он задан через <meta> тег в самом HTML
  body = body.replace(/<meta[^>]+http-equiv=["']?content-security-policy["']?[^>]*>/gi, '');

  const injected = `
<script>
(function () {
  'use strict';
  var BTN_ID = '__sr_video_dl_btn__';
  var SCAN_INTERVAL_MS = 1500;
  var currentUrl = null;

  function findDownloadableVideoSrc() {
    var videos = document.querySelectorAll('video');
    for (var i = 0; i < videos.length; i++) {
      var video = videos[i];
      var src = video.currentSrc || video.src;
      if (!src) {
        var source = video.querySelector('source[src]');
        if (source) src = source.src;
      }
      if (!src) continue;
      if (src.indexOf('blob:') === 0) continue;
      if (/\\.(m3u8|mpd)(\\?.*)?$/i.test(src)) continue;
      return src;
    }
    return null;
  }

  function ensureButton() {
    var btn = document.getElementById(BTN_ID);
    if (btn) return btn;
    btn = document.createElement('div');
    btn.id = BTN_ID;
    btn.textContent = '⬇';
    btn.title = 'Скачать видео';
    btn.style.cssText = 'position:fixed;z-index:2147483647;bottom:16px;right:16px;width:44px;height:44px;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,0.55);color:#fff;border-radius:50%;font-size:20px;cursor:pointer;font-family:sans-serif;box-shadow:0 2px 6px rgba(0,0,0,0.3);transition:opacity 0.2s;opacity:0.5';
    btn.addEventListener('mouseenter', function () { btn.style.opacity = '1'; });
    btn.addEventListener('mouseleave', function () { btn.style.opacity = '0.5'; });
    btn.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      if (!currentUrl) return;
      var a = document.createElement('a');
      a.href = currentUrl;
      a.download = '';
      document.body.appendChild(a);
      a.click();
      a.remove();
    });
    document.body.appendChild(btn);
    return btn;
  }

  function scan() {
    if (!document.body) return;
    var btn = ensureButton();
    var src = findDownloadableVideoSrc();
    currentUrl = src;
    btn.style.display = src ? 'flex' : 'none';
  }

  function start() {
    scan();
    setInterval(scan, SCAN_INTERVAL_MS);
    var observer = new MutationObserver(scan);
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  if (document.body) {
    start();
  } else {
    document.addEventListener('DOMContentLoaded', start);
  }
})();
</script>
`;

  if (body.indexOf('</body>') !== -1) {
    body = body.replace('</body>', injected + '</body>');
  } else {
    body = body + injected;
  }

  $done({ body: body, headers: newHeaders });
}
