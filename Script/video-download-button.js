// video-download-button.js
// Плавающая кнопка "Скачать видео" — не перекрывает плеер,
// появляется только если найден прямой src (не blob/m3u8)

(function () {
  'use strict';

  const BTN_ID = '__sr_video_dl_btn__';
  const SCAN_INTERVAL_MS = 1500;
  let currentUrl = null;

  function findDownloadableVideoSrc() {
    const videos = document.querySelectorAll('video');
    for (const video of videos) {
      const src = video.currentSrc || video.src ||
        (video.querySelector('source[src]') ? video.querySelector('source[src]').src : null);
      if (!src) continue;
      if (src.startsWith('blob:')) continue;
      if (/\.(m3u8|mpd)(\?.*)?$/i.test(src)) continue;
      return src;
    }
    return null;
  }

  function ensureButton() {
    let btn = document.getElementById(BTN_ID);
    if (btn) return btn;

    btn = document.createElement('div');
    btn.id = BTN_ID;
    btn.textContent = '⬇';
    btn.title = 'Скачать видео';
    btn.style.cssText = [
      'position:fixed',
      'z-index:2147483647',
      'bottom:16px',
      'right:16px',
      'width:44px',
      'height:44px',
      'display:none',
      'align-items:center',
      'justify-content:center',
      'background:rgba(0,0,0,0.55)',
      'color:#fff',
      'border-radius:50%',
      'font-size:20px',
      'cursor:pointer',
      'font-family:sans-serif',
      'box-shadow:0 2px 6px rgba(0,0,0,0.3)',
      'transition:opacity 0.2s',
      'opacity:0.5'
    ].join(';');
    btn.style.display = 'none';

    btn.addEventListener('mouseenter', () => { btn.style.opacity = '1'; });
    btn.addEventListener('mouseleave', () => { btn.style.opacity = '0.5'; });

    btn.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      if (!currentUrl) return;
      const a = document.createElement('a');
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
    const btn = ensureButton();
    const src = findDownloadableVideoSrc();
    currentUrl = src;
    btn.style.display = src ? 'flex' : 'none';
  }

  const start = () => {
    scan();
    setInterval(scan, SCAN_INTERVAL_MS);
    const observer = new MutationObserver(scan);
    observer.observe(document.documentElement, { childList: true, subtree: true });
  };

  if (document.body) {
    start();
  } else {
    document.addEventListener('DOMContentLoaded', start);
  }
})();
