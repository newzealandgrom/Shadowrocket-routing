// video-download-button.js
// Инъекция кнопки "Скачать видео" на страницы с <video> тегами

(function () {
  'use strict';

  const BTN_ID = '__sr_video_download_btn__';
  const CHECK_INTERVAL_MS = 1500;
  const processedVideos = new WeakSet();

  function getVideoSrc(video) {
    if (video.currentSrc) return video.currentSrc;
    if (video.src) return video.src;
    const source = video.querySelector('source[src]');
    if (source) return source.src;
    return null;
  }

  function isDirectFile(url) {
    if (!url) return false;
    if (url.startsWith('blob:')) return false;
    return /\.(mp4|webm|mov|m4v)(\?.*)?$/i.test(url) || !/\.(m3u8|mpd)(\?.*)?$/i.test(url);
  }

  function createButton(video) {
    const btn = document.createElement('button');
    btn.textContent = '⬇ Скачать видео';
    btn.style.cssText = [
      'position:absolute',
      'z-index:2147483647',
      'top:8px',
      'right:8px',
      'padding:6px 12px',
      'background:rgba(0,0,0,0.75)',
      'color:#fff',
      'border:none',
      'border-radius:6px',
      'font-size:13px',
      'cursor:pointer',
      'font-family:sans-serif'
    ].join(';');

    btn.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      const url = getVideoSrc(video);
      if (!url) {
        alert('Не удалось определить ссылку на видео');
        return;
      }
      if (url.startsWith('blob:')) {
        alert('Видео передаётся через blob-поток — прямое скачивание невозможно');
        return;
      }
      if (/\.(m3u8|mpd)(\?.*)?$/i.test(url)) {
        // HLS/DASH — просто открываем ссылку на плейлист,
        // реальное скачивание требует внешнего инструмента (yt-dlp и т.п.)
        window.open(url, '_blank');
        return;
      }
      const a = document.createElement('a');
      a.href = url;
      a.download = '';
      document.body.appendChild(a);
      a.click();
      a.remove();
    });

    return btn;
  }

  function attachButtonToVideo(video) {
    if (processedVideos.has(video)) return;
    if (!video.parentElement) return;

    const parent = video.parentElement;
    const computedPosition = window.getComputedStyle(parent).position;
    if (computedPosition === 'static') {
      parent.style.position = 'relative';
    }

    const btn = createButton(video);
    btn.id = BTN_ID + Math.random().toString(36).slice(2);
    parent.appendChild(btn);
    processedVideos.add(video);
  }

  function scanForVideos() {
    const videos = document.querySelectorAll('video');
    videos.forEach(attachButtonToVideo);
  }

  scanForVideos();
  setInterval(scanForVideos, CHECK_INTERVAL_MS);

  const observer = new MutationObserver(() => scanForVideos());
  observer.observe(document.documentElement, { childList: true, subtree: true });
})();
