// m3u8-capture.js
// Выполняется в песочнице Shadowrocket (НЕ в браузере) — доступны только
// $request/$response/$done/$notification, никакого document/window тут нет.
// Ловит запрос к .m3u8 плейлисту и показывает системное уведомление со ссылкой.

var url = $request.url;
$notification.post('Найдена ссылка на видео (m3u8)', '', url);
$done({});
