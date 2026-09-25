# Shadowrocket-routing

Готовый профиль маршрутизации для **Shadowrocket** (iOS), ориентированный на пользователей из России:

- зарубежные сервисы (YouTube, Google, Telegram, Meta, OpenAI, Discord, TikTok, GitHub и др.) и всё, что заблокировано в РФ, идут через прокси;
- российские сайты, банки и локальные сети идут напрямую (DIRECT), экономя трафик и скорость;
- реклама и трекеры блокируются (REJECT);
- отдельный модуль убирает рекламу в YouTube.

Профиль подключается по ссылке и обновляется автоматически вместе со всеми списками.

```
https://raw.githubusercontent.com/newzealandgrom/Shadowrocket-routing/refs/heads/master/SR_RU.conf
```

## Содержимое репозитория

| Путь | Что это |
|---|---|
| `SR_RU.conf` | Главный конфиг: секции `[General]`, `[Rule]`, `[Host]`. Все списки подключаются через `RULE-SET` с raw-ссылок GitHub. |
| `lists/` | Списки правил в формате Shadowrocket (см. таблицу ниже). |
| `lists/overrides/` | Локальные правки к автоматически обновляемым спискам: `<имя>.exclude` (что выкинуть), `<имя>.append` (что добавить). |
| `modules/YT-Premium-V1-RU.module` | Модуль блокировки рекламы YouTube (MITM + скрипт). |
| `modules/Certificate.module` | Шаблон модуля с собственным MITM-сертификатом (`ca-p12` / `ca-passphrase`). |
| `Script/youtube.response.js` | Скрипт, который использует YouTube-модуль. |
| `github_actions/validate_lists.py` | Валидатор списков и конфига (запускается в CI). |
| `github_actions/normalize_lists.py` | Приведение списков к каноническому виду. |
| `github_actions/sync_upstream.py` | Синхронизация списков с upstream-источниками. |

### Списки

Порядок в таблице совпадает с порядком в `SR_RU.conf`: первое подошедшее правило побеждает.

| Файл | Политика | Что содержит | Источник / обновление |
|---|---|---|---|
| `reject.list` | REJECT | Реклама, трекеры, аналитика | вручную |
| `private.list` | DIRECT | Локальные и служебные домены (`.local`, `.lan`, роутеры, `in-addr.arpa`) | автоматически, v2fly `private` |
| `direct.list` | DIRECT | Российские сервисы, которые должны идти напрямую | вручную |
| `domains_banking.list` | DIRECT | Сайты банков по списку ЦБ РФ | вручную |
| `discord.list` | PROXY | Discord | вручную |
| `domains_refilter.list` | PROXY | Домены, заблокированные в РФ (`domains_all.lst`), плюс сайты, ограничивающие доступ из РФ (`community.lst`) | автоматически, [Re-filter](https://github.com/1andrevich/Re-filter-lists) |
| `domains_community.list` | PROXY | Ручные дополнения к списку заблокированного | вручную |
| `TikTok.list` | PROXY | TikTok, CapCut | вручную |
| `GitHub.list` | PROXY | GitHub, npm | автоматически, [blackmatrix7](https://github.com/blackmatrix7/ios_rule_script) |
| `Google.list` | PROXY | Google (без YouTube) | автоматически, blackmatrix7 |
| `Telegram.list` | PROXY | Домены, подсети и ASN Telegram | автоматически, blackmatrix7 |
| `OpenAI.list` | PROXY | ChatGPT, OpenAI API и их поддомены | автоматически, blackmatrix7 |
| `Facebook.list` | PROXY | Facebook, Instagram, WhatsApp, Threads | автоматически, blackmatrix7 |
| `Twitter.list` | PROXY | X/Twitter, Grok | автоматически, blackmatrix7 |
| `Apple.list` | PROXY | Подсети, User-Agent и ключевые слова Apple (доменные правила blackmatrix7 держит в отдельном `Apple_Domain.list`, он не подключён: домены Apple попадают под GEOIP/FINAL) | автоматически, blackmatrix7 |
| `domains_geo_detect.list` | PROXY | Сервисы определения IP и геолокации | автоматически, [MetaCubeX](https://github.com/MetaCubeX/meta-rules-dat) |
| `YouTube.list` | PROXY | YouTube и googlevideo | автоматически, blackmatrix7 |
| `proxy.list` | PROXY | Ручные дополнения: ИИ-сервисы, Spotify, Twitch и т.д. | вручную |
| `voice_ports.list` | PROXY | Порты голосовых и видеозвонков (WhatsApp, Telegram, Google Meet) | вручную |
| `ips_refilter.list` | PROXY | IP-адреса заблокированных в РФ ресурсов | автоматически, Re-filter |
| `meta_ips.list` | PROXY | Подсети Meta (Facebook, Instagram, WhatsApp) | вручную |
| `telegram_ips.list` | PROXY | Подсети Telegram | вручную |

После списков стоят два завершающих правила: `GEOIP,RU,DIRECT` (всё, что резолвится в российские IP, идёт напрямую) и `FINAL,PROXY` (всё остальное через прокси).

## Как устроен конфиг

**`[General]`**

- DNS: DoH Google, ControlD, Cloudflare (`1.1.1.1`) и xbox-dns.ru; резервные Cloudflare DoH, Яндекс DoT/DoH и системный DNS.
- `always-real-ip = *` (fake-IP отключён), `hijack-dns = *:53` (перехват всех DNS-запросов), IPv6 выключен.
- `skip-proxy` и `bypass-tun` исключают локальные сети из туннеля.
- `update-url` — конфиг обновляется из этого репозитория.

**`[Rule]`**, по порядку:

1. Совместимость с Tailscale (`100.64.0.0/10`, `ts.net`) — DIRECT.
2. `reject.list` — REJECT. Стоит первым, поэтому домен из него блокируется, даже если он есть в других списках.
3. `private.list`, `direct.list`, `domains_banking.list` — DIRECT.
4. Доменные списки сервисов и заблокированных ресурсов — PROXY.
5. Порты звонков и IP-списки — PROXY. IP-правила стоят после доменных и помечены `no-resolve`.
6. `GEOIP,RU,DIRECT`, затем `FINAL,PROXY`.

В `SR_RU.conf` нет секции `[MITM]` и модулей: они подключаются отдельно (см. ниже), поэтому базовый профиль работает без установки сертификата.

## Установка

### Требования

- iPhone или iPad с актуальной iOS и приложением **Shadowrocket** из App Store.
- Хотя бы один рабочий прокси-сервер или подписка (VLESS, VMess, Trojan, Shadowsocks, Hysteria2 и т.д.). Без серверов профиль работать не будет.

### Шаг 1. Подключить конфиг по ссылке

1. Скопируйте ссылку на `SR_RU.conf` (см. выше).
2. Shadowrocket → вкладка **Config** → **+** → **Import from URL**, вставьте ссылку.
3. Задайте имя (например, `SR_RU`), включите **Auto Update** и сохраните.
4. Нажмите на добавленный конфиг, чтобы сделать его активным.

### Шаг 2. Добавить свои серверы

1. Вкладка **Proxy** → **+** → ссылка подписки, QR-код или ручной ввод.
2. Убедитесь, что серверы попали в группу **PROXY**: именно эта политика используется в правилах. При необходимости создайте группу с таким именем (режимы `select`, `url-test`, `fallback`, `load-balance`).

### Шаг 3. Проверить

1. Нажмите кнопку подключения на главном экране.
2. YouTube и Telegram должны показывать IP прокси, российские сайты (например, `yandex.ru`) — ваш реальный IP.
3. Для проверки IP подойдут `https://2ip.ru` (идёт напрямую) и `https://browserleaks.com/ip` (идёт через прокси).

### Шаг 4 (по желанию). Модуль YouTube без рекламы

Модуль вырезает рекламу в приложении YouTube и в веб-версии, блокирует Shorts (настраивается) и включает картинку-в-картинке. Работает через MITM, поэтому нужен сертификат.

1. Shadowrocket → **Settings** → **HTTPS Decryption** (Расшифровка HTTPS): включите, сгенерируйте сертификат, установите его в iOS и включите доверие (**Settings → General → About → Certificate Trust Settings**).
2. **Settings** → **Module** → **+** → вставьте ссылку:

   ```
   https://raw.githubusercontent.com/newzealandgrom/Shadowrocket-routing/refs/heads/master/modules/YT-Premium-V1-RU.module
   ```

3. Включите модуль. Аргументы модуля (`captionLang`, `lyricLang`, `blockUpload`, `blockImmersive`, `blockShorts`, `debug`) можно менять в его настройках.

`modules/Certificate.module` — шаблон, чтобы использовать один и тот же MITM-сертификат на нескольких устройствах: подставьте вместо `${CA_P12}` и `${CA_PASSPHRASE}` экспортированный из Shadowrocket сертификат (base64 p12) и пароль к нему, сохраните под своим URL и подключите как модуль.

## Как редактировать списки

- Ручные списки (`direct.list`, `proxy.list`, `reject.list`, `domains_banking.list`, `domains_community.list`, `discord.list`, `TikTok.list`, `voice_ports.list`, `meta_ips.list`, `telegram_ips.list`) правятся напрямую.
- Автоматически обновляемые списки перезаписываются скриптом синхронизации, поэтому правки в них не сохранятся. Вместо этого:
  - `lists/overrides/<имя>.exclude` — правила, которые нужно выкинуть из upstream-версии;
  - `lists/overrides/<имя>.append` — правила, которые нужно добавить.

  Формат тот же, что в списках (`DOMAIN-SUFFIX,example.com`), по одному правилу на строку, `#` — комментарий.
- Синхронизация запускается по расписанию workflow `sync-upstream.yml` и вручную кнопкой **Run workflow** на вкладке Actions. Локально: `python github_actions/sync_upstream.py --dry-run`.

### Проверка

При каждом изменении `lists/` или `SR_RU.conf` в CI запускается `validate_lists.py`. Сборка падает при: неизвестных типах правил, невидимых символах и типографских тире, wildcard в доменных правилах, заглавных буквах, некорректных IP/портах, дубликатах внутри файла, одной и той же записи в списках с политиками DIRECT и PROXY, ссылке `RULE-SET` на несуществующий файл. Предупреждения (пересечения с `reject.list`, записи, перекрытые родительским суффиксом, политика внутри файла списка) сборку не роняют.

Локально:

```
python github_actions/validate_lists.py      # проверить
python github_actions/normalize_lists.py     # привести списки к каноническому виду
```

## Возможные проблемы

| Проблема | Решение |
|---|---|
| Нет интернета после подключения | Проверьте, что в группе PROXY есть рабочие серверы |
| Российские сайты тоже идут через прокси | Убедитесь, что активен именно этот конфиг и он обновлён |
| Сервис заблокирован в РФ, но идёт напрямую | Добавьте домен в `lists/domains_community.list` или `lists/proxy.list` |
| Российский сервис идёт через прокси | Добавьте домен в `lists/direct.list` |
| YouTube-модуль не убирает рекламу | Проверьте, что HTTPS Decryption включён, сертификат установлен и доверен, а модуль активен |
| Ошибка импорта конфига | Проверьте интернет и правильность raw-ссылки |

## Лицензия

См. файл `LICENSE`.
