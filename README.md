# xray-fork

> Совместная разработка Rust-ядра для RemnaNode 3.4.3. Проект распространяется по MPL-2.0; лицензии зависимостей сохранены. Наличие протокола в исходниках не означает, что каждый профиль уже проверен на наших клиентах и узлах.

**Навигация на русском:** [интерактивный установщик](docs/ИНТЕРАКТИВНЫЙ-УСТАНОВЩИК.md) · [протоколы и ограничения](docs/ПРОТОКОЛЫ.md) · [ручная установка на RemnaNode 3.4.3](docs/УСТАНОВКА-REMNANODE-3.4.3.md) · [проверки перед включением клиентов](docs/ПРОВЕРКИ.md).

Ядро на Rust для узлов Remnawave с VLESS, REALITY, Vision и WebSocket. Remnanode 3.4.3 передаёт ему конфигурацию через Unix-сокет и управляет пользователями и счётчиками через gRPC. Нативный режим обслуживает трафик без запуска Go Xray.

## Возможности

- VLESS поверх TCP/RAW + REALITY (X25519), IPv4 и IPv6. Обычные TLS-соединения передаются на `realitySettings.target` с исходным ClientHello.
- VLESS поверх TCP/RAW + TLS 1.2 и 1.3 с одной цепочкой сертификатов и Vision. Сертификат и ключ могут быть заданы в профиле или прочитаны из файлов при старте.
- VLESS поверх WebSocket без TLS на входе ядра. HAProxy может завершать TLS и передавать адрес клиента через PROXY v2 на loopback-порт. Поддерживаются `trustedXForwardedFor`, проверка пути и WebSocket early data Xray.
- Многопользовательский входящий Shadowsocks с `chacha20-ietf-poly1305` для TCP и UDP. Remnanode может обновлять список пользователей через gRPC.
- Маршрутизация по доменам, IP, GeoIP, GeoSite, портам, сети, протоколу, входу и пользователю. Sniffing распознаёт HTTP Host, TLS SNI, QUIC v1/v2 Initial и BitTorrent.
- DNS с UDP-резолверами по IP, DNS-over-TLS (`tls://`) и `localhost`. Поддерживаются приоритет по доменам и GeoSite, выбор семейства IP и кеш по TTL. DNS-over-TLS проверяет сертификат по системному хранилищу CA.
- Выходы Freedom, Blackhole, HTTP CONNECT с Basic Auth, SOCKS5 без авторизации и VLESS/RAW. Для VLESS/TLS проверяется отпечаток сертификата. UDP поддерживается через Freedom, SOCKS5 UDP ASSOCIATE и VLESS.
- Torrent Blocker передаёт события Remnanode, который применяет блокировку через nftables. Для этого контейнеру нужна capability `NET_ADMIN`.
- Remnanode получает счётчики по gRPC. Метрики доступны через `/metrics` панели Remnawave.

В Vision прямое чтение используется в направлении от клиента. В обратном направлении сохраняется внешний TLS. Ядро принимает VLESS TCP Mux и XUDP, в том числе через WebSocket. Маршрутизация, sniffing и счётчики работают для каждого потока. Состояние XUDP привязано к текущему соединению. Входящий XHTTP с REALITY работает по HTTP/2 в режиме `stream-one` с обычным padding. В таком профиле клиент Xray также может использовать `auto` без `downloadSettings`. Входящий gRPC поддерживает `Tun` и `TunMulti` по HTTP/2 с REALITY или по h2c на loopback за TLS-прокси. Для XHTTP и gRPC VLESS flow должен быть пустым. Остальные режимы XHTTP, XHTTP с обычным TLS, DoH и балансировщики требуют расширения реализации.

На Linux переменная `NIGHTVPN_SPLICE=1` включает передачу через `splice(2)` для TLS-заглушки и исходящего к серверу трафика Vision после переключения клиента в raw TCP. Режим по умолчанию выключен. Бюджет открытых труб рассчитывается по мягкому `RLIMIT_NOFILE` процесса; при исчерпании бюджета ядро переходит на обычное копирование. Учёт Remnanode использует те же имена счётчиков: общие счётчики входов и выходов разделены на восемь частей, а время активности обновляется от общих часов.

Для Vision команда перехода в raw TCP приходит от клиента. Xray может продолжать передачу через внешний TLS, если запись внутреннего TLS оказалась разбита между чтениями. Для замера `splice` после TLS-рукопожатия выполните несколько коротких запросов, дожидаясь каждого ответа, затем запускайте основную нагрузку. Проверяйте открытие труб и успешные вызовы `splice`; одного включённого флага недостаточно.

### REALITY за прокси с PROXY protocol

Если на публичном входе REALITY включён `streamSettings.sockopt.acceptProxyProtocol`, укажите в `trustedProxyProtocolSources` адреса TCP-прокси, которые действительно отправляют заголовок PROXY. Ядро проверяет фактический адрес TCP-соседа до чтения заголовка. Для одиночных IPv4-адресов используйте `/32`, для IPv6 — `/128`. Для прямого подключения оставьте `acceptProxyProtocol` выключенным.

```json
{
  "acceptProxyProtocol": true,
  "trustedProxyProtocolSources": ["192.0.2.10/32"]
}
```

## Сборка на Linux

```sh
git clone https://github.com/vpnsaintp/RAST-xray-for-remnanode.git
cd RAST-xray-for-remnanode
git clone https://github.com/ssrlive/reality-rs.git
git -C reality-rs checkout --detach e71b6c20b0860d9fa9589862e81fa8869ed4fa7a
git -C reality-rs apply --check ../prototype/reality-xray.patch
git -C reality-rs apply ../prototype/reality-xray.patch
docker run --rm --cpus 2 --memory 3g -e CARGO_BUILD_JOBS=2 \
  -v "$PWD:/src" -w /src/prototype rust:bookworm cargo build --locked --release
```

Бинарник находится в `prototype/target/release/nightvpn-xray-rust-prototype`.

## Установка в Remnanode 3.4.3

В каталоге существующего Compose-проекта добавьте к сервису `remnanode` монтирование бинарника. Замените путь на абсолютный путь к собранному файлу на хосте.

```yaml
services:
  remnanode:
    volumes:
      - /absolute/path/to/nightvpn-xray-rust-prototype:/usr/local/bin/xray:ro
```

Если правила используют GeoIP или GeoSite, убедитесь, что соответствующие `geoip.dat` и `geosite.dat` доступны внутри контейнера. Примените конфигурацию и проверьте версию ядра.

Чтобы включить `splice`, добавьте `NIGHTVPN_SPLICE: "1"` в блок `environment` сервиса `remnanode`.

```sh
docker compose up -d --no-deps --pull never remnanode
docker compose exec -T remnanode /usr/local/bin/xray version
```

Для возврата на штатное ядро удалите это монтирование и повторите `docker compose up`. Переменная `NIGHTVPN_ROUTE_CORE` позволяет отдельно запустить гибридный режим с Go Xray для маршрутизации.

## Тесты

Для тестов нужны Docker, Python 3, OpenSSL и официальный Linux-бинарник [Xray v26.11.9](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9) под именем `xray-go` в корне репозитория. Для варианта с Torrent Blocker нужны nftables и возможность тестов применять правила в сетевом пространстве контейнера. Тесты запускают отдельный Remnanode и генерируют временные сертификаты и учётные данные.

```sh
docker run --rm --cpus 2 --memory 3g -e CARGO_BUILD_JOBS=2 \
  -v "$PWD:/src" -w /src/prototype rust:bookworm cargo test --locked --release
python3 prototype/test_remnawave.py "$PWD" --native
python3 prototype/test_remnawave.py "$PWD" --native --splice
python3 prototype/test_remnawave.py "$PWD" --native --torrent
```

## Лицензии

Проект распространяется по MPL-2.0. Контракты gRPC основаны на [Xray-core 26.7.28](https://github.com/XTLS/Xray-core/tree/v26.7.28/app). Патч REALITY относится к [ssrlive/reality-rs](https://github.com/ssrlive/reality-rs) и распространяется на условиях лицензий Rustls, сохранённых в `licenses/reality-rs/`.
