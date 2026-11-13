# Установка рядом с действующей RemnaNode 3.4.3

Сначала испытайте отдельный узел или изолированный Compose-проект. Подмена `/usr/local/bin/xray` меняет весь обслуживаемый данным контейнером трафик. Не применяйте этот рецепт к общей производственной ноде без проверенного возврата и резервной копии Compose-файла.

## 1. Сборка на Linux

Требуются Docker, Git, место для сборки и доступ к исходникам. Исходная зависимость `reality-rs` закреплена на конкретном коммите. Перед сборкой проверьте её патч и лицензии.

```sh
git clone https://github.com/vpnsaintp/RAST-xray-for-remnanode.git
cd RAST-xray-for-remnanode
git clone https://github.com/ssrlive/reality-rs.git
git -C reality-rs checkout --detach e71b6c20b0860d9fa9589862e81fa8869ed4fa7a
git -C reality-rs apply --check ../prototype/reality-xray.patch
git -C reality-rs apply ../prototype/reality-xray.patch
docker run --rm --cpus 2 --memory 3g -e CARGO_BUILD_JOBS=2 \
  -v "$PWD:/src" -w /src/prototype rust:bookworm cargo test --locked --release
docker run --rm --cpus 2 --memory 3g -e CARGO_BUILD_JOBS=2 \
  -v "$PWD:/src" -w /src/prototype rust:bookworm cargo build --locked --release
sha256sum prototype/target/release/nightvpn-xray-rust-prototype
```

Если репозиторий ещё не опубликован в указанном адресе, используйте локальную подготовленную копию. Сверяйте хеш собранного бинарника с хешем, который будете ставить на узел. Не скачивайте готовый бинарник из неуказанного источника.

## 2. Способ А: прямая нода

В каталоге действующего Compose-проекта сохраните копию его файла вне публичного Git. Проверьте, какой путь к Xray ожидает именно ваша RemnaNode 3.4.3. Для этой сборки используется `/usr/local/bin/xray`. Скопируйте собранный бинарник в отдельный каталог хоста, доступный Docker только для чтения, и добавьте в `remnanode`:

```yaml
services:
  remnanode:
    volumes:
      - /opt/rast-xray/nightvpn-xray-rust-prototype:/usr/local/bin/xray:ro
```

Проверьте `docker compose config`, затем перезапустите только тестовую RemnaNode:

```sh
docker compose config --quiet
docker compose up -d --no-deps --pull never remnanode
docker compose exec -T remnanode /usr/local/bin/xray version
docker compose ps remnanode
```

Убедитесь, что `geoip.dat` и `geosite.dat` доступны контейнеру, если профиль их использует. Проверьте подключение, выходной IP, `firefox`, динамическую выдачу и отзыв пользователя, счётчики и мониторинг торрентов. Зелёный статус контейнера сам по себе недостаточен.

## 3. Способ Б: выделенный мост, пересылающий TLS байты

Отдельный nginx `stream` или иной TCP-релей может пересылать зашифрованный поток на зарубежный Rust-вход. Nginx здесь не завершает REALITY и не расшифровывает VLESS. Если нужен настоящий IP клиента на выходе, настройте PROXY protocol **с двух сторон** и укажите точный адрес моста в `trustedProxyProtocolSources` для соответствующего REALITY inbound. Вход Rust с PROXY protocol без доверенного источника должен отклоняться. Открытый для Интернета порт с доверием к произвольному PROXY-заголовку запрещён.

Это отдельный путь установки: он не меняет способ А и не требует делить один мост между странами. Для каждого направления используйте выделенный мост, нейтральные домены, DNS-only запись, проверенную TLS-заглушку и HTTP/80 → HTTPS/301. Перед включением торрент-блокировки проверьте, что событие содержит IP клиента, а не IP моста.

## 4. Способ В: WebSocket за TLS-прокси

TLS-прокси завершает обычный HTTPS и направляет WebSocket на loopback-вход ядра. Для upstream-реализации предусмотрен PROXY v2 и `trustedXForwardedFor`. Этот способ требует отдельного профиля в Remnawave; он не эквивалентен сквозному REALITY мосту из способа Б. Проверяйте WebSocket path, early data и реальный IP до выдачи клиентам.

## 5. Возврат

Удалите только добавленный bind mount бинарника и экспериментальные переменные `NIGHTVPN_SPLICE`/`NIGHTVPN_ROUTE_CORE`, если вы их включали. Затем:

```sh
docker compose config --quiet
docker compose up -d --no-deps --pull never remnanode
docker compose exec -T remnanode /usr/local/bin/xray version
```

Проверьте, что вернулась версия штатного ядра, нода видна панели, учёт трафика идёт и тестовый клиент выходит через нужный IP. Сохраняйте предыдущий Compose-файл и хеш бинарника до завершения испытаний.
