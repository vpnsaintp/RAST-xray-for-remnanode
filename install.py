#!/usr/bin/env python3
"""Русское меню для установки Rust-ядра на существующую RemnaNode 3.4.3."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
DEFAULT_PROJECT = Path('/opt/remnanode')
INSTALL_ROOT = Path('/opt/rast-xray')
OVERRIDE = 'compose.rast.yaml'
MARKER = '# RAST-MANAGED-COMPOSE-FILE; удаляется командой rollback'
REALITY_COMMIT = 'e71b6c20b0860d9fa9589862e81fa8869ed4fa7a'
BIN_NAME = 'nightvpn-xray-rust-prototype'
PRIMARY = ('compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml')
AUTO_OVERRIDE = ('compose.override.yaml', 'compose.override.yml',
                 'docker-compose.override.yaml', 'docker-compose.override.yml')


class InstallError(Exception):
    pass


def run(args: list[str], cwd: Path | None = None, timeout: int = 120,
        capture: bool = True) -> str:
    try:
        result = subprocess.run(args, cwd=cwd, text=True, capture_output=capture,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError(f'Не удалось выполнить {args[0]}: {exc}') from exc
    if result.returncode:
        detail = (result.stderr or result.stdout or '').strip()[-1200:]
        raise InstallError(f'{args[0]} завершился с кодом {result.returncode}: {detail}')
    return (result.stdout or '').strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def validate_binary(path: Path) -> str:
    if not path.is_file() or path.stat().st_size < 1_000_000:
        raise InstallError('Нужен существующий бинарник Rust-ядра размером более 1 МиБ.')
    with path.open('rb') as source:
        head = source.read(20)
    if len(head) < 20 or head[:4] != b'\x7fELF' or head[4] != 2:
        raise InstallError('Файл не является 64-битным Linux ELF.')
    machine = int.from_bytes(head[18:20], 'little')
    expected = {'x86_64': 62, 'aarch64': 183}.get(platform.machine())
    if expected is None or machine != expected:
        raise InstallError(f'Архитектура ELF ({machine}) не соответствует серверу ({platform.machine()}).')
    version = run([str(path), 'version'], timeout=10)
    if 'Rust' not in version and 'rust' not in version:
        raise InstallError(f'Бинарник не распознан как Rust-ядро: {version[:160]}')
    return version


def compose_files(project: Path) -> list[str]:
    present = [name for name in PRIMARY if (project / name).is_file()]
    if len(present) != 1:
        raise InstallError('Нужен ровно один основной Compose-файл в каталоге ноды.')
    overrides = [name for name in AUTO_OVERRIDE if (project / name).is_file()]
    return present + overrides


def preflight(project: Path) -> dict:
    if not project.is_dir():
        raise InstallError(f'Каталог ноды не найден: {project}')
    if os.environ.get('COMPOSE_FILE'):
        raise InstallError('В окружении задан COMPOSE_FILE. Уберите его и повторите проверку.')
    if re.search(r'(?m)^\s*(?:export\s+)?COMPOSE_FILE\s*=',
                 (project / '.env').read_text(encoding='utf-8') if (project / '.env').exists() else ''):
        raise InstallError('В .env уже задан COMPOSE_FILE. Автоматическая правка может потерять другие override-файлы.')
    files = compose_files(project)
    data = json.loads(run(['docker', 'compose', 'config', '--format', 'json'], cwd=project, timeout=45))
    service = data.get('services', {}).get('remnanode')
    if not isinstance(service, dict):
        raise InstallError('Сервис remnanode не найден в итоговом Compose.')
    image = service.get('image', '')
    if not re.search(r'(?:^|/)node:3\.4\.3$', image):
        raise InstallError(f'Ожидается образ RemnaNode 3.4.3; найден: {image or "без image"}')
    if (project / OVERRIDE).exists():
        raise InstallError(f'{OVERRIDE} уже существует; не перезаписываю чужой файл.')
    container = run(['docker', 'compose', 'ps', '-q', 'remnanode'], cwd=project, timeout=20)
    if not container:
        raise InstallError('Контейнер remnanode не запущен. Сначала восстановите штатную ноду.')
    link = run(['docker', 'exec', container, 'readlink', '/usr/local/bin/rw-core'], timeout=15)
    if link != '/usr/local/bin/xray':
        raise InstallError(f'Нода уже использует отдельное ядро ({link}); автоматическая подмена отменена.')
    return {'files': files, 'image': image, 'container': container}


def render_override(binary: Path) -> str:
    # JSON-строка является корректным скалярным значением YAML.
    mount = f'{binary}:/usr/local/bin/xray:ro'
    return 'services:\n  remnanode:\n    volumes:\n      - ' + json.dumps(mount) + '\n'


def set_compose_env(project: Path, files: list[str]) -> tuple[str, bool]:
    env = project / '.env'
    current = env.read_text(encoding='utf-8') if env.exists() else ''
    separator = bool(current and not current.endswith('\n'))
    if separator:
        current += '\n'
    value = ':'.join(files + [OVERRIDE])
    env.write_text(current + MARKER + '\nCOMPOSE_FILE=' + value + '\n', encoding='utf-8')
    os.chmod(env, 0o600)
    return value, separator


def clear_compose_env(project: Path, expected: str, separator: bool) -> None:
    env = project / '.env'
    text = env.read_text(encoding='utf-8')
    suffix = MARKER + '\nCOMPOSE_FILE=' + expected + '\n'
    if not text.endswith(suffix):
        raise InstallError('Конец .env изменён после установки; автоматический откат остановлен.')
    original = text[:-len(suffix)]
    if separator:
        if not original.endswith('\n'):
            raise InstallError('Разделитель .env изменён; автоматический откат остановлен.')
        original = original[:-1]
    if original:
        env.write_text(original, encoding='utf-8')
        os.chmod(env, 0o600)
    else:
        env.unlink()


def compose_check(project: Path) -> None:
    run(['docker', 'compose', 'config', '--quiet'], cwd=project, timeout=45)


def restart(project: Path) -> None:
    run(['docker', 'compose', 'up', '-d', '--no-deps', '--pull', 'never', 'remnanode'],
        cwd=project, timeout=180)


def install(project: Path, source: Path) -> None:
    if os.geteuid() != 0:
        raise InstallError('Установка требует root: запустите sudo python3 install.py.')
    info = preflight(project)
    version = validate_binary(source)
    digest = sha256(source)
    print(f'Образ: {info["image"]}\nЯдро: {version}\nSHA-256: {digest}')
    answer = input('Заменить ядро только в сервисе remnanode? Напишите УСТАНОВИТЬ: ')
    if answer != 'УСТАНОВИТЬ':
        print('Отменено без изменений.'); return
    target_dir = INSTALL_ROOT / digest
    target_dir.mkdir(parents=True, exist_ok=False)
    target = target_dir / 'xray'
    env_separator = False
    try:
        with tempfile.NamedTemporaryFile(dir=target_dir, delete=False) as tmp:
            staged = Path(tmp.name)
        shutil.copyfile(source, staged)
        os.chmod(staged, 0o755)
        if sha256(staged) != digest:
            raise InstallError('Хеш бинарника изменился при копировании.')
        staged.replace(target)
        (project / OVERRIDE).write_text(render_override(target), encoding='utf-8')
        compose_value, env_separator = set_compose_env(project, info['files'])
        compose_check(project)
        restart(project)
        container = run(['docker', 'compose', 'ps', '-q', 'remnanode'], cwd=project, timeout=20)
        reported = run(['docker', 'exec', container, '/usr/local/bin/rw-core', 'version'], timeout=15)
        if 'rust' not in reported.lower():
            raise InstallError('После запуска контейнер не сообщил версию Rust-ядра.')
        state = {'project': str(project), 'sha256': digest, 'compose_file': compose_value,
                 'binary': str(target), 'env_separator': env_separator}
        INSTALL_ROOT.mkdir(parents=True, exist_ok=True)
        (INSTALL_ROOT / 'state.json').write_text(json.dumps(state, indent=2) + '\n', encoding='utf-8')
        print('Ядро установлено. Теперь проверьте профиль, реальное подключение, счётчики и выходной IP.')
    except Exception:
        # Возврат Compose-конфигурации при любой ошибке установки.
        state_suffix = ':'.join(info['files'] + [OVERRIDE])
        env = project / '.env'
        if env.exists() and MARKER in env.read_text(encoding='utf-8'):
            clear_compose_env(project, state_suffix, env_separator)
        (project / OVERRIDE).unlink(missing_ok=True)
        try:
            restart(project)
        except InstallError as exc:
            print(f'ВНИМАНИЕ: автоматический возврат контейнера не удался: {exc}', file=sys.stderr)
        raise


def rollback(project: Path) -> None:
    if os.geteuid() != 0:
        raise InstallError('Откат требует root.')
    path = INSTALL_ROOT / 'state.json'
    if not path.is_file():
        raise InstallError('Состояние установки не найдено.')
    state = json.loads(path.read_text(encoding='utf-8'))
    if state['project'] != str(project):
        raise InstallError('Запрошен другой каталог ноды; откат остановлен.')
    answer = input('Вернуть штатный Xray и пересоздать remnanode? Напишите ОТКАТ: ')
    if answer != 'ОТКАТ':
        print('Отменено.'); return
    clear_compose_env(project, state['compose_file'], state['env_separator'])
    (project / OVERRIDE).unlink(missing_ok=False)
    compose_check(project)
    restart(project)
    container = run(['docker', 'compose', 'ps', '-q', 'remnanode'], cwd=project, timeout=20)
    link = run(['docker', 'exec', container, 'readlink', '/usr/local/bin/rw-core'], timeout=15)
    if link != '/usr/local/bin/xray':
        raise InstallError(f'Штатное ядро после отката не подтверждено: {link}')
    path.unlink()
    print('Штатное ядро восстановлено. Проверяйте подключение и счётчики.')


def status(project: Path) -> None:
    print('Каталог ноды:', project)
    try:
        data = json.loads(run(['docker', 'compose', 'config', '--format', 'json'], cwd=project, timeout=45))
        print('Образ:', data.get('services', {}).get('remnanode', {}).get('image', 'не найден'))
        container = run(['docker', 'compose', 'ps', '-q', 'remnanode'], cwd=project, timeout=20)
        print('Контейнер:', container or 'не запущен')
        if container:
            print('Ядро:', run(['docker', 'exec', container, '/usr/local/bin/rw-core', 'version'], timeout=15))
            print('Ссылка:', run(['docker', 'exec', container, 'readlink', '/usr/local/bin/rw-core'], timeout=15))
    except InstallError as exc:
        print('Проверка не завершена:', exc)


def build() -> Path:
    if shutil.which('git') is None or shutil.which('docker') is None:
        raise InstallError('Для сборки нужны git и Docker.')
    dep = ROOT / 'reality-rs'
    if dep.exists():
        raise InstallError('Каталог reality-rs уже существует. Проверьте его вручную; не перезаписываю.')
    print('Получаю закреплённую зависимость и собираю ядро. Это может занять несколько минут.')
    run(['git', 'clone', 'https://github.com/ssrlive/reality-rs.git', str(dep)], timeout=180)
    run(['git', '-C', str(dep), 'checkout', '--detach', REALITY_COMMIT], timeout=60)
    run(['git', '-C', str(dep), 'apply', '--check', '../prototype/reality-xray.patch'], timeout=30)
    run(['git', '-C', str(dep), 'apply', '../prototype/reality-xray.patch'], timeout=30)
    run(['docker', 'run', '--rm', '--cpus', '2', '--memory', '3g', '-e', 'CARGO_BUILD_JOBS=2',
         '-v', f'{ROOT}:/src', '-w', '/src/prototype', 'rust:bookworm',
         'cargo', 'build', '--locked', '--release'], timeout=3600, capture=False)
    binary = ROOT / 'prototype' / 'target' / 'release' / BIN_NAME
    print('Собрано:', binary, 'SHA-256:', sha256(binary))
    return binary


def protocols() -> None:
    print('''\nВыбор протокола выполняется в Config Profile панели Remnawave.
Установщик меняет только исполняемое ядро, а не действующие Host или подписки.

1. VLESS + REALITY + Vision — прямой узел или выделенный TCP-мост. Клиент: firefox.
2. VLESS + TLS + Vision — нужен свой сертификат и его обслуживание.
3. VLESS + WebSocket — за HTTPS-прокси, отдельный путь и проверка IP клиента.
4. Shadowsocks TCP/UDP — только chacha20-ietf-poly1305.
5. XHTTP + REALITY — HTTP/2 stream-one, flow пустой.
6. gRPC + REALITY — Tun/TunMulti, flow пустой.

0. Вернуться без выбора.\n''')
    guidance = {
        '1': 'В панели создайте отдельный VLESS inbound: network raw, security reality, flow xtls-rprx-vision. Укажите cover target, serverName, shortId и ключи. В клиентском Host задайте fingerprint firefox.',
        '2': 'В панели создайте отдельный VLESS inbound: network raw, security tls, flow xtls-rprx-vision. Установите сертификат и ключ; настройте обновление сертификата.',
        '3': 'В панели создайте отдельный VLESS inbound: network ws, security none внутри ядра. Завершите HTTPS на доверенном прокси и задайте совпадающий WebSocket path. Проверьте передачу IP клиента.',
        '4': 'В панели создайте Shadowsocks inbound с chacha20-ietf-poly1305. Проверьте раздельно TCP, UDP, изменение пароля и счётчики.',
        '5': 'В панели создайте VLESS inbound: network xhttp, security reality, mode stream-one, path одинаковый с клиентом, flow пустой.',
        '6': 'В панели создайте VLESS inbound: network grpc, security reality, serviceName одинаковый с клиентом, flow пустой. Для h2c за TLS-прокси нужен отдельный локальный вход.',
    }
    choice = input('Какой протокол планируете испытать? [0–6]: ').strip()
    if choice in guidance:
        print('\nСледующий шаг:', guidance[choice])
        print('Создайте отдельный тестовый профиль и Host без выдачи всем клиентам.')
        print('Проверьте Happ, Incy и Mihomo, выходной IP, счётчики и отзыв пользователя.')
        print('Подробности: docs/ПРОТОКОЛЫ.md и docs/ПРОВЕРКИ.md.\n')
    elif choice != '0':
        print('Неизвестный пункт; профиль не менялся.')


def menu(project: Path) -> None:
    while True:
        print('''\nRAST · RemnaNode 3.4.3
1. Состояние ноды и ядра
2. Собрать Rust-ядро из исходников
3. Установить уже собранный бинарник
4. Протоколы и варианты подключения
5. Вернуть штатное ядро
0. Выход''')
        choice = input('Выберите пункт: ').strip()
        try:
            if choice == '1': status(project)
            elif choice == '2': build()
            elif choice == '3': install(project, Path(input('Абсолютный путь к ELF-бинарнику: ').strip()).resolve())
            elif choice == '4': protocols()
            elif choice == '5': rollback(project)
            elif choice == '0': return
            else: print('Неизвестный пункт.')
        except (InstallError, OSError, ValueError) as exc:
            print('Ошибка:', exc, file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description='Русский установщик Rust-ядра для RemnaNode 3.4.3')
    parser.add_argument('command', nargs='?', default='menu',
                        choices=('menu', 'status', 'build', 'install', 'protocols', 'rollback'))
    parser.add_argument('--project-dir', type=Path, default=DEFAULT_PROJECT)
    parser.add_argument('--binary', type=Path)
    args = parser.parse_args()
    project = args.project_dir.resolve()
    try:
        if args.command == 'menu': menu(project)
        elif args.command == 'status': status(project)
        elif args.command == 'build': build()
        elif args.command == 'protocols': protocols()
        elif args.command == 'install':
            if args.binary is None: parser.error('для install нужен --binary')
            install(project, args.binary.resolve())
        elif args.command == 'rollback': rollback(project)
    except (InstallError, OSError, ValueError) as exc:
        print('Ошибка:', exc, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
