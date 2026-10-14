#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

usage() {
  cat <<'HELP'
Использование: ./deploy.sh [--launch | --check | --version | --help]

Без параметров — создать .venv и установить зависимости.
  --launch   Подготовить окружение и запустить TUI.
  --check    Подготовить окружение и проверить WebDAV.
  --version  Подготовить окружение и показать версию.
  --help     Показать справку без установки.

Требуются Bash, Python 3.10+ и доступ к индексу пакетов при первой установке.
HELP
}

if (( $# > 1 )); then
  usage >&2
  exit 2
fi
case "${1:-}" in
  '')
    bash ./run.sh --version
    printf 'Окружение готово. Запуск: ./deploy.sh --launch (из каталога проекта)\n'
    ;;
  --launch) exec bash ./run.sh ;;
  --check | --version) exec bash ./run.sh "$1" ;;
  --help | -h) usage ;;
  *) usage >&2; exit 2 ;;
esac
