#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$ROOT_DIR/vendor/zabbix-templates"

rm -rf "$TARGET"
git clone --depth 1 --branch release/7.0 --filter=blob:none --sparse \
  https://github.com/zabbix/zabbix.git "$TARGET"
git -C "$TARGET" sparse-checkout set templates

echo "Каталог Zabbix 7.0 получен в: $TARGET/templates"
echo "Он не добавляется в Git Collector. Проверяйте лицензию и источник каждого шаблона перед распространением."

