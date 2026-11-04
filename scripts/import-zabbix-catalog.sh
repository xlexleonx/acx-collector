#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG_DIR="$ROOT_DIR/vendor/zabbix-templates/templates"

if [[ ! -d "$CATALOG_DIR" ]]; then
  echo "Каталог Zabbix не найден. Сначала выполните: bash scripts/fetch-zabbix-template-catalog.sh" >&2
  exit 1
fi

cd "$ROOT_DIR"
docker compose exec -T api python -m app.zabbix_catalog /catalog/zabbix

