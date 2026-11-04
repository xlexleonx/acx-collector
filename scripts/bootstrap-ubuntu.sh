#!/usr/bin/env bash
set -euo pipefail

umask 077
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f .env ]]; then
  cp .env.example .env
  DB_PASSWORD="$(openssl rand -base64 32 | tr -d '\n' | tr '/+' 'ab')"
  FERNET_KEY="$(python3 - <<'PY'
import base64, os
print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
)"
  sed -i "s|change-this-to-a-long-random-password|$DB_PASSWORD|g" .env
  sed -i "s|replace-with-a-fernet-key|$FERNET_KEY|" .env
fi

mkdir -p secrets data backups
if [[ ! -f secrets/bootstrap_token ]]; then
  openssl rand -hex 24 > secrets/bootstrap_token
  chmod 600 secrets/bootstrap_token
  echo "Одноразовый токен первого входа:"
  cat secrets/bootstrap_token
  echo
  echo "Сохраните его до первого входа. После создания пароля token будет удалён."
fi

echo "Подготовка завершена. Запустите: docker compose up -d --build"

