import json
import time
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from passlib.context import CryptContext
from .config import settings

passwords = CryptContext(schemes=["bcrypt"], deprecated="auto")

ROLE_PERMISSIONS = {
    "admin": {"*"},
    "operator": {"devices:view", "devices:edit", "templates:view", "templates:edit", "data:view", "problems:view", "problems:edit", "sync:view"},
    "viewer": {"devices:view", "templates:view", "data:view", "problems:view", "sync:view"},
}


def _fernet() -> Fernet:
    if not settings.master_key or settings.master_key.startswith("replace-with"):
        raise RuntimeError("ACX_MASTER_KEY не задан. Запустите scripts/bootstrap-ubuntu.sh до старта.")
    return Fernet(settings.master_key.encode())


def encrypt_secret(value: dict) -> str:
    return _fernet().encrypt(json.dumps(value).encode()).decode()


def decrypt_secret(value: str) -> dict:
    try:
        return json.loads(_fernet().decrypt(value.encode()).decode())
    except (InvalidToken, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Не удалось расшифровать параметры подключения устройства") from exc


def read_bootstrap_token() -> str | None:
    path: Path = settings.bootstrap_token_file
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8").strip()


def remove_bootstrap_token() -> None:
    path: Path = settings.bootstrap_token_file
    if path.exists():
        path.unlink()


def create_session(user_id: str, role: str) -> str:
    payload = {"sub": user_id, "role": role, "exp": int(time.time()) + 8 * 60 * 60}
    return _fernet().encrypt(json.dumps(payload).encode()).decode()


def read_session(token: str) -> dict:
    try:
        payload = json.loads(_fernet().decrypt(token.encode()).decode())
    except (InvalidToken, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Недействительная сессия") from exc
    if payload.get("exp", 0) < time.time():
        raise ValueError("Сессия истекла")
    return payload


def allows(role: str, overrides: dict, permission: str) -> bool:
    granted = set(ROLE_PERMISSIONS.get(role, set())) | set(overrides.get("allow", []))
    denied = set(overrides.get("deny", []))
    return permission not in denied and ("*" in granted or permission in granted)

