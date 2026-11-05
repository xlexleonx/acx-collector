from datetime import datetime
import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import PortalConnection, SyncOutbox
from .security import decrypt_secret


def configured_portal(db: Session) -> tuple[PortalConnection, dict] | None:
    """Return the UI-managed portal config, including its decrypted token."""
    connection = db.get(PortalConnection, "primary")
    if not connection or not connection.enabled:
        return None
    if not (connection.portal_url and connection.collector_id and connection.sync_token_encrypted):
        return None
    try:
        secret = decrypt_secret(connection.sync_token_encrypted)
        token = secret.get("token", "")
    except ValueError:
        token = ""
    if not token:
        return None
    return connection, {
        "portal_url": connection.portal_url.rstrip("/"),
        "collector_id": connection.collector_id,
        "collector_name": connection.collector_name,
        "token": token,
    }


def _error_text(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        response = exc.response
        detail = response.text.strip().replace("\n", " ")[:300]
        return f"Портал вернул HTTP {response.status_code}" + (f": {detail}" if detail else "")
    if isinstance(exc, httpx.RequestError):
        return f"Не удалось подключиться к порталу: {exc}"
    return str(exc)[:1000]


def send_portal_heartbeat(db: Session) -> tuple[bool, str | None]:
    """Check the configured Portal and persist an operator-friendly status."""
    resolved = configured_portal(db)
    if not resolved:
        return False, "Подключение к порталу не настроено или отключено"
    connection, config = resolved
    connection.last_attempt_at = datetime.utcnow()
    headers = {"Authorization": f"Bearer {config['token']}", "X-ACX-Installation": config["collector_id"]}
    try:
        with httpx.Client(timeout=20, verify=True) as client:
            client.post(
                f"{config['portal_url']}/functions/v1/collector-ingest",
                json={"type": "collector.heartbeat", "payload": {"collector_name": config["collector_name"], "collector_version": "0.1.0"}},
                headers=headers,
            ).raise_for_status()
        connection.last_connected_at = datetime.utcnow()
        connection.last_error = None
        db.commit()
        return True, None
    except Exception as exc:
        message = _error_text(exc)
        connection.last_error = message
        db.commit()
        return False, message


def sync_pending(db: Session) -> int:
    """Send outbox events at-least-once. Portal must de-duplicate by event_id."""
    resolved = configured_portal(db)
    if not resolved:
        return 0
    connection, config = resolved
    headers = {
        "Authorization": f"Bearer {config['token']}",
        "X-ACX-Installation": config["collector_id"],
    }
    pending = db.scalars(select(SyncOutbox).where(SyncOutbox.sent_at.is_(None)).order_by(SyncOutbox.created_at).limit(200)).all()
    sent = 0
    with httpx.Client(timeout=20, verify=True) as client:
        # Heartbeat makes a provisioned Collector visible on the Portal even
        # before it has accumulated the first metric sample.
        connection.last_attempt_at = datetime.utcnow()
        try:
            client.post(
                f"{config['portal_url']}/functions/v1/collector-ingest",
                json={"type": "collector.heartbeat", "payload": {"collector_name": config["collector_name"], "collector_version": "0.1.0"}},
                headers=headers,
            ).raise_for_status()
            connection.last_connected_at, connection.last_error = datetime.utcnow(), None
        except Exception as exc:
            connection.last_error = _error_text(exc)
        for event in pending:
            try:
                response = client.post(f"{config['portal_url']}/functions/v1/collector-ingest", json={"event_id": event.id, "type": event.event_type, "payload": event.payload}, headers=headers)
                response.raise_for_status()
                event.sent_at, event.last_error = datetime.utcnow(), None
                sent += 1
            except Exception as exc:  # error is deliberately retained for UI diagnostics
                event.attempts += 1
                event.last_error = str(exc)[:1000]
    db.commit()
    return sent

