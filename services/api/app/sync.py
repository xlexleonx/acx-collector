from datetime import datetime
import ssl
import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import Device, PortalConnection, SyncOutbox
from .security import decrypt_secret
from .device_items import effective_device_items

SYNC_BATCH_SIZE = 500
SYNC_BATCHES_PER_CYCLE = 10


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
        "portal_api_key": secret.get("portal_api_key", ""),
        "ca_certificate": secret.get("ca_certificate", ""),
    }


def portal_http_client(config: dict) -> httpx.Client:
    """Use the system trust store or an explicitly configured local CA."""
    ca_certificate = config.get("ca_certificate", "")
    if ca_certificate:
        context = ssl.create_default_context(cadata=ca_certificate)
        return httpx.Client(timeout=20, verify=context)
    return httpx.Client(timeout=20, verify=True)


def _headers(config: dict) -> dict[str, str]:
    return {
        # Kong validates the public Supabase key; the Collector's own secret
        # is deliberately kept out of Authorization because it is not a JWT.
        "Authorization": f"Bearer {config['portal_api_key']}",
        "X-ACX-Installation": config["collector_id"],
        "apikey": config["portal_api_key"],
        "X-ACX-Sync-Token": config["token"],
    }


def _iso(value) -> str | None:
    return value.isoformat() if value else None


def _outgoing_event(db: Session, event: SyncOutbox, metadata_cache: dict[str, tuple[Device, dict]]) -> dict:
    """Attach host and metric labels so the Portal can render telemetry alone."""
    payload = dict(event.payload or {})
    device_id = payload.get("device_id")
    if device_id:
        cached = metadata_cache.get(device_id)
        if not cached:
            device = db.get(Device, device_id)
            if device:
                items = {definition["item"].key: definition["item"] for definition in effective_device_items(db, device, include_disabled=True)}
                cached = (device, items)
                metadata_cache[device_id] = cached
        if cached:
            device, items = cached
            payload["device"] = {
                "source_device_id": device.id,
                "name": device.name,
                "address": device.address,
                "protocol": device.protocol,
                "status": device.status,
                "status_message": device.status_message,
                "last_seen_at": _iso(device.last_seen_at),
                "last_poll_at": _iso(device.last_poll_at),
            }
            item_key = payload.get("item_key")
            if event.event_type == "metric.sample" and item_key:
                item = items.get(item_key)
                payload["metric"] = {
                    "key": item_key,
                    "name": item.name if item else item_key,
                    "units": item.units if item else "",
                    "value": payload.get("value", ""),
                    "error": payload.get("error"),
                    "collected_at": _iso(event.created_at),
                }
    return {"event_id": event.id, "type": event.event_type, "payload": payload, "created_at": _iso(event.created_at)}


def _error_text(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        response = exc.response
        detail = response.text.strip().replace("\n", " ")[:300]
        return f"Портал вернул HTTP {response.status_code}" + (f": {detail}" if detail else "")
    if isinstance(exc, httpx.RequestError):
        return f"Не удалось подключиться к порталу: {exc}"
    if isinstance(exc, ssl.SSLError):
        return f"Ошибка доверенного сертификата: {exc}"
    return str(exc)[:1000]


def send_portal_heartbeat(db: Session) -> tuple[bool, str | None]:
    """Check the configured Portal and persist an operator-friendly status."""
    resolved = configured_portal(db)
    if not resolved:
        return False, "Подключение к порталу не настроено или отключено"
    connection, config = resolved
    connection.last_attempt_at = datetime.utcnow()
    headers = _headers(config)
    try:
        with portal_http_client(config) as client:
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
    headers = _headers(config)
    sent = 0
    metadata_cache: dict[str, tuple[Device, dict]] = {}
    with portal_http_client(config) as client:
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
            db.commit()
            return 0
        for _ in range(SYNC_BATCHES_PER_CYCLE):
            pending = db.scalars(select(SyncOutbox).where(SyncOutbox.sent_at.is_(None)).order_by(SyncOutbox.created_at).limit(SYNC_BATCH_SIZE)).all()
            if not pending:
                break
            try:
                response = client.post(
                    f"{config['portal_url']}/functions/v1/collector-ingest",
                    json={"events": [_outgoing_event(db, event, metadata_cache) for event in pending]},
                    headers=headers,
                )
                response.raise_for_status()
                if response.json().get("ingest_version") != 2:
                    raise RuntimeError("Портал ещё не поддерживает пакетный приём данных. Сначала обновите портал.")
                sent_at = datetime.utcnow()
                for event in pending:
                    event.sent_at, event.last_error = sent_at, None
                sent += len(pending)
                db.commit()
            except Exception as exc:  # error is deliberately retained for UI diagnostics
                error = _error_text(exc)
                for event in pending:
                    event.attempts += 1
                    event.last_error = error
                db.commit()
                break
    return sent

