from datetime import datetime
import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session
from .config import settings
from .models import SyncOutbox


def sync_pending(db: Session) -> int:
    """Send outbox events at-least-once. Portal must de-duplicate by event_id."""
    if not (settings.portal_url and settings.portal_installation_id and settings.portal_sync_token):
        return 0
    pending = db.scalars(select(SyncOutbox).where(SyncOutbox.sent_at.is_(None)).order_by(SyncOutbox.created_at).limit(200)).all()
    sent = 0
    headers = {
        "Authorization": f"Bearer {settings.portal_sync_token}",
        "X-ACX-Installation": settings.portal_installation_id,
    }
    with httpx.Client(timeout=20, verify=True) as client:
        for event in pending:
            try:
                response = client.post(f"{settings.portal_url}/functions/v1/collector-ingest", json={"event_id": event.id, "type": event.event_type, "payload": event.payload}, headers=headers)
                response.raise_for_status()
                event.sent_at, event.last_error = datetime.utcnow(), None
                sent += 1
            except Exception as exc:  # error is deliberately retained for UI diagnostics
                event.attempts += 1
                event.last_error = str(exc)[:1000]
    db.commit()
    return sent

