"""Polling and delivery loop. The worker is separate from the web process so UI updates never stop collection."""
from __future__ import annotations
import time
from datetime import datetime
from sqlalchemy import select
from .collector import poll_ipmi, poll_snmp
from .database import Base, SessionLocal, engine
from .models import Device, MetricSample, Problem, SyncOutbox, Template, Trigger
from .security import decrypt_secret
from .sync import sync_pending


def _compare(value: float, operator: str, threshold: float) -> bool:
    return {">": value > threshold, ">=": value >= threshold, "<": value < threshold, "<=": value <= threshold, "==": value == threshold}.get(operator, False)


def _trigger(db, device: Device, trigger: Trigger, raw_value: str) -> None:
    try:
        active = _compare(float(raw_value), trigger.operator, trigger.threshold)
    except ValueError:
        return
    existing = db.scalar(select(Problem).where(Problem.device_id == device.id, Problem.trigger_id == trigger.id, Problem.active.is_(True)))
    if active and not existing:
        problem = Problem(device_id=device.id, trigger_id=trigger.id, severity=trigger.severity, description=trigger.name)
        db.add(problem)
        db.add(SyncOutbox(event_type="problem.opened", payload={"device_id": device.id, "trigger_id": trigger.id, "name": trigger.name, "severity": trigger.severity}))
    elif not active and existing:
        existing.active, existing.closed_at = False, datetime.utcnow()
        db.add(SyncOutbox(event_type="problem.closed", payload={"problem_id": existing.id, "device_id": device.id}))


def poll_once() -> None:
    db = SessionLocal()
    try:
        for device in db.scalars(select(Device).where(Device.enabled.is_(True))).all():
            try:
                credentials = decrypt_secret(device.credentials_encrypted)
            except ValueError as exc:
                device.status, device.status_message = "configuration_error", str(exc)
                continue
            any_success = False
            items = [item for link in device.template_links for item in db.get(Template, link.template_id).items if item.enabled]
            if not items:
                device.status, device.status_message = "configuration_error", "Не привязан активный шаблон с элементами данных"
                continue
            for item in items:
                result = poll_snmp(device.address, credentials, item.oid) if device.protocol.startswith("snmp") else poll_ipmi(device.address, credentials, item.oid)
                value = result.value.rsplit("=", 1)[-1].strip() if result.ok else ""
                db.add(MetricSample(device_id=device.id, item_key=item.key, value=value, error=None if result.ok else result.error))
                if result.ok:
                    any_success = True
                    for trigger in db.scalars(select(Trigger).where(Trigger.template_id.in_([link.template_id for link in device.template_links]), Trigger.item_key == item.key, Trigger.enabled.is_(True))).all():
                        _trigger(db, device, trigger, value)
                db.add(SyncOutbox(event_type="metric.sample", payload={"device_id": device.id, "item_key": item.key, "value": value, "error": result.error or None}))
            device.last_poll_at = datetime.utcnow()
            if any_success:
                device.status, device.status_message, device.failure_count, device.last_seen_at = "available", "Данные получены", 0, datetime.utcnow()
            else:
                device.status, device.status_message, device.failure_count = "unavailable", "Не удалось получить данные ни по одному элементу шаблона", device.failure_count + 1
        db.commit()
        sync_pending(db)
    finally:
        db.close()


def main() -> None:
    Base.metadata.create_all(bind=engine)
    while True:
        try:
            poll_once()
        except Exception as exc:
            print(f"collector worker error: {exc}", flush=True)
        time.sleep(15)


if __name__ == "__main__":
    main()

