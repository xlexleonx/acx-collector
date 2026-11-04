"""Polling and delivery loop. The worker is separate from the web process so UI updates never stop collection."""
from __future__ import annotations
import time
from datetime import datetime
from sqlalchemy import select
from .collector import poll_ipmi, poll_snmp, walk_snmp
from .database import Base, SessionLocal, engine
from .models import Device, DeviceDiscovery, DeviceItem, DiscoveryRule, MetricSample, Problem, SyncOutbox, Template, Trigger
from .security import decrypt_secret
from .sync import sync_pending
from .template_graph import inherited_template_ids


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


_last_discovery: dict[tuple[str, str], float] = {}
_last_poll: dict[tuple[str, str], float] = {}


def _normalize_oid(value: str) -> tuple[str, bool]:
    oid = (value or "").strip()
    if (oid.startswith("get[") or oid.startswith("walk[")) and oid.endswith("]"):
        oid = oid[4:-1].strip()
    direct = oid.lstrip(".").replace(".", "").isdigit() and "." in oid
    return oid, direct


def _discovery_parts(value: str) -> list[tuple[str, str]]:
    """Parse the usual Zabbix ``discovery[{#MACRO},OID,...]`` notation."""
    value = (value or "").strip()
    if value.startswith("discovery[") and value.endswith("]"):
        parts = [part.strip() for part in value[10:-1].split(",")]
        return [(parts[pos], parts[pos + 1]) for pos in range(0, len(parts) - 1, 2) if parts[pos].startswith("{#")]
    if value.startswith("walk[") and value.endswith("]"):
        return [("{#SNMPINDEX}", value[5:-1].strip())]
    return []


def _walk_values(raw: str, base_oid: str) -> dict[str, str]:
    """Map SNMP walk row index to a clean raw value."""
    base = base_oid.lstrip(".")
    values: dict[str, str] = {}
    for line in raw.splitlines():
        if " = " not in line:
            continue
        response_oid, response_value = line.split(" = ", 1)
        current = response_oid.strip().lstrip(".")
        if current == base:
            index = "0"
        elif current.startswith(base + "."):
            index = current[len(base) + 1:]
        else:
            continue
        values[index] = response_value.split(":", 1)[-1].strip().strip('"')
    return values


def _resolve(value: str, macros: dict[str, str]) -> str:
    resolved = value or ""
    for macro, replacement in macros.items():
        resolved = resolved.replace(macro, replacement)
    return resolved


def discover_items(db, device: Device, credentials: dict) -> list[str]:
    """Expand every active SNMP LLD rule from each linked template for a device."""
    if not device.protocol.startswith("snmp"):
        return []
    errors: list[str] = []
    now = time.monotonic()
    template_ids = inherited_template_ids(db, [link.template_id for link in device.template_links])
    rules = db.scalars(select(DiscoveryRule).where(DiscoveryRule.template_id.in_(template_ids), DiscoveryRule.enabled.is_(True))).all()
    for rule in rules:
        schedule_key = (device.id, rule.id)
        if now - _last_discovery.get(schedule_key, 0) < max(30, rule.interval_seconds):
            continue
        _last_discovery[schedule_key] = now
        parts = _discovery_parts(rule.snmp_oid)
        if not parts:
            errors.append(f"{rule.name}: неподдерживаемый формат правила обнаружения")
            continue
        entities: dict[str, dict[str, str]] = {}
        for macro, source_oid in parts:
            source_oid, direct = _normalize_oid(source_oid)
            if not direct:
                errors.append(f"{rule.name}: некорректный OID {source_oid}")
                continue
            result = walk_snmp(device.address, credentials, source_oid)
            if not result.ok:
                errors.append(f"{rule.name}: {result.error}")
                continue
            for index, value in _walk_values(result.value, source_oid).items():
                entity = entities.setdefault(index, {"{#SNMPINDEX}": index})
                entity[macro] = index if macro == "{#SNMPINDEX}" else value
        for index, macros in entities.items():
            discovery = db.scalar(select(DeviceDiscovery).where(
                DeviceDiscovery.device_id == device.id,
                DeviceDiscovery.discovery_rule_id == rule.id,
                DeviceDiscovery.entity_index == index,
            ))
            if not discovery:
                discovery = DeviceDiscovery(device_id=device.id, discovery_rule_id=rule.id, entity_index=index, macros=macros)
                db.add(discovery)
                db.flush()
            else:
                discovery.macros, discovery.last_seen_at = macros, datetime.utcnow()
            for prototype in rule.prototypes:
                if not prototype.enabled:
                    continue
                oid, direct = _normalize_oid(_resolve(prototype.snmp_oid, macros))
                if not direct:
                    continue
                key = _resolve(prototype.key, macros)
                # A broken template may omit the index in its key. Keep every
                # discovered entity separate instead of silently overwriting it.
                if "{#" not in prototype.key and index:
                    key = f"{key}[{index}]"
                item = db.scalar(select(DeviceItem).where(DeviceItem.device_id == device.id, DeviceItem.key == key))
                if not item:
                    item = DeviceItem(device_id=device.id, discovery_id=discovery.id, name=_resolve(prototype.name, macros), key=key, oid=oid)
                    db.add(item)
                item.discovery_id = discovery.id
                item.name = _resolve(prototype.name, macros)
                item.oid, item.value_type, item.units = oid, prototype.value_type, prototype.units
                item.interval_seconds, item.enabled = prototype.interval_seconds, True
    return errors


def _is_due(device: Device, item_key: str, seconds: int) -> bool:
    key = (device.id, item_key)
    now = time.monotonic()
    if now - _last_poll.get(key, 0) < max(10, seconds):
        return False
    _last_poll[key] = now
    return True


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
            template_ids = inherited_template_ids(db, [link.template_id for link in device.template_links])
            discovery_errors = discover_items(db, device, credentials)
            items = [item for template_id in template_ids for item in db.get(Template, template_id).items if item.enabled]
            items.extend(db.scalars(select(DeviceItem).where(DeviceItem.device_id == device.id, DeviceItem.enabled.is_(True))).all())
            if not items:
                reason = discovery_errors[0] if discovery_errors else "Не привязан активный шаблон с элементами данных"
                device.status, device.status_message = "configuration_error", reason
                continue
            attempted = False
            for item in items:
                if not _is_due(device, item.key, item.interval_seconds):
                    continue
                attempted = True
                result = poll_snmp(device.address, credentials, item.oid) if device.protocol.startswith("snmp") else poll_ipmi(device.address, credentials, item.oid)
                value = result.value.rsplit("=", 1)[-1].strip() if result.ok else ""
                db.add(MetricSample(device_id=device.id, item_key=item.key, value=value, error=None if result.ok else result.error))
                if result.ok:
                    any_success = True
                    for trigger in db.scalars(select(Trigger).where(Trigger.template_id.in_(template_ids), Trigger.item_key == item.key, Trigger.enabled.is_(True))).all():
                        _trigger(db, device, trigger, value)
                db.add(SyncOutbox(event_type="metric.sample", payload={"device_id": device.id, "item_key": item.key, "value": value, "error": result.error or None}))
            if not attempted:
                continue
            device.last_poll_at = datetime.utcnow()
            if any_success:
                device.status, device.status_message, device.failure_count, device.last_seen_at = "available", "Данные получены", 0, datetime.utcnow()
            else:
                detail = discovery_errors[0] if discovery_errors else "Не удалось получить данные ни по одному элементу шаблона"
                device.status, device.status_message, device.failure_count = "unavailable", detail, device.failure_count + 1
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

