"""Polling and delivery loop. The worker is separate from the web process so UI updates never stop collection."""
from __future__ import annotations
import time
import re
from datetime import datetime
from sqlalchemy import select
from .collector import poll_ipmi, poll_snmp, walk_snmp
from .database import SessionLocal, ensure_schema
from .models import Device, DeviceDiscovery, DeviceItem, DiscoveryRule, DiscoveryRuleFilter, ItemProcessing, ItemRuntimeState, MetricSample, Problem, SyncOutbox, Template, Trigger, ValueMap
from .security import decrypt_secret
from .sync import sync_pending
from .template_graph import inherited_template_ids
from .device_items import effective_device_items


def _compare(value: float, operator: str, threshold: float) -> bool:
    return {">": value > threshold, ">=": value >= threshold, "<": value < threshold, "<=": value <= threshold, "==": value == threshold}.get(operator, False)


def _numeric(value: str) -> float | None:
    cleaned = re.sub(r"^(?:INTEGER|STRING|Gauge32|Counter32|Counter64|Timeticks|OID|IpAddress):\s*", "", value or "", flags=re.IGNORECASE)
    match = re.search(r"[-+]?\d+(?:[.,]\d+)?", cleaned)
    if not match:
        return None
    try:
        return float(match.group(0).replace(",", "."))
    except ValueError:
        return None


def _format_number(value: float) -> str:
    return str(int(value)) if value.is_integer() else f"{value:.10g}"


def _processing_for(db, source_kind: str, source_ids: list[str]) -> dict[str, ItemProcessing]:
    if not source_ids:
        return {}
    rows = db.scalars(select(ItemProcessing).where(
        ItemProcessing.source_kind == source_kind, ItemProcessing.source_id.in_(source_ids)
    )).all()
    return {row.source_id: row for row in rows}


def _apply_processing(db, device: Device, item_key: str, raw_value: str, processing: ItemProcessing | None) -> str:
    """Execute the safe, generic subset of Zabbix item preprocessing."""
    value = raw_value
    pipeline = processing.pipeline if processing else []
    if any(step.get("type") == "CHANGE_PER_SECOND" for step in pipeline):
        current = _numeric(raw_value)
        if current is not None:
            state = db.scalar(select(ItemRuntimeState).where(
                ItemRuntimeState.device_id == device.id, ItemRuntimeState.item_key == item_key
            ))
            now = datetime.utcnow()
            previous = _numeric(state.last_raw_value) if state else None
            elapsed = (now - state.last_collected_at).total_seconds() if state else 0
            # A counter has no meaningful rate until a second measurement exists.
            value = "0" if previous is None or elapsed <= 0 or current < previous else _format_number((current - previous) / elapsed)
            if not state:
                state = ItemRuntimeState(device_id=device.id, item_key=item_key)
                db.add(state)
            state.last_raw_value, state.last_collected_at = _format_number(current), now
    for step in pipeline:
        if step.get("type") != "MULTIPLIER":
            continue
        current = _numeric(value)
        parameter = (step.get("parameters") or [""])[0]
        multiplier = _numeric(str(parameter))
        if current is not None and multiplier is not None:
            value = _format_number(current * multiplier)
    if processing and processing.value_map_name:
        value_map = db.scalar(select(ValueMap).where(ValueMap.name == processing.value_map_name))
        current = _numeric(value)
        keys = [value]
        if current is not None:
            keys.extend([_format_number(current), str(int(current)) if current.is_integer() else ""])
        if value_map:
            mapped = next((value_map.mappings.get(key) for key in keys if key in value_map.mappings), None)
            if mapped:
                return f"{mapped} ({_format_number(current) if current is not None else value})"
    return value


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


def _matches_discovery_filter(db, rule: DiscoveryRule, macros: dict[str, str]) -> bool:
    """Apply the literal SNMP LLD filters that Zabbix applies before prototypes."""
    filters = db.scalars(select(DiscoveryRuleFilter).where(DiscoveryRuleFilter.discovery_rule_id == rule.id)).all()
    if not filters:
        return True
    checks: list[bool] = []
    evaltype = "AND"
    for filter_row in filters:
        evaltype = (filter_row.evaltype or evaltype).upper()
        for condition in filter_row.conditions or []:
            value = macros.get(str(condition.get("macro") or ""), "")
            pattern = str(condition.get("value") or "")
            if not pattern:
                continue
            try:
                matched = bool(re.search(pattern, value))
            except re.error:
                continue
            operator = str(condition.get("operator") or "MATCHES_REGEX").upper()
            checks.append(not matched if operator in {"NOT_MATCHES_REGEX", "9"} else matched)
    if not checks:
        return True
    return any(checks) if evaltype in {"OR", "1"} else all(checks)


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
            if not _matches_discovery_filter(db, rule, macros):
                continue
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
                    db.flush()
                item.discovery_id = discovery.id
                item.name = _resolve(prototype.name, macros)
                item.oid, item.value_type, item.units = oid, prototype.value_type, prototype.units
                item.interval_seconds, item.enabled = prototype.interval_seconds, True
                source_processing = db.scalar(select(ItemProcessing).where(
                    ItemProcessing.source_kind == "item_prototype", ItemProcessing.source_id == prototype.id
                ))
                if source_processing:
                    target_processing = db.scalar(select(ItemProcessing).where(
                        ItemProcessing.source_kind == "device_item", ItemProcessing.source_id == item.id
                    ))
                    if not target_processing:
                        target_processing = ItemProcessing(source_kind="device_item", source_id=item.id)
                        db.add(target_processing)
                    target_processing.pipeline = source_processing.pipeline
                    target_processing.value_map_name = source_processing.value_map_name
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
            definitions = effective_device_items(db, device)
            template_items = [definition["item"] for definition in definitions if definition["enabled"] and definition["source"] == "template"]
            device_items = [definition["item"] for definition in definitions if definition["enabled"] and definition["source"] == "discovery"]
            template_processing = _processing_for(db, "template_item", [item.id for item in template_items])
            device_processing = _processing_for(db, "device_item", [item.id for item in device_items])
            items = [(item, template_processing.get(item.id)) for item in template_items]
            items.extend((item, device_processing.get(item.id)) for item in device_items)
            if not items:
                reason = discovery_errors[0] if discovery_errors else "Не привязан активный шаблон с элементами данных"
                device.status, device.status_message = "configuration_error", reason
                continue
            attempted = False
            for item, processing in items:
                if not _is_due(device, item.key, item.interval_seconds):
                    continue
                attempted = True
                result = poll_snmp(device.address, credentials, item.oid) if device.protocol.startswith("snmp") else poll_ipmi(device.address, credentials, item.oid)
                raw_value = result.value.rsplit("=", 1)[-1].strip() if result.ok else ""
                value = _apply_processing(db, device, item.key, raw_value, processing) if result.ok else ""
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
    ensure_schema()
    while True:
        try:
            poll_once()
        except Exception as exc:
            print(f"collector worker error: {exc}", flush=True)
        time.sleep(15)


if __name__ == "__main__":
    main()

