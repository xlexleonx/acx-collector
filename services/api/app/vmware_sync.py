"""Synchronise a read-only VMware inventory into managed Collector hosts."""
from __future__ import annotations

from datetime import datetime
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Device, DeviceTemplate, MetricSample, Problem, SyncOutbox, Template, Trigger, VMwareIgnoredMachine
from .security import decrypt_secret, encrypt_secret
from .vmware import discover_virtual_machines
from .device_items import effective_device_items


VMWARE_SOURCES = {"vmware_esxi", "vmware_vcenter"}


def _unique_device_name(db: Session, base: str) -> str:
    existing = set(db.scalars(select(Device.name)).all())
    if base not in existing:
        return base
    number = 2
    while f"{base} ({number})" in existing:
        number += 1
    return f"{base} ({number})"


def _inventory_event(db: Session, device: Device) -> None:
    definitions = effective_device_items(db, device)
    db.add(SyncOutbox(event_type="device.inventory", payload={
        "device_id": device.id,
        "metrics": [{"key": definition["item"].key, "name": definition["item"].name, "units": definition["item"].units} for definition in definitions if definition["enabled"]],
    }))


def _attach_builtin_template(db: Session, device: Device, name: str) -> None:
    template = db.scalar(select(Template).where(Template.name == name, Template.enabled.is_(True)))
    if not template:
        return
    linked = db.scalar(select(DeviceTemplate).where(
        DeviceTemplate.device_id == device.id, DeviceTemplate.template_id == template.id
    ))
    if not linked:
        db.add(DeviceTemplate(device_id=device.id, template_id=template.id))
        db.flush()


def _emit_metrics(db: Session, device: Device, values: dict[str, str], now: datetime) -> None:
    active_keys = {definition["item"].key for definition in effective_device_items(db, device) if definition["enabled"]}
    template_ids = list(db.scalars(select(DeviceTemplate.template_id).where(DeviceTemplate.device_id == device.id)).all())
    for key, value in values.items():
        if key not in active_keys:
            continue
        db.add(MetricSample(device_id=device.id, item_key=key, value=value, error=None, collected_at=now))
        db.add(SyncOutbox(event_type="metric.sample", payload={"device_id": device.id, "item_key": key, "value": value, "error": None}))
        try:
            number = float(value)
        except ValueError:
            continue
        for trigger in db.scalars(select(Trigger).where(Trigger.template_id.in_(template_ids), Trigger.item_key == key, Trigger.enabled.is_(True))).all():
            active = {">": number > trigger.threshold, ">=": number >= trigger.threshold, "<": number < trigger.threshold, "<=": number <= trigger.threshold, "==": number == trigger.threshold}.get(trigger.operator, False)
            problem = db.scalar(select(Problem).where(Problem.device_id == device.id, Problem.trigger_id == trigger.id, Problem.active.is_(True)))
            if active and not problem:
                db.add(Problem(device_id=device.id, trigger_id=trigger.id, severity=trigger.severity, description=trigger.name))
                db.add(SyncOutbox(event_type="problem.opened", payload={"device_id": device.id, "trigger_id": trigger.id, "name": trigger.name, "severity": trigger.severity}))
            elif not active and problem:
                problem.active, problem.closed_at = False, now
                db.add(SyncOutbox(event_type="problem.closed", payload={"problem_id": problem.id, "device_id": device.id, "trigger_id": trigger.id}))


def sync_virtual_machines(db: Session, source: Device) -> tuple[bool, int, str]:
    """Discover VMs and create/update child hosts.  No VMware writes occur."""
    if source.protocol not in VMWARE_SOURCES:
        return False, 0, "Устройство не является подключением VMware"
    try:
        credentials = decrypt_secret(source.credentials_encrypted)
    except ValueError as exc:
        return False, 0, str(exc)
    result = discover_virtual_machines(source.address, credentials)
    now = datetime.utcnow()
    source.last_poll_at = now
    if not result.ok:
        source.status, source.status_message = "unavailable", result.error
        source.failure_count += 1
        return False, 0, result.error

    source.status, source.status_message = "available", f"VMware API доступен; {result.product}"
    source.failure_count, source.last_seen_at = 0, now
    _attach_builtin_template(db, source, "VMware Hypervisor by SOAP")
    _emit_metrics(db, source, {
        "vmware.api.available": "1",
        "vmware.inventory.vms": str(len(result.virtual_machines or [])),
    }, now)
    children = {
        child.vmware_moid: child
        for child in db.scalars(select(Device).where(Device.vmware_parent_id == source.id)).all()
    }
    ignored_moids = set(db.scalars(select(VMwareIgnoredMachine.vmware_moid).where(
        VMwareIgnoredMachine.vmware_parent_id == source.id
    )).all())
    seen: set[str] = set()
    created = 0
    for vm in result.virtual_machines or []:
        moid = vm["moid"]
        if moid in ignored_moids:
            continue
        seen.add(moid)
        child = children.get(moid)
        if child is None:
            child = Device(
                name=_unique_device_name(db, f"{source.name} · {vm['name']}"),
                address=vm["address"],
                protocol="vmware_vm",
                credentials_encrypted=encrypt_secret({"vmware_parent_id": source.id}),
                vmware_parent_id=source.id,
                vmware_moid=moid,
                enabled=True,
            )
            db.add(child)
            db.flush()
            created += 1
        else:
            child.address = vm["address"]
        _attach_builtin_template(db, child, "VMware Guest")
        if vm["power_state"].lower() == "on":
            child.status, child.status_message = "available", f"ВМ включена; VMware: {source.name}"
            child.last_seen_at = now
        else:
            child.status, child.status_message = "unknown", f"ВМ выключена; VMware: {source.name}"
        child.last_poll_at, child.failure_count = now, 0
        power_state = str(vm["power_state"])
        _emit_metrics(db, child, {
            "vmware.vm.power_state": power_state,
            "vmware.vm.powered": "1" if power_state.lower() == "on" else "0",
            "vmware.vm.guest_ip": str(vm["address"]) if not str(vm["address"]).startswith("vmware://") else "",
            "vmware.vm.guest_os": str(vm.get("guest_os") or ""),
        }, now)
        _inventory_event(db, child)
    for moid, child in children.items():
        if moid not in seen:
            child.status = "unavailable"
            child.status_message = "Виртуальная машина больше не найдена в инвентаре VMware"
            child.last_poll_at = now
            _inventory_event(db, child)
    _inventory_event(db, source)
    return True, len(result.virtual_machines or []), f"Обнаружено ВМ: {len(result.virtual_machines or [])}; новых: {created}"
