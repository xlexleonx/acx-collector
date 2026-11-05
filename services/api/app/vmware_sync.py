"""Synchronise a read-only VMware inventory into managed Collector hosts."""
from __future__ import annotations

from datetime import datetime
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Device, SyncOutbox
from .security import decrypt_secret, encrypt_secret
from .vmware import discover_virtual_machines


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
    db.add(SyncOutbox(event_type="device.inventory", payload={"device_id": device.id, "metrics": []}))


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
    children = {
        child.vmware_moid: child
        for child in db.scalars(select(Device).where(Device.vmware_parent_id == source.id)).all()
    }
    seen: set[str] = set()
    created = 0
    for vm in result.virtual_machines or []:
        moid = vm["moid"]
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
        if vm["power_state"].lower() == "on":
            child.status, child.status_message = "available", f"ВМ включена; VMware: {source.name}"
            child.last_seen_at = now
        else:
            child.status, child.status_message = "unknown", f"ВМ выключена; VMware: {source.name}"
        child.last_poll_at, child.failure_count = now, 0
        _inventory_event(db, child)
    for moid, child in children.items():
        if moid not in seen:
            child.status = "unavailable"
            child.status_message = "Виртуальная машина больше не найдена в инвентаре VMware"
            child.last_poll_at = now
            _inventory_event(db, child)
    _inventory_event(db, source)
    return True, len(result.virtual_machines or []), f"Обнаружено ВМ: {len(result.virtual_machines or [])}; новых: {created}"
