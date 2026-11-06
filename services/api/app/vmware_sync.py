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


def _number(value: object, multiplier: int | float = 1) -> str:
    """Convert a VMware scalar to a Collector numeric value without inventing it."""
    try:
        return str(float(str(value)) * multiplier).rstrip("0").rstrip(".")
    except (TypeError, ValueError):
        return ""


def _bool(value: object) -> str:
    if value is None or str(value) == "":
        return ""
    return "1" if str(value).lower() == "true" else "0"


def _vm_values(vm: dict) -> dict[str, str]:
    """Map documented vSphere properties to Collector keys.

    Empty fields are retained only where their absence is meaningful to the UI;
    the writer will skip template keys not supplied by the VMware endpoint.
    """
    p = vm.get("properties") or {}
    values = {
        "vmware.vm.power_state": str(vm.get("power_state") or "unknown"),
        "vmware.vm.powered": "1" if str(vm.get("power_state", "")).lower() == "on" else "0",
        "vmware.vm.guest_ip": str(vm.get("address") or "") if not str(vm.get("address") or "").startswith("vmware://") else "",
        "vmware.vm.guest_os": str(vm.get("guest_os") or ""),
        "vmware.vm.name": str(vm.get("name") or ""),
        "vmware.vm.uuid": str(p.get("config.uuid") or ""),
        "vmware.vm.instance_uuid": str(p.get("config.instanceUuid") or ""),
        "vmware.vm.hardware_version": str(p.get("config.version") or ""),
        "vmware.vm.configuration_version": str(p.get("config.changeVersion") or ""),
        "vmware.vm.annotation": str(p.get("config.annotation") or ""),
        "vmware.vm.path": str(p.get("config.files.vmPathName") or ""),
        "vmware.vm.guest_hostname": str(p.get("guest.hostName") or ""),
        "vmware.vm.guest_id": str(p.get("guest.guestId") or ""),
        "vmware.vm.guest_family": str(p.get("guest.guestFamily") or ""),
        "vmware.vm.guest_state": str(p.get("guest.guestState") or ""),
        "vmware.vm.tools_status": str(p.get("guest.toolsStatus") or ""),
        "vmware.vm.tools_running_status": str(p.get("guest.toolsRunningStatus") or ""),
        "vmware.vm.connection_state": str(p.get("runtime.connectionState") or ""),
        "vmware.vm.boot_time": str(p.get("runtime.bootTime") or ""),
        "vmware.vm.hypervisor_moid": str(p.get("runtime.host") or ""),
        "vmware.vm.cpu.count": _number(p.get("config.hardware.numCPU")),
        "vmware.vm.cpu.cores_per_socket": _number(p.get("config.hardware.numCoresPerSocket")),
        "vmware.vm.memory.configured": _number(p.get("config.hardware.memoryMB"), 1024 * 1024),
        "vmware.vm.cpu.hot_add": _bool(p.get("config.cpuHotAddEnabled")),
        "vmware.vm.memory.hot_add": _bool(p.get("config.memoryHotAddEnabled")),
        "vmware.vm.cpu.limit": _number(p.get("runtime.maxCpuUsage")),
        "vmware.vm.memory.limit": _number(p.get("runtime.maxMemoryUsage"), 1024 * 1024),
        "vmware.vm.cpu.usage_mhz": _number(p.get("summary.quickStats.overallCpuUsage")),
        "vmware.vm.cpu.demand": _number(p.get("summary.quickStats.overallCpuDemand")),
        "vmware.vm.cpu.entitlement": _number(p.get("summary.quickStats.staticCpuEntitlement")),
        "vmware.vm.memory.entitlement": _number(p.get("summary.quickStats.staticMemoryEntitlement"), 1024 * 1024),
        "vmware.vm.memory.guest": _number(p.get("summary.quickStats.guestMemoryUsage"), 1024 * 1024),
        "vmware.vm.memory.host": _number(p.get("summary.quickStats.hostMemoryUsage"), 1024 * 1024),
        "vmware.vm.memory.ballooned": _number(p.get("summary.quickStats.balloonedMemory"), 1024 * 1024),
        "vmware.vm.memory.swapped": _number(p.get("summary.quickStats.swappedMemory"), 1024 * 1024),
        "vmware.vm.memory.compressed": _number(p.get("summary.quickStats.compressedMemory"), 1024 * 1024),
        "vmware.vm.memory.private": _number(p.get("summary.quickStats.privateMemory"), 1024 * 1024),
        "vmware.vm.memory.shared": _number(p.get("summary.quickStats.sharedMemory"), 1024 * 1024),
        "vmware.vm.memory.overhead": _number(p.get("summary.quickStats.consumedOverheadMemoryResource"), 1024 * 1024),
        "vmware.vm.uptime": _number(p.get("summary.quickStats.uptimeSeconds")),
        "vmware.vm.storage.committed": _number(p.get("summary.storage.committed")),
        "vmware.vm.storage.uncommitted": _number(p.get("summary.storage.uncommitted")),
        "vmware.vm.storage.unshared": _number(p.get("summary.storage.unshared")),
        "vmware.vm.consolidation_needed": _bool(p.get("runtime.consolidationNeeded")),
    }
    values.update({key: str(value) for key, value in (vm.get("performance") or {}).items()})
    return values


def _esxi_values(host: dict) -> dict[str, str]:
    p = host.get("properties") or {}
    return {
        "vmware.host.name": str(host.get("name") or ""),
        "vmware.host.connection_state": str(p.get("runtime.connectionState") or ""),
        "vmware.host.maintenance": _bool(p.get("runtime.inMaintenanceMode")),
        "vmware.host.power_state": str(p.get("runtime.powerState") or ""),
        "vmware.host.vendor": str(p.get("summary.hardware.vendor") or ""),
        "vmware.host.model": str(p.get("summary.hardware.model") or ""),
        "vmware.host.cpu_model": str(p.get("summary.hardware.cpuModel") or ""),
        "vmware.host.cpu.cores": _number(p.get("summary.hardware.numCpuCores")),
        "vmware.host.cpu.threads": _number(p.get("summary.hardware.numCpuThreads")),
        "vmware.host.cpu.mhz": _number(p.get("summary.hardware.cpuMhz")),
        "vmware.host.memory.total": _number(p.get("summary.hardware.memorySize")),
        "vmware.host.cpu.usage": _number(p.get("summary.quickStats.overallCpuUsage")),
        "vmware.host.memory.usage": _number(p.get("summary.quickStats.overallMemoryUsage"), 1024 * 1024),
        "vmware.host.uptime": _number(p.get("summary.quickStats.uptime")),
        "vmware.host.product": str(p.get("config.product.fullName") or ""),
        "vmware.host.version": str(p.get("config.product.version") or ""),
        "vmware.host.build": str(p.get("config.product.build") or ""),
    }


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


def _emit_metrics(
    db: Session, device: Device, values: dict[str, str], now: datetime, *, trust_vmware_values: bool = False
) -> None:
    """Save a VMware sample and put it into the portal outbox.

    Built-in VMware templates are attached in the same transaction as an
    inventory refresh.  The explicit bypass is needed for that first refresh:
    SQLAlchemy may not expose freshly linked template items to the relationship
    resolver until the following transaction.  It is deliberately limited to
    values read from the VMware API, never used for SNMP/IPMI polling.
    """
    active_keys = {definition["item"].key for definition in effective_device_items(db, device) if definition["enabled"]}
    accepted_keys = set(values) if trust_vmware_values else active_keys
    template_ids = list(db.scalars(select(DeviceTemplate.template_id).where(DeviceTemplate.device_id == device.id)).all())
    for key, value in values.items():
        if key not in accepted_keys or value is None or str(value) == "":
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
    db.flush()
    _emit_metrics(db, source, {
        "vmware.api.available": "1",
        "vmware.inventory.vms": str(len(result.virtual_machines or [])),
        **(_esxi_values((result.host_systems or [{}])[0]) if source.protocol == "vmware_esxi" and result.host_systems else {}),
    }, now, trust_vmware_values=True)
    # A successful login with an empty inventory can be caused by a temporary
    # PropertyCollector/API privilege response.  It must never turn every
    # previously discovered VM into "removed"; wait for a non-empty inventory.
    if not result.virtual_machines:
        source.status_message = f"VMware API доступен, но инвентарь ВМ пуст; ранее обнаруженные ВМ сохранены"
        for child in db.scalars(select(Device).where(Device.vmware_parent_id == source.id)).all():
            if child.status_message == "Виртуальная машина больше не найдена в инвентаре VMware":
                child.status = "unknown"
                child.status_message = "Ожидание подтверждения инвентаря VMware"
        _inventory_event(db, source)
        return True, 0, "Инвентарь ВМ пуст: существующие ВМ не изменены"
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
        db.flush()
        if vm["power_state"].lower() == "on":
            child.status, child.status_message = "available", f"ВМ включена; VMware: {source.name}"
            child.last_seen_at = now
        else:
            child.status, child.status_message = "unknown", f"ВМ выключена; VMware: {source.name}"
        child.last_poll_at, child.failure_count = now, 0
        _emit_metrics(db, child, _vm_values(vm), now, trust_vmware_values=True)
        _inventory_event(db, child)
    # Do not infer deletion from one inventory response.  ESXi/vCenter may
    # return a partial view during maintenance or when API privileges change.
    # The operator can explicitly exclude a VM; that exclusion is persisted.
    _inventory_event(db, source)
    return True, len(result.virtual_machines or []), f"Обнаружено ВМ: {len(result.virtual_machines or [])}; новых: {created}"
