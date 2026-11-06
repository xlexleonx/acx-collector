from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import Template, TemplateItem, Trigger


def _add_missing_items(db: Session, template: Template, definitions: list[tuple[str, str, str, str, str, int]]) -> bool:
    """Extend built-ins on upgrade without deleting an operator's data/history."""
    known = set(db.scalars(select(TemplateItem.key).where(TemplateItem.template_id == template.id)).all())
    added = False
    for name, key, oid, value_type, units, interval in definitions:
        if key in known:
            continue
        db.add(TemplateItem(
            template_id=template.id, name=name, key=key, oid=oid,
            value_type=value_type, units=units, interval_seconds=interval,
        ))
        added = True
    return added


def seed_builtin_templates(db: Session) -> None:
    """Small safe starter catalog. Full Zabbix imports remain explicit and reviewable."""
    changed = False
    if not db.scalar(select(Template).where(Template.name == "Generic device by SNMP")):
        db.add(Template(
            name="Generic device by SNMP",
            source="acrotix-built-in",
            version="0.1",
            description="Базовая проверка SNMP-доступности и системных идентификаторов устройства.",
            items=[
                TemplateItem(name="System description", key="system.description", oid="1.3.6.1.2.1.1.1.0", value_type="text", interval_seconds=300),
                TemplateItem(name="System name", key="system.name", oid="1.3.6.1.2.1.1.5.0", value_type="text", interval_seconds=300),
                TemplateItem(name="System uptime", key="system.uptime", oid="1.3.6.1.2.1.1.3.0", value_type="numeric", units="s", interval_seconds=60),
            ],
        ))
        changed = True
    hypervisor = db.scalar(select(Template).where(Template.name == "VMware Hypervisor by SOAP"))
    if not hypervisor:
        hypervisor = Template(
            name="VMware Hypervisor by SOAP",
            source="acrotix-vmware",
            version="1.1",
            description="Инвентарь, доступность и ресурсы ESXi, получаемые через VMware vSphere SOAP API.",
        )
        db.add(hypervisor)
        db.flush()
        changed = True
    else:
        hypervisor.version = "1.1"
    changed = _add_missing_items(db, hypervisor, [
        ("VMware API availability", "vmware.api.available", "vmware://api/available", "numeric", "", 300),
        ("Virtual machines discovered", "vmware.inventory.vms", "vmware://inventory/vms", "numeric", "", 300),
        ("Hypervisor name", "vmware.host.name", "vmware://host/name", "text", "", 3600),
        ("Connection state", "vmware.host.connection_state", "vmware://host/connection-state", "text", "", 300),
        ("Maintenance mode", "vmware.host.maintenance", "vmware://host/maintenance", "numeric", "", 300),
        ("Power state", "vmware.host.power_state", "vmware://host/power-state", "text", "", 300),
        ("Hardware vendor", "vmware.host.vendor", "vmware://host/vendor", "text", "", 3600),
        ("Hardware model", "vmware.host.model", "vmware://host/model", "text", "", 3600),
        ("CPU model", "vmware.host.cpu_model", "vmware://host/cpu-model", "text", "", 3600),
        ("CPU cores", "vmware.host.cpu.cores", "vmware://host/cpu-cores", "numeric", "", 3600),
        ("CPU threads", "vmware.host.cpu.threads", "vmware://host/cpu-threads", "numeric", "", 3600),
        ("CPU frequency", "vmware.host.cpu.mhz", "vmware://host/cpu-mhz", "numeric", "MHz", 3600),
        ("Total memory", "vmware.host.memory.total", "vmware://host/memory-total", "numeric", "B", 3600),
        ("CPU usage", "vmware.host.cpu.usage", "vmware://host/cpu-usage", "numeric", "MHz", 300),
        ("Memory usage", "vmware.host.memory.usage", "vmware://host/memory-usage", "numeric", "B", 300),
        ("Host uptime", "vmware.host.uptime", "vmware://host/uptime", "numeric", "s", 300),
        ("VMware product", "vmware.host.product", "vmware://host/product", "text", "", 3600),
        ("VMware version", "vmware.host.version", "vmware://host/version", "text", "", 3600),
        ("VMware build", "vmware.host.build", "vmware://host/build", "text", "", 3600),
    ]) or changed

    guest = db.scalar(select(Template).where(Template.name == "VMware Guest"))
    if not guest:
        guest = Template(
            name="VMware Guest",
            source="acrotix-vmware",
            version="1.3",
            description="Конфигурация, состояние и доступные показатели виртуальной машины из VMware ESXi/vCenter.",
        )
        db.add(guest)
        db.flush()
        changed = True
    else:
        guest.version = "1.3"
    changed = _add_missing_items(db, guest, [
        ("Power state", "vmware.vm.power_state", "vmware://guest/power-state", "text", "", 300),
        ("Powered on", "vmware.vm.powered", "vmware://guest/powered", "numeric", "", 300),
        ("Virtual machine name", "vmware.vm.name", "vmware://guest/name", "text", "", 3600),
        ("VM UUID", "vmware.vm.uuid", "vmware://guest/uuid", "text", "", 3600),
        ("VM instance UUID", "vmware.vm.instance_uuid", "vmware://guest/instance-uuid", "text", "", 3600),
        ("Virtual hardware version", "vmware.vm.hardware_version", "vmware://guest/hardware-version", "text", "", 3600),
        ("VM configuration version", "vmware.vm.configuration_version", "vmware://guest/configuration-version", "text", "", 3600),
        ("VM annotation", "vmware.vm.annotation", "vmware://guest/annotation", "text", "", 3600),
        ("VM configuration path", "vmware.vm.path", "vmware://guest/path", "text", "", 3600),
        ("Guest IP address", "vmware.vm.guest_ip", "vmware://guest/ip", "text", "", 300),
        ("Guest host name", "vmware.vm.guest_hostname", "vmware://guest/hostname", "text", "", 300),
        ("Guest operating system", "vmware.vm.guest_os", "vmware://guest/os", "text", "", 3600),
        ("Guest OS ID", "vmware.vm.guest_id", "vmware://guest/os-id", "text", "", 3600),
        ("Guest OS family", "vmware.vm.guest_family", "vmware://guest/os-family", "text", "", 3600),
        ("Guest state", "vmware.vm.guest_state", "vmware://guest/state", "text", "", 300),
        ("VMware Tools status", "vmware.vm.tools_status", "vmware://guest/tools-status", "text", "", 300),
        ("VMware Tools running status", "vmware.vm.tools_running_status", "vmware://guest/tools-running-status", "text", "", 300),
        ("VMware Tools version", "vmware.vm.tools_version", "vmware://guest/tools-version", "numeric", "", 3600),
        ("VMware Tools version status", "vmware.vm.tools_version_status", "vmware://guest/tools-version-status", "text", "", 3600),
        ("Connection state", "vmware.vm.connection_state", "vmware://guest/connection-state", "text", "", 300),
        ("Boot time", "vmware.vm.boot_time", "vmware://guest/boot-time", "text", "", 300),
        ("Hypervisor object ID", "vmware.vm.hypervisor_moid", "vmware://guest/hypervisor", "text", "", 3600),
        ("vCPU count", "vmware.vm.cpu.count", "vmware://guest/cpu-count", "numeric", "", 3600),
        ("CPU cores per socket", "vmware.vm.cpu.cores_per_socket", "vmware://guest/cpu-cores-per-socket", "numeric", "", 3600),
        ("Configured memory", "vmware.vm.memory.configured", "vmware://guest/memory-configured", "numeric", "B", 3600),
        ("CPU hot add enabled", "vmware.vm.cpu.hot_add", "vmware://guest/cpu-hot-add", "numeric", "", 3600),
        ("Memory hot add enabled", "vmware.vm.memory.hot_add", "vmware://guest/memory-hot-add", "numeric", "", 3600),
        ("CPU limit", "vmware.vm.cpu.limit", "vmware://guest/cpu-limit", "numeric", "MHz", 300),
        ("Memory limit", "vmware.vm.memory.limit", "vmware://guest/memory-limit", "numeric", "B", 300),
        ("CPU usage", "vmware.vm.cpu.usage_mhz", "vmware://guest/cpu-usage", "numeric", "MHz", 300),
        ("CPU demand", "vmware.vm.cpu.demand", "vmware://guest/cpu-demand", "numeric", "MHz", 300),
        ("CPU entitlement", "vmware.vm.cpu.entitlement", "vmware://guest/cpu-entitlement", "numeric", "MHz", 300),
        ("Memory entitlement", "vmware.vm.memory.entitlement", "vmware://guest/memory-entitlement", "numeric", "B", 300),
        ("Guest memory usage", "vmware.vm.memory.guest", "vmware://guest/memory-guest", "numeric", "B", 300),
        ("Host memory usage", "vmware.vm.memory.host", "vmware://guest/memory-host", "numeric", "B", 300),
        ("Ballooned memory", "vmware.vm.memory.ballooned", "vmware://guest/memory-ballooned", "numeric", "B", 300),
        ("Swapped memory", "vmware.vm.memory.swapped", "vmware://guest/memory-swapped", "numeric", "B", 300),
        ("Compressed memory", "vmware.vm.memory.compressed", "vmware://guest/memory-compressed", "numeric", "B", 300),
        ("Private memory", "vmware.vm.memory.private", "vmware://guest/memory-private", "numeric", "B", 300),
        ("Shared memory", "vmware.vm.memory.shared", "vmware://guest/memory-shared", "numeric", "B", 300),
        ("Memory overhead", "vmware.vm.memory.overhead", "vmware://guest/memory-overhead", "numeric", "B", 300),
        ("Guest uptime", "vmware.vm.uptime", "vmware://guest/uptime", "numeric", "s", 300),
        ("Committed storage", "vmware.vm.storage.committed", "vmware://guest/storage-committed", "numeric", "B", 300),
        ("Uncommitted storage", "vmware.vm.storage.uncommitted", "vmware://guest/storage-uncommitted", "numeric", "B", 300),
        ("Unshared storage", "vmware.vm.storage.unshared", "vmware://guest/storage-unshared", "numeric", "B", 300),
        ("Snapshot consolidation required", "vmware.vm.consolidation_needed", "vmware://guest/consolidation-needed", "numeric", "", 300),
        ("Snapshot count", "vmware.vm.snapshot_count", "vmware://guest/snapshot-count", "numeric", "", 3600),
        ("Snapshot latest date", "vmware.vm.snapshot_latest", "vmware://guest/snapshot-latest", "text", "", 3600),
        ("CPU usage in percent", "vmware.vm.cpu.usage_percent", "vmware://perf/cpu-usage", "numeric", "%", 300),
        ("CPU ready time", "vmware.vm.cpu.ready_ms", "vmware://perf/cpu-ready", "numeric", "ms", 300),
        ("CPU wait time", "vmware.vm.cpu.wait_ms", "vmware://perf/cpu-wait", "numeric", "ms", 300),
        ("CPU co-stop time", "vmware.vm.cpu.costop_ms", "vmware://perf/cpu-costop", "numeric", "ms", 300),
        ("Memory usage in percent", "vmware.vm.memory.usage_percent", "vmware://perf/memory-usage", "numeric", "%", 300),
        ("Active memory", "vmware.vm.memory.active", "vmware://perf/memory-active", "numeric", "B", 300),
        ("Memory swap-in rate", "vmware.vm.memory.swap_in_rate", "vmware://perf/memory-swap-in", "numeric", "Bps", 300),
        ("Memory swap-out rate", "vmware.vm.memory.swap_out_rate", "vmware://perf/memory-swap-out", "numeric", "Bps", 300),
        ("Network usage", "vmware.vm.net.usage", "vmware://perf/network-usage", "numeric", "Bps", 300),
        ("Network received", "vmware.vm.net.received", "vmware://perf/network-received", "numeric", "Bps", 300),
        ("Network transmitted", "vmware.vm.net.transmitted", "vmware://perf/network-transmitted", "numeric", "Bps", 300),
        ("Disk usage", "vmware.vm.disk.usage", "vmware://perf/disk-usage", "numeric", "Bps", 300),
        ("Disk read", "vmware.vm.disk.read", "vmware://perf/disk-read", "numeric", "Bps", 300),
        ("Disk write", "vmware.vm.disk.write", "vmware://perf/disk-write", "numeric", "Bps", 300),
        ("Disk read latency", "vmware.vm.disk.read_latency", "vmware://perf/disk-read-latency", "numeric", "ms", 300),
        ("Disk write latency", "vmware.vm.disk.write_latency", "vmware://perf/disk-write-latency", "numeric", "ms", 300),
    ]) or changed
    if not db.scalar(select(Trigger).where(Trigger.template_id == guest.id, Trigger.item_key == "vmware.vm.powered")):
        db.add(Trigger(name="VMware Guest: virtual machine is powered off", item_key="vmware.vm.powered", operator="==", threshold=0, severity="warning", template_id=guest.id))
        changed = True
    if changed:
        db.commit()

