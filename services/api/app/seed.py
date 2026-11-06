from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import Template, TemplateItem, Trigger


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
    if not db.scalar(select(Template).where(Template.name == "VMware Hypervisor by SOAP")):
        db.add(Template(
            name="VMware Hypervisor by SOAP",
            source="acrotix-vmware",
            version="1.0",
            description="Доступность VMware SOAP API и количество обнаруженных виртуальных машин.",
            items=[
                TemplateItem(name="VMware API availability", key="vmware.api.available", oid="vmware://api/available", value_type="numeric", interval_seconds=300),
                TemplateItem(name="Virtual machines discovered", key="vmware.inventory.vms", oid="vmware://inventory/vms", value_type="numeric", interval_seconds=300),
            ],
        ))
        changed = True
    if not db.scalar(select(Template).where(Template.name == "VMware Guest")):
        db.add(Template(
            name="VMware Guest",
            source="acrotix-vmware",
            version="1.0",
            description="Базовые сведения и состояние виртуальной машины, получаемые через ESXi/vCenter.",
            items=[
                TemplateItem(name="Power state", key="vmware.vm.power_state", oid="vmware://guest/power-state", value_type="text", interval_seconds=300),
                TemplateItem(name="Powered on", key="vmware.vm.powered", oid="vmware://guest/powered", value_type="numeric", interval_seconds=300),
                TemplateItem(name="Guest IP address", key="vmware.vm.guest_ip", oid="vmware://guest/ip", value_type="text", interval_seconds=300),
                TemplateItem(name="Guest operating system", key="vmware.vm.guest_os", oid="vmware://guest/os", value_type="text", interval_seconds=300),
            ],
            triggers=[
                Trigger(name="VMware Guest: virtual machine is powered off", item_key="vmware.vm.powered", operator="==", threshold=0, severity="warning"),
            ],
        ))
        changed = True
    if changed:
        db.commit()

