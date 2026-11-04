from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import Template, TemplateItem


def seed_builtin_templates(db: Session) -> None:
    """Small safe starter catalog. Full Zabbix imports remain explicit and reviewable."""
    if db.scalar(select(Template).where(Template.name == "Generic device by SNMP")):
        return
    generic = Template(
        name="Generic device by SNMP",
        source="acrotix-built-in",
        version="0.1",
        description="Базовая проверка SNMP-доступности и системных идентификаторов устройства.",
        items=[
            TemplateItem(name="System description", key="system.description", oid="1.3.6.1.2.1.1.1.0", value_type="text", interval_seconds=300),
            TemplateItem(name="System name", key="system.name", oid="1.3.6.1.2.1.1.5.0", value_type="text", interval_seconds=300),
            TemplateItem(name="System uptime", key="system.uptime", oid="1.3.6.1.2.1.1.3.0", value_type="numeric", units="s", interval_seconds=60),
        ],
    )
    db.add(generic)
    db.commit()

