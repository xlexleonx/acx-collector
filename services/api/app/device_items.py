"""Resolve all metric definitions effective for one Collector host."""
from __future__ import annotations

from sqlalchemy import select

from .models import Device, DeviceItem, DeviceItemOverride, DeviceTemplate, Template
from .template_graph import inherited_template_ids


def effective_device_items(db, device: Device, include_disabled: bool = False) -> list[dict]:
    links = db.scalars(select(DeviceTemplate).where(DeviceTemplate.device_id == device.id)).all()
    template_ids = inherited_template_ids(db, [link.template_id for link in links])
    overrides = {
        item.item_key: item.enabled
        for item in db.scalars(select(DeviceItemOverride).where(DeviceItemOverride.device_id == device.id)).all()
    }
    result: dict[str, dict] = {}
    for template_id in template_ids:
        template = db.get(Template, template_id)
        if not template:
            continue
        for item in template.items:
            enabled = item.enabled and overrides.get(item.key, True)
            if include_disabled or enabled:
                result[item.key] = {"item": item, "enabled": enabled, "source": "template", "template_name": template.name}
    for item in db.scalars(select(DeviceItem).where(DeviceItem.device_id == device.id)).all():
        enabled = item.enabled and overrides.get(item.key, True)
        if include_disabled or enabled:
            result[item.key] = {"item": item, "enabled": enabled, "source": "discovery", "template_name": "Обнаружено по шаблону"}
    return list(result.values())
