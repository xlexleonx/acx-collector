"""Resolve all metric definitions effective for one Collector host."""
from __future__ import annotations

from sqlalchemy import or_, select

from .models import Device, DeviceDiscovery, DeviceItem, DeviceItemOverride, DeviceTemplate, DiscoveryRule, Template
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
    # LLD creates physical DeviceItem rows. Restrict them to discovery rules of
    # templates that are still linked; otherwise an unlinked template would
    # keep contributing its historical discovered items to the host view.
    active_discovery_ids = db.scalars(
        select(DeviceDiscovery.id).join(DiscoveryRule, DeviceDiscovery.discovery_rule_id == DiscoveryRule.id).where(
            DeviceDiscovery.device_id == device.id,
            DiscoveryRule.template_id.in_(template_ids) if template_ids else False,
        )
    ).all()
    discovered_items = select(DeviceItem).where(DeviceItem.device_id == device.id)
    if active_discovery_ids:
        discovered_items = discovered_items.where(or_(
            DeviceItem.discovery_id.is_(None), DeviceItem.discovery_id.in_(active_discovery_ids)
        ))
    else:
        discovered_items = discovered_items.where(DeviceItem.discovery_id.is_(None))
    for item in db.scalars(discovered_items).all():
        enabled = item.enabled and overrides.get(item.key, True)
        if include_disabled or enabled:
            result[item.key] = {"item": item, "enabled": enabled, "source": "discovery", "template_name": "Обнаружено по шаблону"}
    return list(result.values())
