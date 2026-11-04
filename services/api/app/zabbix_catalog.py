"""Import the official Zabbix 7 YAML catalog into the local Collector database.

The Collector imports direct SNMP items and SNMP low-level discovery (LLD) rules.
Complex Zabbix expressions and dependent items remain visible but disabled until
their semantics can be translated safely to the Collector engine.
"""
from __future__ import annotations
import re
import sys
from pathlib import Path
import yaml
from sqlalchemy import delete, select
from .database import Base, SessionLocal, engine
from .models import DeviceDiscovery, DeviceItem, DiscoveryRule, ItemPrototype, Template, TemplateInheritance, TemplateItem, Trigger


def interval(value: object) -> int:
    match = re.match(r"^\s*(\d+)\s*([smhdSMHD]?)", str(value or "60"))
    if not match:
        return 60
    multiplier = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2).lower()]
    return max(10, int(match.group(1)) * multiplier)


def normalize_snmp_oid(value: object) -> tuple[str, bool]:
    """Zabbix 7 serializes ordinary SNMP gets as get[1.3.6...].

    ``walk[...]`` is also a usable numeric OID when it represents one resolved
    item. Macro OIDs stay visible in the catalog but are resolved per device.
    """
    oid = str(value or "").strip()
    if (oid.startswith("get[") or oid.startswith("walk[")) and oid.endswith("]"):
        oid = oid[4:-1].strip()
    is_direct_numeric_oid = bool(re.fullmatch(r"\.?\d+(?:\.\d+)+", oid))
    return oid, is_direct_numeric_oid


def is_enabled(source: dict) -> bool:
    return source.get("status", "ENABLED") != "DISABLED"


def clear_template_catalog(template: Template, db) -> None:
    """Remove prior imported objects while preserving device-to-template links."""
    rule_ids = list(db.scalars(select(DiscoveryRule.id).where(DiscoveryRule.template_id == template.id)))
    if rule_ids:
        discovery_ids = list(db.scalars(select(DeviceDiscovery.id).where(DeviceDiscovery.discovery_rule_id.in_(rule_ids))))
        if discovery_ids:
            db.execute(delete(DeviceItem).where(DeviceItem.discovery_id.in_(discovery_ids)))
            db.execute(delete(DeviceDiscovery).where(DeviceDiscovery.id.in_(discovery_ids)))
        db.execute(delete(ItemPrototype).where(ItemPrototype.discovery_rule_id.in_(rule_ids)))
        db.execute(delete(DiscoveryRule).where(DiscoveryRule.id.in_(rule_ids)))
    db.execute(delete(TemplateItem).where(TemplateItem.template_id == template.id))
    db.execute(delete(Trigger).where(Trigger.template_id == template.id))


def import_discovery_rules(source: dict, template: Template, db) -> int:
    """Store generic Zabbix SNMP LLD rules and their item prototypes.

    Macro substitution happens per device in the worker after an ``snmpwalk``.
    Unsupported prototype types are retained but disabled, rather than queried as
    invalid OIDs.
    """
    skipped = 0
    for raw_rule in source.get("discovery_rules", []):
        rule = DiscoveryRule(
            template_id=template.id,
            name=raw_rule.get("name", raw_rule.get("key", "SNMP discovery rule")),
            key=raw_rule.get("key", "discovery"),
            snmp_oid=str(raw_rule.get("snmp_oid", "")).strip(),
            interval_seconds=interval(raw_rule.get("delay", 300)),
            enabled=is_enabled(raw_rule) and raw_rule.get("type") == "SNMP_AGENT" and bool(raw_rule.get("snmp_oid")),
        )
        db.add(rule)
        db.flush()
        for prototype in raw_rule.get("item_prototypes", []):
            oid, direct = normalize_snmp_oid(prototype.get("snmp_oid"))
            enabled = is_enabled(prototype) and prototype.get("type") == "SNMP_AGENT" and bool(oid)
            # An OID with an LLD macro will become numeric only after discovery.
            enabled = enabled and (direct or "{#" in oid)
            if not enabled:
                skipped += 1
            db.add(ItemPrototype(
                discovery_rule_id=rule.id,
                name=prototype.get("name", prototype.get("key", "Unnamed item prototype")),
                key=prototype.get("key", oid),
                snmp_oid=oid,
                value_type=str(prototype.get("value_type", "numeric")).lower(),
                units=prototype.get("units", ""),
                interval_seconds=interval(prototype.get("delay")),
                enabled=enabled,
            ))
    return skipped


def import_file(path: Path, db) -> tuple[int, int]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    export = raw.get("zabbix_export", raw)
    imported, skipped = 0, 0
    for source in export.get("templates", []):
        name = source.get("template") or source.get("name")
        if not name:
            continue
        template = db.scalar(select(Template).where(Template.name == name))
        if not template:
            template = Template(name=name, source="zabbix-7.0", version=str(export.get("version", "7.0")))
            db.add(template)
            db.flush()
        else:
            clear_template_catalog(template, db)
            template.source, template.version = "zabbix-7.0", str(export.get("version", "7.0"))
        template.description = f"Импортировано из Zabbix: {path.name}. Поддерживаются прямые SNMP и LLD; сложные элементы требуют адаптации."
        for item in source.get("items", []):
            oid, is_direct_oid = normalize_snmp_oid(item.get("snmp_oid"))
            if item.get("type") != "SNMP_AGENT" or not oid:
                skipped += 1
                continue
            enabled = is_enabled(item) and is_direct_oid
            template.items.append(TemplateItem(
                name=item.get("name", item.get("key", "Unnamed SNMP item")),
                key=item.get("key", oid), oid=oid,
                value_type=str(item.get("value_type", "numeric")).lower(),
                units=item.get("units", ""), interval_seconds=interval(item.get("delay")), enabled=enabled,
            ))
        skipped += import_discovery_rules(source, template, db)
        trigger_sources = list(source.get("triggers", []))
        trigger_sources.extend(trigger for item in source.get("items", []) for trigger in item.get("triggers", []))
        for trigger in trigger_sources:
            # Preserve visibility of the trigger in the template without executing
            # an unconverted Zabbix expression against a different engine.
            template.triggers.append(Trigger(
                name=trigger.get("name", "Zabbix trigger"), item_key="", operator=">",
                threshold=0, severity=str(trigger.get("priority", "warning")).lower(), enabled=False,
            ))
        imported += 1
    db.commit()
    return imported, skipped


def template_name(reference: object) -> str:
    if isinstance(reference, str):
        return reference
    if isinstance(reference, dict):
        return str(reference.get("name") or reference.get("template") or "")
    return ""


def import_template_inheritance(root: Path, db) -> int:
    """Link template hierarchy after the entire catalog is present in the DB."""
    db.execute(delete(TemplateInheritance))
    linked = 0
    for path in root.rglob("*.yaml"):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        export = raw.get("zabbix_export", raw)
        for source in export.get("templates", []):
            current_name = source.get("template") or source.get("name")
            if not current_name:
                continue
            current = db.scalar(select(Template).where(Template.name == current_name))
            if not current:
                continue
            for reference in source.get("templates", []):
                inherited_name = template_name(reference)
                inherited = db.scalar(select(Template).where(Template.name == inherited_name))
                if inherited and inherited.id != current.id:
                    db.add(TemplateInheritance(template_id=current.id, linked_template_id=inherited.id))
                    linked += 1
    db.commit()
    return linked


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/catalog/zabbix")
    if not root.is_dir():
        raise SystemExit(f"Каталог не найден: {root}")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    templates = skipped = files = 0
    try:
        for path in root.rglob("*.yaml"):
            try:
                loaded, skipped_count = import_file(path, db)
                templates += loaded
                skipped += skipped_count
                files += 1
            except Exception as exc:
                db.rollback()
                print(f"SKIP {path}: {exc}", file=sys.stderr)
        inherited = import_template_inheritance(root, db)
        print(f"Обработано файлов: {files}; шаблонов: {templates}; связей наследования: {inherited}; неподдержанных элементов: {skipped}")
    finally:
        db.close()


if __name__ == "__main__":
    main()

