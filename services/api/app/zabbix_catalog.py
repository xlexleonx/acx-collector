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
from .database import SessionLocal, ensure_schema
from .models import DeviceDiscovery, DeviceItem, DiscoveryRule, DiscoveryRuleFilter, ItemProcessing, ItemPrototype, Template, TemplateInheritance, TemplateItem, Trigger, ValueMap


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


def value_map_name(source: dict) -> str:
    value_map = source.get("valuemap") or source.get("value_map") or ""
    if isinstance(value_map, dict):
        return str(value_map.get("name") or "")
    return str(value_map)


def processing_pipeline(source: dict) -> list[dict]:
    pipeline: list[dict] = []
    for step in source.get("preprocessing", []) or []:
        if not isinstance(step, dict) or not step.get("type"):
            continue
        parameters = step.get("parameters", [])
        if not isinstance(parameters, list):
            parameters = [parameters]
        pipeline.append({"type": str(step["type"]).upper(), "parameters": [str(value) for value in parameters]})
    return pipeline


def store_processing(db, source_kind: str, source_id: str, source: dict) -> None:
    db.add(ItemProcessing(
        source_kind=source_kind,
        source_id=source_id,
        pipeline=processing_pipeline(source),
        value_map_name=value_map_name(source),
    ))


def import_value_maps(export: dict, db) -> None:
    """Import simple Zabbix equality maps used for status and type labels."""
    value_maps = list(export.get("value_maps", []) or [])
    value_maps.extend(export.get("valuemaps", []) or [])
    for source in value_maps:
        name = str(source.get("name") or "")
        if not name:
            continue
        mappings: dict[str, str] = {}
        for mapping in source.get("mappings", []) or []:
            if "value" in mapping and "newvalue" in mapping:
                mappings[str(mapping["value"])] = str(mapping["newvalue"])
        # Catalog exports may repeat a map in the same YAML file. The import
        # session deliberately has autoflush disabled, so also look at rows
        # queued for insertion before querying PostgreSQL.
        row = next((candidate for candidate in db.new if isinstance(candidate, ValueMap) and candidate.name == name), None)
        if not row:
            row = db.scalar(select(ValueMap).where(ValueMap.name == name))
        if row:
            row.mappings = mappings
        else:
            db.add(ValueMap(name=name, mappings=mappings))


def clear_template_catalog(template: Template, db) -> None:
    """Remove prior imported objects while preserving device-to-template links."""
    template_item_ids = list(db.scalars(select(TemplateItem.id).where(TemplateItem.template_id == template.id)))
    if template_item_ids:
        db.execute(delete(ItemProcessing).where(
            ItemProcessing.source_kind == "template_item", ItemProcessing.source_id.in_(template_item_ids)
        ))
    rule_ids = list(db.scalars(select(DiscoveryRule.id).where(DiscoveryRule.template_id == template.id)))
    if rule_ids:
        db.execute(delete(DiscoveryRuleFilter).where(DiscoveryRuleFilter.discovery_rule_id.in_(rule_ids)))
        prototype_ids = list(db.scalars(select(ItemPrototype.id).where(ItemPrototype.discovery_rule_id.in_(rule_ids))))
        if prototype_ids:
            db.execute(delete(ItemProcessing).where(
                ItemProcessing.source_kind == "item_prototype", ItemProcessing.source_id.in_(prototype_ids)
            ))
        discovery_ids = list(db.scalars(select(DeviceDiscovery.id).where(DeviceDiscovery.discovery_rule_id.in_(rule_ids))))
        if discovery_ids:
            device_item_ids = list(db.scalars(select(DeviceItem.id).where(DeviceItem.discovery_id.in_(discovery_ids))))
            if device_item_ids:
                db.execute(delete(ItemProcessing).where(
                    ItemProcessing.source_kind == "device_item", ItemProcessing.source_id.in_(device_item_ids)
                ))
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
        filter_config = raw_rule.get("filter") or {}
        conditions = filter_config.get("conditions") or []
        literal_conditions = [
            {"macro": str(condition.get("macro") or ""), "value": str(condition.get("value") or ""), "operator": str(condition.get("operator") or "MATCHES_REGEX")}
            for condition in conditions if isinstance(condition, dict) and condition.get("macro") and "{" not in str(condition.get("value") or "")
        ]
        if literal_conditions:
            db.add(DiscoveryRuleFilter(
                discovery_rule_id=rule.id,
                evaltype=str(filter_config.get("evaltype") or "AND").upper(),
                conditions=literal_conditions,
            ))
        for prototype in raw_rule.get("item_prototypes", []):
            oid, direct = normalize_snmp_oid(prototype.get("snmp_oid"))
            enabled = is_enabled(prototype) and prototype.get("type") == "SNMP_AGENT" and bool(oid)
            # An OID with an LLD macro will become numeric only after discovery.
            enabled = enabled and (direct or "{#" in oid)
            if not enabled:
                skipped += 1
            item_prototype = ItemPrototype(
                discovery_rule_id=rule.id,
                name=prototype.get("name", prototype.get("key", "Unnamed item prototype")),
                key=prototype.get("key", oid),
                snmp_oid=oid,
                value_type=str(prototype.get("value_type", "numeric")).lower(),
                units=prototype.get("units", ""),
                interval_seconds=interval(prototype.get("delay")),
                enabled=enabled,
            )
            db.add(item_prototype)
            db.flush()
            store_processing(db, "item_prototype", item_prototype.id, prototype)
            # In Zabbix 7 trigger prototypes belong to their item prototype.
            # Keep each source expression visible in the Collector catalog.
            for trigger in prototype.get("trigger_prototypes", []) or []:
                template.triggers.append(Trigger(
                    name=trigger.get("name", "Zabbix trigger prototype"), item_key="", operator=">", threshold=0,
                    expression=str(trigger.get("expression") or ""),
                    severity=str(trigger.get("priority", "warning")).lower(), enabled=False,
                ))
        # These prototypes are kept visible in the template. They cannot be
        # executed until their Zabbix expressions are translated by the worker.
        for trigger in raw_rule.get("trigger_prototypes", []) or []:
            template.triggers.append(Trigger(
                name=trigger.get("name", "Zabbix trigger prototype"), item_key="", operator=">", threshold=0,
                expression=str(trigger.get("expression") or ""), severity=str(trigger.get("priority", "warning")).lower(), enabled=False,
            ))
    return skipped


def import_file(path: Path, db) -> tuple[int, int]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    export = raw.get("zabbix_export", raw)
    import_value_maps(export, db)
    imported, skipped = 0, 0
    for source in export.get("templates", []):
        import_value_maps(source, db)
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
            template_item = TemplateItem(
                template_id=template.id,
                name=item.get("name", item.get("key", "Unnamed SNMP item")),
                key=item.get("key", oid), oid=oid,
                value_type=str(item.get("value_type", "numeric")).lower(),
                units=item.get("units", ""), interval_seconds=interval(item.get("delay")), enabled=enabled,
            )
            db.add(template_item)
            db.flush()
            store_processing(db, "template_item", template_item.id, item)
        skipped += import_discovery_rules(source, template, db)
        trigger_sources = list(source.get("triggers", []))
        trigger_sources.extend(trigger for item in source.get("items", []) for trigger in item.get("triggers", []))
        for trigger in trigger_sources:
            # Preserve visibility of the trigger in the template without executing
            # an unconverted Zabbix expression against a different engine.
            template.triggers.append(Trigger(
                name=trigger.get("name", "Zabbix trigger"), item_key="", operator=">", threshold=0,
                expression=str(trigger.get("expression") or ""), severity=str(trigger.get("priority", "warning")).lower(), enabled=False,
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
    ensure_schema()
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

