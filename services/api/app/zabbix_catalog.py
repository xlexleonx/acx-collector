"""Import the official Zabbix 7 YAML catalog into the local Collector database.

The Collector deliberately imports only direct SNMP items as active checks. Complex
Zabbix expressions, discovery rules and dependent items are represented as disabled
triggers for inventory and manual adaptation; they must not silently create alerts.
"""
from __future__ import annotations
import re
import sys
from pathlib import Path
import yaml
from sqlalchemy import select
from .database import Base, SessionLocal, engine
from .models import Template, TemplateItem, Trigger


def interval(value: object) -> int:
    match = re.match(r"^(\d+)", str(value or "60"))
    return max(10, int(match.group(1))) if match else 60


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
            db.query(TemplateItem).filter(TemplateItem.template_id == template.id).delete(synchronize_session=False)
            db.query(Trigger).filter(Trigger.template_id == template.id).delete(synchronize_session=False)
            template.source, template.version = "zabbix-7.0", str(export.get("version", "7.0"))
        template.description = f"Импортировано из Zabbix: {path.name}. Сложные элементы требуют ручной адаптации."
        for item in source.get("items", []):
            oid = str(item.get("snmp_oid", ""))
            if item.get("type") != "SNMP_AGENT" or not oid:
                skipped += 1
                continue
            enabled = item.get("status", "ENABLED") != "DISABLED" and not ("{" in oid or "[" in oid)
            template.items.append(TemplateItem(
                name=item.get("name", item.get("key", "Unnamed SNMP item")),
                key=item.get("key", oid), oid=oid,
                value_type=str(item.get("value_type", "numeric")).lower(),
                units=item.get("units", ""), interval_seconds=interval(item.get("delay")), enabled=enabled,
            ))
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
        print(f"Обработано файлов: {files}; шаблонов: {templates}; неподдержанных элементов: {skipped}")
    finally:
        db.close()


if __name__ == "__main__":
    main()

