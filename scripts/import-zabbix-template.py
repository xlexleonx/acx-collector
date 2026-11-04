#!/usr/bin/env python3
"""Convert a local Zabbix YAML/JSON export into Collector template JSON.

The importer preserves source metadata and items/triggers that use direct SNMP OIDs.
Complex discovery, dependent items and calculated expressions are recorded for review,
not silently transformed into an incorrect check.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import yaml


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    raw = args.source.read_text(encoding="utf-8")
    data = json.loads(raw) if args.source.suffix.lower() == ".json" else yaml.safe_load(raw)
    export = data.get("zabbix_export", data)
    templates = export.get("templates", [])
    result = {"source": "zabbix-import", "templates": [], "needs_review": []}
    for template in templates:
        name = template.get("template") or template.get("name")
        converted = {"name": name, "version": str(export.get("version", "unknown")), "items": [], "triggers": []}
        for item in template.get("items", []):
            if item.get("type", "SNMP_AGENT") != "SNMP_AGENT" or not item.get("snmp_oid"):
                result["needs_review"].append({"template": name, "item": item.get("name"), "reason": "Неподдерживаемый тип элемента или нет SNMP OID"})
                continue
            converted["items"].append({"name": item.get("name"), "key": item.get("key"), "oid": item["snmp_oid"], "units": item.get("units", ""), "enabled": item.get("status", "ENABLED") == "ENABLED"})
        for trigger in template.get("triggers", []):
            result["needs_review"].append({"template": name, "trigger": trigger.get("name"), "reason": "Выражение требует перевода в модель триггеров Collector"})
        result["templates"].append(converted)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Шаблонов: {len(result['templates'])}; элементов на ручную проверку: {len(result['needs_review'])}")


if __name__ == "__main__":
    main()

