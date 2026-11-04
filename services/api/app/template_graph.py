"""Resolve inherited Zabbix template content without relying on a fixed hierarchy."""
from __future__ import annotations

from sqlalchemy import select

from .models import TemplateInheritance


def inherited_template_ids(db, root_ids: list[str]) -> list[str]:
    """Return each selected template and every recursively linked template once."""
    result: list[str] = []
    pending = list(root_ids)
    seen: set[str] = set()
    while pending:
        template_id = pending.pop(0)
        if template_id in seen:
            continue
        seen.add(template_id)
        result.append(template_id)
        pending.extend(db.scalars(select(TemplateInheritance.linked_template_id).where(
            TemplateInheritance.template_id == template_id
        )).all())
    return result
