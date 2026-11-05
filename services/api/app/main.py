from datetime import datetime
import re
import ssl
from fastapi import Depends, FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .collector import test_connection
from .database import ensure_schema, get_db
from .config import settings
from .models import Device, DeviceDiscovery, DeviceItem, DeviceItemDisplay, DeviceItemOverride, DeviceTemplate, DiscoveryRule, ItemPrototype, MetricSample, PortalConnection, Problem, SyncOutbox, Template, TemplateInheritance, TemplateItem, Trigger, User, UserProfile
from .schemas import ActivationRequest, DeviceCreate, DeviceMetricUpdate, DeviceMetricVisibilityUpdate, DeviceUpdate, EnabledUpdate, LoginRequest, PortalConnectionUpdate, ProfileUpdate, TemplateCreate, TemplateImport, TemplateItemCreate, TemplateItemUpdate, TemplateTriggerCreate, TemplateTriggerUpdate, TemplateUpdate, UserCreate, UserUpdate, ZabbixTemplateImport
from .security import allows, create_session, decrypt_secret, encrypt_secret, passwords, read_bootstrap_token, read_session, remove_bootstrap_token
from .seed import seed_builtin_templates
from .template_graph import inherited_template_ids
from .device_items import effective_device_items
from .sync import configured_portal, send_portal_heartbeat

app = FastAPI(title="ACROTIX Collector API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def startup() -> None:
    ensure_schema()
    db = next(get_db())
    try:
        seed_builtin_templates(db)
    finally:
        db.close()


def device_view(device: Device) -> dict:
    return {
        "id": device.id, "name": device.name, "address": device.address, "protocol": device.protocol,
        "enabled": device.enabled, "status": device.status, "status_message": device.status_message,
        "last_seen_at": device.last_seen_at, "last_poll_at": device.last_poll_at, "failure_count": device.failure_count,
    }


def clean_metric_value(value: str) -> str:
    """Make net-snmp output suitable for an operator-facing last-value table."""
    cleaned = re.sub(r"^(?:INTEGER|STRING|Gauge32|Counter32|Counter64|Timeticks|OID|IpAddress):\s*", "", value or "").strip()
    return cleaned.strip('"')


def numeric_value(value: str) -> float | None:
    match = re.search(r"[-+]?\d+(?:[.,]\d+)?", clean_metric_value(value))
    if not match:
        return None
    try:
        return float(match.group(0).replace(",", "."))
    except ValueError:
        return None


def format_metric_value(value: str, units: str = "", key: str = "", name: str = "") -> str:
    """Use the same operator-facing unit rules as the Portal metric view."""
    raw = clean_metric_value(value)
    if not raw:
        return "—"
    if not re.fullmatch(r"[-+]?\d+(?:[.,]\d+)?", raw):
        return raw[:20]
    number = float(raw.replace(",", "."))
    unit = (units or "").strip()
    lower_unit = unit.lower()
    text = f"{key} {name}".lower()

    def trim(number_value: float) -> str:
        if abs(number_value) >= 100:
            return f"{number_value:.0f}"
        if abs(number_value) >= 10:
            return f"{number_value:.1f}"
        return f"{number_value:.2f}"

    def scaled(number_value: float, base: float, labels: list[str]) -> str:
        sign, value_abs, index = ("-" if number_value < 0 else ""), abs(number_value), 0
        while value_abs >= base and index < len(labels) - 1:
            value_abs /= base
            index += 1
        return f"{sign}{trim(value_abs)} {labels[index]}"

    if unit == "%" or re.search(r"\butil\b|pused|percent|%|загруж|использ|заполн", text):
        if 0 < number <= 1 and re.search(r"\butil\b|fraction|ratio", text):
            number *= 100
        return f"{min(100, max(0, number)):.1f} %"
    if lower_unit == "uptime" or re.search(r"uptime|время.*работ", key, re.IGNORECASE):
        seconds = max(0, int(number))
        days, remainder = divmod(seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        if days:
            return f"{days}д {hours}ч"
        if hours:
            return f"{hours}ч {minutes}м"
        if minutes:
            return f"{minutes}м {seconds}с"
        return f"{seconds}с"
    if lower_unit in {"s", "sec", "seconds", "с"}:
        if number < 0.001:
            return f"{number * 1_000_000:.0f} мкс"
        if number < 1:
            return f"{number * 1000:.0f} мс"
        if number < 60:
            return f"{trim(number)} с"
        minutes, seconds = divmod(int(number), 60)
        return f"{minutes}м {seconds}с"
    byte_multipliers = {"b": 1, "byte": 1, "bytes": 1, "байт": 1, "kb": 1024, "mb": 1024**2, "gb": 1024**3, "tb": 1024**4}
    if lower_unit in byte_multipliers:
        return scaled(number * byte_multipliers[lower_unit], 1024, ["B", "KB", "MB", "GB", "TB", "PB", "EB"])
    bit_multipliers = {"bps": 1, "bits/s": 1, "bit/s": 1, "b/s": 1, "kbps": 1e3, "mbps": 1e6, "gbps": 1e9}
    if lower_unit in bit_multipliers:
        return scaled(number * bit_multipliers[lower_unit], 1000, ["bps", "Kbps", "Mbps", "Gbps", "Tbps"])
    hz_multipliers = {"hz": 1, "khz": 1e3, "mhz": 1e6, "ghz": 1e9}
    if lower_unit in hz_multipliers:
        return scaled(number * hz_multipliers[lower_unit], 1000, ["Hz", "KHz", "MHz", "GHz", "THz"])
    if lower_unit in {"c", "°c", "celsius"}:
        return f"{trim(number)} °C"
    if abs(number) >= 1000 and not unit:
        return scaled(number, 1000, ["", "K", "M", "G", "T", "P"])
    return f"{trim(number)}{f' {unit}' if unit else ''}"


def latest_rows_for_device(device: Device, db: Session) -> list[dict]:
    definitions = effective_device_items(db, device)
    history = db.scalars(select(MetricSample).where(MetricSample.device_id == device.id).order_by(MetricSample.collected_at.desc()).limit(5000)).all()
    by_key: dict[str, list[MetricSample]] = {}
    for sample in history:
        by_key.setdefault(sample.item_key, []).append(sample)
    rows = []
    for definition in definitions:
        item = definition["item"]
        samples = by_key.get(item.key, [])
        latest, previous = (samples + [None, None])[:2]
        value = format_metric_value(latest.value, item.units, item.key, item.name) if latest and not latest.error else "—"
        change = None
        if latest and previous and not latest.error and not previous.error:
            current_number, previous_number = numeric_value(latest.value), numeric_value(previous.value)
            if current_number is not None and previous_number is not None:
                delta = current_number - previous_number
                change = f"{delta:+.3g}{item.units}" if item.units else f"{delta:+.3g}"
        rows.append({
            "device_id": device.id, "device_name": device.name, "item_key": item.key,
            "name": item.name, "units": item.units, "last_check_at": latest.collected_at if latest else None,
            "last_value": value, "change": change, "error": latest.error if latest and latest.error else ("Данные ещё не получены" if not latest else None),
            "enabled": definition["enabled"], "source": definition["source"], "template_name": definition["template_name"],
        })
    return rows


def current_user(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Требуется вход в систему")
    try:
        session = read_session(authorization.removeprefix("Bearer "))
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    user = db.get(User, session.get("sub"))
    if not user or not user.active:
        raise HTTPException(status_code=401, detail="Пользователь недоступен")
    return user


def require_permission(permission: str):
    def check(user: User = Depends(current_user)) -> User:
        if not allows(user.role, user.permissions or {}, permission):
            raise HTTPException(status_code=403, detail="Недостаточно прав для этого модуля")
        return user
    return check


@app.get("/api/health")
def health(db: Session = Depends(get_db)) -> dict:
    devices = db.scalar(select(func.count()).select_from(Device)) or 0
    waiting = db.scalar(select(func.count()).select_from(Problem).where(Problem.active.is_(True))) or 0
    return {"status": "ok", "devices": devices, "active_problems": waiting, "time": datetime.utcnow()}


@app.get("/api/auth/setup-state")
def setup_state(db: Session = Depends(get_db)) -> dict:
    admin = db.scalar(select(User).where(User.username == "admin"))
    setup_required = admin is None or admin.password_hash is None
    return {"setup_required": setup_required, "bootstrap_token_available": setup_required and read_bootstrap_token() is not None}


@app.post("/api/auth/activate")
def activate(request: ActivationRequest, db: Session = Depends(get_db)) -> dict:
    token = read_bootstrap_token()
    if not token or request.token != token:
        raise HTTPException(status_code=403, detail="Одноразовый токен недействителен или уже использован")
    if db.scalar(select(User).where(User.username == "admin")):
        raise HTTPException(status_code=409, detail="Администратор уже активирован")
    db.add(User(username="admin", password_hash=passwords.hash(request.password), role="admin", must_change_password=False))
    db.commit()
    remove_bootstrap_token()
    return {"ok": True, "message": "Администратор создан. Одноразовый токен удалён."}


@app.post("/api/auth/login")
def login(request: LoginRequest, db: Session = Depends(get_db)) -> dict:
    user = db.scalar(select(User).where(User.username == request.username, User.active.is_(True)))
    if not user or not user.password_hash or not passwords.verify(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Неверные учётные данные")
    return {"ok": True, "access_token": create_session(user.id, user.role), "token_type": "bearer", "user": {"username": user.username, "role": user.role}}


def get_profile(db: Session, user_id: str) -> UserProfile:
    profile = db.scalar(select(UserProfile).where(UserProfile.user_id == user_id))
    if not profile:
        profile = UserProfile(user_id=user_id)
        db.add(profile)
        db.flush()
    return profile


def user_view(user: User, db: Session) -> dict:
    profile = get_profile(db, user.id)
    return {
        "id": user.id, "username": user.username, "role": user.role, "active": user.active, "permissions": user.permissions or {},
        "full_name": profile.full_name, "phone": profile.phone, "organization": profile.organization, "position": profile.position,
        "created_at": user.created_at,
    }


@app.get("/api/auth/me")
def me(db: Session = Depends(get_db), user: User = Depends(current_user)) -> dict:
    return user_view(user, db)


@app.patch("/api/auth/me")
def update_my_profile(payload: ProfileUpdate, db: Session = Depends(get_db), user: User = Depends(current_user)) -> dict:
    changes = payload.model_dump(exclude_unset=True)
    username = changes.get("username")
    if username and username != user.username:
        if db.scalar(select(User).where(User.username == username)):
            raise HTTPException(status_code=409, detail="Пользователь с таким именем уже существует")
        user.username = username
    if changes.get("password"):
        user.password_hash, user.must_change_password = passwords.hash(changes["password"]), False
    profile = get_profile(db, user.id)
    for field in ("full_name", "phone", "organization", "position"):
        if field in changes:
            setattr(profile, field, changes[field] or "")
    db.commit()
    return user_view(user, db)


@app.get("/api/devices")
def list_devices(db: Session = Depends(get_db), _: User = Depends(require_permission("devices:view"))) -> list[dict]:
    return [device_view(row) for row in db.scalars(select(Device).order_by(Device.name)).all()]


@app.post("/api/devices")
def create_device(payload: DeviceCreate, db: Session = Depends(get_db), _: User = Depends(require_permission("devices:edit"))) -> dict:
    if payload.protocol not in ("snmp_v2c", "snmp_v3", "ipmi"):
        raise HTTPException(status_code=422, detail="Поддерживаются только snmp_v2c, snmp_v3 и ipmi")
    try:
        secret = encrypt_secret(payload.credentials)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    device = Device(name=payload.name, address=payload.address, protocol=payload.protocol, credentials_encrypted=secret)
    db.add(device)
    db.commit()
    db.refresh(device)
    return device_view(device)


@app.patch("/api/devices/{device_id}")
def update_device(device_id: str, payload: DeviceUpdate, db: Session = Depends(get_db), _: User = Depends(require_permission("devices:edit"))) -> dict:
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    changes = payload.model_dump(exclude_unset=True)
    protocol = changes.get("protocol", device.protocol)
    if protocol not in ("snmp_v2c", "snmp_v3", "ipmi"):
        raise HTTPException(status_code=422, detail="Поддерживаются только snmp_v2c, snmp_v3 и ipmi")
    for field in ("name", "address", "protocol"):
        if field in changes:
            setattr(device, field, changes[field])
    if changes.get("credentials") is not None:
        try:
            device.credentials_encrypted = encrypt_secret(changes["credentials"])
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
    device.status, device.status_message, device.failure_count = "unknown", "Параметры изменены; выполните проверку связи", 0
    db.commit()
    db.refresh(device)
    return device_view(device)


@app.delete("/api/devices/{device_id}")
def delete_device(device_id: str, db: Session = Depends(get_db), _: User = Depends(require_permission("devices:edit"))) -> dict:
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    # Delete dependent local history explicitly; the portal receives no device credentials.
    db.query(MetricSample).filter(MetricSample.device_id == device_id).delete(synchronize_session=False)
    db.query(Problem).filter(Problem.device_id == device_id).delete(synchronize_session=False)
    db.query(DeviceItem).filter(DeviceItem.device_id == device_id).delete(synchronize_session=False)
    db.query(DeviceItemOverride).filter(DeviceItemOverride.device_id == device_id).delete(synchronize_session=False)
    db.query(DeviceItemDisplay).filter(DeviceItemDisplay.device_id == device_id).delete(synchronize_session=False)
    db.query(DeviceDiscovery).filter(DeviceDiscovery.device_id == device_id).delete(synchronize_session=False)
    db.query(DeviceTemplate).filter(DeviceTemplate.device_id == device_id).delete(synchronize_session=False)
    db.delete(device)
    db.commit()
    return {"ok": True}


@app.post("/api/devices/{device_id}/test")
def check_device(device_id: str, db: Session = Depends(get_db), _: User = Depends(require_permission("devices:view"))) -> dict:
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    result = test_connection(device.protocol, device.address, decrypt_secret(device.credentials_encrypted))
    device.last_poll_at = datetime.utcnow()
    if result.ok:
        device.status, device.status_message, device.failure_count, device.last_seen_at = "available", "Связь подтверждена", 0, datetime.utcnow()
    else:
        device.status, device.status_message, device.failure_count = "unavailable", result.error, device.failure_count + 1
    db.commit()
    return {"ok": result.ok, "value": result.value if result.ok else None, "error": result.error if not result.ok else None, "device": device_view(device)}


@app.get("/api/devices/{device_id}/latest-data")
def latest_data(device_id: str, db: Session = Depends(get_db), _: User = Depends(require_permission("data:view"))) -> list[dict]:
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    return latest_rows_for_device(device, db)


@app.get("/api/devices/{device_id}/metrics")
def list_device_metrics(device_id: str, db: Session = Depends(get_db), _: User = Depends(require_permission("data:view"))) -> list[dict]:
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    history = db.scalars(select(MetricSample).where(MetricSample.device_id == device.id).order_by(MetricSample.collected_at.desc()).limit(5000)).all()
    latest_by_key: dict[str, MetricSample] = {}
    for sample in history:
        latest_by_key.setdefault(sample.item_key, sample)
    hidden_by_key = {
        row.item_key: row.hidden
        for row in db.scalars(select(DeviceItemDisplay).where(DeviceItemDisplay.device_id == device.id)).all()
    }
    rows = []
    # Match the Portal view: count only supported, active items that can be
    # collected, not disabled definitions retained from a catalog import.
    for definition in effective_device_items(db, device):
        item = definition["item"]
        sample = latest_by_key.get(item.key)
        rows.append({
            "key": item.key, "name": item.name, "oid": item.oid, "units": item.units,
            "enabled": definition["enabled"], "source": definition["source"], "template_name": definition["template_name"],
            "raw_value": clean_metric_value(sample.value) if sample and not sample.error else "—",
            "last_value": format_metric_value(sample.value, item.units, item.key, item.name) if sample and not sample.error else "—",
            "last_check_at": sample.collected_at if sample else None,
            "error": sample.error if sample else None,
            "hidden": hidden_by_key.get(item.key, False),
        })
    return rows


@app.patch("/api/devices/{device_id}/metrics")
def set_device_metric(device_id: str, payload: DeviceMetricUpdate, db: Session = Depends(get_db), _: User = Depends(require_permission("devices:edit"))) -> dict:
    if not db.get(Device, device_id):
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    override = db.scalar(select(DeviceItemOverride).where(
        DeviceItemOverride.device_id == device_id, DeviceItemOverride.item_key == payload.item_key
    ))
    if not override:
        override = DeviceItemOverride(device_id=device_id, item_key=payload.item_key, enabled=payload.enabled)
        db.add(override)
    else:
        override.enabled = payload.enabled
    db.commit()
    return {"ok": True, "enabled": payload.enabled}


@app.patch("/api/devices/{device_id}/metric-visibility")
def set_device_metric_visibility(device_id: str, payload: DeviceMetricVisibilityUpdate, db: Session = Depends(get_db), _: User = Depends(require_permission("devices:edit"))) -> dict:
    if not db.get(Device, device_id):
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    display = db.scalar(select(DeviceItemDisplay).where(
        DeviceItemDisplay.device_id == device_id, DeviceItemDisplay.item_key == payload.item_key
    ))
    if not display:
        display = DeviceItemDisplay(device_id=device_id, item_key=payload.item_key, hidden=payload.hidden)
        db.add(display)
    else:
        display.hidden = payload.hidden
    db.add(SyncOutbox(event_type="metric.visibility", payload={
        "device_id": device_id, "item_key": payload.item_key, "hidden": payload.hidden,
    }))
    db.commit()
    return {"ok": True, "hidden": display.hidden}


@app.get("/api/devices/{device_id}/triggers")
def list_device_triggers(device_id: str, db: Session = Depends(get_db), _: User = Depends(require_permission("templates:view"))) -> list[dict]:
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    template_ids = inherited_template_ids(db, [link.template_id for link in device.template_links])
    triggers = db.scalars(select(Trigger).where(Trigger.template_id.in_(template_ids)).order_by(Trigger.name)).all()
    return [{"id": row.id, "name": row.name, "item_key": row.item_key, "severity": row.severity, "enabled": row.enabled,
             "template_name": db.get(Template, row.template_id).name if db.get(Template, row.template_id) else "—"} for row in triggers]


@app.patch("/api/triggers/{trigger_id}")
def set_trigger(trigger_id: str, payload: EnabledUpdate, db: Session = Depends(get_db), _: User = Depends(require_permission("templates:edit"))) -> dict:
    trigger = db.get(Trigger, trigger_id)
    if not trigger:
        raise HTTPException(status_code=404, detail="Триггер не найден")
    trigger.enabled = payload.enabled
    db.commit()
    return {"ok": True, "enabled": trigger.enabled}


@app.get("/api/latest-data")
def all_latest_data(device_id: str | None = None, db: Session = Depends(get_db), _: User = Depends(require_permission("data:view"))) -> list[dict]:
    devices = [db.get(Device, device_id)] if device_id else db.scalars(select(Device).order_by(Device.name)).all()
    if device_id and not devices[0]:
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    return [row for device in devices if device for row in latest_rows_for_device(device, db)]


def template_view(template: Template, db: Session, detailed: bool = False) -> dict:
    rules = db.scalars(select(DiscoveryRule).where(DiscoveryRule.template_id == template.id).order_by(DiscoveryRule.name)).all()
    prototypes = [prototype for rule in rules for prototype in rule.prototypes]
    data = {
        "id": template.id, "name": template.name, "source": template.source, "version": template.version,
        "description": template.description, "enabled": template.enabled, "items": len(template.items),
        "item_prototypes": len(prototypes), "metric_definitions": len(template.items) + len(prototypes),
        "discovery_rules": len(rules), "triggers": len(template.triggers),
    }
    if detailed:
        data["items"] = [{
            "id": item.id, "name": item.name, "key": item.key, "oid": item.oid, "value_type": item.value_type,
            "units": item.units, "interval_seconds": item.interval_seconds, "enabled": item.enabled,
        } for item in sorted(template.items, key=lambda row: row.name.lower())]
        data["triggers"] = [{
            "id": trigger.id, "name": trigger.name, "item_key": trigger.item_key, "operator": trigger.operator,
            "threshold": trigger.threshold, "expression": trigger.expression, "severity": trigger.severity, "enabled": trigger.enabled,
        } for trigger in sorted(template.triggers, key=lambda row: row.name.lower())]
        data["discovery_rules"] = [{
            "id": rule.id, "name": rule.name, "key": rule.key, "snmp_oid": rule.snmp_oid,
            "interval_seconds": rule.interval_seconds, "enabled": rule.enabled,
            "prototypes": [{
                "id": prototype.id, "name": prototype.name, "key": prototype.key, "oid": prototype.snmp_oid,
                "value_type": prototype.value_type, "units": prototype.units, "interval_seconds": prototype.interval_seconds,
                "enabled": prototype.enabled,
            } for prototype in sorted(rule.prototypes, key=lambda row: row.name.lower())],
        } for rule in rules]
    return data


@app.get("/api/templates")
def list_templates(db: Session = Depends(get_db), _: User = Depends(require_permission("templates:view"))) -> list[dict]:
    rows = db.scalars(select(Template).order_by(Template.name)).all()
    return [template_view(row, db) for row in rows]


@app.post("/api/templates")
def create_template(payload: TemplateCreate, db: Session = Depends(get_db), _: User = Depends(require_permission("templates:edit"))) -> dict:
    if db.scalar(select(Template).where(Template.name == payload.name)):
        raise HTTPException(status_code=409, detail="Шаблон с таким именем уже существует")
    template = Template(name=payload.name, description=payload.description, source=payload.source, version=payload.version, enabled=payload.enabled)
    template.items = [TemplateItem(**item.model_dump()) for item in payload.items]
    template.triggers = [Trigger(**trigger.model_dump()) for trigger in payload.triggers]
    db.add(template)
    db.commit()
    return template_view(template, db, detailed=True)


@app.get("/api/templates/{template_id}")
def get_template(template_id: str, db: Session = Depends(get_db), _: User = Depends(require_permission("templates:view"))) -> dict:
    template = db.get(Template, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Шаблон не найден")
    return template_view(template, db, detailed=True)


@app.patch("/api/templates/{template_id}")
def update_template(template_id: str, payload: TemplateUpdate, db: Session = Depends(get_db), _: User = Depends(require_permission("templates:edit"))) -> dict:
    template = db.get(Template, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Шаблон не найден")
    changes = payload.model_dump(exclude_unset=True)
    if "name" in changes and changes["name"] != template.name:
        if db.scalar(select(Template).where(Template.name == changes["name"])):
            raise HTTPException(status_code=409, detail="Шаблон с таким именем уже существует")
    for field, value in changes.items():
        setattr(template, field, value)
    db.commit()
    return template_view(template, db, detailed=True)


@app.delete("/api/templates/{template_id}")
def delete_template(template_id: str, db: Session = Depends(get_db), _: User = Depends(require_permission("templates:edit"))) -> dict:
    template = db.get(Template, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Шаблон не найден")
    from .zabbix_catalog import clear_template_catalog
    clear_template_catalog(template, db)
    db.query(DeviceTemplate).filter(DeviceTemplate.template_id == template_id).delete(synchronize_session=False)
    db.query(TemplateInheritance).filter(
        (TemplateInheritance.template_id == template_id) | (TemplateInheritance.linked_template_id == template_id)
    ).delete(synchronize_session=False)
    db.delete(template)
    db.commit()
    return {"ok": True}


@app.get("/api/templates/{template_id}/export")
def export_template(template_id: str, db: Session = Depends(get_db), _: User = Depends(require_permission("templates:view"))) -> dict:
    template = db.get(Template, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Шаблон не найден")
    return {"format": "acrotix-collector-template", "version": 1, "template": template_view(template, db, detailed=True)}


@app.post("/api/templates/import")
def import_template(payload: TemplateImport, db: Session = Depends(get_db), _: User = Depends(require_permission("templates:edit"))) -> dict:
    data = payload.template
    if db.scalar(select(Template).where(Template.name == data.name)):
        raise HTTPException(status_code=409, detail="Шаблон с таким именем уже существует")
    template = Template(name=data.name, description=data.description, source=data.source or "import", version=data.version, enabled=data.enabled)
    template.items = [TemplateItem(**item.model_dump()) for item in data.items]
    template.triggers = [Trigger(**trigger.model_dump()) for trigger in data.triggers]
    db.add(template)
    db.commit()
    return template_view(template, db, detailed=True)


@app.post("/api/templates/import/zabbix")
def import_zabbix_template(payload: ZabbixTemplateImport, db: Session = Depends(get_db), _: User = Depends(require_permission("templates:edit"))) -> dict:
    from .zabbix_catalog import import_document, yaml
    try:
        raw = yaml.safe_load(payload.content) or {}
        imported, skipped = import_document(raw, db, payload.filename)
    except (ValueError, yaml.YAMLError) as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=f"Некорректный шаблон Zabbix: {exc}") from exc
    return {"imported": imported, "skipped": skipped}


@app.post("/api/templates/import/zabbix/preview")
def preview_zabbix_template(payload: ZabbixTemplateImport, _: User = Depends(require_permission("templates:edit"))) -> dict:
    from .zabbix_catalog import preview_document, yaml
    try:
        return preview_document(yaml.safe_load(payload.content) or {})
    except (ValueError, yaml.YAMLError) as exc:
        raise HTTPException(status_code=422, detail=f"Некорректный шаблон Zabbix: {exc}") from exc


@app.post("/api/templates/{template_id}/items")
def create_template_item(template_id: str, payload: TemplateItemCreate, db: Session = Depends(get_db), _: User = Depends(require_permission("templates:edit"))) -> dict:
    if not db.get(Template, template_id):
        raise HTTPException(status_code=404, detail="Шаблон не найден")
    item = TemplateItem(template_id=template_id, **payload.model_dump())
    db.add(item)
    db.commit()
    return {"id": item.id}


@app.patch("/api/templates/{template_id}/items/{item_id}")
def update_template_item(template_id: str, item_id: str, payload: TemplateItemUpdate, db: Session = Depends(get_db), _: User = Depends(require_permission("templates:edit"))) -> dict:
    item = db.get(TemplateItem, item_id)
    if not item or item.template_id != template_id:
        raise HTTPException(status_code=404, detail="Метрика шаблона не найдена")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(item, field, value)
    db.commit()
    return {"ok": True}


@app.delete("/api/templates/{template_id}/items/{item_id}")
def delete_template_item(template_id: str, item_id: str, db: Session = Depends(get_db), _: User = Depends(require_permission("templates:edit"))) -> dict:
    item = db.get(TemplateItem, item_id)
    if not item or item.template_id != template_id:
        raise HTTPException(status_code=404, detail="Метрика шаблона не найдена")
    db.delete(item)
    db.commit()
    return {"ok": True}


@app.post("/api/templates/{template_id}/triggers")
def create_template_trigger(template_id: str, payload: TemplateTriggerCreate, db: Session = Depends(get_db), _: User = Depends(require_permission("templates:edit"))) -> dict:
    if not db.get(Template, template_id):
        raise HTTPException(status_code=404, detail="Шаблон не найден")
    trigger = Trigger(template_id=template_id, **payload.model_dump())
    db.add(trigger)
    db.commit()
    return {"id": trigger.id}


@app.patch("/api/templates/{template_id}/triggers/{trigger_id}")
def update_template_trigger(template_id: str, trigger_id: str, payload: TemplateTriggerUpdate, db: Session = Depends(get_db), _: User = Depends(require_permission("templates:edit"))) -> dict:
    trigger = db.get(Trigger, trigger_id)
    if not trigger or trigger.template_id != template_id:
        raise HTTPException(status_code=404, detail="Триггер шаблона не найден")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(trigger, field, value)
    db.commit()
    return {"ok": True}


@app.delete("/api/templates/{template_id}/triggers/{trigger_id}")
def delete_template_trigger(template_id: str, trigger_id: str, db: Session = Depends(get_db), _: User = Depends(require_permission("templates:edit"))) -> dict:
    trigger = db.get(Trigger, trigger_id)
    if not trigger or trigger.template_id != template_id:
        raise HTTPException(status_code=404, detail="Триггер шаблона не найден")
    db.delete(trigger)
    db.commit()
    return {"ok": True}


@app.post("/api/devices/{device_id}/templates/{template_id}")
def link_template(device_id: str, template_id: str, db: Session = Depends(get_db), _: User = Depends(require_permission("devices:edit"))) -> dict:
    if not db.get(Device, device_id) or not db.get(Template, template_id):
        raise HTTPException(status_code=404, detail="Устройство или шаблон не найден")
    db.add(DeviceTemplate(device_id=device_id, template_id=template_id))
    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Шаблон уже привязан к устройству") from exc
    return {"ok": True}


@app.get("/api/devices/{device_id}/templates")
def list_device_templates(device_id: str, db: Session = Depends(get_db), _: User = Depends(require_permission("devices:view"))) -> list[dict]:
    if not db.get(Device, device_id):
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    linked_ids = set(db.scalars(select(DeviceTemplate.template_id).where(DeviceTemplate.device_id == device_id)).all())
    templates = db.scalars(select(Template).order_by(Template.name)).all()
    return [{
        "id": template.id, "name": template.name, "source": template.source, "enabled": template.enabled,
        "linked": template.id in linked_ids, "items": len(template.items), "triggers": len(template.triggers),
    } for template in templates]


@app.delete("/api/devices/{device_id}/templates/{template_id}")
def unlink_template(device_id: str, template_id: str, db: Session = Depends(get_db), _: User = Depends(require_permission("devices:edit"))) -> dict:
    link = db.scalar(select(DeviceTemplate).where(DeviceTemplate.device_id == device_id, DeviceTemplate.template_id == template_id))
    if not link:
        raise HTTPException(status_code=404, detail="Шаблон не привязан к этому устройству")
    db.delete(link)
    db.commit()
    return {"ok": True}


@app.get("/api/users")
def list_users(db: Session = Depends(get_db), _: User = Depends(require_permission("users:edit"))) -> list[dict]:
    return [user_view(user, db) for user in db.scalars(select(User).order_by(User.username)).all()]


@app.post("/api/users")
def create_user(payload: UserCreate, db: Session = Depends(get_db), _: User = Depends(require_permission("users:edit"))) -> dict:
    if payload.role not in ("admin", "operator", "viewer"):
        raise HTTPException(status_code=422, detail="Допустимые роли: admin, operator, viewer")
    if db.scalar(select(User).where(User.username == payload.username)):
        raise HTTPException(status_code=409, detail="Пользователь с таким именем уже существует")
    user = User(username=payload.username, password_hash=passwords.hash(payload.password), role=payload.role, permissions=payload.permissions, must_change_password=True)
    db.add(user)
    db.flush()
    db.add(UserProfile(user_id=user.id, full_name=payload.full_name, phone=payload.phone, organization=payload.organization, position=payload.position))
    db.commit()
    return user_view(user, db)


def ensure_admin_remains(db: Session, user: User, role: str, active: bool) -> None:
    if user.role != "admin" or (role == "admin" and active):
        return
    remaining = db.scalar(select(func.count()).select_from(User).where(
        User.role == "admin", User.active.is_(True), User.id != user.id
    )) or 0
    if remaining == 0:
        raise HTTPException(status_code=409, detail="Нельзя удалить, отключить или понизить последнего активного администратора")


@app.patch("/api/users/{user_id}")
def update_user(user_id: str, payload: UserUpdate, db: Session = Depends(get_db), current: User = Depends(require_permission("users:edit"))) -> dict:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    changes = payload.model_dump(exclude_unset=True)
    role, active = changes.get("role", user.role), changes.get("active", user.active)
    if role not in ("admin", "operator", "viewer"):
        raise HTTPException(status_code=422, detail="Допустимые роли: admin, operator, viewer")
    ensure_admin_remains(db, user, role, active)
    username = changes.get("username")
    if username and username != user.username:
        if db.scalar(select(User).where(User.username == username)):
            raise HTTPException(status_code=409, detail="Пользователь с таким именем уже существует")
        user.username = username
    for field in ("role", "active", "permissions"):
        if field in changes:
            setattr(user, field, changes[field])
    if changes.get("password"):
        user.password_hash, user.must_change_password = passwords.hash(changes["password"]), True
    profile = get_profile(db, user.id)
    for field in ("full_name", "phone", "organization", "position"):
        if field in changes:
            setattr(profile, field, changes[field] or "")
    db.commit()
    return user_view(user, db)


@app.delete("/api/users/{user_id}")
def delete_user(user_id: str, db: Session = Depends(get_db), current: User = Depends(require_permission("users:edit"))) -> dict:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if user.id == current.id:
        raise HTTPException(status_code=409, detail="Нельзя удалить собственную учётную запись")
    ensure_admin_remains(db, user, "viewer", False)
    db.query(UserProfile).filter(UserProfile.user_id == user.id).delete(synchronize_session=False)
    db.delete(user)
    db.commit()
    return {"ok": True}


@app.get("/api/problems")
def list_problems(db: Session = Depends(get_db), _: User = Depends(require_permission("problems:view"))) -> list[dict]:
    problems = db.scalars(select(Problem).order_by(Problem.active.desc(), Problem.opened_at.desc()).limit(200)).all()
    return [{
        "id": problem.id,
        "device_name": db.get(Device, problem.device_id).name if db.get(Device, problem.device_id) else "Удалённое устройство",
        "description": problem.description,
        "severity": problem.severity,
        "active": problem.active,
        "opened_at": problem.opened_at,
        "closed_at": problem.closed_at,
    } for problem in problems]


@app.get("/api/sync/status")
def sync_status(db: Session = Depends(get_db), _: User = Depends(require_permission("sync:view"))) -> dict:
    pending = db.scalar(select(func.count()).select_from(SyncOutbox).where(SyncOutbox.sent_at.is_(None))) or 0
    oldest = db.scalar(select(func.min(SyncOutbox.created_at)).where(SyncOutbox.sent_at.is_(None)))
    connection = db.get(PortalConnection, "primary")
    configured = configured_portal(db)
    has_ca_certificate = has_portal_api_key = False
    if connection and connection.sync_token_encrypted:
        try:
            secret = decrypt_secret(connection.sync_token_encrypted)
            has_ca_certificate = bool(secret.get("ca_certificate"))
            has_portal_api_key = bool(secret.get("portal_api_key"))
        except ValueError:
            pass
    return {
        "configured": bool(configured),
        "enabled": bool(connection and connection.enabled),
        "portal_url": connection.portal_url if connection and connection.portal_url else None,
        "collector_id": connection.collector_id if connection and connection.collector_id else None,
        "collector_name": connection.collector_name if connection else settings.collector_name,
        "has_token": bool(connection and connection.sync_token_encrypted),
        "has_portal_api_key": has_portal_api_key,
        "has_ca_certificate": has_ca_certificate,
        "last_attempt_at": connection.last_attempt_at if connection else None,
        "last_connected_at": connection.last_connected_at if connection else None,
        "last_error": connection.last_error if connection else None,
        "pending_events": pending,
        "oldest_pending_at": oldest,
    }


@app.put("/api/sync/connection")
def save_portal_connection(payload: PortalConnectionUpdate, db: Session = Depends(get_db), _: User = Depends(require_permission("sync:edit"))) -> dict:
    portal_url = payload.portal_url.strip().rstrip("/")
    if not portal_url.startswith(("https://", "http://")):
        raise HTTPException(status_code=422, detail="Укажите URL портала, начинающийся с http:// или https://")
    connection = db.get(PortalConnection, "primary")
    if not connection:
        connection = PortalConnection(id="primary")
        db.add(connection)
    previous_secret: dict = {}
    if connection.sync_token_encrypted:
        try:
            previous_secret = decrypt_secret(connection.sync_token_encrypted)
        except ValueError:
            pass
    token = (payload.sync_token or "").strip() or previous_secret.get("token", "")
    if not token:
        raise HTTPException(status_code=422, detail="Введите токен подключения, выданный порталом")
    portal_api_key = (payload.portal_api_key or "").strip() or previous_secret.get("portal_api_key", "")
    if not portal_api_key:
        raise HTTPException(status_code=422, detail="Введите публичный API-ключ портала из параметров коллектора")
    certificate = (payload.ca_certificate or "").strip()
    if certificate and "-----BEGIN CERTIFICATE-----" not in certificate:
        raise HTTPException(status_code=422, detail="Загруженный файл не похож на PEM-сертификат")
    if certificate:
        try:
            ssl.create_default_context(cadata=certificate)
        except ssl.SSLError as exc:
            raise HTTPException(status_code=422, detail=f"Некорректный сертификат: {exc}") from exc
    elif payload.clear_ca_certificate:
        certificate = ""
    else:
        certificate = previous_secret.get("ca_certificate", "")
    connection.sync_token_encrypted = encrypt_secret({"token": token, "portal_api_key": portal_api_key, "ca_certificate": certificate})
    connection.portal_url = portal_url
    connection.collector_id = payload.collector_id.strip()
    connection.collector_name = payload.collector_name.strip()
    connection.enabled = payload.enabled
    connection.last_error = None
    db.commit()
    return sync_status(db, _)


@app.post("/api/sync/connection/test")
def test_portal_connection(db: Session = Depends(get_db), _: User = Depends(require_permission("sync:edit"))) -> dict:
    ok, error = send_portal_heartbeat(db)
    if not ok:
        raise HTTPException(status_code=502, detail=error)
    return {"ok": True, "message": "Портал подтвердил подключение"}


@app.delete("/api/sync/connection")
def delete_portal_connection(db: Session = Depends(get_db), _: User = Depends(require_permission("sync:edit"))) -> dict:
    connection = db.get(PortalConnection, "primary")
    if connection:
        # Preserve the audit row but remove every secret and destination field.
        connection.portal_url = ""
        connection.collector_id = ""
        connection.sync_token_encrypted = ""
        connection.enabled = False
        connection.last_error = None
        connection.last_attempt_at = None
        connection.last_connected_at = None
        db.commit()
    return {"ok": True}


app.mount("/", StaticFiles(directory="app/static", html=True), name="ui")

