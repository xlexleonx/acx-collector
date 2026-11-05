from datetime import datetime
import re
from fastapi import Depends, FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .collector import test_connection
from .database import Base, engine, get_db
from .config import settings
from .models import Device, DeviceDiscovery, DeviceItem, DeviceItemOverride, DeviceTemplate, MetricSample, Problem, SyncOutbox, Template, TemplateItem, Trigger, User
from .schemas import ActivationRequest, DeviceCreate, DeviceMetricUpdate, DeviceUpdate, EnabledUpdate, LoginRequest, ProfileUpdate, TemplateCreate, UserCreate, UserUpdate
from .security import allows, create_session, decrypt_secret, encrypt_secret, passwords, read_bootstrap_token, read_session, remove_bootstrap_token
from .seed import seed_builtin_templates
from .template_graph import inherited_template_ids
from .device_items import effective_device_items

app = FastAPI(title="ACROTIX Collector API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)
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
        value = clean_metric_value(latest.value) if latest and not latest.error else "—"
        if value != "—" and item.units and item.units not in value:
            value = f"{value} {item.units}"
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


def user_view(user: User) -> dict:
    return {"id": user.id, "username": user.username, "role": user.role, "active": user.active, "permissions": user.permissions or {}}


@app.get("/api/auth/me")
def me(user: User = Depends(current_user)) -> dict:
    return user_view(user)


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
    db.commit()
    return user_view(user)


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
    rows = []
    for definition in effective_device_items(db, device, include_disabled=True):
        item = definition["item"]
        sample = latest_by_key.get(item.key)
        rows.append({
            "key": item.key, "name": item.name, "oid": item.oid, "units": item.units,
            "enabled": definition["enabled"], "source": definition["source"], "template_name": definition["template_name"],
            "last_value": clean_metric_value(sample.value) if sample and not sample.error else "—",
            "last_check_at": sample.collected_at if sample else None,
            "error": sample.error if sample else None,
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


@app.get("/api/templates")
def list_templates(db: Session = Depends(get_db), _: User = Depends(require_permission("templates:view"))) -> list[dict]:
    rows = db.scalars(select(Template).order_by(Template.name)).all()
    return [{"id": r.id, "name": r.name, "source": r.source, "version": r.version, "enabled": r.enabled, "items": len(r.items), "triggers": len(r.triggers)} for r in rows]


@app.post("/api/templates")
def create_template(payload: TemplateCreate, db: Session = Depends(get_db), _: User = Depends(require_permission("templates:edit"))) -> dict:
    template = Template(name=payload.name, description=payload.description, source=payload.source, version=payload.version)
    template.items = [TemplateItem(**item.model_dump()) for item in payload.items]
    db.add(template)
    db.commit()
    return {"id": template.id, "name": template.name, "items": len(template.items)}


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
    return [{"id": template.id, "name": template.name, "source": template.source, "enabled": template.enabled, "linked": template.id in linked_ids} for template in templates]


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
    return [user_view(user) for user in db.scalars(select(User).order_by(User.username)).all()]


@app.post("/api/users")
def create_user(payload: UserCreate, db: Session = Depends(get_db), _: User = Depends(require_permission("users:edit"))) -> dict:
    if payload.role not in ("admin", "operator", "viewer"):
        raise HTTPException(status_code=422, detail="Допустимые роли: admin, operator, viewer")
    if db.scalar(select(User).where(User.username == payload.username)):
        raise HTTPException(status_code=409, detail="Пользователь с таким именем уже существует")
    user = User(username=payload.username, password_hash=passwords.hash(payload.password), role=payload.role, permissions=payload.permissions, must_change_password=True)
    db.add(user)
    db.commit()
    return user_view(user)


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
    db.commit()
    return user_view(user)


@app.delete("/api/users/{user_id}")
def delete_user(user_id: str, db: Session = Depends(get_db), current: User = Depends(require_permission("users:edit"))) -> dict:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if user.id == current.id:
        raise HTTPException(status_code=409, detail="Нельзя удалить собственную учётную запись")
    ensure_admin_remains(db, user, "viewer", False)
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
    return {
        "configured": bool(settings.portal_url and settings.portal_installation_id and settings.portal_sync_token),
        "portal_url": settings.portal_url or None,
        "pending_events": pending,
        "oldest_pending_at": oldest,
    }


app.mount("/", StaticFiles(directory="app/static", html=True), name="ui")

