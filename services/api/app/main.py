from datetime import datetime
from fastapi import Depends, FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .collector import test_connection
from .database import Base, engine, get_db
from .config import settings
from .models import Device, DeviceTemplate, MetricSample, Problem, SyncOutbox, Template, TemplateItem, User
from .schemas import ActivationRequest, DeviceCreate, DeviceUpdate, LoginRequest, TemplateCreate, UserCreate
from .security import allows, create_session, decrypt_secret, encrypt_secret, passwords, read_bootstrap_token, read_session, remove_bootstrap_token
from .seed import seed_builtin_templates

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
    samples = db.scalars(select(MetricSample).where(MetricSample.device_id == device_id).order_by(MetricSample.collected_at.desc()).limit(200)).all()
    return [{"item_key": s.item_key, "value": s.value, "collected_at": s.collected_at, "error": s.error} for s in samples]


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
    users = db.scalars(select(User).order_by(User.username)).all()
    return [{"id": user.id, "username": user.username, "role": user.role, "active": user.active, "permissions": user.permissions or {}} for user in users]


@app.post("/api/users")
def create_user(payload: UserCreate, db: Session = Depends(get_db), _: User = Depends(require_permission("users:edit"))) -> dict:
    if payload.role not in ("admin", "operator", "viewer"):
        raise HTTPException(status_code=422, detail="Допустимые роли: admin, operator, viewer")
    if db.scalar(select(User).where(User.username == payload.username)):
        raise HTTPException(status_code=409, detail="Пользователь с таким именем уже существует")
    user = User(username=payload.username, password_hash=passwords.hash(payload.password), role=payload.role, permissions=payload.permissions, must_change_password=True)
    db.add(user)
    db.commit()
    return {"id": user.id, "username": user.username, "role": user.role}


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

