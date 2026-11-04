import uuid
from datetime import datetime
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base


def uid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(String(30), default="viewer")
    permissions: Mapped[dict] = mapped_column(JSON, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(160), unique=True)
    address: Mapped[str] = mapped_column(String(255), index=True)
    protocol: Mapped[str] = mapped_column(String(20))  # snmp_v2c, snmp_v3, ipmi
    credentials_encrypted: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(32), default="unknown")
    status_message: Mapped[str] = mapped_column(Text, default="Опрос ещё не выполнялся")
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_poll_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    template_links: Mapped[list["DeviceTemplate"]] = relationship(back_populates="device", cascade="all, delete-orphan")


class Template(Base):
    __tablename__ = "templates"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    source: Mapped[str] = mapped_column(String(40), default="custom")
    version: Mapped[str] = mapped_column(String(50), default="1.0")
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    items: Mapped[list["TemplateItem"]] = relationship(back_populates="template", cascade="all, delete-orphan")
    triggers: Mapped[list["Trigger"]] = relationship(back_populates="template", cascade="all, delete-orphan")


class TemplateInheritance(Base):
    """A Zabbix template may inherit items and discovery rules from templates it links."""
    __tablename__ = "template_inheritance"
    __table_args__ = (UniqueConstraint("template_id", "linked_template_id", name="uq_template_inheritance"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    template_id: Mapped[str] = mapped_column(ForeignKey("templates.id"), index=True)
    linked_template_id: Mapped[str] = mapped_column(ForeignKey("templates.id"), index=True)


class ValueMap(Base):
    """Zabbix value maps, for example ifOperStatus: 1 -> up."""
    __tablename__ = "value_maps"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    mappings: Mapped[dict] = mapped_column(JSON, default=dict)


class ItemProcessing(Base):
    """Processing and value map belonging to an imported item definition."""
    __tablename__ = "item_processing"
    __table_args__ = (UniqueConstraint("source_kind", "source_id", name="uq_item_processing_source"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    source_kind: Mapped[str] = mapped_column(String(30), index=True)
    source_id: Mapped[str] = mapped_column(String(36), index=True)
    pipeline: Mapped[list] = mapped_column(JSON, default=list)
    value_map_name: Mapped[str] = mapped_column(String(255), default="")


class ItemRuntimeState(Base):
    """The last raw counter is kept separately to calculate rates safely."""
    __tablename__ = "item_runtime_state"
    __table_args__ = (UniqueConstraint("device_id", "item_key", name="uq_item_runtime_state"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    item_key: Mapped[str] = mapped_column(String(255), index=True)
    last_raw_value: Mapped[str] = mapped_column(Text, default="")
    last_collected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class TemplateItem(Base):
    __tablename__ = "template_items"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    template_id: Mapped[str] = mapped_column(ForeignKey("templates.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    key: Mapped[str] = mapped_column(String(200))
    oid: Mapped[str] = mapped_column(String(512))
    value_type: Mapped[str] = mapped_column(String(30), default="numeric")
    units: Mapped[str] = mapped_column(String(30), default="")
    interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    template: Mapped[Template] = relationship(back_populates="items")


class Trigger(Base):
    __tablename__ = "triggers"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    template_id: Mapped[str] = mapped_column(ForeignKey("templates.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    item_key: Mapped[str] = mapped_column(String(200))
    operator: Mapped[str] = mapped_column(String(5), default=">")
    threshold: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(20), default="warning")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    template: Mapped[Template] = relationship(back_populates="triggers")


class DiscoveryRule(Base):
    __tablename__ = "discovery_rules"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    template_id: Mapped[str] = mapped_column(ForeignKey("templates.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    key: Mapped[str] = mapped_column(String(255))
    snmp_oid: Mapped[str] = mapped_column(Text)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=300)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    prototypes: Mapped[list["ItemPrototype"]] = relationship(back_populates="rule", cascade="all, delete-orphan")


class ItemPrototype(Base):
    __tablename__ = "item_prototypes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    discovery_rule_id: Mapped[str] = mapped_column(ForeignKey("discovery_rules.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    key: Mapped[str] = mapped_column(String(255))
    snmp_oid: Mapped[str] = mapped_column(Text)
    value_type: Mapped[str] = mapped_column(String(30), default="numeric")
    units: Mapped[str] = mapped_column(String(30), default="")
    interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    rule: Mapped[DiscoveryRule] = relationship(back_populates="prototypes")


class DeviceDiscovery(Base):
    __tablename__ = "device_discoveries"
    __table_args__ = (UniqueConstraint("device_id", "discovery_rule_id", "entity_index", name="uq_device_discovery_entity"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    discovery_rule_id: Mapped[str] = mapped_column(ForeignKey("discovery_rules.id"), index=True)
    entity_index: Mapped[str] = mapped_column(String(255))
    macros: Mapped[dict] = mapped_column(JSON, default=dict)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class DeviceItem(Base):
    __tablename__ = "device_items"
    __table_args__ = (UniqueConstraint("device_id", "key", name="uq_device_item_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    discovery_id: Mapped[str | None] = mapped_column(ForeignKey("device_discoveries.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    key: Mapped[str] = mapped_column(String(255))
    oid: Mapped[str] = mapped_column(Text)
    value_type: Mapped[str] = mapped_column(String(30), default="numeric")
    units: Mapped[str] = mapped_column(String(30), default="")
    interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class DeviceTemplate(Base):
    __tablename__ = "device_templates"
    __table_args__ = (UniqueConstraint("device_id", "template_id", name="uq_device_template"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"))
    template_id: Mapped[str] = mapped_column(ForeignKey("templates.id"))
    device: Mapped[Device] = relationship(back_populates="template_links")


class MetricSample(Base):
    __tablename__ = "metric_samples"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    item_key: Mapped[str] = mapped_column(String(200), index=True)
    value: Mapped[str] = mapped_column(Text)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class Problem(Base):
    __tablename__ = "problems"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    trigger_id: Mapped[str] = mapped_column(ForeignKey("triggers.id"))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    opened_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class SyncOutbox(Base):
    __tablename__ = "sync_outbox"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    event_type: Mapped[str] = mapped_column(String(80))
    payload: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

