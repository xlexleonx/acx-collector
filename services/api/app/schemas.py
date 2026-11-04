from pydantic import BaseModel, Field


class ActivationRequest(BaseModel):
    token: str = Field(min_length=20)
    password: str = Field(min_length=12)


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=12)
    role: str = "viewer"
    permissions: dict = {}


class DeviceCreate(BaseModel):
    name: str
    address: str
    protocol: str
    credentials: dict


class TemplateItemCreate(BaseModel):
    name: str
    key: str
    oid: str
    value_type: str = "numeric"
    units: str = ""
    interval_seconds: int = Field(default=60, ge=10)


class TemplateCreate(BaseModel):
    name: str
    description: str = ""
    source: str = "custom"
    version: str = "1.0"
    items: list[TemplateItemCreate] = []

