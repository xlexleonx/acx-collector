from pydantic import BaseModel, Field, field_validator


def _check_bcrypt_password(value: str) -> str:
    # bcrypt accepts at most 72 UTF-8 bytes. Reject explicitly instead of truncating.
    if len(value.encode("utf-8")) > 72:
        raise ValueError("Пароль не должен превышать 72 байта в UTF-8")
    return value


class ActivationRequest(BaseModel):
    token: str = Field(min_length=20)
    password: str = Field(min_length=12)

    _password_limit = field_validator("password")(_check_bcrypt_password)


class LoginRequest(BaseModel):
    username: str
    password: str

    _password_limit = field_validator("password")(_check_bcrypt_password)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=12)
    role: str = "viewer"
    permissions: dict = {}

    _password_limit = field_validator("password")(_check_bcrypt_password)


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

