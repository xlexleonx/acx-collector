from pydantic import BaseModel, Field, field_validator


def _check_bcrypt_password(value: str | None) -> str | None:
    # bcrypt accepts at most 72 UTF-8 bytes. Reject explicitly instead of truncating.
    if value is None:
        return value
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
    full_name: str = Field(default="", max_length=200)
    phone: str = Field(default="", max_length=80)
    organization: str = Field(default="", max_length=200)
    position: str = Field(default="", max_length=200)

    _password_limit = field_validator("password")(_check_bcrypt_password)


class UserUpdate(BaseModel):
    username: str | None = Field(default=None, min_length=3, max_length=80)
    password: str | None = Field(default=None, min_length=12)
    role: str | None = None
    active: bool | None = None
    permissions: dict | None = None
    full_name: str | None = Field(default=None, max_length=200)
    phone: str | None = Field(default=None, max_length=80)
    organization: str | None = Field(default=None, max_length=200)
    position: str | None = Field(default=None, max_length=200)

    _password_limit = field_validator("password")(_check_bcrypt_password)


class ProfileUpdate(BaseModel):
    username: str | None = Field(default=None, min_length=3, max_length=80)
    password: str | None = Field(default=None, min_length=12)
    full_name: str | None = Field(default=None, max_length=200)
    phone: str | None = Field(default=None, max_length=80)
    organization: str | None = Field(default=None, max_length=200)
    position: str | None = Field(default=None, max_length=200)

    _password_limit = field_validator("password")(_check_bcrypt_password)


class EnabledUpdate(BaseModel):
    enabled: bool


class DeviceMetricUpdate(EnabledUpdate):
    item_key: str = Field(min_length=1, max_length=255)


class DeviceMetricVisibilityUpdate(BaseModel):
    item_key: str = Field(min_length=1, max_length=255)
    hidden: bool


class DeviceCreate(BaseModel):
    name: str
    address: str
    protocol: str
    credentials: dict


class DeviceUpdate(BaseModel):
    name: str | None = None
    address: str | None = None
    protocol: str | None = None
    # Omit credentials to retain encrypted connection details already stored.
    credentials: dict | None = None


class TemplateItemCreate(BaseModel):
    name: str
    key: str
    oid: str
    value_type: str = "numeric"
    units: str = ""
    interval_seconds: int = Field(default=60, ge=10)
    enabled: bool = True


class TemplateItemUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    key: str | None = Field(default=None, max_length=200)
    oid: str | None = Field(default=None, max_length=512)
    value_type: str | None = Field(default=None, max_length=30)
    units: str | None = Field(default=None, max_length=30)
    interval_seconds: int | None = Field(default=None, ge=10)
    enabled: bool | None = None


class TemplateTriggerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    item_key: str = Field(default="", max_length=200)
    operator: str = Field(default=">", max_length=5)
    threshold: float = 0
    expression: str = ""
    severity: str = Field(default="warning", max_length=20)
    enabled: bool = True


class TemplateTriggerUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    item_key: str | None = Field(default=None, max_length=200)
    operator: str | None = Field(default=None, max_length=5)
    threshold: float | None = None
    expression: str | None = None
    severity: str | None = Field(default=None, max_length=20)
    enabled: bool | None = None


class TemplateCreate(BaseModel):
    name: str
    description: str = ""
    source: str = "custom"
    version: str = "1.0"
    enabled: bool = True
    items: list[TemplateItemCreate] = []
    triggers: list[TemplateTriggerCreate] = []


class TemplateUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    description: str | None = None
    version: str | None = Field(default=None, max_length=50)
    enabled: bool | None = None


class TemplateImport(BaseModel):
    template: TemplateCreate

