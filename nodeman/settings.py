from contextlib import suppress
from typing import Annotated, Self

from argon2 import PasswordHasher
from pydantic import AnyHttpUrl, BaseModel, Field, FilePath, StringConstraints, UrlConstraints, model_validator
from pydantic_core import Url
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict, TomlConfigSettingsSource

from dnstapir.opentelemetry import OtlpSettings

MqttUrl = Annotated[
    Url,
    UrlConstraints(allowed_schemes=["mqtt", "mqtts"], default_port=1883, host_required=True),
]

MongodbUrl = Annotated[
    Url,
    UrlConstraints(allowed_schemes=["mongodb", "mongomock"], default_port=27017, host_required=True),
]


class MongoDB(BaseModel):
    server: MongodbUrl | None = Field(default="mongodb://localhost/keys")
    timeout: int = Field(default=5)


class StepSettings(BaseModel):
    ca_url: AnyHttpUrl
    ca_fingerprint: str | None = None
    ca_fingerprint_file: FilePath | None = None
    provisioner_name: str
    provisioner_private_key: FilePath


class VaultSettings(BaseModel):
    server: AnyHttpUrl | None = Field(default="http://localhost:8200")
    mount_point: str | None = None


class NodesSettings(BaseModel):
    domain: str = Field(default="example.com")
    trusted_keys: FilePath | None = Field(default=None)
    mqtt_broker: MqttUrl = Field(default="mqtt://localhost")
    mqtt_topics: dict[str, str] = Field(default={})


class User(BaseModel):
    username: Annotated[str, StringConstraints(min_length=2, max_length=32, pattern=r"^[a-zA-Z0-9_-]+$")]
    password_hash: str

    def verify_password(self, password: str) -> bool:
        ph = PasswordHasher()
        with suppress(Exception):
            return ph.verify(self.password_hash, password)
        return False

    @classmethod
    def create(cls, username: str, password: str) -> Self:
        ph = PasswordHasher()
        return cls(username=username, password_hash=ph.hash(password))


class Settings(BaseSettings):
    mongodb: MongoDB = Field(default=MongoDB())
    step: StepSettings | None = None
    # vault: VaultSettings = Field(default=VaultSettings())
    otlp: OtlpSettings | None = None
    users: list[User] = Field(default=[])

    nodes: NodesSettings = Field(default=NodesSettings())

    model_config = SettingsConfigDict(toml_file="nodeman.toml")

    @model_validator(mode="after")
    def validate_unique_usernames(self) -> Self:
        username_set = set()
        for user in self.users:
            if user.username in username_set:
                raise ValueError(f"Duplicate username found: {user.username}")
            username_set.add(user.username)
        return self

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (TomlConfigSettingsSource(settings_cls),)
