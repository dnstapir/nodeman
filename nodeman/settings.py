from contextlib import suppress
from typing import Annotated, Self

from argon2 import PasswordHasher
from jwcrypto.jwk import JWK
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    DirectoryPath,
    Field,
    FilePath,
    StringConstraints,
    UrlConstraints,
    model_validator,
)
from pydantic.networks import IPv4Address, IPvAnyAddress, IPvAnyNetwork
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


class HttpSettings(BaseModel):
    trusted_hosts: list[IPvAnyAddress | IPvAnyNetwork] = Field(default=[IPv4Address("127.0.0.1")])


class MongoDB(BaseModel):
    server: MongodbUrl | None = Field(default="mongodb://localhost/keys")
    timeout: int = Field(default=5)


class StepSettings(BaseModel):
    ca_url: AnyHttpUrl
    ca_server_verify: bool = True
    ca_fingerprint: str | None = None
    ca_fingerprint_file: FilePath | None = None
    provisioner_name: str
    provisioner_private_key: FilePath


class InternalCaSettings(BaseModel):
    issuer_ca_certificate: FilePath
    issuer_ca_private_key: FilePath
    root_ca_certificate: FilePath | None = None
    validity_days: int = Field(default=90)


class NodesSettings(BaseModel):
    nodeman_url: AnyHttpUrl | None = Field(default=None)
    aggrec_url: AnyHttpUrl | None = Field(default=None)
    domain: str = Field(default="example.com")
    trusted_jwks: FilePath | None = Field(default=None)
    mqtt_broker: MqttUrl = Field(default="mqtt://localhost")
    mqtt_topics: dict[str, str] = Field(default={})
    configuration_ttl: int = Field(
        default=300,
        gt=0,
        le=86400,
        description="Configuration cache TTL in seconds",
    )


class EnrollmentSettings(BaseModel):
    kty: str = Field(default="oct")
    alg: str = Field(default="HS256")
    crv: str | None = Field(default=None)
    size: int | None = Field(default=None)

    @model_validator(mode="after")
    def validate_jwk_parameters(self) -> Self:
        kwargs = self.generate_kwargs()
        try:
            JWK.generate(**kwargs)
        except Exception as exc:
            raise ValueError("Invalid enrollment key parameters") from exc
        return self

    def generate_kwargs(self) -> dict[str, str | int]:
        match self.kty:
            case "oct":
                if self.crv:
                    raise ValueError(f"Cannot specify curve for {self.kty}")
                return {"kty": self.kty, "alg": self.alg, "size": self.size or 256}
            case "RSA":
                if self.crv:
                    raise ValueError(f"Cannot specify curve for {self.kty}")
                return {"kty": self.kty, "alg": self.alg, "size": self.size or 2048}
            case "EC" | "OKP":
                if self.crv is None:
                    raise ValueError("Unknown curve")
                if self.size:
                    raise ValueError(f"size not supported for {self.kty}")
                return {"kty": self.kty, "alg": self.alg, "crv": self.crv}
            case _:
                raise ValueError("Unsupported key type")


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
    otlp: OtlpSettings | None = None
    users: list[User] = Field(default=[])

    step: StepSettings | None = None
    internal_ca: InternalCaSettings | None = None

    nodes: NodesSettings = Field(default=NodesSettings())
    enrollment: EnrollmentSettings = Field(default=EnrollmentSettings())

    legacy_nodes_directory: DirectoryPath | None = None

    http: HttpSettings = Field(default=HttpSettings())

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
