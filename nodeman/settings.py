import hashlib
import os
from contextlib import suppress
from datetime import timedelta
from ipaddress import IPv4Address, IPv4Network, IPv6Network
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
from pydantic.networks import IPvAnyAddress, IPvAnyNetwork
from pydantic_core import Url
from pydantic_settings import BaseSettings, EnvSettingsSource, PydanticBaseSettingsSource, TomlConfigSettingsSource

from dnstapir.opentelemetry import OtlpSettings

ENV_PREFIX = "NODEMAN_"

MqttUrl = Annotated[
    Url,
    UrlConstraints(allowed_schemes=["mqtt", "mqtts"], host_required=True),
]

MongodbUrl = Annotated[
    Url,
    UrlConstraints(allowed_schemes=["mongodb", "mongodb+srv", "mongomock"], host_required=True),
]


class HttpSettings(BaseModel):
    trusted_hosts: list[IPvAnyAddress | IPvAnyNetwork] = Field(
        default=[
            IPv4Address("127.0.0.1"),
        ]
    )
    healthcheck_hosts: list[IPvAnyNetwork] = Field(
        default=[
            IPv4Network("127.0.0.1/32"),
            IPv4Network("10.0.0.0/8"),
            IPv4Network("172.16.0.0/12"),
            IPv4Network("192.168.0.0/16"),
            IPv6Network("fe80::/10"),
        ]
    )


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

    default_validity: timedelta = Field(default=timedelta(days=90), ge=timedelta(seconds=0))
    min_validity: timedelta | None = Field(default=None, ge=timedelta(seconds=0))
    max_validity: timedelta | None = Field(default=None, ge=timedelta(seconds=0))
    time_skew: timedelta = Field(default=timedelta(seconds=0), ge=timedelta(seconds=0))

    # for backward compatibility
    validity_days: int | None = Field(default=None, ge=0)
    min_validity_seconds: int | None = Field(default=None, ge=0)
    max_validity_seconds: int | None = Field(default=None, ge=0)
    time_skew_seconds: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _validate_validity(self) -> Self:
        """Validate and normalize validity settings"""

        if self.validity_days is not None:
            self.default_validity = timedelta(days=self.validity_days)
        if self.min_validity_seconds is not None:
            self.min_validity = timedelta(seconds=self.min_validity_seconds)
        if self.max_validity_seconds is not None:
            self.max_validity = timedelta(seconds=self.max_validity_seconds)
        if self.time_skew_seconds is not None:
            self.time_skew = timedelta(seconds=self.time_skew_seconds)

        if self.min_validity is not None and self.max_validity is not None and self.min_validity > self.max_validity:
            raise ValueError("min validity must be <= max validity")

        if self.min_validity is not None and self.default_validity < self.min_validity:
            raise ValueError("default validity shorter than min validity")

        if self.max_validity is not None and self.default_validity > self.max_validity:
            raise ValueError("default validity larger than max validity")

        return self


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
    node_public_key_ttl: int = Field(
        default=3600,
        gt=0,
        le=86400,
        description="Node public key cache TTL in seconds",
    )
    deterministic_node_names: bool = Field(default=True)


class EnrollmentSettings(BaseModel):
    kty: str = Field(default="oct")
    alg: str = Field(default="HS256")
    crv: str | None = Field(default=None)
    size: int | None = Field(default=None)
    ttl: int | None = Field(default=None, gt=0, le=31536000)  # TTL in seconds, max 1 year

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
                if not self.crv:
                    raise ValueError("Curve required")
                if self.size:
                    raise ValueError(f"Size not supported for {self.kty}")
                return {"kty": self.kty, "alg": self.alg, "crv": self.crv}
            case "AKP":
                if not self.alg:
                    raise ValueError("Algorithm required")
                if self.size:
                    raise ValueError(f"Size not supported for {self.kty}")
                return {"kty": self.kty, "alg": self.alg}
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

    def get_combined_hash(self, password: str) -> bytes:
        """Return hash of username, password hash and plaintext password"""
        h = hashlib.sha256()
        h.update(self.username.encode())
        h.update(self.password_hash.encode())
        h.update(password.encode())
        return h.digest()

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
        return (
            EnvSettingsSource(
                settings_cls,
                env_prefix=ENV_PREFIX,
                env_nested_delimiter="__",
                env_ignore_empty=True,
                case_sensitive=False,
            ),
            TomlConfigSettingsSource(
                settings_cls,
                toml_file=os.environ.get("NODEMAN_CONFIG", "nodeman.toml"),
            ),
        )
