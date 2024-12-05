from datetime import datetime, timezone
from enum import StrEnum
from typing import Self

from cryptography.x509 import load_pem_x509_certificates
from pydantic import BaseModel, Field, field_validator

from .db_models import TapirNode
from .settings import MqttUrl

MAX_REQUEST_AGE = 300


class PublicKeyFormat(StrEnum):
    PEM = "application/x-pem-file"
    JWK = "application/jwk+json"

    @classmethod
    def from_accept(cls, accept: str | None) -> Self:
        if accept is None or cls.JWK in accept or "application/json" in accept:
            return cls.JWK
        elif cls.PEM in accept:
            return cls.PEM
        raise ValueError(f"Unsupported format. Acceptable formats: {[f.value for f in cls]}")


class PublicJwk(BaseModel):
    kty: str

    # for EC and ED
    crv: str | None = None
    x: str | None = None

    # for EC
    y: str | None = None

    # for RSA
    n: str | None = None
    e: str | None = None


class NodeRequest(BaseModel):
    timestamp: datetime = Field(title="Timestamp")
    x509_csr: str = Field(title="X.509 Client Certificate Bundle")

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, ts: datetime):
        if (td := (datetime.now(tz=timezone.utc) - ts).total_seconds()) > MAX_REQUEST_AGE:
            raise ValueError(f"Request too old or in the future, delta={td}")


class EnrollmentRequest(NodeRequest):
    public_key: PublicJwk = Field(title="Public data key")


class RewnewalRequest(NodeRequest):
    pass


class NodeInformation(BaseModel):
    name: str = Field(title="Node name")
    public_key: PublicJwk | None = Field(title="Public key")
    activated: datetime | None = Field(title="Activated")

    @classmethod
    def from_db_model(cls, node: TapirNode):
        return cls(
            name=node.name,
            public_key=PublicJwk(**node.public_key) if node.public_key else None,
            activated=node.activated,
        )


class NodeCollection(BaseModel):
    nodes: list[NodeInformation] = Field(title="Nodes")


class NodeBootstrapInformation(BaseModel):
    name: str = Field(title="Node name")
    secret: str = Field(title="Enrollment secret")


class NodeCertificate(BaseModel):
    x509_certificate: str = Field(title="X.509 Client Certificate Bundle")
    x509_ca_certificate: str = Field(title="X.509 CA Certificate Bundle")
    x509_certificate_serial_number: int | None = Field(default=None, exclude=True)

    @field_validator("x509_certificate", "x509_ca_certificate")
    @classmethod
    def validate_pem_bundle(cls, v: str):
        _ = load_pem_x509_certificates(v.encode())
        return v


class NodeConfiguration(NodeCertificate):
    name: str = Field(title="Node name", examples=["node.example.com"])
    mqtt_broker: MqttUrl = Field(title="MQTT Broker", examples=["mqtts://broker.example.com"])
    mqtt_topics: dict[str, str] = Field(
        title="MQTT Topics",
        default={},
        examples=[{"edm": "configuration/node.example.com/edm", "pop": "configuration/node.example.com/pop"}],
    )
    trusted_keys: list[PublicJwk] = Field(title="Trusted keys")
