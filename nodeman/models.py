import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Self

from cryptography.x509 import load_pem_x509_certificates
from pydantic import AnyHttpUrl, BaseModel, Field, StringConstraints, field_validator
from pydantic.types import AwareDatetime

from .db_models import TapirCertificate, TapirNode
from .jose import PrivateJwk, PrivateSymmetric, PublicJwk, PublicJwks, public_key_factory
from .settings import MqttUrl

MAX_REQUEST_AGE = 300

DOMAIN_NAME_RE = re.compile(r"^(?=.{1,255}$)(?!-)[A-Za-z0-9\-]{1,63}(\.[A-Za-z0-9\-]{1,63})*\.?(?<!-)$")

NodeTag = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9/\-\.]{1,100}$")]


class PublicKeyFormat(StrEnum):
    PEM = "application/x-pem-file"
    JWK = "application/jwk+json"

    @classmethod
    def from_accept(cls, accept: str | None) -> Self:
        if accept is None or cls.JWK in accept or "application/json" in accept or "*/*" in accept:
            return cls.JWK
        elif cls.PEM in accept:
            return cls.PEM
        raise ValueError(f"Unsupported format. Acceptable formats: {[f.value for f in cls]} or */*")


class NodeCreateRequest(BaseModel):
    name: str | None = Field(
        title="Node name",
        description="Optional hostname for the node. Must be a valid domain name.",
        json_schema_extra={"format": "hostname"},
        default=None,
    )
    tags: list[NodeTag] | None = Field(
        title="Node tags",
        description="Optional list of tags for categorizing the node. Each tag must be alphanumeric with optional /, -, or . characters.",
        max_length=100,
        default=None,
    )


class NodeRequest(BaseModel):
    timestamp: AwareDatetime = Field(title="Timestamp")
    x509_csr: str = Field(title="X.509 Client Certificate Bundle")

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, ts: datetime):
        if (td := (datetime.now(tz=UTC) - ts).total_seconds()) > MAX_REQUEST_AGE:
            raise ValueError(f"Request too old or in the future, delta={td}")


class EnrollmentRequest(NodeRequest):
    public_key: PublicJwk = Field(title="Public data key")


class RenewalRequest(NodeRequest):
    pass


class NodeInformation(BaseModel):
    name: str = Field(title="Node name")
    public_key: PublicJwk | None = Field(title="Public key")
    activated: AwareDatetime | None = Field(title="Activated")
    tags: list[str] | None = Field(title="Node tags")

    @classmethod
    def from_db_model(cls, node: TapirNode):
        return cls(
            name=node.name,
            public_key=public_key_factory(node.public_key) if node.public_key else None,
            activated=node.activated,
            tags=node.tags,
        )


class NodeCollection(BaseModel):
    nodes: list[NodeInformation] = Field(title="Nodes")


class NodeBootstrapInformation(BaseModel):
    name: str = Field(title="Node name")
    key: PrivateSymmetric | PrivateJwk = Field(title="Enrollment JWK")
    nodeman_url: AnyHttpUrl | None = Field("Nodeman base URL")


class NodeCertificate(BaseModel):
    x509_certificate: str = Field(title="X.509 Client Certificate Bundle")
    x509_ca_certificate: str | None = Field(title="X.509 CA Certificate Bundle")
    x509_certificate_serial_number: str
    x509_certificate_not_valid_after: datetime

    @field_validator("x509_certificate", "x509_ca_certificate")
    @classmethod
    def validate_pem_bundle(cls, v: str | None):
        if v is not None:
            _ = load_pem_x509_certificates(v.encode())
        return v

    @classmethod
    def from_db_model(cls, certificate: TapirCertificate):
        return cls(
            x509_certificate=certificate.certificate,
            x509_ca_certificate=None,
            x509_certificate_serial_number=str(certificate.serial),
            x509_certificate_not_valid_after=certificate.not_valid_after,
        )


class NodeConfiguration(BaseModel):
    name: str = Field(title="Node name", examples=["node.example.com"])
    mqtt_broker: MqttUrl = Field(title="MQTT Broker", examples=["mqtts://broker.example.com"])
    mqtt_topics: dict[str, str] = Field(
        title="MQTT Topics",
        default={},
        examples=[{"edm": "configuration/node.example.com/edm", "pop": "configuration/node.example.com/pop"}],
    )
    trusted_jwks: PublicJwks = Field(title="Trusted JWKS")
    nodeman_url: AnyHttpUrl | None = Field("Nodeman base URL")
    aggrec_url: AnyHttpUrl | None = Field("Aggregate receiver base URL")


class NodeEnrollmentResult(NodeConfiguration, NodeCertificate):
    pass
