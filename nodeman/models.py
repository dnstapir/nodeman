from datetime import datetime

from cryptography.x509 import load_pem_x509_certificates
from pydantic import AnyHttpUrl, BaseModel, Field, field_validator

from .db_models import TapirNode
from .settings import MqttUrl


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


class NodeConfiguration(BaseModel):
    name: str = Field(title="Node name")
    mqtt_broker: MqttUrl = Field(title="MQTT Broker")
    mqtt_topics: dict[str, str] = Field(title="MQTT Topics", default={})
    trusted_keys: list[PublicJwk] = Field(title="Trusted keys")
    x509_certificate: str = Field(title="X.509 Client Certificate Bundle")
    x509_ca_certificate: str = Field(title="X.509 CA Certificate Bundle")
    x509_ca_url: AnyHttpUrl = Field(title="X.509 CA URL")

    @field_validator("x509_certificate", "x509_ca_certificate")
    @classmethod
    def validate_pem_bundle(cls, v: str):
        _ = load_pem_x509_certificates(v.encode())
        return v


class NodeBootstrapInformation(BaseModel):
    name: str = Field(title="Node name")
    secret: str = Field(title="Enrollment secret")
