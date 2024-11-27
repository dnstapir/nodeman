from datetime import datetime

from pydantic import BaseModel, Field

from .db_models import TapirNode


class PublicJwk(BaseModel):
    kty: str
    crv: str
    x: str


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
    mqtt_broker: str = Field(title="MQTT Broker")
    mqtt_topics: dict[str, str] = Field(title="MQTT Topics", default={})
    trusted_keys: list[dict[str, str]] = Field(title="Trusted keys")
    x509_certificate: str = Field(title="X.509 Certificate")
    x509_ca_bundle: str = Field(title="X.509 CA Certificate Bundle")
    x509_ca_url: str = Field(title="X.509 CA URL")


class NodeBootstrapInformation(BaseModel):
    name: str = Field(title="Node name")
    secret: str = Field(title="Enrollment secret")
