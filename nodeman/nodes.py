import json
import logging
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS, InvalidJWSSignature
from opentelemetry import metrics, trace
from pydantic import BaseModel, Field

from .db_models import TapirNode, TapirNodeSecret
from .utils import verify_x509_csr

logger = logging.getLogger(__name__)

tracer = trace.get_tracer("nodeman.tracer")
meter = metrics.get_meter("nodeman.meter")

router = APIRouter()


class PublicJwk(BaseModel):
    kty: str
    crv: str
    x: str


class NodeInformation(BaseModel):
    name: str = Field(title="Node name")
    public_key: PublicJwk | None = Field(title="Public key")

    @classmethod
    def from_db_model(cls, node: TapirNode):
        return cls(name=node.name, public_key=PublicJwk(**node.public_key))


class NodeConfiguration(BaseModel):
    name: str = Field(title="Node name")
    mqtt_broker: str = Field(title="MQTT Broker")
    mqtt_topics: dict[str, str] = Field("MQTT Topics")
    trusted_keys: list[dict[str, str]] = Field(title="Trusted keys")
    x509_certificate: str = Field(title="X.509 Certificate")
    x509_ca_bundle: str = Field(title="X.509 CA Certificate Bundle")
    x509_ca_url: str = Field(title="X.509 CA URL")


class NodeBootstrapInformation(BaseModel):
    name: str = Field(title="Node name")
    secret: str = Field(title="Enrollment secret")


@router.post(
    "/api/v1/node",
    status_code=201,
    responses={
        201: {"model": NodeBootstrapInformation},
    },
    tags=["backend"],
)
async def create_node(request: Request) -> NodeBootstrapInformation:
    secret = JWK.generate(kty="oct", size=256).k
    node = TapirNode.create_next_node(domain=request.app.settings.nodes.domain)
    logging.debug("Created node %s", node.name)
    node_secret = TapirNodeSecret(name=node.name, secret=secret).save()
    return NodeBootstrapInformation(name=node.name, secret=node_secret.secret)


@router.get(
    "/api/v1/node/{name}",
    responses={
        200: {"model": NodeInformation},
        404: {},
    },
    tags=["backend"],
)
def get_node_information(name: str) -> NodeInformation:
    """Get node information"""

    node: TapirNode | None
    node = TapirNode.objects(name=name, deleted=None).first()
    if node is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    return NodeInformation.from_db_model(node)


@router.get(
    "/api/v1/node/{name}/public_key",
    responses={
        200: {
            "content": {
                "application/json": {
                    "title": "JWK",
                    "schema": PublicJwk.model_json_schema(),
                },
                "application/pem": {"title": "PEM", "schema": {"type": "string"}},
            },
        },
        404: {},
    },
    tags=["client"],
)
async def get_node_public_key(
    name: str,
    accept: Annotated[
        str | None,
        Header(description="Accept"),
    ],
    request: Request,
) -> Response:
    """Get public key (JWK/PEM) for node"""

    node: TapirNode | None
    node = TapirNode.objects(name=name, deleted=None).first()
    if node is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    if "application/pem" in accept:
        pem = JWK(**node.public_key).export_to_pem().decode()
        return Response(content=pem, media_type="application/pem")

    return Response(content=json.dumps(node.public_key), media_type="application/json")


@router.delete(
    "/api/v1/node/{name}",
    responses={
        204: {"description": "Node deleted", "content": None},
        404: {},
    },
    tags=["backend"],
)
def delete_node(
    name: str,
    request: Request,
) -> Response:
    """Delete node"""

    node: TapirNode | None
    node = TapirNode.objects(name=name).first()
    if node is None or node.deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    node.deleted = datetime.now(tz=timezone.utc)
    node.save()

    if node_secret := TapirNodeSecret.objects(name=name).first():
        node_secret.delete()

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/api/v1/node/{name}/enroll",
    responses={
        201: {"model": NodeConfiguration},
    },
    tags=["client"],
)
async def enroll_node(
    name: str,
    request: Request,
) -> NodeConfiguration:
    """Enroll new node"""

    node: TapirNode | None
    node = TapirNode.objects(name=name, deleted=None).first()
    if node is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    if node.activated:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Node already enrolled")

    node_secret: TapirNodeSecret | None
    node_secret = TapirNodeSecret.objects(name=name).first()
    if node_secret is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Node enrollment failed")
    hmac_key = JWK(kty="oct", k=node_secret.secret)

    body = await request.body()

    jws = JWS()
    jws.deserialize(json.loads(body.decode()))

    # Verify signature by HMAC key
    try:
        jws.verify(key=hmac_key)
        logger.debug("Valid HMAC signature from %s", name)
    except InvalidJWSSignature as exc:
        logger.warning("Invalid HMAC signature from %s", name)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid HMAC signature") from exc

    message = json.loads(jws.payload)

    public_key = JWK(**message["public_key"])

    # Verify signature by public key
    try:
        jws.verify(key=public_key)
        logger.debug("Valid proof-of-possession signature from %s", name)
    except InvalidJWSSignature as exc:
        logger.warning("Invalid proof-of-possession signature from %s", name)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid proof-of-possession signature") from exc
    node.public_key = public_key.export(as_dict=True)

    # Verify X.509 CSR
    x509_csr_pem = message["x509_csr"]
    verify_x509_csr(name=name, csr_pem=x509_csr_pem)

    # TODO: issue certificate via StepCA
    x509_certificate = "__CERTIFICATE_PLACEHOLDER_"
    x509_ca_bundle = "__CA_BUNDLE_PLACEHOLDER__"

    node.activated = datetime.now(tz=timezone.utc)
    node.save()
    node_secret.delete()

    x509_ca_url = str(request.app.settings.step_ca.server)

    return NodeConfiguration(
        name=name,
        mqtt_broker=str(request.app.settings.nodes.mqtt_broker),
        mqtt_topics=request.app.settings.nodes.mqtt_topics,
        trusted_keys=request.app.trusted_keys,
        x509_certificate=x509_certificate,
        x509_ca_bundle=x509_ca_bundle,
        x509_ca_url=x509_ca_url,
    )
