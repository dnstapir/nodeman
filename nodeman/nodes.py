import json
import logging
from datetime import datetime, timezone
from typing import Annotated

from cryptography import x509
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS, InvalidJWSSignature
from opentelemetry import metrics, trace

from .authn import get_current_username
from .db_models import TapirNode, TapirNodeSecret
from .models import (
    NodeBootstrapInformation,
    NodeCertificate,
    NodeCollection,
    NodeConfiguration,
    NodeInformation,
    PublicJwk,
    PublicKeyFormat,
)
from .x509 import process_csr_request

logger = logging.getLogger(__name__)

tracer = trace.get_tracer("nodeman.tracer")
meter = metrics.get_meter("nodeman.meter")

nodes_created = meter.create_counter("nodes.created", description="The number of nodes created")
nodes_enrolled = meter.create_counter("nodes.enrolled", description="The number of nodes certificate enrolled")
nodes_renewed = meter.create_counter("nodes.renewed", description="The number of node certificate renewed")
nodes_public_key_queries = meter.create_counter(
    "nodes.public_key_queries", description="The number of node public keys queried"
)

router = APIRouter()


def find_node(name: str) -> TapirNode:
    """Find node, raise exception if not found"""
    if node := TapirNode.objects(name=name, deleted=None).first():
        return node
    logging.debug("Node %s not found", name, extra={"nodename": name})
    raise HTTPException(status.HTTP_404_NOT_FOUND)


@router.post(
    "/api/v1/node",
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_201_CREATED: {"model": NodeBootstrapInformation},
    },
    tags=["backend"],
)
async def create_node(
    request: Request, username: Annotated[str, Depends(get_current_username)], name: str | None = None
) -> NodeBootstrapInformation:
    secret = JWK.generate(kty="oct", size=256).k
    domain = request.app.settings.nodes.domain

    if name is None:
        node = TapirNode.create_next_node(domain=request.app.settings.nodes.domain)
    elif name.endswith(f".{domain}"):
        logging.debug("Explicit node name %s requested", name, extra={"nodename": name})
        node = TapirNode(name=name, domain=domain).save()
    else:
        logging.warning("Explicit node name %s not acceptable", name, extra={"nodename": name})
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid node name")

    node_secret = TapirNodeSecret(name=node.name, secret=secret).save()

    nodes_created.add(1, {"creator": username})

    logging.info("%s created node %s", username, node.name, extra={"username": username, "nodename": node.name})
    return NodeBootstrapInformation(name=node.name, secret=node_secret.secret)


@router.get(
    "/api/v1/node/{name}",
    responses={
        status.HTTP_200_OK: {"model": NodeInformation},
        status.HTTP_404_NOT_FOUND: {},
    },
    tags=["backend"],
)
def get_node_information(name: str, username: Annotated[str, Depends(get_current_username)]) -> NodeInformation:
    """Get node information"""

    node = find_node(name)
    logging.info("%s queried for node %s", username, node.name, extra={"username": username, "nodename": name})
    return NodeInformation.from_db_model(node)


@router.get(
    "/api/v1/nodes",
    responses={
        status.HTTP_200_OK: {"model": NodeCollection},
    },
    tags=["backend"],
)
def get_all_nodes(username: Annotated[str, Depends(get_current_username)]) -> NodeCollection:
    """Get all nodes"""
    logging.info("%s queried for all nodes", username, extra={"username": username})
    return NodeCollection(nodes=[NodeInformation.from_db_model(node) for node in TapirNode.objects(deleted=None)])


@router.get(
    "/api/v1/node/{name}/public_key",
    responses={
        status.HTTP_200_OK: {
            "content": {
                PublicKeyFormat.JWK: {
                    "title": "JWK",
                    "schema": PublicJwk.model_json_schema(),
                },
                PublicKeyFormat.PEM: {"title": "PEM", "schema": {"type": "string"}},
            },
        },
        status.HTTP_404_NOT_FOUND: {},
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

    node = find_node(name)

    span = trace.get_current_span()
    span.set_attribute("node.name", name)

    try:
        match media_type := PublicKeyFormat.from_accept(accept):
            case PublicKeyFormat.PEM:
                with tracer.start_as_current_span("get_public_key_pem"):
                    content = JWK(**node.public_key).export_to_pem().decode()
            case PublicKeyFormat.JWK:
                with tracer.start_as_current_span("get_public_key_jwk"):
                    content = json.dumps(node.public_key)
    except ValueError as exc:
        raise HTTPException(status.HTTP_406_NOT_ACCEPTABLE) from exc

    nodes_public_key_queries.add(1, {"media_type": str(media_type)})
    return Response(content=content, media_type=media_type)


@router.delete(
    "/api/v1/node/{name}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        status.HTTP_204_NO_CONTENT: {"description": "Node deleted", "content": None},
        status.HTTP_404_NOT_FOUND: {},
    },
    tags=["backend"],
)
def delete_node(name: str, username: Annotated[str, Depends(get_current_username)]) -> Response:
    """Delete node"""

    node = find_node(name)

    if node.deleted:
        logging.info("Node %s deleted", name, extra={"nodename": name})
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    node.deleted = datetime.now(tz=timezone.utc)
    node.save()

    if node_secret := TapirNodeSecret.objects(name=name).first():
        node_secret.delete()

    logging.info("%s deleted node %s", username, node.name, extra={"username": username, "nodename": node.name})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/api/v1/node/{name}/enroll",
    responses={
        status.HTTP_200_OK: {"model": NodeConfiguration},
        status.HTTP_404_NOT_FOUND: {},
    },
    tags=["client"],
)
async def enroll_node(
    name: str,
    request: Request,
) -> NodeConfiguration:
    """Enroll new node"""

    node = find_node(name)

    if node.activated:
        logging.info("Node %s already enrolled", name, extra={"nodename": name})
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Node already enrolled")

    span = trace.get_current_span()
    span.set_attribute("node.name", name)

    node_secret: TapirNodeSecret | None
    node_secret = TapirNodeSecret.objects(name=name).first()
    if node_secret is None:
        logging.info("Node %s enrollment failed", name, extra={"nodename": name})
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Node enrollment failed")
    hmac_key = JWK(kty="oct", k=node_secret.secret)

    body = await request.body()

    with tracer.start_as_current_span("verify_jws"):
        jws = JWS()
        jws.deserialize(json.loads(body.decode()))

        # Verify signature by HMAC key
        try:
            jws.verify(key=hmac_key)
            logger.debug("Valid HMAC signature from %s", name, extra={"nodename": name})
        except InvalidJWSSignature as exc:
            logger.warning("Invalid HMAC signature from %s", name, extra={"nodename": name})
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid HMAC signature") from exc

        message = json.loads(jws.payload)
        public_key = JWK(**message["public_key"])

        # Verify signature by public data key
        try:
            jws.verify(key=public_key)
            logger.debug("Valid proof-of-possession signature from %s", name, extra={"nodename": name})
        except InvalidJWSSignature as exc:
            logger.warning("Invalid proof-of-possession signature from %s", name, extra={"nodename": name})
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid proof-of-possession signature") from exc
        node.public_key = public_key.export(as_dict=True, private_key=False)

    # Verify X.509 CSR and issue certificate
    x509_csr = x509.load_pem_x509_csr(message["x509_csr"].encode())
    with tracer.start_as_current_span("issue_certificate"):
        node_certificate = process_csr_request(csr=x509_csr, name=name, request=request)

    node.activated = datetime.now(tz=timezone.utc)
    node.save()
    node_secret.delete()

    nodes_enrolled.add(1)

    return NodeConfiguration(
        name=name,
        mqtt_broker=request.app.settings.nodes.mqtt_broker,
        mqtt_topics=request.app.settings.nodes.mqtt_topics,
        trusted_keys=request.app.trusted_keys,
        x509_certificate=node_certificate.x509_certificate,
        x509_ca_certificate=node_certificate.x509_ca_certificate,
        x509_certificate_serial_number=node_certificate.x509_certificate_serial_number,
    )


@router.post(
    "/api/v1/node/{name}/renew",
    responses={
        status.HTTP_200_OK: {"model": NodeCertificate},
        status.HTTP_404_NOT_FOUND: {},
    },
    tags=["client"],
)
async def renew_node(
    name: str,
    request: Request,
) -> NodeCertificate:
    """Renew node certificate"""

    node = find_node(name)

    if not node.activated:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Node not activated")

    span = trace.get_current_span()
    span.set_attribute("node.name", name)

    body = await request.body()

    with tracer.start_as_current_span("verify_jws"):
        jws = JWS()
        jws.deserialize(json.loads(body.decode()))
        public_key = JWK(**node.public_key)
        # Verify signature by public data key
        try:
            jws.verify(key=public_key)
            logger.debug("Valid proof-of-possession signature from %s", name, extra={"nodename": name})
        except InvalidJWSSignature as exc:
            logger.warning("Invalid proof-of-possession signature from %s", name, extra={"nodename": name})
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid proof-of-possession signature") from exc
        message = json.loads(jws.payload)

    # Verify X.509 CSR and issue certificate
    x509_csr = x509.load_pem_x509_csr(message["x509_csr"].encode())
    with tracer.start_as_current_span("issue_certificate"):
        res = process_csr_request(csr=x509_csr, name=name, request=request)

    nodes_renewed.add(1)

    return res
