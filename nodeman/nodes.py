import json
import logging
from datetime import datetime, timezone
from typing import Annotated

from cryptography import x509
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS, InvalidJWSSignature
from opentelemetry import metrics, trace
from pydantic_core import ValidationError

from .authn import get_current_username
from .db_models import TapirNode, TapirNodeEnrollment
from .jose import PublicEC, PublicOKP, PublicRSA
from .models import (
    EnrollmentRequest,
    NodeBootstrapInformation,
    NodeCertificate,
    NodeCollection,
    NodeConfiguration,
    NodeInformation,
    PublicKeyFormat,
    RenewalRequest,
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
    response_model_exclude_none=True,
)
async def create_node(
    request: Request, username: Annotated[str, Depends(get_current_username)], name: str | None = None
) -> NodeBootstrapInformation:
    """Create node"""

    node_enrollment_key = JWK.generate(kty="oct", size=256, alg="HS256")
    domain = request.app.settings.nodes.domain

    if name is None:
        node = TapirNode.create_next_node(domain=request.app.settings.nodes.domain)
    elif name.endswith(f".{domain}"):
        logging.debug("Explicit node name %s requested", name, extra={"nodename": name})
        node = TapirNode(name=name, domain=domain).save()
    else:
        logging.warning("Explicit node name %s not acceptable", name, extra={"nodename": name})
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid node name")

    TapirNodeEnrollment(
        name=node.name,
        key=node_enrollment_key.export(as_dict=True, private_key=node_enrollment_key.kty == "oct"),
    ).save()

    nodes_created.add(1, {"creator": username})

    logging.info("%s created node %s", username, node.name, extra={"username": username, "nodename": node.name})

    return NodeBootstrapInformation(name=node.name, key=node_enrollment_key.export(as_dict=True, private_key=True))


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
                    "schema": {
                        "anyOf": [
                            PublicRSA.model_json_schema(),
                            PublicEC.model_json_schema(),
                            PublicOKP.model_json_schema(),
                        ]
                    },
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
                    jwk_dict = {**node.public_key, "kid": name}
                    content = json.dumps(jwk_dict)
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

    if node_enrollment := TapirNodeEnrollment.objects(name=name).first():
        node_enrollment.delete()

    logging.info("%s deleted node %s", username, node.name, extra={"username": username, "nodename": node.name})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/api/v1/node/{name}/enroll",
    responses={
        status.HTTP_200_OK: {"model": NodeConfiguration},
        status.HTTP_404_NOT_FOUND: {},
    },
    tags=["client"],
    response_model_exclude_none=True,
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

    node_enrollment: TapirNodeEnrollment | None
    node_enrollment = TapirNodeEnrollment.objects(name=name).first()
    if node_enrollment is None:
        logging.info("Node %s enrollment failed", name, extra={"nodename": name})
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Node enrollment failed")

    enrollment_key = JWK(**node_enrollment.key)

    body = await request.body()

    with tracer.start_as_current_span("verify_jws"):
        jws = JWS()
        jws.deserialize(body.decode())

        # Verify signature by enrollment key
        try:
            jws.verify(key=enrollment_key)
            logger.debug("Valid enrollment signature from %s", name, extra={"nodename": name})
        except InvalidJWSSignature as exc:
            logger.warning("Invalid enrollment signature from %s", name, extra={"nodename": name})
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid enrollment signature") from exc

        try:
            message = EnrollmentRequest.model_validate_json(jws.payload)
        except ValidationError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST) from exc

        public_key = JWK(**message.public_key.model_dump(exclude_none=True))

        # Verify signature by public data key
        try:
            jws.verify(key=public_key)
            logger.debug("Valid data signature from %s", name, extra={"nodename": name})
        except InvalidJWSSignature as exc:
            logger.warning("Invalid data signature from %s", name, extra={"nodename": name})
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid data signature") from exc
        node.public_key = public_key.export(as_dict=True, private_key=False)

    # Verify X.509 CSR and issue certificate
    x509_csr = x509.load_pem_x509_csr(message.x509_csr.encode())
    with tracer.start_as_current_span("issue_certificate"):
        node_certificate = process_csr_request(csr=x509_csr, name=name, request=request)

    node.activated = datetime.now(tz=timezone.utc)
    node.save()
    node_enrollment.delete()

    nodes_enrolled.add(1)

    return NodeConfiguration(
        name=name,
        mqtt_broker=request.app.settings.nodes.mqtt_broker,
        mqtt_topics=request.app.settings.nodes.mqtt_topics,
        trusted_jwks=request.app.trusted_jwks,
        x509_certificate=node_certificate.x509_certificate,
        x509_ca_certificate=node_certificate.x509_ca_certificate,
        x509_certificate_serial_number=node_certificate.x509_certificate_serial_number,
        x509_certificate_not_valid_after=node_certificate.x509_certificate_not_valid_after,
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
        logging.debug("Renewal attempt for non-activated node %s", name, extra={"nodename": name})
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Node not activated")

    span = trace.get_current_span()
    span.set_attribute("node.name", name)

    body = await request.body()

    with tracer.start_as_current_span("verify_jws"):
        jws = JWS()
        jws.deserialize(body.decode())

        public_key = JWK(**node.public_key)

        # Verify signature by public data key
        try:
            jws.verify(key=public_key)
            logger.debug("Valid data signature from %s", name, extra={"nodename": name})
        except InvalidJWSSignature as exc:
            logger.warning("Invalid data signature from %s", name, extra={"nodename": name})
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid data signature") from exc
        try:
            message = RenewalRequest.model_validate_json(jws.payload)
        except ValidationError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST) from exc

    # Verify X.509 CSR and issue certificate
    x509_csr = x509.load_pem_x509_csr(message.x509_csr.encode())
    with tracer.start_as_current_span("issue_certificate"):
        res = process_csr_request(csr=x509_csr, name=name, request=request)

    nodes_renewed.add(1)

    return res
