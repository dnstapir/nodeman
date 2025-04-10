import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from bson import ObjectId
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS, InvalidJWSSignature
from mongoengine import Q
from opentelemetry import metrics, trace
from pydantic_core import ValidationError

from dnstapir.key_resolver import KEY_ID_VALIDATOR

from .authn import get_current_username
from .db_models import TapirCertificate, TapirNode, TapirNodeEnrollment
from .jose import PublicEC, PublicOKP, PublicRSA
from .models import (
    DOMAIN_NAME_RE,
    EnrollmentRequest,
    HealthcheckResult,
    NodeBootstrapInformation,
    NodeCertificate,
    NodeCollection,
    NodeConfiguration,
    NodeCreateRequest,
    NodeEnrollmentResult,
    NodeInformation,
    PublicKeyFormat,
    RenewalRequest,
)

logger = logging.getLogger(__name__)

tracer = trace.get_tracer("nodeman.tracer")
meter = metrics.get_meter("nodeman.meter")

nodes_created = meter.create_counter("nodes.created", description="The number of nodes created")
nodes_enrolled = meter.create_counter("nodes.enrolled", description="The number of nodes certificate enrolled")
nodes_renewed = meter.create_counter("nodes.renewed", description="The number of node certificate renewed")
nodes_public_key_queries = meter.create_counter(
    "nodes.public_key_queries", description="The number of node public keys queried"
)
node_configurations_requested = meter.create_counter(
    "nodes.configurations", description="The number of node configurations requested"
)

router = APIRouter()


def find_node(name: str) -> TapirNode:
    """Find node, raise exception if not found"""
    if node := TapirNode.objects(name=name, deleted=None).first():
        return node
    logging.debug("Node %s not found", name, extra={"nodename": name})
    raise HTTPException(status.HTTP_404_NOT_FOUND)


def find_legacy_node(name: str, legacy_nodes_directory: Path) -> TapirNode:
    """Return node from fallback nodes directory"""
    try:
        if not KEY_ID_VALIDATOR.match(name):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid node name")
        with open(legacy_nodes_directory / f"{name}.pem", "rb") as fp:
            public_key = JWK.from_pem(fp.read())
        logging.info("Returning legacy node %s", name)
        return TapirNode(name=name, public_key=public_key.export(as_dict=True, private_key=False))
    except FileNotFoundError:
        pass
    raise HTTPException(status.HTTP_404_NOT_FOUND)


def create_node_configuration(name: str, request: Request) -> NodeConfiguration:
    return NodeConfiguration(
        name=name,
        mqtt_broker=request.app.settings.nodes.mqtt_broker,
        mqtt_topics=request.app.settings.nodes.mqtt_topics,
        trusted_jwks=request.app.trusted_jwks,
        nodeman_url=request.app.settings.nodes.nodeman_url,
        aggrec_url=request.app.settings.nodes.aggrec_url,
    )


def process_csr_request(request: Request, csr: x509.CertificateSigningRequest, name: str) -> NodeCertificate:
    """Verify CSR and issue certificate"""

    try:
        ca_response = request.app.ca_client.sign_csr(csr, name)
    except Exception as exc:
        logger.error("Failed to process CSR for %s: %s", name, str(exc), exc_info=exc)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error issuing certificate") from exc

    x509_certificate_pem = "".join(
        [certificate.public_bytes(serialization.Encoding.PEM).decode() for certificate in ca_response.cert_chain]
    )
    x509_ca_certificate_pem = ca_response.ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    x509_certificate: x509.Certificate = ca_response.cert_chain[0]
    x509_certificate_serial_number = x509_certificate.serial_number
    x509_not_valid_after_utc = x509_certificate.not_valid_after_utc.isoformat()

    TapirCertificate.from_x509_certificate(name=name, x509_certificate=x509_certificate).save()

    logger.info(
        "Issued certificate for name=%s serial=%s not_valid_after=%s",
        name,
        x509_certificate_serial_number,
        x509_not_valid_after_utc,
        extra={
            "nodename": name,
            "x509_certificate_serial_number": x509_certificate_serial_number,
            "not_valid_after": x509_not_valid_after_utc,
        },
    )

    return NodeCertificate(
        x509_certificate=x509_certificate_pem,
        x509_ca_certificate=x509_ca_certificate_pem,
        x509_certificate_serial_number=str(x509_certificate_serial_number),
        x509_certificate_not_valid_after=x509_certificate.not_valid_after_utc,
    )


@router.get(
    "/api/v1/healthcheck",
    responses={
        status.HTTP_200_OK: {"model": HealthcheckResult},
    },
    tags=["backend"],
)
def healthcheck(
    request: Request,
) -> HealthcheckResult:
    """Perform healthcheck with database and CA access"""

    node_count = len(TapirNode.objects() or [])
    cert_count = len(TapirCertificate.objects() or [])

    return HealthcheckResult(
        status="OK",
        node_count=node_count,
        cert_count=cert_count,
        ca_fingerprint=request.app.ca_client.ca_fingerprint,
    )


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
    username: Annotated[str, Depends(get_current_username)],
    request: Request,
    create_request: NodeCreateRequest | None = None,
) -> NodeBootstrapInformation:
    """
    Create a new node with optional name and tags.

    Args:
        username: The authenticated user creating the node.
        request: The FastAPI request object.
        create_request: Optional request containing:
            - name: Optional hostname (must be a valid domain name)
            - tags: Optional list of tags (alphanumeric with /, -, or .)
                    Maximum length: 100 characters per tag

    Returns:
        NodeBootstrapInformation: Information needed to bootstrap the node.

    Raises:
        HTTPException: If the node name is invalid.
    """

    name = create_request.name if create_request and create_request.name else None
    tags = list(set(create_request.tags)) if create_request and create_request.tags else None

    domain = request.app.settings.nodes.domain

    node_enrollment_id = ObjectId()
    node_enrollment_key = request.app.generate_enrollment_key(kid=str(node_enrollment_id))

    if name is None:
        node = TapirNode.create_next_node(domain=domain)
    elif name.endswith(f".{domain}") and DOMAIN_NAME_RE.match(name):
        logging.debug("Explicit node name %s requested", name, extra={"nodename": name})
        node = TapirNode(name=name, domain=domain).save()
    else:
        logging.warning("Explicit node name %s not acceptable", name, extra={"nodename": name})
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid node name")

    node.tags = tags
    node.save()

    TapirNodeEnrollment(
        id=node_enrollment_id,
        name=node.name,
        key=node_enrollment_key.export(as_dict=True, private_key=node_enrollment_key.kty == "oct"),
    ).save()

    nodes_created.add(1, {"creator": username})

    logging.info("%s created node %s", username, node.name, extra={"username": username, "nodename": node.name})

    return NodeBootstrapInformation(
        name=node.name,
        key=node_enrollment_key.export(as_dict=True, private_key=True),
        nodeman_url=request.app.settings.nodes.nodeman_url,
    )


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
    response_model_exclude_none=False,
)
def get_all_nodes(username: Annotated[str, Depends(get_current_username)], tags: str | None = None) -> NodeCollection:
    """Get all nodes"""
    query = Q(deleted=None)
    if tags:
        query_tags = sorted(set(tags.split(",")))
        logging.info("%s queried for nodes with tags %s", username, query_tags, extra={"username": username})
        query &= Q(tags__all=sorted(set(query_tags)))
    else:
        logging.info("%s queried for all nodes", username, extra={"username": username})
    return NodeCollection(nodes=[NodeInformation.from_db_model(node) for node in TapirNode.objects(query)])


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

    try:
        node = find_node(name)
    except HTTPException as exc:
        if exc.status_code == 404 and request.app.settings.legacy_nodes_directory:
            node = find_legacy_node(name, request.app.settings.legacy_nodes_directory)
        else:
            raise exc

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

    node.deleted = datetime.now(tz=UTC)
    node.save()

    if node_enrollment := TapirNodeEnrollment.objects(name=name).first():
        node_enrollment.delete()

    logging.info("%s deleted node %s", username, node.name, extra={"username": username, "nodename": node.name})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/api/v1/node/{name}/enroll",
    responses={
        status.HTTP_200_OK: {"model": NodeEnrollmentResult},
        status.HTTP_404_NOT_FOUND: {},
    },
    tags=["client"],
    response_model_exclude_none=True,
)
async def enroll_node(
    name: str,
    request: Request,
) -> NodeEnrollmentResult:
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
            logger.info(
                "Valid enrollment signature from %s",
                name,
                extra={"nodename": name, "enrollment_key_id": enrollment_key.key_id},
            )
        except InvalidJWSSignature as exc:
            logger.warning(
                "Invalid enrollment signature from %s",
                name,
                extra={"nodename": name, "enrollment_key_id": enrollment_key.key_id},
            )

            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid enrollment signature") from exc

        try:
            message = EnrollmentRequest.model_validate_json(jws.payload)
        except ValidationError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST) from exc

        public_key = JWK(**message.public_key.model_dump(exclude_none=True))

        # Verify signature by public data key
        try:
            jws.verify(key=public_key)
            logger.info(
                "Valid data signature from %s", name, extra={"nodename": name, "thumbprint": public_key.thumbprint()}
            )
        except InvalidJWSSignature as exc:
            logger.warning(
                "Invalid data signature from %s", name, extra={"nodename": name, "thumbprint": public_key.thumbprint()}
            )
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid data signature") from exc

        if public_key.key_id and public_key.key_id != name:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Invalid data name")

        node.public_key = public_key.export(as_dict=True, private_key=False)
        node.public_key.pop("kid", None)
        node.thumbprint = public_key.thumbprint()

    # Verify X.509 CSR and issue certificate
    with tracer.start_as_current_span("issue_certificate"):
        try:
            x509_csr = x509.load_pem_x509_csr(message.x509_csr.encode())
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid CSR") from exc
        node_certificate = process_csr_request(csr=x509_csr, name=name, request=request)

    node.activated = datetime.now(tz=UTC)
    node.save()
    node_enrollment.delete()

    nodes_enrolled.add(1)

    return NodeEnrollmentResult(
        **create_node_configuration(name=name, request=request).model_dump(),
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
            logger.info(
                "Valid data signature from %s", name, extra={"nodename": name, "thumbprint": public_key.thumbprint()}
            )
        except InvalidJWSSignature as exc:
            logger.warning(
                "Invalid data signature from %s", name, extra={"nodename": name, "thumbprint": public_key.thumbprint()}
            )
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid data signature") from exc
        try:
            message = RenewalRequest.model_validate_json(jws.payload)
        except ValidationError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST) from exc

    # Verify X.509 CSR and issue certificate
    with tracer.start_as_current_span("issue_certificate"):
        try:
            x509_csr = x509.load_pem_x509_csr(message.x509_csr.encode())
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid CSR") from exc
        res = process_csr_request(csr=x509_csr, name=name, request=request)

    nodes_renewed.add(1)

    return res


@router.get(
    "/api/v1/node/{name}/configuration",
    responses={
        status.HTTP_200_OK: {"model": NodeConfiguration},
        status.HTTP_404_NOT_FOUND: {},
    },
    tags=["client"],
    response_model_exclude_none=True,
)
async def get_node_configuration(
    name: str,
    request: Request,
    response: Response,
) -> NodeConfiguration:
    """Get node configuration"""

    node = find_node(name)

    if not node.activated:
        logging.debug("Node %s not activated", name, extra={"nodename": name})
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Node not activated")

    res = create_node_configuration(name=name, request=request)

    node_configurations_requested.add(1)

    # Cache response for 5 minutes
    max_age = request.app.settings.nodes.configuration_ttl
    response.headers["Cache-Control"] = f"public, max-age={max_age}"

    return res


@router.get(
    "/api/v1/node/{name}/certificate",
    responses={
        status.HTTP_200_OK: {"model": NodeCertificate},
        status.HTTP_404_NOT_FOUND: {},
    },
    tags=["client"],
    response_model_exclude_none=True,
)
async def get_node_certificate(name: str) -> NodeCertificate:
    """Get node certificate"""

    node = find_node(name)

    if certificate := TapirCertificate.objects(name=node.name).order_by("-_id").first():
        return NodeCertificate.from_db_model(certificate)

    logging.debug("Certificate for node %s not found", name, extra={"nodename": name})
    raise HTTPException(status.HTTP_404_NOT_FOUND)
