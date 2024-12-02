import json
import logging
from datetime import datetime, timezone
from typing import Annotated

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS, InvalidJWSSignature
from opentelemetry import metrics, trace

from .const import MIME_TYPE_JWK, MIME_TYPE_PEM
from .db_models import TapirNode, TapirNodeSecret
from .models import (
    NodeBootstrapInformation,
    NodeCertificate,
    NodeCollection,
    NodeConfiguration,
    NodeInformation,
    PublicJwk,
)
from .x509 import verify_x509_csr

logger = logging.getLogger(__name__)

tracer = trace.get_tracer("nodeman.tracer")
meter = metrics.get_meter("nodeman.meter")

router = APIRouter()

security = HTTPBasic()


def get_current_username(
    request: Request,
    credentials: Annotated[HTTPBasicCredentials, Depends(security)],
):
    if user := request.app.users.get(credentials.username):
        if user.verify_password(credentials.password):
            return credentials.username
        else:
            logger.warning("Invalid password for user %s", credentials.username)
    else:
        logger.warning("Unknown user %s", credentials.username)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Basic"},
    )


def process_csr(csr: x509.CertificateSigningRequest, name: str, request: Request) -> NodeCertificate:
    """Verify CSR and issuer certificate"""

    verify_x509_csr(name=name, csr=csr)

    try:
        ca_response = request.app.ca_client.sign_csr(csr, name)
    except Exception as exc:
        logger.error("Failed to process CSR for %s", name)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error issuing certificate") from exc

    x509_certificate = "".join(
        [certificate.public_bytes(serialization.Encoding.PEM).decode() for certificate in ca_response.cert_chain]
    )
    x509_ca_certificate = ca_response.ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    x509_certificate_serial_number = ca_response.cert_chain[0].serial_number

    logger.info(
        "Issued certificate for name=%s serial=%d",
        name,
        x509_certificate_serial_number,
        extra={"nodename": name, "x509_certificate_serial_number": x509_certificate_serial_number},
    )

    return NodeCertificate(
        x509_certificate=x509_certificate,
        x509_ca_certificate=x509_ca_certificate,
        x509_certificate_serial_number=x509_certificate_serial_number,
    )


@router.post(
    "/api/v1/node",
    status_code=201,
    responses={
        201: {"model": NodeBootstrapInformation},
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
        logging.debug("Explicit node name %s requested", name)
        node = TapirNode(name=name, domain=domain).save()
    else:
        logging.warning("Explicit node name %s not acceptable", name)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid node name")

    node_secret = TapirNodeSecret(name=node.name, secret=secret).save()

    logging.info("%s created node %s", username, node.name, extra={"username": username, "nodename": node.name})
    return NodeBootstrapInformation(name=node.name, secret=node_secret.secret)


@router.get(
    "/api/v1/node/{name}",
    responses={
        200: {"model": NodeInformation},
        404: {},
    },
    tags=["backend"],
)
def get_node_information(name: str, username: Annotated[str, Depends(get_current_username)]) -> NodeInformation:
    """Get node information"""

    node: TapirNode | None
    node = TapirNode.objects(name=name, deleted=None).first()
    if node is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    logging.info("%s queried for node %s", username, node.name, extra={"username": username, "nodename": name})
    return NodeInformation.from_db_model(node)


@router.get(
    "/api/v1/nodes",
    responses={
        200: {"model": NodeCollection},
        404: {},
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
        200: {
            "content": {
                MIME_TYPE_JWK: {
                    "title": "JWK",
                    "schema": PublicJwk.model_json_schema(),
                },
                MIME_TYPE_PEM: {"title": "PEM", "schema": {"type": "string"}},
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

    if MIME_TYPE_PEM in accept:
        pem = JWK(**node.public_key).export_to_pem().decode()
        return Response(content=pem, media_type=MIME_TYPE_PEM)

    return Response(content=json.dumps(node.public_key), media_type=MIME_TYPE_JWK)


@router.delete(
    "/api/v1/node/{name}",
    responses={
        204: {"description": "Node deleted", "content": None},
        404: {},
    },
    tags=["backend"],
)
def delete_node(name: str, username: Annotated[str, Depends(get_current_username)]) -> Response:
    """Delete node"""

    node: TapirNode | None
    node = TapirNode.objects(name=name).first()
    if node is None or node.deleted:
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
        200: {"model": NodeConfiguration},
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

    # Verify X.509 CSR and issue certificate
    x509_csr = x509.load_pem_x509_csr(message["x509_csr"].encode())
    node_certificate = process_csr(csr=x509_csr, name=name, request=request)

    node.activated = datetime.now(tz=timezone.utc)
    node.save()
    node_secret.delete()

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
        200: {"model": NodeCertificate},
    },
    tags=["client"],
)
async def renew_node(
    name: str,
    request: Request,
) -> NodeCertificate:
    """Renew node certificate"""

    node: TapirNode | None
    node = TapirNode.objects(name=name, deleted=None).first()
    if node is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    if node.activated is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Node not activated")

    body = await request.body()

    jws = JWS()
    jws.deserialize(json.loads(body.decode()))

    # Verify signature by public key
    public_key = JWK(**node.public_key)
    try:
        jws.verify(key=public_key)
        logger.debug("Valid proof-of-possession signature from %s", name)
    except InvalidJWSSignature as exc:
        logger.warning("Invalid proof-of-possession signature from %s", name)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid proof-of-possession signature") from exc

    message = json.loads(jws.payload)

    # Verify X.509 CSR and issue certificate
    x509_csr = x509.load_pem_x509_csr(message["x509_csr"].encode())
    return process_csr(csr=x509_csr, name=name, request=request)
