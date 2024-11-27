import json
import logging
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS, InvalidJWSSignature
from opentelemetry import metrics, trace

from .db_models import TapirNode, TapirNodeSecret
from .models import NodeBootstrapInformation, NodeCollection, NodeConfiguration, NodeInformation, PublicJwk
from .utils import verify_x509_csr

logger = logging.getLogger(__name__)

tracer = trace.get_tracer("nodeman.tracer")
meter = metrics.get_meter("nodeman.meter")

router = APIRouter()


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
    "/api/v1/nodes",
    responses={
        200: {"model": NodeCollection},
        404: {},
    },
    tags=["backend"],
)
def get_all_nodes() -> NodeCollection:
    """Get all nodes"""

    return NodeCollection(nodes=[NodeInformation.from_db_model(node) for node in TapirNode.objects(deleted=None)])


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
    x509_certificate = """
-----BEGIN CERTIFICATE-----
MIICUTCCAfigAwIBAgIQIeTTK2bCEzCbi3oFPEwAjjAKBggqhkjOPQQDAjBQMR4w
HAYDVQQKExVETlMgVEFQSVIgRGV2ZWxvcG1lbnQxLjAsBgNVBAMTJUROUyBUQVBJ
UiBEZXZlbG9wbWVudCBJbnRlcm1lZGlhdGUgQ0EwHhcNMjQxMTI3MDgzNzExWhcN
MjQxMTI4MDgzODExWjAiMSAwHgYDVQQDExdleGFtcGxlLmRldi5kbnN0YXBpci5z
ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABITC/mXGuwQQRxDk/j6JWweHmTGv
yiSvjVjVkghEJLiPMf/xw9eIplMJ6/am+VTLpGDY3a7Nyw6/cWxhySXxT4ejgeEw
gd4wDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAdBgNVHQ4EFgQUgkraniNmsMvzKeSucc2NiBQ3N8wwHwYDVR0jBBgwFoAU+BTb
OgWQQHMnqW6jW1BcKNSW5dkwIgYDVR0RBBswGYIXZXhhbXBsZS5kZXYuZG5zdGFw
aXIuc2UwSQYMKwYBBAGCpGTGKEABBDkwNwIBAQQFYWRtaW4EK0JybWpFd2RMVFF4
OVZvX0NOUGVDX196M01aUjlNTGFhX2dCZzA0VkxwSWcwCgYIKoZIzj0EAwIDRwAw
RAIgHS49wTwHbXFuly0y0zamWsuXYKJRPawLQud4G7hALqQCIHw92lr9oiY7XAe6
d57ra+ag1F6X7Ix71igrxZPOyr7U
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB/DCCAaKgAwIBAgIQIpjXFAKEg0IDm+E5uYuhlTAKBggqhkjOPQQDAjBIMR4w
HAYDVQQKExVETlMgVEFQSVIgRGV2ZWxvcG1lbnQxJjAkBgNVBAMTHUROUyBUQVBJ
UiBEZXZlbG9wbWVudCBSb290IENBMB4XDTIzMDgyOTExMTIyM1oXDTMzMDgyNjEx
MTIyM1owUDEeMBwGA1UEChMVRE5TIFRBUElSIERldmVsb3BtZW50MS4wLAYDVQQD
EyVETlMgVEFQSVIgRGV2ZWxvcG1lbnQgSW50ZXJtZWRpYXRlIENBMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEVLtZDO6SuGslPRZvzkaiglmELmYouwYSDLTvgtfr
PxfvzxZYyXlA0Dfs3M4yFn77OBxq1C5/R0qgucuUkp5TQ6NmMGQwDgYDVR0PAQH/
BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFPgU2zoFkEBzJ6lu
o1tQXCjUluXZMB8GA1UdIwQYMBaAFFq+HmvHMyGR7Lm+OXSbkIvVjfvNMAoGCCqG
SM49BAMCA0gAMEUCIA1ng0NqREdHUA4p17Y9hpXYxmC6U5Kz6+zAsGfcaFA5AiEA
1T7Uz4xMHhlA9Wl8u9MYUyxVmA+jb6ylqmG/D/EQF24=
-----END CERTIFICATE-----
"""

    x509_ca_bundle = """
-----BEGIN CERTIFICATE-----
MIIB1DCCAXqgAwIBAgIRAP8qglZYdllt06JygJ/NKTQwCgYIKoZIzj0EAwIwSDEe
MBwGA1UEChMVRE5TIFRBUElSIERldmVsb3BtZW50MSYwJAYDVQQDEx1ETlMgVEFQ
SVIgRGV2ZWxvcG1lbnQgUm9vdCBDQTAeFw0yMzA4MjkxMTEyMjJaFw0zMzA4MjYx
MTEyMjJaMEgxHjAcBgNVBAoTFUROUyBUQVBJUiBEZXZlbG9wbWVudDEmMCQGA1UE
AxMdRE5TIFRBUElSIERldmVsb3BtZW50IFJvb3QgQ0EwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAAShWMzpiyNTGWQW75q8Ac5+K+t0S3MWlkpqVVCSGRkqwtgpKK8b
E8WqJfV/KftwG/V67uBjCS3GptuLtUwAjER1o0UwQzAOBgNVHQ8BAf8EBAMCAQYw
EgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUWr4ea8czIZHsub45dJuQi9WN
+80wCgYIKoZIzj0EAwIDSAAwRQIgb3/xC7FGZ2jlVh+62hPIMjdS56Q5OgCsninc
tVryoi0CIQCs5HThsuvcCn0EC7vIgG6wRx6D6L37UNuwVPPVpEkYBQ==
-----END CERTIFICATE-----
"""

    print(x509_ca_bundle)

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
