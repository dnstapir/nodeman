import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509.oid import NameOID
from fastapi import status
from fastapi.testclient import TestClient
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from pydantic_settings import SettingsConfigDict

from nodeman.internal_ca import InternalCertificateAuthority
from nodeman.jose import jwk_to_alg
from nodeman.models import PublicKeyFormat
from nodeman.server import NodemanServer
from nodeman.settings import Settings
from nodeman.x509 import RSA_EXPONENT, CertificateAuthorityClient, generate_x509_csr
from tests.utils import generate_ca_certificate, rekey

ADMIN_TEST_NODE_COUNT = 100
BACKEND_CREDENTIALS = ("username", "password")

PrivateKey = ec.EllipticCurvePrivateKey | rsa.RSAPublicKey | Ed25519PrivateKey | Ed448PrivateKey

Settings.model_config = SettingsConfigDict(toml_file="tests/test.toml")
settings = Settings()


def get_ca_client() -> CertificateAuthorityClient:
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Internal Test CA")])
    ca_private_key = ec.generate_private_key(ec.SECP256R1())
    ca_certificate = generate_ca_certificate(ca_name, ca_private_key)
    validity = timedelta(minutes=10)
    return InternalCertificateAuthority(
        issuer_ca_certificate=ca_certificate,
        issuer_ca_private_key=ca_private_key,
        validity=validity,
    )


def get_test_client() -> TestClient:
    app = NodemanServer(settings)
    app.ca_client = get_ca_client()
    app.connect_mongodb()
    return TestClient(app)


class FailedToCreateNode(RuntimeError):
    pass


def _test_enroll(data_key: JWK, x509_key: PrivateKey, requested_name: str | None = None) -> None:
    client = get_test_client()

    admin_client = get_test_client()
    admin_client.auth = BACKEND_CREDENTIALS

    server = ""

    logging.basicConfig(level=logging.DEBUG)
    logging.debug("Testing enrollment")

    #############
    # Create node

    response = admin_client.post(
        urljoin(server, "/api/v1/node"), params={"name": requested_name} if requested_name else None
    )
    if response.status_code != status.HTTP_201_CREATED:
        raise FailedToCreateNode
    assert response.status_code == status.HTTP_201_CREATED
    create_response = response.json()
    name = create_response["name"]
    secret = create_response["secret"]
    if requested_name:
        assert name == requested_name
    logging.info("Got name=%s secret=%s", name, secret)

    node_url = urljoin(server, f"/api/v1/node/{name}")

    #######################
    # Get node information

    response = admin_client.get(node_url)
    assert response.status_code == status.HTTP_200_OK
    node_information = response.json()
    assert node_information["name"] == name
    assert node_information["activated"] is None

    #####################
    # Enroll created node

    hmac_key = JWK(kty="oct", k=secret)
    hmac_alg = "HS256"

    data_alg = jwk_to_alg(data_key)

    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

    payload = {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "x509_csr": x509_csr,
        "public_key": data_key.export_public(as_dict=True),
    }

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=hmac_key, alg=hmac_alg, protected={"alg": hmac_alg})
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    enrollment_request = jws.serialize()

    node_enroll_url = f"{node_url}/enroll"

    response = client.post(node_enroll_url, json=enrollment_request)
    assert response.status_code == status.HTTP_200_OK

    enrollment_response = response.json()
    print(json.dumps(enrollment_response, indent=4))
    certs = x509.load_pem_x509_certificates(enrollment_response["x509_certificate"].encode())
    certificate_serial_number_1 = certs[0].serial_number

    ##########################################
    # Enroll created node again (should fail)

    response = client.post(node_enroll_url, json=enrollment_request)
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    ######################
    # Get node information

    response = admin_client.get(node_url)
    assert response.status_code == status.HTTP_200_OK
    node_information = response.json()
    print(json.dumps(node_information, indent=4))
    assert node_information["name"] == name
    assert node_information["activated"] is not None

    #####################
    # Get node public key

    public_key_url = f"{node_url}/public_key"

    response = client.get(public_key_url, headers={"Accept": "application/json"})
    assert response.status_code == status.HTTP_200_OK
    _ = JWK.from_json(response.text)

    response = client.get(public_key_url, headers={"Accept": PublicKeyFormat.JWK})
    assert response.status_code == status.HTTP_200_OK
    _ = JWK.from_json(response.text)

    response = client.get(public_key_url, headers={"Accept": PublicKeyFormat.PEM})
    assert response.status_code == status.HTTP_200_OK
    _ = load_pem_public_key(response.text.encode())

    response = client.get(public_key_url, headers={"Accept": "text/html"})
    assert response.status_code == status.HTTP_406_NOT_ACCEPTABLE

    #########################
    # Renew certificate (bad)

    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()
    payload = {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "x509_csr": x509_csr,
    }

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=rekey(data_key), alg=data_alg, protected={"alg": data_alg})
    renew_request = jws.serialize()

    response = client.post(f"{node_url}/renew", json=renew_request)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    ###################
    # Renew certificate

    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()
    payload = {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "x509_csr": x509_csr,
    }

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    renew_request = jws.serialize()

    response = client.post(f"{node_url}/renew", json=renew_request)
    assert response.status_code == status.HTTP_200_OK

    renew_response = response.json()
    print(json.dumps(renew_response, indent=4))
    certs = x509.load_pem_x509_certificates(renew_response["x509_certificate"].encode())
    certificate_serial_number_2 = certs[0].serial_number
    assert certificate_serial_number_1 != certificate_serial_number_2

    ###########
    # Clean up

    response = admin_client.delete(node_url)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    response = admin_client.delete(node_url)
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_enroll_p256() -> None:
    data_key = JWK.generate(kty="EC", crv="P-256")
    x509_key = ec.generate_private_key(ec.SECP256R1())
    _test_enroll(data_key=data_key, x509_key=x509_key)


def test_enroll_p384() -> None:
    data_key = JWK.generate(kty="EC", crv="P-384")
    x509_key = ec.generate_private_key(ec.SECP384R1())
    _test_enroll(data_key=data_key, x509_key=x509_key)


def test_enroll_ed25519_p256() -> None:
    data_key = JWK.generate(kty="OKP", crv="Ed25519")
    x509_key = ec.generate_private_key(ec.SECP256R1())
    _test_enroll(data_key=data_key, x509_key=x509_key)


def test_enroll_ed25519() -> None:
    data_key = JWK.generate(kty="OKP", crv="Ed25519")
    x509_key = Ed25519PrivateKey.generate()
    _test_enroll(data_key=data_key, x509_key=x509_key)


def test_enroll_ed448() -> None:
    data_key = JWK.generate(kty="OKP", crv="Ed448")
    x509_key = Ed448PrivateKey.generate()
    _test_enroll(data_key=data_key, x509_key=x509_key)


def test_enroll_rsa() -> None:
    data_key = JWK.generate(kty="RSA", size=2048)
    x509_key = rsa.generate_private_key(public_exponent=RSA_EXPONENT, key_size=2048)
    _test_enroll(data_key=data_key, x509_key=x509_key)


def test_enroll_p256_named_node() -> None:
    data_key = JWK.generate(kty="EC", crv="P-256")
    x509_key = ec.generate_private_key(ec.SECP256R1())
    requested_name = ".".join(["xyzzy", settings.nodes.domain])
    _test_enroll(data_key=data_key, x509_key=x509_key, requested_name=requested_name)


def test_enroll_p256_bad_named_node() -> None:
    data_key = JWK.generate(kty="EC", crv="P-256")
    x509_key = ec.generate_private_key(ec.SECP256R1())
    requested_name = "xyzzy.example.com"
    with pytest.raises(FailedToCreateNode):
        _test_enroll(data_key=data_key, x509_key=x509_key, requested_name=requested_name)


def test_enroll_bad_hmac_signature() -> None:
    client = get_test_client()
    server = ""

    kty = "OKP"
    crv = "Ed25519"

    logging.basicConfig(level=logging.DEBUG)

    response = client.post(urljoin(server, "/api/v1/node"), auth=BACKEND_CREDENTIALS)
    assert response.status_code == status.HTTP_201_CREATED
    create_response = response.json()
    name = create_response["name"]

    hmac_key = JWK.generate(kty="oct")
    hmac_alg = "HS256"

    data_key = JWK.generate(kty=kty, crv=crv)
    data_alg = jwk_to_alg(data_key)

    x509_key = ec.generate_private_key(ec.SECP256R1())
    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

    payload = {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "x509_csr": x509_csr,
        "public_key": data_key.export_public(as_dict=True),
    }

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=hmac_key, alg=hmac_alg, protected={"alg": hmac_alg})
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    enrollment_request = jws.serialize()

    url = urljoin(server, f"/api/v1/node/{name}/enroll")
    response = client.post(url, json=enrollment_request)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = client.delete(urljoin(server, f"/api/v1/node/{name}"), auth=BACKEND_CREDENTIALS)
    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_enroll_bad_data_signature() -> None:
    client = get_test_client()

    admin_client = get_test_client()
    admin_client.auth = BACKEND_CREDENTIALS

    server = ""

    kty = "OKP"
    crv = "Ed25519"

    logging.basicConfig(level=logging.DEBUG)

    response = admin_client.post(urljoin(server, "/api/v1/node"))
    assert response.status_code == status.HTTP_201_CREATED
    create_response = response.json()
    name = create_response["name"]
    secret = create_response["secret"]

    hmac_key = JWK(kty="oct", k=secret)
    hmac_alg = "HS256"

    data_key = JWK.generate(kty=kty, crv=crv)
    bad_data_key = JWK.generate(kty=kty, crv=crv)
    data_alg = jwk_to_alg(data_key)

    x509_key = ec.generate_private_key(ec.SECP256R1())
    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

    payload = {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "x509_csr": x509_csr,
        "public_key": data_key.export_public(as_dict=True),
    }

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=hmac_key, alg=hmac_alg, protected={"alg": hmac_alg})
    jws.add_signature(key=bad_data_key, alg=data_alg, protected={"alg": data_alg})
    enrollment_request = jws.serialize()

    url = urljoin(server, f"/api/v1/node/{name}/enroll")
    response = client.post(url, json=enrollment_request)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = admin_client.delete(urljoin(server, f"/api/v1/node/{name}"))
    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_admin() -> None:
    client = get_test_client()
    client.auth = BACKEND_CREDENTIALS

    server = ""

    for _ in range(ADMIN_TEST_NODE_COUNT):
        response = client.post(urljoin(server, "/api/v1/node"))
        assert response.status_code == status.HTTP_201_CREATED

    response = client.get(urljoin(server, "/api/v1/nodes"))
    assert response.status_code == status.HTTP_200_OK

    node_collection = response.json()
    assert len(node_collection["nodes"]) >= ADMIN_TEST_NODE_COUNT

    for node in node_collection["nodes"]:
        assert "name" in node
        assert "activated" in node

    for node in node_collection["nodes"]:
        name = node["name"]
        response = client.delete(f"{server}/api/v1/node/{name}")
        assert response.status_code == status.HTTP_204_NO_CONTENT


def test_backend_authentication() -> None:
    client = get_test_client()
    server = ""

    # correct password
    response = client.get(urljoin(server, "/api/v1/nodes"), auth=BACKEND_CREDENTIALS)
    assert response.status_code == status.HTTP_200_OK

    # no password
    response = client.get(urljoin(server, "/api/v1/nodes"))
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    # invalid user
    response = client.get(urljoin(server, "/api/v1/nodes"), auth=("invalid", ""))
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    # wrong password for existing user
    response = client.get(urljoin(server, "/api/v1/nodes"), auth=(BACKEND_CREDENTIALS[0], "wrong"))
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_not_found() -> None:
    client = get_test_client()
    client.auth = BACKEND_CREDENTIALS
    server = ""
    name = str(uuid.uuid4())

    response = client.get(urljoin(server, f"/api/v1/node/{name}"))
    assert response.status_code == status.HTTP_404_NOT_FOUND

    response = client.post(urljoin(server, f"/api/v1/node/{name}/enroll"))
    assert response.status_code == status.HTTP_404_NOT_FOUND

    response = client.get(urljoin(server, f"/api/v1/node/{name}/public_key"), headers={"Accept": PublicKeyFormat.JWK})
    assert response.status_code == status.HTTP_404_NOT_FOUND

    response = client.get(urljoin(server, f"/api/v1/node/{name}/public_key"), headers={"Accept": PublicKeyFormat.PEM})
    assert response.status_code == status.HTTP_404_NOT_FOUND
