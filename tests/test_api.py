import json
import logging
import uuid
from urllib.parse import urljoin

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi.testclient import TestClient
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from pydantic_settings import SettingsConfigDict

from nodeman.const import MIME_TYPE_JWK, MIME_TYPE_PEM
from nodeman.jose import jwk_to_alg
from nodeman.server import NodemanServer
from nodeman.settings import Settings
from nodeman.x509 import generate_x509_csr
from tests.utils import CaTestClient

ADMIN_TEST_NODE_COUNT = 100
BACKEND_CREDENTIALS = ("username", "password")

Settings.model_config = SettingsConfigDict(toml_file="tests/test.toml")


def get_test_client() -> TestClient:
    settings = Settings()
    app = NodemanServer(settings)
    app.ca_client = CaTestClient()
    app.connect_mongodb()
    return TestClient(app)


def _test_enroll(data_key, x509_key) -> None:
    client = get_test_client()

    admin_client = get_test_client()
    admin_client.auth = BACKEND_CREDENTIALS

    server = ""

    logging.basicConfig(level=logging.DEBUG)
    logging.debug("Testing enrollment")

    response = admin_client.post(urljoin(server, "/api/v1/node"))
    assert response.status_code == 201
    create_response = response.json()
    name = create_response["name"]
    secret = create_response["secret"]
    logging.info("Got name=%s secret=%s", name, secret)

    node_url = urljoin(server, f"/api/v1/node/{name}")

    response = admin_client.get(node_url)
    assert response.status_code == 200
    node_information = response.json()
    assert node_information["name"] == name
    assert node_information["activated"] is None

    hmac_key = JWK(kty="oct", k=secret)
    hmac_alg = "HS256"

    data_alg = jwk_to_alg(data_key)

    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

    payload = {"x509_csr": x509_csr, "public_key": data_key.export_public(as_dict=True)}

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=hmac_key, alg=hmac_alg, protected={"alg": hmac_alg})
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    enrollment_request = jws.serialize()

    node_enroll_url = f"{node_url}/enroll"

    response = client.post(node_enroll_url, json=enrollment_request)
    assert response.status_code == 200

    enrollment_response = response.json()
    print(json.dumps(enrollment_response, indent=4))

    response = client.post(node_enroll_url, json=enrollment_request)
    assert response.status_code == 400

    response = admin_client.get(node_url)
    assert response.status_code == 200
    node_information = response.json()
    print(json.dumps(node_information, indent=4))
    assert node_information["name"] == name
    assert node_information["activated"] is not None

    public_key_url = f"{node_url}/public_key"

    response = client.get(public_key_url, headers={"Accept": "application/json"})
    assert response.status_code == 200
    _ = JWK.from_json(response.text)

    response = client.get(public_key_url, headers={"Accept": "application/x-pem-file"})
    assert response.status_code == 200
    _ = load_pem_public_key(response.text.encode())

    response = admin_client.delete(node_url)
    assert response.status_code == 204

    response = admin_client.delete(node_url)
    assert response.status_code == 404


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
    x509_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _test_enroll(data_key=data_key, x509_key=x509_key)


def test_enroll_bad_hmac_signature() -> None:
    client = get_test_client()
    server = ""

    kty = "OKP"
    crv = "Ed25519"

    logging.basicConfig(level=logging.DEBUG)

    response = client.post(urljoin(server, "/api/v1/node"), auth=BACKEND_CREDENTIALS)
    assert response.status_code == 201
    create_response = response.json()
    name = create_response["name"]

    hmac_key = JWK.generate(kty="oct")
    hmac_alg = "HS256"

    data_key = JWK.generate(kty=kty, crv=crv)
    data_alg = jwk_to_alg(data_key)

    x509_key = ec.generate_private_key(ec.SECP256R1())
    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

    payload = {"x509_csr": x509_csr, "public_key": data_key.export_public(as_dict=True)}

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=hmac_key, alg=hmac_alg, protected={"alg": hmac_alg})
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    enrollment_request = jws.serialize()

    url = urljoin(server, f"/api/v1/node/{name}/enroll")
    response = client.post(url, json=enrollment_request)
    assert response.status_code == 401

    response = client.delete(urljoin(server, f"/api/v1/node/{name}"), auth=BACKEND_CREDENTIALS)
    assert response.status_code == 204


def test_enroll_bad_data_signature() -> None:
    client = get_test_client()

    admin_client = get_test_client()
    admin_client.auth = BACKEND_CREDENTIALS

    server = ""

    kty = "OKP"
    crv = "Ed25519"

    logging.basicConfig(level=logging.DEBUG)

    response = admin_client.post(urljoin(server, "/api/v1/node"))
    assert response.status_code == 201
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

    payload = {"x509_csr": x509_csr, "public_key": data_key.export_public(as_dict=True)}

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=hmac_key, alg=hmac_alg, protected={"alg": hmac_alg})
    jws.add_signature(key=bad_data_key, alg=data_alg, protected={"alg": data_alg})
    enrollment_request = jws.serialize()

    url = urljoin(server, f"/api/v1/node/{name}/enroll")
    response = client.post(url, json=enrollment_request)
    assert response.status_code == 401

    response = admin_client.delete(urljoin(server, f"/api/v1/node/{name}"))
    assert response.status_code == 204


def test_admin() -> None:
    client = get_test_client()
    client.auth = BACKEND_CREDENTIALS

    server = ""

    for _ in range(ADMIN_TEST_NODE_COUNT):
        response = client.post(urljoin(server, "/api/v1/node"))
        assert response.status_code == 201

    response = client.get(urljoin(server, "/api/v1/nodes"))
    assert response.status_code == 200

    node_collection = response.json()
    assert len(node_collection["nodes"]) >= ADMIN_TEST_NODE_COUNT

    for node in node_collection["nodes"]:
        assert "name" in node
        assert "activated" in node

    for node in node_collection["nodes"]:
        name = node["name"]
        response = client.delete(f"{server}/api/v1/node/{name}")
        assert response.status_code == 204


def test_backend_authentication() -> None:
    client = get_test_client()
    server = ""

    # correct password
    response = client.get(urljoin(server, "/api/v1/nodes"), auth=BACKEND_CREDENTIALS)
    assert response.status_code == 200

    # no password
    response = client.get(urljoin(server, "/api/v1/nodes"))
    assert response.status_code == 401

    # invalid user
    response = client.get(urljoin(server, "/api/v1/nodes"), auth=("invalid", ""))
    assert response.status_code == 401

    # wrong password for existing user
    response = client.get(urljoin(server, "/api/v1/nodes"), auth=(BACKEND_CREDENTIALS[0], "wrong"))
    assert response.status_code == 401


def test_not_found() -> None:
    client = get_test_client()
    client.auth = BACKEND_CREDENTIALS
    server = ""
    name = str(uuid.uuid4())

    response = client.get(urljoin(server, f"/api/v1/node/{name}"))
    assert response.status_code == 404

    response = client.post(urljoin(server, f"/api/v1/node/{name}/enroll"))
    assert response.status_code == 404

    response = client.get(urljoin(server, f"/api/v1/node/{name}/public_key"), headers={"Accept": MIME_TYPE_JWK})
    assert response.status_code == 404

    response = client.get(urljoin(server, f"/api/v1/node/{name}/public_key"), headers={"Accept": MIME_TYPE_PEM})
    assert response.status_code == 404
