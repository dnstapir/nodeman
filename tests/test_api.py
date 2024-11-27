import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from pydantic_settings import SettingsConfigDict

from nodeman.server import NodemanServer
from nodeman.settings import MongoDB, Settings
from nodeman.step import StepSignResponse
from nodeman.utils import generate_x509_csr, jwk_to_alg

ADMIN_TEST_NODE_COUNT = 100

Settings.model_config = SettingsConfigDict(toml_file="tests/test.toml")


class TestStepClient:
    def __init__(self):
        self.ca_name = "ca.example.com"
        self.ca_url = "https://ca.example.com"

    def sign_csr(self, csr: x509.CertificateSigningRequest, name: str) -> StepSignResponse:
        now = datetime.now(tz=timezone.utc)
        one_day = timedelta(days=1)

        ca_private_key = ec.generate_private_key(ec.SECP256R1())
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name)]))
        builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name)]))
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + one_day)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(ca_private_key.public_key())
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        ca_certificate = builder.sign(
            private_key=ca_private_key,
            algorithm=hashes.SHA256(),
        )

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name)]))
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + one_day)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(csr.public_key())
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=False,
        )
        certificate = builder.sign(
            private_key=ca_private_key,
            algorithm=hashes.SHA256(),
        )
        return StepSignResponse(cert_chain=[certificate], ca_cert=ca_certificate)


def get_test_client() -> TestClient:
    settings = Settings()
    app = NodemanServer(settings)
    app.step_client = TestStepClient()
    app.connect_mongodb()
    return TestClient(app)


def test_enroll() -> None:
    client = get_test_client()
    server = ""

    kty = "OKP"
    crv = "Ed25519"

    logging.basicConfig(level=logging.DEBUG)
    logging.debug("Testing enrollment")

    response = client.post(urljoin(server, "/api/v1/node"))
    assert response.status_code == 201
    create_response = response.json()
    name = create_response["name"]
    secret = create_response["secret"]
    logging.info("Got name=%s secret=%s", name, secret)

    node_url = urljoin(server, f"/api/v1/node/{name}")

    response = client.get(node_url)
    assert response.status_code == 200
    node_information = response.json()
    assert node_information["name"] == name
    assert node_information["activated"] is None

    hmac_key = JWK(kty="oct", k=secret)
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

    node_enroll_url = f"{node_url}/enroll"

    response = client.post(node_enroll_url, json=enrollment_request)
    assert response.status_code == 200

    enrollment_response = response.json()
    print(json.dumps(enrollment_response, indent=4))

    response = client.post(node_enroll_url, json=enrollment_request)
    assert response.status_code == 400

    response = client.get(node_url)
    assert response.status_code == 200
    node_information = response.json()
    print(json.dumps(node_information, indent=4))
    assert node_information["name"] == name
    assert node_information["activated"] is not None

    public_key_url = f"{node_url}/public_key"

    response = client.get(public_key_url, headers={"Accept": "application/json"})
    assert response.status_code == 200
    _ = JWK.from_json(response.text)

    response = client.get(public_key_url, headers={"Accept": "application/pem"})
    assert response.status_code == 200
    _ = load_pem_public_key(response.text.encode())

    response = client.delete(node_url)
    assert response.status_code == 204

    response = client.delete(node_url)
    assert response.status_code == 404


def test_enroll_bad_hmac_signature() -> None:
    client = get_test_client()
    server = ""

    kty = "OKP"
    crv = "Ed25519"

    logging.basicConfig(level=logging.DEBUG)

    response = client.post(urljoin(server, "/api/v1/node"))
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

    response = client.delete(urljoin(server, f"/api/v1/node/{name}"))
    assert response.status_code == 204


def test_enroll_bad_data_signature() -> None:
    client = get_test_client()
    server = ""

    kty = "OKP"
    crv = "Ed25519"

    logging.basicConfig(level=logging.DEBUG)

    response = client.post(urljoin(server, "/api/v1/node"))
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

    response = client.delete(urljoin(server, f"/api/v1/node/{name}"))
    assert response.status_code == 204


def test_admin() -> None:
    client = get_test_client()
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


def test_not_found() -> None:
    client = get_test_client()
    server = ""
    name = str(uuid.uuid4())

    response = client.get(urljoin(server, f"/api/v1/node/{name}"))
    assert response.status_code == 404

    response = client.post(urljoin(server, f"/api/v1/node/{name}/enroll"))
    assert response.status_code == 404

    response = client.get(urljoin(server, f"/api/v1/node/{name}/public_key"), headers={"Accept": "application/json"})
    assert response.status_code == 404

    response = client.get(urljoin(server, f"/api/v1/node/{name}/public_key"), headers={"Accept": "application/pem"})
    assert response.status_code == 404
