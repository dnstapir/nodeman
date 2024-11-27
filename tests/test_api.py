import json
import logging
import uuid
from urllib.parse import urljoin

from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS

from nodeman.server import NodemanServer
from nodeman.settings import MongoDB, Settings
from nodeman.utils import generate_x509_csr, jwk_to_alg


def get_test_client() -> TestClient:
    settings = Settings(MongoDB(server="mongomock://localhost/test"))
    app = NodemanServer(settings)
    app.connect_mongodb()
    return TestClient(app)


def test_enroll() -> None:
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
    logging.info("Got name=%s secret=%s", name, secret)

    hmac_key = JWK(kty="oct", k=secret)
    hmac_alg = "HS256"

    data_key = JWK.generate(kty=kty, crv=crv)
    data_alg = jwk_to_alg(data_key)

    x509_key = ec.generate_private_key(ec.SECP256R1())
    x509_csr = generate_x509_csr(key=x509_key, name=name).decode()

    payload = {"x509_csr": x509_csr, "public_key": data_key.export_public(as_dict=True)}

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=hmac_key, alg=hmac_alg, protected={"alg": hmac_alg})
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    enrollment_request = jws.serialize()

    url = urljoin(server, f"/api/v1/node/{name}/enroll")
    response = client.post(url, json=enrollment_request)
    assert response.status_code == 200

    enrollment_response = response.json()
    print(json.dumps(enrollment_response, indent=4))

    url = urljoin(server, f"/api/v1/node/{name}/enroll")
    response = client.post(url, json=enrollment_request)
    assert response.status_code == 400

    response = client.get(urljoin(server, f"/api/v1/node/{name}"))
    assert response.status_code == 200
    print(json.dumps(response.json(), indent=4))

    public_key_url = urljoin(server, f"/api/v1/node/{name}/public_key")

    response = client.get(public_key_url, headers={"Accept": "application/json"})
    assert response.status_code == 200
    print(json.dumps(response.json(), indent=4))

    response = client.get(public_key_url, headers={"Accept": "application/pem"})
    assert response.status_code == 200
    print(response.text)

    response = client.delete(urljoin(server, f"/api/v1/node/{name}"))
    assert response.status_code == 204

    response = client.delete(urljoin(server, f"/api/v1/node/{name}"))
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
    x509_csr = generate_x509_csr(key=x509_key, name=name).decode()

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
    x509_csr = generate_x509_csr(key=x509_key, name=name).decode()

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
