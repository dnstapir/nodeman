import json
import logging
import os
import uuid
from datetime import UTC, datetime, timedelta
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

from nodeman.internal_ca import InternalCertificateAuthority
from nodeman.jose import generate_similar_jwk, jwk_to_alg
from nodeman.models import NodeCollection, PublicKeyFormat
from nodeman.server import NodemanServer
from nodeman.settings import Settings
from nodeman.x509 import RSA_EXPONENT, CertificateAuthorityClient, generate_ca_certificate, generate_x509_csr

ADMIN_TEST_NODE_COUNT = 100
ADMIN_TEST_NODE_COUNT_TAGS = 10
BACKEND_CREDENTIALS = ("username", "password")

PrivateKey = ec.EllipticCurvePrivateKey | rsa.RSAPublicKey | Ed25519PrivateKey | Ed448PrivateKey

# Set test configuration file - note that environment variables with NODEMAN_ prefix
# will take precedence over values in this file
os.environ["NODEMAN_CONFIG"] = "tests/test.toml"
settings = Settings()


def get_ca_client() -> CertificateAuthorityClient:
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Internal Test CA")])
    ca_private_key = ec.generate_private_key(ec.SECP256R1())
    ca_certificate = generate_ca_certificate(ca_name, ca_private_key)
    return InternalCertificateAuthority(
        issuer_ca_certificate=ca_certificate,
        issuer_ca_private_key=ca_private_key,
        default_validity=timedelta(seconds=60),
        min_validity=timedelta(seconds=10),
        max_validity=timedelta(seconds=3600),
        time_skew=timedelta(seconds=0),
    )


def get_test_client() -> TestClient:
    app = NodemanServer(settings)
    app.ca_client = get_ca_client()
    app.connect_mongodb()
    return TestClient(app, client=("127.0.0.1", 4242))


class FailedToCreateNode(RuntimeError):
    pass


def _test_enroll(data_key: JWK, x509_key: PrivateKey, requested_name: str | None = None) -> None:
    client = get_test_client()

    admin_client = get_test_client()
    admin_client.auth = BACKEND_CREDENTIALS

    server = ""

    logging.basicConfig(level=logging.DEBUG)
    logging.debug("Testing enrollment")

    tags = ["test", str(uuid.uuid4())]

    #############
    # Create node

    node_create_request = {**({"name": requested_name} if requested_name else {}), "tags": tags}
    response = admin_client.post(urljoin(server, "/api/v1/node"), json=node_create_request)
    if response.status_code != status.HTTP_201_CREATED:
        raise FailedToCreateNode
    assert response.status_code == status.HTTP_201_CREATED
    create_response = response.json()
    name = create_response["name"]
    nodeman_url = create_response["nodeman_url"]
    logging.info("Got name=%s", name)
    if requested_name:
        assert name == requested_name
    assert "https://" in nodeman_url

    node_url = response.headers["Location"]

    #######################
    # Get node information

    response = admin_client.get(node_url)
    assert response.status_code == status.HTTP_200_OK
    node_information = response.json()
    assert node_information["name"] == name
    assert node_information["activated"] is None
    assert "test" in node_information["tags"]

    #####################
    # Enroll created node

    enrollment_key = JWK(**create_response["key"])

    data_alg = data_key.get("alg") or jwk_to_alg(data_key)

    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

    payload = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "x509_csr": x509_csr,
        "public_key": data_key.export_public(as_dict=True),
    }

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=enrollment_key, alg=enrollment_key.alg, protected={"alg": enrollment_key.alg})
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    enrollment_request = json.loads(jws.serialize())

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

    #########################
    # Get node configuration

    response = client.get(f"{node_url}/configuration")
    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("Cache-Control") is not None
    node_configuration = response.json()
    print(json.dumps(node_configuration, indent=4))
    assert node_configuration["name"] == name
    assert node_configuration["nodeman_url"] == str(settings.nodes.nodeman_url)
    assert node_configuration["aggrec_url"] == str(settings.nodes.aggrec_url)

    ######################
    # Get node certificate

    response = client.get(f"{node_url}/certificate")
    assert response.status_code == status.HTTP_200_OK
    node_certificate = response.json()
    print(json.dumps(node_certificate, indent=4))
    assert node_certificate["x509_certificate"] == enrollment_response["x509_certificate"]
    assert isinstance(node_certificate["x509_certificate_serial_number"], str)
    assert node_certificate["x509_certificate_serial_number"] == enrollment_response["x509_certificate_serial_number"]
    assert (
        node_certificate["x509_certificate_not_valid_after"] == enrollment_response["x509_certificate_not_valid_after"]
    )

    #####################
    # Get node public key

    public_key_url = f"{node_url}/public_key"

    response = client.get(public_key_url, headers={"Accept": "application/json"})
    assert response.status_code == status.HTTP_200_OK
    res = JWK.from_json(response.text)
    assert res.kid == name

    response = client.get(public_key_url, headers={"Accept": "*/*"})
    assert response.status_code == status.HTTP_200_OK
    res = JWK.from_json(response.text)
    assert res.kid == name

    response = client.get(public_key_url, headers={"Accept": PublicKeyFormat.JWK})
    assert response.status_code == status.HTTP_200_OK
    res = JWK.from_json(response.text)
    assert res.kid == name

    response = client.get(public_key_url, headers={"Accept": PublicKeyFormat.PEM})
    assert response.status_code == status.HTTP_200_OK
    _ = load_pem_public_key(response.text.encode())

    response = client.get(public_key_url, headers={"Accept": "text/html"})
    assert response.status_code == status.HTTP_406_NOT_ACCEPTABLE

    #########################
    # Renew certificate (bad)

    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()
    payload = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "x509_csr": x509_csr,
    }

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=generate_similar_jwk(data_key), alg=data_alg, protected={"alg": data_alg})
    renew_request = json.loads(jws.serialize())

    response = client.post(f"{node_url}/renew", json=renew_request)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    #####################################################
    # Renew certificate with default certificate lifetime

    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()
    payload = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "x509_csr": x509_csr,
    }

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    renew_request = json.loads(jws.serialize())

    response = client.post(f"{node_url}/renew", json=renew_request)
    assert response.status_code == status.HTTP_200_OK

    renew_response = response.json()
    print(json.dumps(renew_response, indent=4))
    certs = x509.load_pem_x509_certificates(renew_response["x509_certificate"].encode())
    certificate_serial_number_2 = certs[0].serial_number
    assert certificate_serial_number_1 != certificate_serial_number_2

    ttl = certs[0].not_valid_after_utc - certs[0].not_valid_before_utc
    assert ttl.total_seconds() == client.app.ca_client.default_validity.total_seconds()

    ###################################################
    # Renew certificate with short certificate lifetime

    x509_lifetime = 42
    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()
    payload = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "x509_csr": x509_csr,
        "x509_lifetime": x509_lifetime,
    }

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    renew_request = json.loads(jws.serialize())

    response = client.post(f"{node_url}/renew", json=renew_request)
    assert response.status_code == status.HTTP_200_OK

    renew_response = response.json()
    print(json.dumps(renew_response, indent=4))
    certs = x509.load_pem_x509_certificates(renew_response["x509_certificate"].encode())
    certificate_serial_number_2 = certs[0].serial_number
    assert certificate_serial_number_1 != certificate_serial_number_2

    ttl = certs[0].not_valid_after_utc - certs[0].not_valid_before_utc
    assert ttl.total_seconds() == x509_lifetime

    #########################################
    # Renew certificate with invalid lifetime

    x509_lifetime = 7200
    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()
    payload = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "x509_csr": x509_csr,
        "x509_lifetime": x509_lifetime,
    }

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    renew_request = json.loads(jws.serialize())

    response = client.post(f"{node_url}/renew", json=renew_request)
    assert response.status_code == status.HTTP_400_BAD_REQUEST

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


def test_enroll_p256_name_mismatch() -> None:
    data_key = JWK.generate(kty="EC", crv="P-256", kid="xyzzy")
    x509_key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(AssertionError):
        _test_enroll(data_key=data_key, x509_key=x509_key)


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

    hmac_key = JWK.generate(kty="oct", size=256, alg="HS256")
    hmac_alg = hmac_key.alg

    assert hmac_alg == "HS256"

    data_key = JWK.generate(kty=kty, crv=crv)
    data_alg = data_key.get("alg") or jwk_to_alg(data_key)

    x509_key = ec.generate_private_key(ec.SECP256R1())
    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

    payload = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "x509_csr": x509_csr,
        "public_key": data_key.export_public(as_dict=True),
    }

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=hmac_key, alg=hmac_alg, protected={"alg": hmac_alg})
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    enrollment_request = json.loads(jws.serialize())

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

    response = admin_client.post(urljoin(server, "/api/v1/node"), json={})
    assert response.status_code == status.HTTP_201_CREATED
    create_response = response.json()
    name = create_response["name"]

    enrollment_key = JWK(**create_response["key"])

    data_key = JWK.generate(kty=kty, crv=crv, alg="EdDSA")
    bad_data_key = JWK.generate(kty=kty, crv=crv, alg="EdDSA")

    x509_key = ec.generate_private_key(ec.SECP256R1())
    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

    payload = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "x509_csr": x509_csr,
        "public_key": data_key.export_public(as_dict=True),
    }

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=enrollment_key, alg=enrollment_key.alg, protected={"alg": enrollment_key.alg})
    jws.add_signature(key=bad_data_key, alg=bad_data_key.alg, protected={"alg": bad_data_key.alg})
    enrollment_request = json.loads(jws.serialize())

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
        assert "activated" not in node

    for node in node_collection["nodes"]:
        name = node["name"]
        response = client.delete(f"{server}/api/v1/node/{name}")
        assert response.status_code == status.HTTP_204_NO_CONTENT


def test_admin_tags() -> None:
    client = get_test_client()
    client.auth = BACKEND_CREDENTIALS

    server = ""

    for node_number in range(ADMIN_TEST_NODE_COUNT_TAGS):
        tags = ["odd"] if node_number % 2 else ["even"]
        if node_number == 0:
            tags.append("zero")
        response = client.post(urljoin(server, "/api/v1/node"), json={"tags": tags})
        assert response.status_code == status.HTTP_201_CREATED

    # half of the nodes should have tag even
    response = client.get(urljoin(server, "/api/v1/nodes"), params={"tags": "even"})
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["nodes"]) == ADMIN_TEST_NODE_COUNT_TAGS // 2

    # exactly one node should have tags even & zero
    response = client.get(urljoin(server, "/api/v1/nodes"), params={"tags": "even,zero"})
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["nodes"]) == 1

    # no nodes should have both tags even & odd
    response = client.get(urljoin(server, "/api/v1/nodes"), params={"tags": "even,odd"})
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["nodes"]) == 0


def test_tags_filter() -> None:
    client = get_test_client()
    client.auth = BACKEND_CREDENTIALS

    server = ""
    domain = settings.nodes.domain

    node_tags = {
        f"node1.{domain}": ["tag1"],
        f"node2.{domain}": ["tag1", "tag2"],
    }

    for name, tags in node_tags.items():
        response = client.post(urljoin(server, "/api/v1/node"), json={"name": name, "tags": tags})
        assert response.status_code == status.HTTP_201_CREATED

        node_url = response.headers["Location"]
        data_key = JWK.generate(kty="OKP", crv="Ed25519")
        x509_key = Ed25519PrivateKey.generate()

        create_response = response.json()
        enrollment_key = JWK(**create_response["key"])
        data_alg = data_key.get("alg") or jwk_to_alg(data_key)
        x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

        enroll_payload = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "x509_csr": x509_csr,
            "public_key": data_key.export_public(as_dict=True),
        }

        jws = JWS(payload=json.dumps(enroll_payload))
        jws.add_signature(key=enrollment_key, alg=enrollment_key.alg, protected={"alg": enrollment_key.alg})
        jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
        enrollment_request = json.loads(jws.serialize())

        node_enroll_url = f"{node_url}/enroll"

        response = client.post(node_enroll_url, json=enrollment_request)
        assert response.status_code == status.HTTP_200_OK

    # Find public key without tag filter
    node_name = f"node1.{domain}"
    node_url = urljoin(server, f"/api/v1/node/{node_name}")
    public_key_url = f"{node_url}/public_key"
    response = client.get(public_key_url, headers={"Accept": "application/json"})
    assert response.status_code == status.HTTP_200_OK
    res = JWK.from_json(response.text)
    assert res.kid == node_name
    assert response.json().get("tags") == sorted(node_tags[node_name])

    # Find public key with tag
    node_name = f"node1.{domain}"
    node_url = urljoin(server, f"/api/v1/node/{node_name}")
    public_key_url = f"{node_url}/public_key?tags=tag1"
    response = client.get(public_key_url, headers={"Accept": "application/json"})
    assert response.status_code == status.HTTP_200_OK
    res = JWK.from_json(response.text)
    assert res.kid == node_name
    assert response.json().get("tags") == sorted(node_tags[node_name])

    # Find public key with unknown tag
    node_name = f"node1.{domain}"
    node_url = urljoin(server, f"/api/v1/node/{node_name}")
    public_key_url = f"{node_url}/public_key?tags=tag2"
    response = client.get(public_key_url, headers={"Accept": "application/json"})
    assert response.status_code == status.HTTP_404_NOT_FOUND

    # Find public key with one tag (node having two tags)
    node_name = f"node2.{domain}"
    node_url = urljoin(server, f"/api/v1/node/{node_name}")
    public_key_url = f"{node_url}/public_key?tags=tag1"
    response = client.get(public_key_url, headers={"Accept": "application/json"})
    assert response.status_code == status.HTTP_200_OK
    res = JWK.from_json(response.text)
    assert res.kid == node_name
    assert response.json().get("tags") == sorted(node_tags[node_name])

    # Find public key with two tags required
    node_name = f"node2.{domain}"
    node_url = urljoin(server, f"/api/v1/node/{node_name}")
    public_key_url = f"{node_url}/public_key?tags=tag1,tag2"
    response = client.get(public_key_url, headers={"Accept": "application/json"})
    assert response.status_code == status.HTTP_200_OK
    res = JWK.from_json(response.text)
    assert res.kid == node_name
    assert response.json().get("tags") == sorted(node_tags[node_name])

    # Find public key with three tags required
    node_name = f"node2.{domain}"
    node_url = urljoin(server, f"/api/v1/node/{node_name}")
    public_key_url = f"{node_url}/public_key?tags=tag1,tag2,tag3"
    response = client.get(public_key_url, headers={"Accept": "application/json"})
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_thumbprint_filter() -> None:
    client = get_test_client()
    client.auth = BACKEND_CREDENTIALS

    server = ""
    domain = settings.nodes.domain
    name = "thumbprint." + domain

    response = client.post(urljoin(server, "/api/v1/node"), json={"name": name})
    assert response.status_code == status.HTTP_201_CREATED

    node_url = response.headers["Location"]
    data_key = JWK.generate(kty="OKP", crv="Ed25519")
    x509_key = Ed25519PrivateKey.generate()

    create_response = response.json()
    enrollment_key = JWK(**create_response["key"])
    data_alg = data_key.get("alg") or jwk_to_alg(data_key)
    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

    enroll_payload = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "x509_csr": x509_csr,
        "public_key": data_key.export_public(as_dict=True),
    }

    jws = JWS(payload=json.dumps(enroll_payload))
    jws.add_signature(key=enrollment_key, alg=enrollment_key.alg, protected={"alg": enrollment_key.alg})
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    enrollment_request = json.loads(jws.serialize())

    node_enroll_url = f"{node_url}/enroll"
    response = client.post(node_enroll_url, json=enrollment_request)
    assert response.status_code == status.HTTP_200_OK

    thumbprint = data_key.thumbprint()

    # Find public key by thumbprint
    nodes_url = urljoin(server, f"/api/v1/nodes?thumbprint={thumbprint}")
    response = client.get(nodes_url, headers={"Accept": "application/json"})
    assert response.status_code == status.HTTP_200_OK
    nodes = NodeCollection.model_validate(response.json())
    assert len(nodes.nodes) == 1
    assert nodes.nodes[0].name == name

    # Find public key by unknown thumbprint
    unknown_thumbprint = JWK.generate(kty="OKP", crv="Ed25519").thumbprint()
    nodes_url = urljoin(server, f"/api/v1/nodes?thumbprint={unknown_thumbprint}")
    response = client.get(nodes_url, headers={"Accept": "application/json"})
    assert response.status_code == status.HTTP_200_OK
    nodes = NodeCollection.model_validate(response.json())
    assert len(nodes.nodes) == 0


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


def test_legacy_node_public_key() -> None:
    client = get_test_client()
    name = "legacy"
    public_key_url = f"/api/v1/node/{name}/public_key"

    response = client.get(public_key_url, headers={"Accept": PublicKeyFormat.JWK})
    assert response.status_code == status.HTTP_200_OK
    _ = JWK.from_json(response.text)

    response = client.get(public_key_url, headers={"Accept": PublicKeyFormat.PEM})
    assert response.status_code == status.HTTP_200_OK
    _ = JWK.from_pem(response.text.encode())


def test_legacy_node_public_key_invalid_name() -> None:
    client = get_test_client()
    name = "räksmörgås"
    public_key_url = f"/api/v1/node/{name}/public_key"

    response = client.get(public_key_url, headers={"Accept": PublicKeyFormat.JWK})
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_create_node_valid_name() -> None:
    admin_client = get_test_client()
    admin_client.auth = BACKEND_CREDENTIALS
    server = ""

    node_create_request = {"name": "hostname.test.dnstapir.se"}
    response = admin_client.post(urljoin(server, "/api/v1/node"), json=node_create_request)
    assert response.status_code == status.HTTP_201_CREATED


def test_create_node_invalid_name() -> None:
    admin_client = get_test_client()
    admin_client.auth = BACKEND_CREDENTIALS
    server = ""

    node_create_request = {"name": "räksmörgås.test.dnstapir.se"}
    response = admin_client.post(urljoin(server, "/api/v1/node"), json=node_create_request)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_create_node_invalid_tags() -> None:
    admin_client = get_test_client()
    admin_client.auth = BACKEND_CREDENTIALS
    server = ""

    node_create_request = {"tags": ["räksmörgås"]}
    response = admin_client.post(urljoin(server, "/api/v1/node"), json=node_create_request)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_healthcehck() -> None:
    admin_client = get_test_client()
    server = ""

    response = admin_client.get(urljoin(server, "/api/v1/healthcheck"))
    assert response.status_code == status.HTTP_200_OK


def test_bad_username() -> None:
    admin_client = get_test_client()
    admin_client.auth = ("username-name", "password")
    server = ""

    node_create_request = {"name": "hostname.test.dnstapir.se"}
    response = admin_client.post(urljoin(server, "/api/v1/node"), json=node_create_request)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
