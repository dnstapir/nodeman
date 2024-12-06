import argparse
import json
import logging
import os
from datetime import datetime, timezone
from urllib.parse import urljoin

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS

from nodeman.jose import jwk_to_alg
from nodeman.models import NodeBootstrapInformation, NodeCertificate, NodeConfiguration
from nodeman.x509 import generate_x509_csr

PrivateKey = ec.EllipticCurvePrivateKey | rsa.RSAPublicKey | Ed25519PrivateKey | Ed448PrivateKey


def enroll(name: str, server: str, hmac_key: JWK, data_key: JWK, x509_key: PrivateKey) -> NodeConfiguration:
    """Enroll new node"""

    hmac_alg = "HS256"
    data_alg = jwk_to_alg(data_key)
    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

    jws_payload = json.dumps(
        {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "x509_csr": x509_csr,
            "public_key": data_key.export_public(as_dict=True),
        }
    )

    jws = JWS(payload=jws_payload)
    jws.add_signature(key=hmac_key, alg=hmac_alg, protected={"alg": hmac_alg})
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    enrollment_request = jws.serialize()

    url = urljoin(server, f"/api/v1/node/{name}/enroll")

    try:
        response = httpx.post(url, json=enrollment_request)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        logging.error(response.text)
        raise SystemExit(1) from exc

    enrollment_response = response.json()

    logging.debug("Response: %s", json.dumps(enrollment_response, indent=4))

    return NodeConfiguration(**enrollment_response)


def renew(name: str, server: str, data_key: JWK, x509_key: PrivateKey) -> NodeCertificate:
    """Renew existing node"""

    data_alg = jwk_to_alg(data_key)
    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

    jws_payload = json.dumps(
        {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "x509_csr": x509_csr,
        }
    )

    jws = JWS(payload=jws_payload)
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    renewal_request = jws.serialize()

    url = urljoin(server, f"/api/v1/node/{name}/renew")
    try:
        response = httpx.post(url, json=renewal_request)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        logging.error(response.text)
        raise SystemExit(1) from exc

    renewal_response = response.json()

    logging.debug("Response: %s", json.dumps(renewal_response, indent=4))

    return NodeCertificate(**renewal_response)


def save_x509(args: argparse.Namespace, x509_key: PrivateKey, x509_certificate: str, x509_ca_certificate: str) -> None:
    """Save X.509 key, certificate and CA certificate"""

    with open(args.tls_key_file, "wb") as fp:
        fp.write(
            x509_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(args.tls_cert_file, "w") as fp:
        fp.write(x509_certificate)

    with open(args.tls_ca_file, "w") as fp:
        fp.write(x509_ca_certificate)


def get_admin_client(args) -> httpx.Client:
    """Get admin client"""

    username = getattr(args, "username", None) or os.environ.get("NODEMAN_USERNAME")
    password = getattr(args, "password", None) or os.environ.get("NODEMAN_PASSWORD")

    if not (username and password):
        logging.error("Admin username & password required")
        raise SystemExit(1)

    auth = (username, password)

    return httpx.Client(auth=auth)


def command_create(args: argparse.Namespace) -> NodeBootstrapInformation:
    """Create node"""

    client = get_admin_client(args)

    try:
        response = client.post(urljoin(args.server, "/api/v1/node"))
        response.raise_for_status()
    except httpx.HTTPError as exc:
        logging.error("Failed to create node: %s", str(exc))
        raise SystemExit(1) from exc

    create_response = response.json()
    name = create_response["name"]
    secret = create_response["secret"]
    logging.info("Created node with name=%s secret=%s", name, secret)

    return NodeBootstrapInformation(name=name, secret=secret)


def command_delete(args: argparse.Namespace) -> None:
    """Delete node"""

    client = get_admin_client(args)

    try:
        response = client.delete(urljoin(args.server, f"/api/v1/node/{args.name}"))
        response.raise_for_status()
    except httpx.HTTPError as exc:
        logging.error("Failed to delete node: %s", str(exc))
        raise SystemExit(1) from exc

    logging.info("Deleted node with name=%s", args.name)


def command_get(args: argparse.Namespace) -> None:
    """Get node"""

    client = get_admin_client(args)

    try:
        response = client.get(urljoin(args.server, f"/api/v1/node/{args.name}"))
        response.raise_for_status()
    except httpx.HTTPError as exc:
        logging.error("Failed to get node: %s", str(exc))
        raise SystemExit(1) from exc

    print(json.dumps(response.json(), indent=4))


def command_list(args: argparse.Namespace) -> None:
    """List nodes"""

    client = get_admin_client(args)

    try:
        response = client.get(urljoin(args.server, "/api/v1/nodes"))
        response.raise_for_status()
    except httpx.HTTPError as exc:
        logging.error("Failed to list nodes: %s", str(exc))
        raise SystemExit(1) from exc

    print(json.dumps(response.json(), indent=4))


def command_enroll(args: argparse.Namespace) -> NodeConfiguration:
    """Enroll node"""

    if args.create:
        node_bootstrap_information = command_create(args)
        name = node_bootstrap_information.name
        secret = node_bootstrap_information.secret
    else:
        name = args.name
        secret = args.secret

    if not name:
        logging.error("Node name not set")
        raise SystemExit(1)

    hmac_key = JWK(kty="oct", k=secret)
    data_key = JWK.generate(kty=args.kty, crv=args.crv, kid=name)
    x509_key = ec.generate_private_key(ec.SECP256R1())

    result = enroll(name=name, server=args.server, hmac_key=hmac_key, data_key=data_key, x509_key=x509_key)

    with open(args.data_jwk_file, "w") as fp:
        fp.write(data_key.export())

    save_x509(args, x509_key, result.x509_certificate, result.x509_ca_certificate)

    return result


def command_renew(args: argparse.Namespace) -> NodeCertificate:
    """Renew node certificate"""

    with open(args.data_jwk_file) as fp:
        data_key = JWK.from_json(fp.read())
    x509_key = ec.generate_private_key(ec.SECP256R1())

    name = data_key.kid or args.name

    if not name:
        logging.error("Node name not set")
        raise SystemExit(1)

    result = renew(name=name, server=args.server, data_key=data_key, x509_key=x509_key)

    save_x509(args, x509_key, result.x509_certificate, result.x509_ca_certificate)

    return result


def add_admin_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--username",
        metavar="username",
        help="Admin username",
    )
    parser.add_argument(
        "--password",
        metavar="password",
        help="Admin password",
    )


def main() -> None:
    """Main function"""

    parser = argparse.ArgumentParser(description="Node Manager Client")

    parser.add_argument(
        "--data-jwk-file",
        metavar="filename",
        help="JWK private key",
        required=False,
        default="data.json",
    )
    parser.add_argument(
        "--tls-cert-file",
        metavar="filename",
        help="TLS client certificate",
        required=False,
        default="tls.crt",
    )
    parser.add_argument(
        "--tls-key-file",
        metavar="filename",
        help="TLS client private key",
        required=False,
        default="tls.key",
    )
    parser.add_argument(
        "--tls-ca-file",
        metavar="filename",
        help="TLS CA certificate",
        required=False,
        default="tls-ca.crt",
    )
    parser.add_argument(
        "--server",
        metavar="URL",
        help="Aggregate receiver",
        default="http://127.0.0.1:8080",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debugging")

    subparsers = parser.add_subparsers(dest="command")

    admin_create_parser = subparsers.add_parser("create", help="Create new node")
    admin_create_parser.set_defaults(func=command_create)
    add_admin_arguments(admin_create_parser)
    admin_create_parser.add_argument("--name", metavar="name", help="Node name")

    admin_get_parser = subparsers.add_parser("get", help="Get node")
    admin_get_parser.set_defaults(func=command_get)
    add_admin_arguments(admin_get_parser)
    admin_get_parser.add_argument("--name", metavar="name", help="Node name", required=True)

    admin_delete_parser = subparsers.add_parser("delete", help="Delete node")
    admin_delete_parser.set_defaults(func=command_delete)
    add_admin_arguments(admin_delete_parser)
    admin_delete_parser.add_argument("--name", metavar="name", help="Node name", required=True)

    admin_list_parser = subparsers.add_parser("list", help="List nodes")
    admin_list_parser.set_defaults(func=command_list)
    add_admin_arguments(admin_list_parser)

    enroll_parser = subparsers.add_parser("enroll", help="Enroll new node")
    enroll_parser.add_argument("--create", action="store_true", help="Create node")
    enroll_parser.set_defaults(func=command_enroll)
    enroll_parser.add_argument("--name", metavar="name", help="Node name")
    enroll_parser.add_argument("--secret", metavar="secret", help="Node secret")
    enroll_parser.add_argument("--kty", metavar="type", help="Key type", default="OKP")
    enroll_parser.add_argument("--crv", metavar="type", help="Key curve", default="Ed25519")

    renew_parser = subparsers.add_parser("renew", help="Renew existing certificate")
    renew_parser.set_defaults(func=command_renew)
    renew_parser.add_argument("--name", metavar="name", help="Node name")

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    try:
        result = args.func(args)
    except (ValueError, AttributeError) as exc:
        if args.debug:
            raise exc
        parser.print_help()
        return

    if result:
        print(result.model_dump_json(indent=4, exclude_none=True))


if __name__ == "__main__":
    main()
