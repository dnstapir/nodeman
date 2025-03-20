import argparse
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS

from nodeman.jose import jwk_to_alg
from nodeman.models import NodeBootstrapInformation, NodeCertificate, NodeConfiguration, NodeEnrollmentResult
from nodeman.x509 import generate_x509_csr

PrivateKey = ec.EllipticCurvePrivateKey | rsa.RSAPublicKey | Ed25519PrivateKey | Ed448PrivateKey

DEFAULT_SERVER = os.environ.get("NODEMAN_SERVER", "http://127.0.0.1:8080")


def enroll(name: str, server: str, enrollment_key: JWK, data_key: JWK, x509_key: PrivateKey) -> NodeConfiguration:
    """Enroll new node"""

    enrollment_alg = enrollment_key.alg or jwk_to_alg(enrollment_key)
    data_alg = jwk_to_alg(data_key)
    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

    jws_payload = json.dumps(
        {
            "timestamp": datetime.now(tz=datetime.UTC).isoformat(),
            "x509_csr": x509_csr,
            "public_key": data_key.export_public(as_dict=True),
        }
    )

    jws = JWS(payload=jws_payload)
    jws.add_signature(key=enrollment_key, alg=enrollment_alg, protected={"alg": enrollment_alg})
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    enrollment_request = json.loads(jws.serialize())

    url = urljoin(server, f"/api/v1/node/{name}/enroll")

    try:
        response = httpx.post(url, json=enrollment_request)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        logging.error(response.text)
        raise SystemExit(1) from exc

    enrollment_response = response.json()

    logging.debug("Response: %s", json.dumps(enrollment_response, indent=4))

    return NodeEnrollmentResult(**enrollment_response)


def renew(name: str, server: str, data_key: JWK, x509_key: PrivateKey) -> NodeCertificate:
    """Renew existing node"""

    data_alg = jwk_to_alg(data_key)
    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

    jws_payload = json.dumps(
        {
            "timestamp": datetime.now(tz=datetime.UTC).isoformat(),
            "x509_csr": x509_csr,
        }
    )

    jws = JWS(payload=jws_payload)
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    renewal_request = json.loads(jws.serialize())

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
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(args.tls_cert_file, "w") as fp:
        fp.write(x509_certificate)

    with open(args.tls_ca_file, "w") as fp:
        fp.write(x509_ca_certificate)


def get_admin_client(args: argparse.Namespace) -> httpx.Client:
    """Get admin client"""

    username = getattr(args, "username", None) or os.environ.get("NODEMAN_USERNAME")
    password = getattr(args, "password", None) or os.environ.get("NODEMAN_PASSWORD")

    if not (username and password):
        logging.error("Admin username & password required")
        raise SystemExit(1)

    auth = (username, password)

    return httpx.Client(auth=auth)


def generate_x509_key(kty: str, crv: str) -> PrivateKey:
    match (kty, crv):
        case ("RSA", _):
            raise ValueError("RSA not supported")
        case ("EC", "P-256"):
            return ec.generate_private_key(ec.SECP256R1())
        case ("EC", "P-384"):
            return ec.generate_private_key(ec.SECP384R1())
        case ("OKP", "Ed25519"):
            return Ed25519PrivateKey.generate()
        case ("OKP", "Ed448"):
            return Ed448PrivateKey.generate()
        case _:
            raise ValueError("Unsupported key type")


def command_create(args: argparse.Namespace) -> NodeBootstrapInformation:
    """Create node"""

    client = get_admin_client(args)

    payload = {
        **({"name": args.name} if args.name else {}),
        **(
            {"tags": [tag.strip() for tag in args.tags.split(",") if tag.strip()]}
            if hasattr(args, "tags") and args.tags
            else {}
        ),
    }

    server = args.server or DEFAULT_SERVER

    try:
        response = client.post(urljoin(server, "/api/v1/node"), json=payload)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        logging.error("Failed to create node: %s", str(exc))
        raise SystemExit(1) from exc

    create_response = response.json()
    name = create_response["name"]

    logging.debug("Response: %s", json.dumps(create_response, indent=4))
    logging.info("Created node with name=%s", name)

    return NodeBootstrapInformation(name=name, key=create_response["key"])


def command_delete(args: argparse.Namespace) -> None:
    """Delete node"""

    client = get_admin_client(args)

    server = args.server or DEFAULT_SERVER

    try:
        response = client.delete(urljoin(server, f"/api/v1/node/{args.name}"))
        response.raise_for_status()
    except httpx.HTTPError as exc:
        logging.error("Failed to delete node: %s", str(exc))
        raise SystemExit(1) from exc

    logging.info("Deleted node with name=%s", args.name)


def command_get(args: argparse.Namespace) -> None:
    """Get node"""

    client = get_admin_client(args)

    server = args.server or DEFAULT_SERVER

    try:
        response = client.get(urljoin(server, f"/api/v1/node/{args.name}"))
        response.raise_for_status()
    except httpx.HTTPError as exc:
        logging.error("Failed to get node: %s", str(exc))
        raise SystemExit(1) from exc

    print(json.dumps(response.json(), indent=4))


def command_list(args: argparse.Namespace) -> None:
    """List nodes"""

    client = get_admin_client(args)

    server = args.server or DEFAULT_SERVER

    try:
        response = client.get(urljoin(server, "/api/v1/nodes"))
        response.raise_for_status()
    except httpx.HTTPError as exc:
        logging.error("Failed to list nodes: %s", str(exc))
        raise SystemExit(1) from exc

    print(json.dumps(response.json(), indent=4))


def command_enroll(args: argparse.Namespace) -> NodeConfiguration:
    """Enroll node"""

    if args.create:
        server = args.server or DEFAULT_SERVER
        node_bootstrap_information = command_create(args)
        name = node_bootstrap_information.name
        enrollment_key = JWK(**node_bootstrap_information.key.model_dump())
    elif args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            logging.error("Enrollment file does not exist: %s", args.file)
            raise SystemExit(2)
        if not file_path.is_file():
            logging.error("Enrollment file is not a file: %s", args.file)
            raise SystemExit(2)
        with open(file_path) as fp:
            enrollment_data = json.load(fp)
        try:
            name = enrollment_data["name"]
            server = enrollment_data["nodeman_url"]
            enrollment_key = JWK(**enrollment_data["key"])
        except Exception as exc:
            logging.error("Error parsing enrollment file", exc_info=exc)
            raise SystemExit(2) from exc
    else:
        server = args.server
        name = args.name
        enrollment_key = JWK(kty="oct", k=args.secret, alg="HS256")

    if not name:
        logging.error("Node name not set")
        raise SystemExit(1)

    data_key = JWK.generate(kty=args.kty, crv=args.crv, kid=name)
    x509_key = generate_x509_key(kty=args.kty, crv=args.crv)

    result = enroll(name=name, server=server, enrollment_key=enrollment_key, data_key=data_key, x509_key=x509_key)

    data_key["iss"] = server

    with open(args.data_jwk_file, "w") as fp:
        fp.write(data_key.export())

    save_x509(args, x509_key, result.x509_certificate, result.x509_ca_certificate)

    return result


def command_renew(args: argparse.Namespace) -> NodeCertificate:
    """Renew node certificate"""

    with open(args.data_jwk_file) as fp:
        data_key = JWK.from_json(fp.read())

    x509_key = generate_x509_key(kty=data_key.kty, crv=data_key.crv)

    server = args.server or data_key.get("iss") or DEFAULT_SERVER

    name = data_key.kid or args.name

    if not name:
        logging.error("Node name not set")
        raise SystemExit(1)

    result = renew(name=name, server=server, data_key=data_key, x509_key=x509_key)

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
        help="Nodeman server",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debugging")

    subparsers = parser.add_subparsers(dest="command")

    admin_create_parser = subparsers.add_parser("create", help="Create new node")
    admin_create_parser.set_defaults(func=command_create)
    add_admin_arguments(admin_create_parser)
    admin_create_parser.add_argument("--name", metavar="name", help="Node name")
    admin_create_parser.add_argument("--tags", metavar="tags", help="Node tags")

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
    enroll_parser.set_defaults(func=command_enroll)
    enrollment_group = enroll_parser.add_mutually_exclusive_group(required=True)
    enrollment_group.add_argument("--create", action="store_true", help="Create node")
    enrollment_group.add_argument("--file", metavar="filename", help="JSON file containing enrollment data")
    enrollment_group.add_argument("--secret", metavar="secret", help="Node secret")
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
