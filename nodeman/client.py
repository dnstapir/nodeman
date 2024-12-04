import argparse
import json
import logging
import sys
from urllib.parse import urljoin

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS

from nodeman.jose import jwk_to_alg
from nodeman.models import NodeCertificate, NodeConfiguration
from nodeman.x509 import generate_x509_csr

PrivateKey = ec.EllipticCurvePrivateKey | rsa.RSAPublicKey | Ed25519PrivateKey | Ed448PrivateKey


def enroll(name: str, server: str, hmac_key: JWK, data_key: JWK, x509_key: PrivateKey) -> NodeConfiguration:
    """Enroll new node"""

    hmac_alg = "HS256"
    data_alg = jwk_to_alg(data_key)
    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

    jws_payload = json.dumps({"x509_csr": x509_csr, "public_key": data_key.export_public(as_dict=True)})

    jws = JWS(payload=jws_payload)
    jws.add_signature(key=hmac_key, alg=hmac_alg, protected={"alg": hmac_alg})
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    enrollment_request = jws.serialize()

    url = urljoin(server, f"/api/v1/node/{name}/enroll")
    response = httpx.post(url, json=enrollment_request)
    response.raise_for_status()

    enrollment_response = response.json()

    logging.debug("Response: %s", json.dumps(enrollment_response, indent=4))

    return NodeConfiguration(**enrollment_response)


def renew(name: str, server: str, data_key: JWK, x509_key: PrivateKey) -> NodeCertificate:
    """Renew existing node"""

    data_alg = jwk_to_alg(data_key)
    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

    jws_payload = json.dumps({"x509_csr": x509_csr, "public_key": data_key.export_public(as_dict=True)})

    jws = JWS(payload=jws_payload)
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    renewal_request = jws.serialize()

    url = urljoin(server, f"/api/v1/node/{name}/renew")
    response = httpx.post(url, json=renewal_request)
    response.raise_for_status()

    renewal_response = response.json()

    logging.debug("Response: %s", json.dumps(renewal_response, indent=4))

    return NodeCertificate(**renewal_response)


def main() -> None:
    """Main function"""

    parser = argparse.ArgumentParser(description="Node Manager Client")

    parser.add_argument("--name", metavar="name", help="Node name")
    parser.add_argument("--secret", metavar="secret", help="Node secret")

    parser.add_argument("--username", metavar="username", help="Admin username")
    parser.add_argument("--password", metavar="password", help="Admin psername")

    parser.add_argument("--kty", metavar="type", help="Key type", default="OKP")
    parser.add_argument("--crv", metavar="type", help="Key curve", default="Ed25519")

    parser.add_argument(
        "--data-jwk-file", metavar="filename", help="JWK private key", required=False, default="data.json"
    )
    parser.add_argument(
        "--tls-cert-file", metavar="filename", help="TLS client certificate", required=False, default="tls.crt"
    )
    parser.add_argument(
        "--tls-key-file", metavar="filename", help="TLS client private key", required=False, default="tls.key"
    )
    parser.add_argument(
        "--tls-ca-file", metavar="filename", help="TLS CA certificate", required=False, default="tls-ca.crt"
    )
    parser.add_argument("--server", metavar="URL", help="Aggregate receiver", default="http://127.0.0.1:8080")
    parser.add_argument("--renew", action="store_true", help="Renew existing certificate")
    parser.add_argument("--debug", action="store_true", help="Enable debugging")

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    x509_key = ec.generate_private_key(ec.SECP256R1())

    if args.renew:
        with open(args.data_jwk_file, "r") as fp:
            data_key = JWK.from_json(fp.read())
        result = renew(name=args.name, server=args.server, data_key=data_key, x509_key=x509_key)
    else:
        if args.name and args.secret:
            name = args.name
            secret = args.secret
        else:
            if not (args.username and args.password):
                logging.error("Admin username & password required")
                sys.exit(-1)
            try:
                auth = (args.username, args.password)
                response = httpx.post(urljoin(args.server, "/api/v1/node"), auth=auth)
                response.raise_for_status()
            except httpx.HTTPError as exc:
                logging.error("Failed to create node: %s", str(exc))
                raise SystemExit(1) from exc
            create_response = response.json()
            name = create_response["name"]
            secret = create_response["secret"]
            logging.info("Got name=%s secret=%s", name, secret)

        hmac_key = JWK(kty="oct", k=secret)
        data_key = JWK.generate(kty=args.kty, crv=args.crv)

        result = enroll(name=name, server=args.server, hmac_key=hmac_key, data_key=data_key, x509_key=x509_key)

        if args.data_jwk_file:
            with open(args.data_jwk_file, "w") as fp:
                fp.write(data_key.export())

    if args.tls_key_file:
        with open(args.tls_key_file, "wb") as fp:
            fp.write(
                x509_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

    if args.tls_cert_file:
        with open(args.tls_cert_file, "w") as fp:
            fp.write(result.x509_certificate)

    if args.tls_ca_file:
        with open(args.tls_ca_file, "w") as fp:
            fp.write(result.x509_ca_certificate)

    print(result.model_dump_json(indent=4, exclude_none=True))


if __name__ == "__main__":
    main()
