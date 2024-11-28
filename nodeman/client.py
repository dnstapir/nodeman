import argparse
import json
import logging
from urllib.parse import urljoin

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS

from nodeman.jose import generate_x509_csr, jwk_to_alg


def main() -> None:
    """Main function"""

    parser = argparse.ArgumentParser(description="Node Manager Client")

    parser.add_argument(
        "--name",
        metavar="name",
        help="Node name",
    )
    parser.add_argument(
        "--secret",
        metavar="secret",
        help="Node secret",
    )
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
    parser.add_argument(
        "--server",
        metavar="URL",
        help="Aggregate receiver",
        default="http://127.0.0.1:8080",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debugging")

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.name is None and args.secret is None:
        try:
            response = httpx.post(urljoin(args.server, "/api/v1/node"))
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logging.error("Failed to create node: %s", str(exc))
            raise SystemExit(1) from exc
        create_response = response.json()
        name = create_response["name"]
        secret = create_response["secret"]
        logging.info("Got name=%s secret=%s", name, secret)
    else:
        name = args.name
        secret = args.secret

    hmac_key = JWK(kty="oct", k=secret)
    hmac_alg = "HS256"

    data_key = JWK.generate(kty=args.kty, crv=args.crv)
    data_alg = jwk_to_alg(data_key)

    x509_key = ec.generate_private_key(ec.SECP256R1())
    x509_csr = generate_x509_csr(key=x509_key, name=name).public_bytes(serialization.Encoding.PEM).decode()

    payload = {"x509_csr": x509_csr, "public_key": data_key.export_public(as_dict=True)}

    jws = JWS(payload=json.dumps(payload))
    jws.add_signature(key=hmac_key, alg=hmac_alg, protected={"alg": hmac_alg})
    jws.add_signature(key=data_key, alg=data_alg, protected={"alg": data_alg})
    enrollment_request = jws.serialize()

    url = urljoin(args.server, f"/api/v1/node/{name}/enroll")
    response = httpx.post(url, json=enrollment_request)
    response.raise_for_status()

    enrollment_response = response.json()
    if args.debug:
        print(json.dumps(enrollment_response, indent=4))

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
            fp.write(enrollment_response["x509_certificate"])

    if args.tls_ca_file:
        with open(args.tls_ca_file, "w") as fp:
            fp.write(enrollment_response["x509_ca_certificate"])


if __name__ == "__main__":
    main()
