from datetime import datetime, timedelta, timezone

from cryptography import x509
from jwcrypto.common import base64url_decode
from jwcrypto.jwk import JWK

from nodeman.x509 import PrivateKey, get_hash_algorithm_from_key


def rekey(key: JWK) -> JWK:
    """Generate similar key"""
    params = {param: key.get(param) for param in ["kty", "crv"] if param in key}
    match key.get("kty"):
        case "RSA":
            params["size"] = key._get_public_key().key_size
        case "oct":
            params["size"] = len(base64url_decode(key.k)) * 8
        case _:
            pass
    return JWK.generate(**params)


def generate_ca_certificate(
    issuer_ca_name: x509.Name,
    issuer_ca_private_key: PrivateKey,
    root_ca_name: x509.Name | None = None,
    root_ca_private_key: PrivateKey | None = None,
) -> x509.Certificate:
    """Generate CA Certificate"""

    now = datetime.now(tz=timezone.utc)
    validity = timedelta(days=1)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(issuer_ca_name)
    builder = builder.issuer_name(root_ca_name or issuer_ca_name)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + validity)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(issuer_ca_private_key.public_key())
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    return builder.sign(
        private_key=root_ca_private_key or issuer_ca_private_key,
        algorithm=get_hash_algorithm_from_key(issuer_ca_private_key),
    )
