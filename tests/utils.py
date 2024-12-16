from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
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


def generate_ca_certificate(ca_name: x509.Name | str, ca_private_key: PrivateKey) -> x509.Certificate:
    """Generate CA Certificate"""

    now = datetime.now(tz=timezone.utc)
    validity = timedelta(days=1)

    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_name)]) if isinstance(ca_name, str) else ca_name

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(ca_name)
    builder = builder.issuer_name(ca_name)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + validity)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(ca_private_key.public_key())
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

    return builder.sign(private_key=ca_private_key, algorithm=get_hash_algorithm_from_key(ca_private_key))
