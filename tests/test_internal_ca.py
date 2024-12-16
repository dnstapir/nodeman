from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from nodeman.internal_ca import InternalCertificateAuthority
from nodeman.x509 import PrivateKey, generate_x509_csr, verify_x509_csr
from tests.utils import generate_ca_certificate


def _test_internal_ca(ca_private_key: PrivateKey) -> None:
    """Test Internal CA"""

    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Internal Test CA")])
    ca_certificate = generate_ca_certificate(ca_name, ca_private_key)

    validity = timedelta(minutes=10)
    ca_client = InternalCertificateAuthority(
        ca_certificate=ca_certificate, ca_private_key=ca_private_key, validity=validity
    )

    name = "hostname.example.com"
    key = ec.generate_private_key(ec.SECP256R1())
    csr = generate_x509_csr(key=key, name=name)

    verify_x509_csr(name=name, csr=csr)

    res = ca_client.sign_csr(csr, name)
    x509_certificate_pem = "".join(
        [certificate.public_bytes(serialization.Encoding.PEM).decode() for certificate in res.cert_chain]
    )
    print(x509_certificate_pem)


def test_internal_ca_rsa() -> None:
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _test_internal_ca(ca_private_key)


def test_internal_ca_p256() -> None:
    ca_private_key = ec.generate_private_key(ec.SECP256R1())
    return _test_internal_ca(ca_private_key)


def test_internal_ca_p384() -> None:
    ca_private_key = ec.generate_private_key(ec.SECP384R1())
    return _test_internal_ca(ca_private_key)


def test_internal_ca_ed25519() -> None:
    ca_private_key = Ed25519PrivateKey.generate()
    return _test_internal_ca(ca_private_key)


def test_internal_ca_ed448() -> None:
    ca_private_key = Ed448PrivateKey.generate()
    return _test_internal_ca(ca_private_key)
