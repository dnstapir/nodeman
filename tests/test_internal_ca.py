import os
from datetime import timedelta
from pathlib import Path
from tempfile import NamedTemporaryFile

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from nodeman.internal_ca import InternalCertificateAuthority
from nodeman.x509 import RSA_EXPONENT, CertificateInformation, PrivateKey, generate_similar_key, generate_x509_csr
from tests.utils import generate_ca_certificate


def _verify_certification_information(res: CertificateInformation) -> None:
    store = x509.verification.Store([res.ca_cert])
    builder = x509.verification.PolicyBuilder()
    builder = builder.store(store)
    verifier = builder.build_client_verifier()
    peer_certificate = res.cert_chain[0]
    untrusted_intermediates = res.cert_chain[1:]
    verified_client = verifier.verify(peer_certificate, untrusted_intermediates)
    assert verified_client.subjects is not None


def _test_internal_ca(ca_private_key: PrivateKey, verify: bool = True) -> None:
    """Test Internal CA"""

    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Internal Test CA")])
    ca_certificate = generate_ca_certificate(ca_name, ca_private_key)

    validity = timedelta(minutes=10)
    ca_client = InternalCertificateAuthority(
        issuer_ca_certificate=ca_certificate, issuer_ca_private_key=ca_private_key, validity=validity
    )

    _ = ca_client.ca_fingerprint

    key = generate_similar_key(ca_private_key)
    name = "hostname.example.com"
    csr = generate_x509_csr(key=key, name=name)

    res = ca_client.sign_csr(csr, name)

    # Assert that the certificate chain is not empty
    assert len(res.cert_chain) > 0, "Certificate chain should contain at least one certificate"

    # Verify the subject name in the certificate
    certificate = res.cert_chain[0]
    common_name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert common_name == name, f"Expected common name '{name}', got '{common_name}'"

    x509_certificate_pem = "".join(
        [certificate.public_bytes(serialization.Encoding.PEM).decode() for certificate in res.cert_chain]
    )
    print(x509_certificate_pem)

    x509_ca_certificate_pem = res.ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    print(x509_ca_certificate_pem)

    if verify:
        _verify_certification_information(res)


def test_internal_sub_ca() -> None:
    """Test internal issuer CA with separate root CA"""

    root_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root Test CA")])
    root_ca_private_key = ec.generate_private_key(ec.SECP256R1())
    root_ca_certificate = generate_ca_certificate(root_ca_name, root_ca_private_key)

    issuer_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Issuer Test CA")])
    issuer_ca_private_key = ec.generate_private_key(ec.SECP256R1())
    issuer_ca_certificate = generate_ca_certificate(
        issuer_ca_name=issuer_ca_name,
        issuer_ca_private_key=issuer_ca_private_key,
        root_ca_name=root_ca_name,
        root_ca_private_key=root_ca_private_key,
    )

    validity = timedelta(minutes=10)
    ca_client = InternalCertificateAuthority(
        issuer_ca_certificate=issuer_ca_certificate,
        issuer_ca_private_key=issuer_ca_private_key,
        root_ca_certificate=root_ca_certificate,
        validity=validity,
    )

    name = "hostname.example.com"
    key = ec.generate_private_key(ec.SECP256R1())
    csr = generate_x509_csr(key=key, name=name)

    res = ca_client.sign_csr(csr, name)
    _verify_certification_information(res)


def test_internal_ca_file() -> None:
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Internal Test CA")])
    ca_private_key = ec.generate_private_key(ec.SECP256R1())
    ca_certificate = generate_ca_certificate(ca_name, ca_private_key)

    with NamedTemporaryFile(mode="wb", delete=False, suffix=".pem") as fp:
        fp.write(
            ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        ca_private_key_file = Path(fp.name)

    with NamedTemporaryFile(mode="wb", delete=False, suffix=".pem") as fp:
        fp.write(ca_certificate.public_bytes(encoding=serialization.Encoding.PEM))
        ca_certificate_file = Path(fp.name)

    _ = InternalCertificateAuthority.load(
        issuer_ca_certificate_file=ca_certificate_file,
        issuer_ca_private_key_file=ca_private_key_file,
    )

    os.unlink(ca_certificate_file)
    os.unlink(ca_private_key_file)


def test_internal_ca_rsa() -> None:
    ca_private_key = rsa.generate_private_key(public_exponent=RSA_EXPONENT, key_size=2048)
    return _test_internal_ca(ca_private_key)


def test_internal_ca_p256() -> None:
    ca_private_key = ec.generate_private_key(ec.SECP256R1())
    return _test_internal_ca(ca_private_key)


def test_internal_ca_p384() -> None:
    ca_private_key = ec.generate_private_key(ec.SECP384R1())
    return _test_internal_ca(ca_private_key)


def test_internal_ca_ed25519() -> None:
    ca_private_key = Ed25519PrivateKey.generate()
    return _test_internal_ca(ca_private_key, verify=False)


def test_internal_ca_ed448() -> None:
    ca_private_key = Ed448PrivateKey.generate()
    return _test_internal_ca(ca_private_key, verify=False)
