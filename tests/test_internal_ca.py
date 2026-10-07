import os
from datetime import timedelta
from pathlib import Path
from tempfile import NamedTemporaryFile

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PrivateKey, MLDSA65PrivateKey, MLDSA87PrivateKey
from cryptography.x509.oid import NameOID

from nodeman.internal_ca import InternalCertificateAuthority
from nodeman.x509 import (
    RSA_EXPONENT,
    CertificateInformation,
    PrivateKey,
    generate_ca_certificate,
    generate_similar_key,
    generate_x509_csr,
)


def _verify_certification_information(res: CertificateInformation) -> None:
    """Helper function to verify certification information."""

    store = x509.verification.Store([res.ca_cert])
    builder = x509.verification.PolicyBuilder()
    builder = builder.store(store)
    verifier = builder.build_client_verifier()
    peer_certificate = res.cert_chain[0]
    untrusted_intermediates = res.cert_chain[1:]
    verified_client = verifier.verify(peer_certificate, untrusted_intermediates)
    assert verified_client.subjects is not None


def _get_ca_client(
    ca_private_key: PrivateKey,
    root_ca_private_key: PrivateKey | None = None,
) -> InternalCertificateAuthority:
    """Helper function to create CA client."""

    if root_ca_private_key is not None:
        root_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root Test CA")])
        root_ca_certificate = generate_ca_certificate(root_ca_name, root_ca_private_key)
        issuer_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Issuing Test CA")])
        issuer_ca_certificate = generate_ca_certificate(
            issuer_ca_name=issuer_ca_name,
            issuer_ca_private_key=ca_private_key,
            root_ca_name=root_ca_name,
            root_ca_private_key=root_ca_private_key,
        )
    else:
        root_ca_certificate = None
        issuer_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Internal Test CA")])
        issuer_ca_certificate = generate_ca_certificate(issuer_ca_name, ca_private_key)

    validity = timedelta(minutes=10)

    return InternalCertificateAuthority(
        issuer_ca_certificate=issuer_ca_certificate,
        issuer_ca_private_key=ca_private_key,
        root_ca_certificate=root_ca_certificate,
        default_validity=validity,
    )


def _test_internal_ca(
    ca_private_key: PrivateKey,
    root_ca_private_key: PrivateKey | None = None,
    client_private_key: PrivateKey | None = None,
    verify: bool = True,
) -> CertificateInformation:
    """Helper function to test Internal CA."""

    ca_client = _get_ca_client(ca_private_key=ca_private_key, root_ca_private_key=root_ca_private_key)

    _ = ca_client.ca_fingerprint

    key = client_private_key or generate_similar_key(ca_private_key)
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

    return res


def test_internal_sub_ca() -> None:
    """Test internal issuer CA with separate root CA."""

    root_ca_private_key = ec.generate_private_key(ec.SECP256R1())

    issuer_ca_private_key = ec.generate_private_key(ec.SECP256R1())

    ca_client = _get_ca_client(ca_private_key=issuer_ca_private_key, root_ca_private_key=root_ca_private_key)

    name = "hostname.example.com"
    key = ec.generate_private_key(ec.SECP256R1())
    csr = generate_x509_csr(key=key, name=name)

    res = ca_client.sign_csr(csr, name)
    _verify_certification_information(res)


def test_internal_ca_file() -> None:
    """Test internal CA loading from certificate and private key files."""

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
        default_validity=timedelta(seconds=0),
    )

    os.unlink(ca_certificate_file)
    os.unlink(ca_private_key_file)


def test_internal_ca_rsa() -> None:
    """Test internal CA with an RSA CA and client."""

    ca_private_key = rsa.generate_private_key(public_exponent=RSA_EXPONENT, key_size=2048)
    res = _test_internal_ca(ca_private_key=ca_private_key, verify=True)
    certificate = res.cert_chain[0]
    assert isinstance(certificate, x509.Certificate)
    assert certificate.extensions.get_extension_for_class(x509.KeyUsage).value.key_encipherment is True


def test_internal_ca_p256() -> None:
    """Test internal CA with a P-256 EC CA and client."""

    ca_private_key = ec.generate_private_key(ec.SECP256R1())
    _test_internal_ca(ca_private_key=ca_private_key, verify=True)


def test_internal_ca_p384() -> None:
    """Test internal CA with a P-384 EC CA and client."""

    ca_private_key = ec.generate_private_key(ec.SECP384R1())
    _test_internal_ca(ca_private_key=ca_private_key, verify=True)


def test_internal_ca_ed25519() -> None:
    """Test internal CA with an Ed25519 CA and client."""

    ca_private_key = Ed25519PrivateKey.generate()
    _test_internal_ca(ca_private_key=ca_private_key, verify=False)


def test_internal_ca_ed448() -> None:
    """Test internal CA with an Ed448 CA and client."""

    ca_private_key = Ed448PrivateKey.generate()
    _test_internal_ca(ca_private_key=ca_private_key, verify=False)


def test_internal_ca_mldsa44() -> None:
    """Test internal CA with an ML-DSA-44 CA and client."""

    ca_private_key = MLDSA44PrivateKey.generate()
    res = _test_internal_ca(ca_private_key=ca_private_key, verify=False)
    certificate = res.cert_chain[0]
    assert isinstance(certificate, x509.Certificate)
    assert certificate.extensions.get_extension_for_class(x509.KeyUsage).value.key_encipherment is False


def test_internal_ca_mldsa65() -> None:
    """Test internal CA with an ML-DSA-65 CA and client."""

    ca_private_key = MLDSA65PrivateKey.generate()
    res = _test_internal_ca(ca_private_key=ca_private_key, verify=False)
    certificate = res.cert_chain[0]
    assert isinstance(certificate, x509.Certificate)
    assert certificate.extensions.get_extension_for_class(x509.KeyUsage).value.key_encipherment is False


def test_internal_ca_mldsa87() -> None:
    """Test internal CA with an ML-DSA-87 CA and client."""

    ca_private_key = MLDSA87PrivateKey.generate()
    res = _test_internal_ca(ca_private_key=ca_private_key, verify=False)
    certificate = res.cert_chain[0]
    assert isinstance(certificate, x509.Certificate)
    assert certificate.extensions.get_extension_for_class(x509.KeyUsage).value.key_encipherment is False


def test_internal_ca_mixed_ed25519_mldsa44() -> None:
    """Test internal CA with a mixed Ed25519 CA and ML-DSA-44 client."""

    ca_private_key = Ed25519PrivateKey.generate()
    client_private_key = MLDSA44PrivateKey.generate()
    res = _test_internal_ca(
        ca_private_key=ca_private_key,
        client_private_key=client_private_key,
        verify=False,
    )
    certificate = res.cert_chain[0]
    assert isinstance(certificate, x509.Certificate)


def test_internal_ca_mixed_rsa_mldsa44() -> None:
    """Test internal CA with a mixed RSA CA and ML-DSA-44 client."""

    ca_private_key = rsa.generate_private_key(public_exponent=RSA_EXPONENT, key_size=2048)
    client_private_key = MLDSA44PrivateKey.generate()
    res = _test_internal_ca(
        ca_private_key=ca_private_key,
        client_private_key=client_private_key,
        verify=False,
    )
    certificate = res.cert_chain[0]
    assert isinstance(certificate, x509.Certificate)


def test_internal_ca_mixed_rsa_p256_mldsa44() -> None:
    """Test internal CA with a root RSA CA, P-256 issuing CA and ML-DSA-44 client."""

    root_ca_private_key = rsa.generate_private_key(public_exponent=RSA_EXPONENT, key_size=2048)
    ca_private_key = ec.generate_private_key(ec.SECP256R1())
    client_private_key = MLDSA44PrivateKey.generate()
    res = _test_internal_ca(
        root_ca_private_key=root_ca_private_key,
        ca_private_key=ca_private_key,
        client_private_key=client_private_key,
        verify=True,
    )
    certificate = res.cert_chain[0]
    assert isinstance(certificate, x509.Certificate)
