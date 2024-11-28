import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from nodeman.x509 import (
    CertificateSigningRequestException,
    SubjectAlternativeNameMismatchError,
    SubjectCommonNameMismatchError,
    verify_x509_csr,
)

type PrivateKey = ec.EllipticCurvePrivateKey

NAME_1 = "host1.example.com"
NAME_2 = "host2.example.com"


def build_csr(subject: str, san: str | None = None, ca: bool | None = None) -> x509.CertificateSigningRequest:
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
    if san is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
    if ca is not None:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=None),
            critical=True,
        )
    return builder.sign(key, hashes.SHA256())


def test_x509_csr_name_correct() -> None:
    csr = build_csr(subject=NAME_1, san=NAME_1)
    verify_x509_csr(name=NAME_1, csr=csr)


def test_x509_csr_subject_mismatch() -> None:
    csr = build_csr(subject=NAME_2, san=NAME_1)
    with pytest.raises(SubjectCommonNameMismatchError):
        verify_x509_csr(name=NAME_1, csr=csr)


def test_x509_csr_san_mismatch() -> None:
    csr = build_csr(subject=NAME_1, san=NAME_2)
    with pytest.raises(SubjectAlternativeNameMismatchError):
        verify_x509_csr(name=NAME_1, csr=csr)


def test_x509_csr_san_missing() -> None:
    csr = build_csr(subject=NAME_1)
    with pytest.raises(CertificateSigningRequestException):
        verify_x509_csr(name=NAME_1, csr=csr)


def test_x509_csr_is_ca() -> None:
    csr = build_csr(subject=NAME_1, san=NAME_1, ca=True)
    with pytest.raises(CertificateSigningRequestException):
        verify_x509_csr(name=NAME_1, csr=csr)
