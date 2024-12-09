import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import ExtensionOID, NameOID
from fastapi import HTTPException, Request, status

from .models import NodeCertificate

type PrivateKey = RSAPrivateKey | EllipticCurvePrivateKey | Ed25519PrivateKey | Ed448PrivateKey

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CertificateInformation:
    cert_chain: list[x509.Certificate]
    ca_cert: x509.Certificate


class CertificateAuthorityClient(ABC):
    @abstractmethod
    def sign_csr(self, csr: x509.CertificateSigningRequest, name: str) -> CertificateInformation:
        pass


def get_hash_algorithm_from_key(key: PrivateKey) -> hashes.HashAlgorithm | None:
    if isinstance(key, (Ed25519PrivateKey, Ed448PrivateKey)):
        return None
    if isinstance(key, EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP384R1):
        return hashes.SHA384()
    return hashes.SHA256()


def generate_x509_csr(name: str, key: PrivateKey) -> x509.CertificateSigningRequest:
    """Generate X.509 CSR with name and key"""
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name)]),
            critical=False,
        )
        .sign(key, get_hash_algorithm_from_key(key))
    )


class CertificateSigningRequestException(ValueError):
    pass


class SubjectCommonNameMissing(CertificateSigningRequestException):
    pass


class SubjectCommonNameMismatchError(CertificateSigningRequestException):
    pass


class SubjectAlternativeNameMismatchError(CertificateSigningRequestException):
    pass


def verify_x509_csr(name: str, csr: x509.CertificateSigningRequest) -> None:
    """Verify X.509 CSR against name"""

    # ensure Subject is correct
    if len(csr.subject) != 1:
        raise CertificateSigningRequestException("Invalid Subject")
    cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(cn) == 0:
        raise SubjectCommonNameMissing("Missing CommonName")
    elif len(cn) > 1:
        raise CertificateSigningRequestException(f"Multiple CommonName, got {len(cn)} extensions, expected 1")
    elif cn[0].value != name:
        raise SubjectCommonNameMismatchError(f"Invalid CommonName, got {cn[0].value} expected {name}")

    # ensure we only have a single extension
    if len(csr.extensions) == 0:
        raise CertificateSigningRequestException("Missing extensions")
    elif len(csr.extensions) > 1:
        raise CertificateSigningRequestException("Multiple extensions")

    if not csr.is_signature_valid:
        raise CertificateSigningRequestException("Invalid CSR signature")

    # ensure SubjectAlternativeName is correct
    san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    san_value = san_ext.value.get_values_for_type(x509.DNSName)
    if san_value != [name]:
        raise SubjectAlternativeNameMismatchError(f"Invalid SubjectAlternativeName, got {san_value} expected {name}")


def process_csr_request(request: Request, csr: x509.CertificateSigningRequest, name: str) -> NodeCertificate:
    """Verify CSR and issue certificate"""

    verify_x509_csr(name=name, csr=csr)

    try:
        ca_response = request.app.ca_client.sign_csr(csr, name)
    except Exception as exc:
        logger.error("Failed to process CSR for %s", name)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error issuing certificate") from exc

    x509_certificate = "".join(
        [certificate.public_bytes(serialization.Encoding.PEM).decode() for certificate in ca_response.cert_chain]
    )
    x509_ca_certificate = ca_response.ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    x509_certificate_serial_number = ca_response.cert_chain[0].serial_number

    logger.info(
        "Issued certificate for name=%s serial=%d",
        name,
        x509_certificate_serial_number,
        extra={"nodename": name, "x509_certificate_serial_number": x509_certificate_serial_number},
    )

    return NodeCertificate(
        x509_certificate=x509_certificate,
        x509_ca_certificate=x509_ca_certificate,
        x509_certificate_serial_number=x509_certificate_serial_number,
    )
