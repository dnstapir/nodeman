import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.x509.oid import ExtensionOID, NameOID
from fastapi import HTTPException, Request, status

from .models import NodeCertificate

RSA_EXPONENT = 65537
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


def generate_similar_key(key: PrivateKey) -> PrivateKey:
    """Generate similar new private key"""

    if isinstance(key, rsa.RSAPrivateKey):
        return rsa.generate_private_key(public_exponent=RSA_EXPONENT, key_size=key.key_size)
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        return ec.generate_private_key(curve=key.curve)
    elif isinstance(key, Ed25519PrivateKey):
        return Ed25519PrivateKey.generate()
    elif isinstance(key, Ed448PrivateKey):
        return Ed448PrivateKey.generate()
    else:
        raise ValueError("Unsupported algorithm")


class CertificateSigningRequestException(ValueError):
    pass


class SubjectCommonNameMissing(CertificateSigningRequestException):
    pass


class SubjectCommonNameMismatchError(CertificateSigningRequestException):
    pass


class SubjectAlternativeNameMismatchError(CertificateSigningRequestException):
    pass


def verify_x509_csr(csr: x509.CertificateSigningRequest, name: str, validate_name: bool = True) -> None:
    """Verify X.509 CSR"""

    verify_x509_csr_signature(csr=csr, name=name)
    verify_x509_csr_data(csr=csr, name=name, validate_name=validate_name)


def verify_x509_csr_data(csr: x509.CertificateSigningRequest, name: str, validate_name: bool = True) -> None:
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

    logger.info("Verified CSR data for %s", name)


def verify_x509_csr_signature(csr: x509.CertificateSigningRequest, name: str) -> None:
    """Verify X.509 CSR signature"""

    public_key = csr.public_key()
    verify_kwargs: dict[str, Any] = {}

    if isinstance(public_key, RSAPublicKey):
        verify_kwargs = {
            "algorithm": csr.signature_hash_algorithm,
            "padding": csr.signature_algorithm_parameters,
        }
    elif isinstance(public_key, EllipticCurvePublicKey):
        verify_kwargs = {
            "signature_algorithm": ec.ECDSA(csr.signature_hash_algorithm),
        }
    elif isinstance(public_key, (Ed25519PublicKey, Ed448PublicKey)):
        pass
    else:
        raise ValueError(f"Unsupported algorithm: {public_key}")

    try:
        public_key.verify(signature=csr.signature, data=csr.tbs_certrequest_bytes, **verify_kwargs)
    except Exception as exc:
        logger.error("CSR signature not valid: %s", exc, exc_info=exc)
        raise ValueError("Invalid CSR signature") from exc

    logger.info("Verified CSR signature for %s", name)


def process_csr_request(request: Request, csr: x509.CertificateSigningRequest, name: str) -> NodeCertificate:
    """Verify CSR and issue certificate"""

    verify_x509_csr_data(name=name, csr=csr)

    try:
        ca_response = request.app.ca_client.sign_csr(csr, name)
    except Exception as exc:
        logger.error("Failed to process CSR for %s: %s", name, str(exc), exc_info=exc)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error issuing certificate") from exc

    x509_certificate_pem = "".join(
        [certificate.public_bytes(serialization.Encoding.PEM).decode() for certificate in ca_response.cert_chain]
    )
    x509_ca_certificate_pem = ca_response.ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    x509_certificate: x509.Certificate = ca_response.cert_chain[0]
    x509_certificate_serial_number = x509_certificate.serial_number
    x509_not_valid_after_utc = x509_certificate.not_valid_after_utc.isoformat()

    logger.info(
        "Issued certificate for name=%s serial=%d not_valid_after=%s",
        name,
        x509_certificate_serial_number,
        x509_not_valid_after_utc,
        extra={
            "nodename": name,
            "x509_certificate_serial_number": x509_certificate_serial_number,
            "not_valid_after": x509_not_valid_after_utc,
        },
    )

    return NodeCertificate(
        x509_certificate=x509_certificate_pem,
        x509_ca_certificate=x509_ca_certificate_pem,
        x509_certificate_serial_number=x509_certificate_serial_number,
    )
