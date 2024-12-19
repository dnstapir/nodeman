import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import ExtensionOID, NameOID
from fastapi import HTTPException, Request, status

from .db_models import TapirCertificate
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
    """Get hash algorithm for private key"""
    if isinstance(key, RSAPrivateKey):
        return hashes.SHA256()
    elif isinstance(key, EllipticCurvePrivateKey):
        return hashes.SHA384() if isinstance(key.curve, ec.SECP384R1) else hashes.SHA256()
    elif isinstance(key, (Ed25519PrivateKey, Ed448PrivateKey)):
        return None
    else:
        raise ValueError("Unsupported private key type")


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


def verify_x509_csr_data(csr: x509.CertificateSigningRequest, name: str) -> None:
    """Verify X.509 CSR data"""

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

    # ensure SubjectAlternativeName is correct
    san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    san_value = san_ext.value.get_values_for_type(x509.DNSName)
    if san_value != [name]:
        raise SubjectAlternativeNameMismatchError(f"Invalid SubjectAlternativeName, got {san_value} expected {name}")

    logger.info("Verified CSR data for %s", name)


def verify_x509_csr_signature(csr: x509.CertificateSigningRequest, name: str) -> None:
    """Verify X.509 CSR signature"""

    if not csr.is_signature_valid:
        raise CertificateSigningRequestException("Invalid CSR signature")

    logger.info("Verified CSR signature for %s", name)


def process_csr_request(request: Request, csr: x509.CertificateSigningRequest, name: str) -> NodeCertificate:
    """Verify CSR and issue certificate"""

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

    TapirCertificate(
        name=name,
        issuer=x509_certificate.issuer.rfc4514_string(),
        subject=x509_certificate.subject.rfc4514_string(),
        certificate=x509_certificate.public_bytes(serialization.Encoding.PEM).decode(),
        serial=str(x509_certificate.serial_number),
        not_valid_before=x509_certificate.not_valid_before_utc,
        not_valid_after=x509_certificate.not_valid_after_utc,
    ).save()

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
        x509_certificate_not_valid_after=x509_certificate.not_valid_after_utc,
    )


def generate_ca_certificate(
    issuer_ca_name: x509.Name,
    issuer_ca_private_key: PrivateKey,
    root_ca_name: x509.Name | None = None,
    root_ca_private_key: PrivateKey | None = None,
    validity_days: int = 1,
) -> x509.Certificate:
    """Generate CA Certificate"""

    now = datetime.now(tz=timezone.utc)
    validity = timedelta(days=validity_days)

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

    private_key = root_ca_private_key or issuer_ca_private_key

    return builder.sign(
        private_key=private_key,
        algorithm=get_hash_algorithm_from_key(private_key),
    )
