import logging
from abc import ABC, abstractmethod
from binascii import hexlify
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier

RSA_EXPONENT = 65537
type PrivateKey = RSAPrivateKey | EllipticCurvePrivateKey | Ed25519PrivateKey | Ed448PrivateKey

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CertificateInformation:
    cert_chain: list[x509.Certificate]
    ca_cert: x509.Certificate


class CertificateRequestRefused(ValueError):
    pass


class CertificateAuthorityClient(ABC):
    @abstractmethod
    def sign_csr(
        self,
        csr: x509.CertificateSigningRequest,
        name: str,
        requested_validity: timedelta | None = None,
    ) -> CertificateInformation:
        pass


def get_hash_algorithm_from_key(key: PrivateKey) -> hashes.HashAlgorithm | None:
    """Get hash algorithm for private key"""
    if isinstance(key, RSAPrivateKey):
        return hashes.SHA256()
    elif isinstance(key, EllipticCurvePrivateKey):
        return hashes.SHA384() if isinstance(key.curve, ec.SECP384R1) else hashes.SHA256()
    elif isinstance(key, Ed25519PrivateKey | Ed448PrivateKey):
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


def get_x509_extensions_hex(x509_certificate: x509.Certificate, oid: ObjectIdentifier) -> str | None:
    """
    Extract and hex-encode an X.509 certificate extension.

    Args:
        x509_certificate: The certificate to extract from
        oid: The extension OID to extract

    Returns:
        Hex-encoded extension value or None if not found
    """
    try:
        ext = x509_certificate.extensions.get_extension_for_oid(oid)
        return hexlify(ext.value.public_bytes()).decode()
    except ExtensionNotFound:
        return None


def verify_x509_csr_signature(csr: x509.CertificateSigningRequest, name: str) -> None:
    """Verify X.509 CSR signature"""

    if not csr.is_signature_valid:
        raise CertificateSigningRequestException("Invalid CSR signature")

    logger.info("Verified CSR signature for %s", name)


def generate_ca_certificate(
    issuer_ca_name: x509.Name,
    issuer_ca_private_key: PrivateKey,
    root_ca_name: x509.Name | None = None,
    root_ca_private_key: PrivateKey | None = None,
    validity_days: int = 1,
) -> x509.Certificate:
    """Generate CA Certificate"""

    now = datetime.now(tz=UTC)
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
