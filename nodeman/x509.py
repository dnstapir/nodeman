from abc import ABC, abstractmethod
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID

type PrivateKey = ec.EllipticCurvePrivateKey


@dataclass(frozen=True)
class CertificateInformation:
    cert_chain: list[x509.Certificate]
    ca_cert: x509.Certificate


class CertificateAuthorityClient(ABC):
    @abstractmethod
    def sign_csr(self, csr: x509.CertificateSigningRequest, name: str) -> CertificateInformation:
        pass


def generate_x509_csr(name: str, key: PrivateKey) -> x509.CertificateSigningRequest:
    """Generate X.509 CSR with name and key"""
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )


def verify_x509_csr(name: str, csr: x509.CertificateSigningRequest) -> None:
    """Verify X.509 CSR against name"""

    # ensure Subject is correct
    if len(csr.subject) != 1:
        raise ValueError("Invalid Subject")
    cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(cn) == 0:
        raise ValueError("Missing CommonName")
    elif len(cn) > 1:
        raise ValueError("Multiple CommonName")
    elif cn[0].value != name:
        raise ValueError("Invalid CommonName")

    # ensure we only have a single extension
    if len(csr.extensions) != 1:
        raise ValueError("Multiple extensions")

    # ensure SubjectAlternativeName is correct
    ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if ext.value.get_values_for_type(x509.DNSName) != [name]:
        raise ValueError("Invalid SubjectAlternativeName")
