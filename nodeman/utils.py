from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID
from jwcrypto.jwk import JWK

type PrivateKey = ec.EllipticCurvePrivateKey


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


def jwk_to_alg(key: JWK) -> str:
    match (key.kty, key.get("crv")):
        case ("RSA", None):
            return "RS256"
        case ("EC", "P-256"):
            return "ES256"
        case ("EC", "P-384"):
            return "ES384"
        case ("OKP", "Ed25519"):
            return "EdDSA"
        case ("OKP", "Ed448"):
            return "EdDSA"
    raise ValueError
