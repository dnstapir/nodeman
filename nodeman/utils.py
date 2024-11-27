from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from jwcrypto.jwk import JWK

type PrivateKey = ec.EllipticCurvePrivateKey


def generate_x509_csr(name: str, key: PrivateKey) -> bytes:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def verify_x509_csr(name: str, csr_pem: str) -> None:
    _ = x509.load_pem_x509_csr(csr_pem.encode())


def jwk_to_alg(key: JWK) -> str:
    match (key.kty, key.get("crv")):
        case ("RSA", None):
            return "RS256"
        case ("EC", "P256"):
            return "ES256"
        case ("EC", "P384"):
            return "ES384"
        case ("OKP", "Ed25519"):
            return "EdDSA"
        case ("OKP", "Ed448"):
            return "EdDSA"
    raise ValueError
