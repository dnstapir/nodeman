from datetime import datetime, timedelta, timezone
from typing import Self

from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from nodeman.x509 import CertificateAuthorityClient, CertificateInformation, PrivateKey, get_hash_algorithm_from_key


class InternalCertificateAuthority(CertificateAuthorityClient):
    """Internal CA"""

    KEY_USAGE = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )

    EXTENDED_KEY_USAGE = x509.ExtendedKeyUsage(
        usages=[
            ExtendedKeyUsageOID.CLIENT_AUTH,
            ExtendedKeyUsageOID.SERVER_AUTH,
        ]
    )

    def __init__(
        self,
        ca_certificate: x509.Certificate,
        ca_private_key: PrivateKey,
        validity: timedelta | None = None,
        time_skew: timedelta | None = None,
    ):
        self.ca_certificate = ca_certificate
        self.ca_private_key = ca_private_key
        self.time_skew = time_skew or timedelta(minutes=10)
        self.validity = validity or timedelta(minutes=10)
        self.signature_hash_algorithm = get_hash_algorithm_from_key(self.ca_private_key)

    @classmethod
    def load(
        cls,
        ca_certificate_file: str,
        ca_private_key_file: str,
        validity: timedelta | None = None,
        time_skew: timedelta | None = None,
    ) -> Self:
        with open(ca_certificate_file, "rb") as fp:
            ca_certificate = x509.load_pem_x509_certificate(fp.read())

        with open(ca_private_key_file, "rb") as fp:
            ca_private_key = load_pem_private_key(fp.read())
            if not isinstance(ca_private_key, PrivateKey):
                raise ValueError("Unsupported private key algorithm")

        return cls(ca_certificate=ca_certificate, ca_private_key=ca_private_key, validity=validity, time_skew=time_skew)

    def sign_csr(self, csr: x509.CertificateSigningRequest, name: str) -> CertificateInformation:
        """Sign CSR with CA private key"""

        now = datetime.now(tz=timezone.utc)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        builder = builder.issuer_name(self.ca_certificate.subject)
        builder = builder.not_valid_before(now - self.time_skew)
        builder = builder.not_valid_after(now + self.validity)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(csr.public_key())

        builder = builder.add_extension(self.KEY_USAGE, critical=True)
        builder = builder.add_extension(self.EXTENDED_KEY_USAGE, critical=False)

        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_certificate.public_key()), critical=False
        )
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )

        certificate = builder.sign(private_key=self.ca_private_key, algorithm=self.signature_hash_algorithm)

        return CertificateInformation(cert_chain=[certificate], ca_cert=self.ca_certificate)
