from datetime import datetime, timedelta, timezone
from pathlib import Path
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
        issuer_ca_certificate: x509.Certificate,
        issuer_ca_private_key: PrivateKey,
        root_ca_certificate: x509.Certificate | None = None,
        validity_days: int = 1,
        validity: timedelta | None = None,
        time_skew: timedelta | None = None,
    ):
        self.issuer_ca_certificate = issuer_ca_certificate
        self.issuer_ca_private_key = issuer_ca_private_key
        self.root_ca_certificate = root_ca_certificate or issuer_ca_certificate
        self.time_skew = time_skew or timedelta(minutes=10)
        self.validity = validity or timedelta(days=validity_days)
        self.signature_hash_algorithm = get_hash_algorithm_from_key(self.issuer_ca_private_key)

    @classmethod
    def load(
        cls,
        issuer_ca_certificate_file: Path,
        issuer_ca_private_key_file: Path,
        root_ca_certificate_file: Path | None = None,
        validity_days: int = 1,
        time_skew: timedelta | None = None,
    ) -> Self:
        with open(issuer_ca_certificate_file, "rb") as fp:
            issuer_ca_certificate = x509.load_pem_x509_certificate(fp.read())

        with open(issuer_ca_private_key_file, "rb") as fp:
            issuer_ca_private_key = load_pem_private_key(fp.read(), password=None)

        if root_ca_certificate_file:
            with open(root_ca_certificate_file, "rb") as fp:
                root_ca_certificate = x509.load_pem_x509_certificate(fp.read())
        else:
            root_ca_certificate = None

        return cls(
            issuer_ca_certificate=issuer_ca_certificate,
            issuer_ca_private_key=issuer_ca_private_key,
            root_ca_certificate=root_ca_certificate,
            validity_days=validity_days,
            time_skew=time_skew,
        )

    def sign_csr(self, csr: x509.CertificateSigningRequest, name: str) -> CertificateInformation:
        """Sign CSR with CA private key"""

        now = datetime.now(tz=timezone.utc)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        builder = builder.issuer_name(self.issuer_ca_certificate.subject)
        builder = builder.not_valid_before(now - self.time_skew)
        builder = builder.not_valid_after(now + self.validity)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(csr.public_key())

        builder = builder.add_extension(self.KEY_USAGE, critical=True)
        builder = builder.add_extension(self.EXTENDED_KEY_USAGE, critical=False)

        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self.issuer_ca_certificate.public_key()), critical=False
        )
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )

        certificate = builder.sign(private_key=self.issuer_ca_private_key, algorithm=self.signature_hash_algorithm)

        if self.root_ca_certificate != self.issuer_ca_certificate:
            cert_chain = [certificate, self.issuer_ca_certificate]
        else:
            cert_chain = [certificate]

        return CertificateInformation(cert_chain=cert_chain, ca_cert=self.root_ca_certificate)
