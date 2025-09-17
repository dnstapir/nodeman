import logging
from binascii import hexlify
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Self

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from nodeman.x509 import (
    CertificateAuthorityClient,
    CertificateInformation,
    CertificateRequestRefused,
    PrivateKey,
    verify_x509_csr_data,
    verify_x509_csr_signature,
)


class InternalCertificateAuthority(CertificateAuthorityClient):
    """Internal CA"""

    KEY_USAGE = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
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
        default_validity: timedelta,
        root_ca_certificate: x509.Certificate | None = None,
        max_validity: timedelta | None = None,
        min_validity: timedelta | None = None,
        time_skew: timedelta | None = None,
    ):
        self.logger = logging.getLogger(__name__).getChild(self.__class__.__name__)
        self.issuer_ca_certificate = issuer_ca_certificate
        self.issuer_ca_private_key = issuer_ca_private_key
        self.root_ca_certificate = root_ca_certificate or issuer_ca_certificate
        self.time_skew = timedelta(minutes=10) if time_skew is None else time_skew
        self.default_validity = default_validity
        self.max_validity = max_validity or self.default_validity
        self.min_validity = min_validity or self.default_validity

        # Invariants
        if self.time_skew < timedelta(0):
            raise ValueError("time_skew must be non-negative")
        if self.min_validity < timedelta(0) or self.max_validity < timedelta(0):
            raise ValueError("validity bounds must be positive")
        if self.min_validity > self.max_validity:
            raise ValueError("min_validity must be ≤ max_validity")
        if not (self.min_validity <= self.default_validity <= self.max_validity):
            raise ValueError("default_validity must lie within [min_validity, max_validity]")

    @classmethod
    def load(
        cls,
        issuer_ca_certificate_file: Path,
        issuer_ca_private_key_file: Path,
        default_validity: timedelta,
        root_ca_certificate_file: Path | None = None,
        max_validity: timedelta | None = None,
        min_validity: timedelta | None = None,
        time_skew: timedelta | None = None,
    ) -> Self:
        with open(issuer_ca_certificate_file, "rb") as fp:
            issuer_ca_certificate = x509.load_pem_x509_certificate(fp.read())

        with open(issuer_ca_private_key_file, "rb") as fp:
            issuer_ca_private_key = load_pem_private_key(fp.read(), password=None)
        if not isinstance(
            issuer_ca_private_key, RSAPrivateKey | EllipticCurvePrivateKey | Ed25519PrivateKey | Ed448PrivateKey
        ):
            raise ValueError("Unsupported private key type")

        if root_ca_certificate_file:
            with open(root_ca_certificate_file, "rb") as fp:
                root_ca_certificate = x509.load_pem_x509_certificate(fp.read())
        else:
            root_ca_certificate = None

        return cls(
            issuer_ca_certificate=issuer_ca_certificate,
            issuer_ca_private_key=issuer_ca_private_key,
            root_ca_certificate=root_ca_certificate,
            default_validity=default_validity,
            max_validity=max_validity,
            min_validity=min_validity,
            time_skew=time_skew,
        )

    @property
    def ca_fingerprint(self) -> str:
        return hexlify(self.issuer_ca_certificate.fingerprint(hashes.SHA256())).decode()

    def sign_csr(
        self,
        csr: x509.CertificateSigningRequest,
        name: str,
        requested_validity: timedelta | None = None,
    ) -> CertificateInformation:
        """Sign CSR with CA private key"""

        self.logger.debug("Processing CSR from %s", name)

        verify_x509_csr_signature(csr=csr, name=name)

        # not strictly required since we don't use anything except the public key from the CSR
        verify_x509_csr_data(csr=csr, name=name)

        if requested_validity is not None:
            if self.min_validity <= requested_validity <= self.max_validity:
                validity = requested_validity
                self.logger.debug("Using requested certificate validity %s for %s", requested_validity, name)
            else:
                self.logger.error(
                    "Refusing requested certificate validity %s for %s (allowed: %s..%s)",
                    requested_validity,
                    name,
                    self.min_validity,
                    self.max_validity,
                )
                raise CertificateRequestRefused(
                    f"Requested validity {requested_validity} outside allowed range "
                    f"[{self.min_validity}, {self.max_validity}]"
                )
        else:
            validity = self.default_validity

        now = datetime.now(tz=UTC)
        not_valid_before = now - self.time_skew
        not_valid_after = now + validity

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        builder = builder.issuer_name(self.issuer_ca_certificate.subject)
        builder = builder.not_valid_before(not_valid_before)
        builder = builder.not_valid_after(not_valid_after)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(csr.public_key())

        builder = builder.add_extension(self.KEY_USAGE, critical=True)
        builder = builder.add_extension(self.EXTENDED_KEY_USAGE, critical=False)

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self.issuer_ca_certificate.public_key()),
            critical=False,
        )
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name)]),
            critical=False,
        )
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )

        certificate = builder.sign(
            private_key=self.issuer_ca_private_key,
            algorithm=self.issuer_ca_certificate.signature_hash_algorithm,
        )

        if self.root_ca_certificate != self.issuer_ca_certificate:
            cert_chain = [certificate, self.issuer_ca_certificate]
        else:
            cert_chain = [certificate]

        return CertificateInformation(cert_chain=cert_chain, ca_cert=self.root_ca_certificate)
