from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from nodeman.step import StepSignResponse


class TestStepClient:
    def __init__(self):
        self.ca_name = "ca.example.com"
        self.ca_url = "https://ca.example.com"

    def sign_csr(self, csr: x509.CertificateSigningRequest, name: str) -> StepSignResponse:
        now = datetime.now(tz=timezone.utc)
        one_day = timedelta(days=1)
        ca_private_key = ec.generate_private_key(ec.SECP256R1())

        # build CA certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name)]))
        builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name)]))
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + one_day)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(ca_private_key.public_key())
        builder = builder.add_extension(x509.IssuerAlternativeName([x509.DNSName(self.ca_name)]), critical=False)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        ca_certificate = builder.sign(
            private_key=ca_private_key,
            algorithm=hashes.SHA256(),
        )

        # build client certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name)]))
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + one_day)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(csr.public_key())
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        certificate = builder.sign(
            private_key=ca_private_key,
            algorithm=hashes.SHA256(),
        )

        return StepSignResponse(cert_chain=[certificate], ca_cert=ca_certificate)
