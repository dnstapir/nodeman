from cryptography.hazmat.primitives.asymmetric import ec

from nodeman.x509 import generate_x509_csr, verify_x509_csr
from tests.utils import CaTestClient


def test_dummy_ca() -> None:
    """Test dummy CA client"""

    ca_client = CaTestClient()

    name = "hostname.example.com"
    key = ec.generate_private_key(ec.SECP256R1())
    csr = generate_x509_csr(key=key, name=name)

    verify_x509_csr(name=name, csr=csr)

    res = ca_client.sign_csr(csr, name)
    print(res)
