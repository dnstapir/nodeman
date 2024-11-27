from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK

from nodeman.settings import StepSettings
from nodeman.step import StepClient
from nodeman.utils import generate_x509_csr


def test_step_ca() -> None:
    """Test Step CA client"""

    try:
        with open("root_ca_fingerprint.txt") as fp:
            ca_fingerprint = fp.read().rstrip()
    except FileNotFoundError:
        return

    settings = StepSettings(
        ca_url="https://localhost:9000",
        ca_fingerprint=ca_fingerprint,
        provisioner_name="test",
        provisioner_private_key=Path("provisioner_private.json"),
    )

    with open(str(settings.provisioner_private_key)) as fp:
        provisioner_jwk = JWK.from_json(fp.read())

    name = "xyzzy"
    key = ec.generate_private_key(ec.SECP256R1())
    csr = generate_x509_csr(key=key, name=name)

    client = StepClient(
        ca_url=str(settings.ca_url),
        ca_fingerprint=settings.ca_fingerprint,
        provisioner_name=settings.provisioner_name,
        provisioner_jwk=provisioner_jwk,
    )
    res = client.sign_csr(csr, name)
    print(res)
