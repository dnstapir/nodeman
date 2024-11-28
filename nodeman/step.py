import atexit
import os
import tempfile
import time
import uuid
from urllib.parse import urljoin

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT

from .jose import jwk_to_alg
from .x509 import CertificateAuthorityClient, CertificateInformation


class StepClient(CertificateAuthorityClient):
    def __init__(self, ca_url: str, ca_fingerprint: str, provisioner_name: str, provisioner_jwk: JWK):
        self.ca_url = ca_url
        self.ca_fingerprint = ca_fingerprint
        self.provisioner_name = provisioner_name
        self.provisioner_jwk = provisioner_jwk
        self.ca_bundle_filename = self._get_root_ca_cert()
        self.token_ttl = 300

    def sign_csr(self, csr: x509.CertificateSigningRequest, name: str) -> CertificateInformation:
        csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM).decode()
        token = self._get_token(name)
        response = httpx.post(
            urljoin(self.ca_url, "1.0/sign"),
            verify=self.ca_bundle_filename,
            json={"csr": csr_pem, "ott": token},
        )
        response.raise_for_status()
        payload = response.json()
        return CertificateInformation(
            cert_chain=[x509.load_pem_x509_certificate(cert.encode()) for cert in payload["certChain"]],
            ca_cert=x509.load_pem_x509_certificate(payload["ca"].encode()),
        )

    def _get_token(self, name: str) -> str:
        now = int(time.time())
        claims: dict[str, str | int | list[str]] = {
            "aud": urljoin(self.ca_url, "/1.0/sign"),
            "sha": self.ca_fingerprint,
            "iat": now,
            "nbf": now,
            "exp": now + self.token_ttl,
            "jti": str(uuid.uuid4()),
            "iss": self.provisioner_name,
            "sub": name,
            "sans": [name],
        }
        alg = self.provisioner_jwk.get("alg", jwk_to_alg(self.provisioner_jwk))
        token = JWT(header={"alg": alg, "kid": self.provisioner_jwk.key_id}, claims=claims)
        token.make_signed_token(key=self.provisioner_jwk)
        return token.serialize()

    def _get_root_ca_cert(self) -> str:
        """Get root CA cert and return temporary filename"""
        response = httpx.get(urljoin(self.ca_url, f"root/{self.ca_fingerprint}"), verify=False)
        response.raise_for_status()
        root_ca_pem = response.json()["ca"]
        self._compare_fingerprints(root_ca_pem, self.ca_fingerprint)
        return self._save_tempfile(root_ca_pem.encode())

    def _save_tempfile(self, contents: bytes) -> str:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".pem") as fp:
            fp.write(contents)
        atexit.register(self._tempfile_unlinker(fp.name))
        return str(fp.name)

    def _tempfile_unlinker(self, fn):
        return lambda: os.unlink(fn)

    @staticmethod
    def _compare_fingerprints(pem: str, fingerprint: str) -> None:
        cert = x509.load_pem_x509_certificate(str.encode(pem))
        if cert.fingerprint(hashes.SHA256()) != bytes.fromhex(fingerprint):
            raise ConnectionError("Fingerprint mismatch")
