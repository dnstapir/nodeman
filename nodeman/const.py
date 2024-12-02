from enum import StrEnum
from typing import Self

MIME_TYPE_JWK = "application/jwk+json"
MIME_TYPE_PEM = "application/x-pem-file"


class PublicKeyFormat(StrEnum):
    PEM = MIME_TYPE_PEM
    JWK = MIME_TYPE_JWK

    @classmethod
    def from_accept(cls, accept: str) -> Self:
        if MIME_TYPE_PEM in accept:
            return cls.PEM
        if accept is None or MIME_TYPE_JWK in accept or "application/json" in accept:
            return cls.JWK
        raise ValueError
