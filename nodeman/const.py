from enum import StrEnum
from typing import Self


class PublicKeyFormat(StrEnum):
    PEM = "application/x-pem-file"
    JWK = "application/jwk+json"

    @classmethod
    def from_accept(cls, accept: str | None) -> Self:
        if accept is None or cls.JWK in accept or "application/json" in accept:
            return cls.JWK
        elif cls.PEM in accept:
            return cls.PEM
        raise ValueError(f"Unsupported format. Acceptable formats: {[f.value for f in cls]}")
