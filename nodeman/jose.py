from typing import Annotated

from jwcrypto.common import base64url_decode
from jwcrypto.jwk import JWK
from pydantic import BaseModel
from pydantic.types import StringConstraints

Base64UrlString = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]+$")]


class BaseJWK(BaseModel):
    """RFC 7517: JSON Web Key (JWK)"""

    kty: str
    kid: str | None = None
    alg: str | None = None


class PublicRSA(BaseJWK):
    """JWK: Public RSA key"""

    kty: Annotated[str, StringConstraints(pattern=r"^RSA$")]
    n: Base64UrlString
    e: Base64UrlString


class PrivateRSA(PublicRSA):
    d: Base64UrlString
    p: Base64UrlString
    q: Base64UrlString


class PublicEC(BaseJWK):
    """JWK: Public EC key (P-256/P-384)"""

    kty: Annotated[str, StringConstraints(pattern=r"^EC$")]
    crv: Annotated[str, StringConstraints(pattern=r"^P-(256|384)$")]
    x: Base64UrlString
    y: Base64UrlString


class PrivateEC(PublicEC):
    d: Base64UrlString


class PublicOKP(BaseJWK):
    """JWK: Public OKP key"""

    kty: Annotated[str, StringConstraints(pattern=r"^OKP$")]
    crv: Annotated[str, StringConstraints(pattern=r"^(Ed|X)(25519|448)$")]
    x: Base64UrlString


class PrivateOKP(PublicOKP):
    d: Base64UrlString


class PrivateSymmetric(BaseJWK):
    """JWK: Private symmetric key"""

    kty: Annotated[str, StringConstraints(pattern=r"^oct$")]
    k: Base64UrlString


PublicJwk = PublicRSA | PublicEC | PublicOKP
PrivateJwk = PrivateRSA | PrivateEC | PrivateOKP


class PublicJwks(BaseModel):
    keys: list[PublicJwk]


def public_key_factory(jwk_dict: dict[str, str]) -> PublicJwk:
    match jwk_dict.get("kty"):
        case "RSA":
            return PublicRSA(**jwk_dict)
        case "EC":
            return PublicEC(**jwk_dict)
        case "OKP":
            return PublicOKP(**jwk_dict)
        case _:
            raise ValueError("Unsupported key type")


def jwk_to_alg(key: JWK) -> str:
    kty = str(key.kty)
    crv = key.get("crv")
    match (kty, crv):
        case ("RSA", None):
            return "RS256"
        case ("EC", "P-256"):
            return "ES256"
        case ("EC", "P-384"):
            return "ES384"
        case ("OKP", "Ed25519"):
            return "EdDSA"
        case ("OKP", "Ed448"):
            return "EdDSA"
    raise ValueError(f"Unsupported key type: {kty}" + (f" with curve: {crv}" if crv else ""))


def generate_similar_jwk(key: JWK) -> JWK:
    """Generate similar JWK"""

    params = {param: key.get(param) for param in ["kty", "crv"] if param in key}
    match key.get("kty"):
        case "RSA":
            params["size"] = key._get_public_key().key_size
        case "oct":
            params["size"] = len(base64url_decode(key.k)) * 8
        case _:
            pass
    return JWK.generate(**params)
