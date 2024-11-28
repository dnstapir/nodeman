from jwcrypto.jwk import JWK


def jwk_to_alg(key: JWK) -> str:
    match (key.kty, key.get("crv")):
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
    raise ValueError
