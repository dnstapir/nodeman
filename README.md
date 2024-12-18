# DNS TAPIR Node Manager

This repository contains the DNS TAPIR Node Manager, a server component for managing nodes.


## Enrollment

### Request

The enrollment request is a JWS sign with both the data key (algorithm depending on key algorithm) and the enrollment secret (algorithm `HS256`). JWS payload is a dictionary with the following properties:

- `timestamp`, A timestamp with the current time (ISO8601)
- `x509_csr`, A string with a PEM-encoded X.509 Certificate Signing Request with _Common Name_ and _Subject Alterantive Name_ set to the full node name.
- `public_key`, A JWK dictionary containing the public data key.

### Response

The enrollment response is a dictionary containing at least the following properties:

- `x509_certificate`, X.509 Client Certificate Bundle (PEM)
- `x509_ca_certificate`, X.509 CA Certificate Bundle (PEM)
- `mqtt_broker`, MQTT broker address (URI)
- `mqtt_topics`, Dictionary of per application MQTT configuration topic
- `trusted_jwks`, JWKSet with keys used for signing data from core services


## Renewal

### Request

The renewal request is a JWS sign with the data key (algorithm depending on key algorithm). JWS payload is a dictionary with the following properties:

- `timestamp`, A timestamp with the current time (ISO8601)
- `x509_csr`, A string with a PEM-encoded X.509 Certificate Signing Request with _Common Name_ and _Subject Alterantive Name_ set to the full node name.

### Response

The enrollment response is a dictionary containing at least the following properties:

- `x509_certificate`, X.509 Client Certificate Bundle (PEM)
- `x509_ca_certificate`, X.509 CA Certificate Bundle (PEM)
