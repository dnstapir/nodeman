CONTAINER=		ghcr.io/dnstapir/nodeman:latest
CONTAINER_BASE=		nodeman:latest
BUILDINFO=		nodeman/buildinfo.py
OPENAPI=		nodeman-api.yaml

DEPENDS=		$(BUILDINFO)

CA_CERT=		root_ca.crt
CA_URL=			https://localhost:9000
CA_PROVISIONER_NAME=	test
CA_PROVISIONER_FILES=	provisioner_private.json provisioner_public.json
CA_FINGERPRINT=		root_ca_fingerprint.txt
CA_PASSWORD=		root_ca_password.txt

STEP_CA_FILES=		$(CA_CERT) $(CA_PASSWORD) $(CA_FINGERPRINT) $(CA_PROVISIONER_FILES)
CLIENT_FILES=		data.json tls.crt tls.key tls-ca.crt

all: $(DEPENDS)

$(BUILDINFO):
	printf "__commit__ = \"`git rev-parse HEAD`\"\n__timestamp__ = \"`date +'%Y-%m-%d %H:%M:%S %Z'`\"\n" > $(BUILDINFO)

openapi: $(OPENAPI)

$(OPENAPI): $(DEPENDS)
	poetry run python tools/export_openapi_yaml.py > $@

container: $(DEPENDS)
	docker buildx build -t $(CONTAINER) -t $(CONTAINER_BASE) .

push-container:
	docker push $(CONTAINER)

server: $(DEPENDS)
	poetry run nodeman_server --host 127.0.0.1 --port 8080 --debug

test-client: test-client-enroll test-client-renew

test-client-enroll:
	rm -f tls.crt tls-ca.crt tls.key data.json
	NODEMAN_USERNAME=username NODEMAN_PASSWORD=password poetry run nodeman_client --debug enroll --create
	step crypto jwk public < data.json
	step certificate inspect tls.crt
	step certificate inspect tls-ca.crt

test-client-renew:
	rm -f tls.crt tls-ca.crt tls.key
	poetry run nodeman_client --debug renew
	step crypto jwk public < data.json
	step certificate inspect tls.crt
	step certificate inspect tls-ca.crt

internal_ca:
	step certificate create root-ca internal_ca_certificate.pem internal_ca_private_key.pem --profile root-ca --insecure --no-password

step:
	docker compose exec step cat /home/step/certs/root_ca.crt > $(CA_CERT)
	docker compose exec step cat secrets/password > $(CA_PASSWORD)
	docker compose exec step step certificate fingerprint /home/step/certs/root_ca.crt > $(CA_FINGERPRINT)
	step crypto jwk create \
		provisioner_public.json \
		provisioner_private.json \
		--kty EC --crv P-256 --insecure --no-password --force
	step ca provisioner add $(CA_PROVISIONER_NAME) --type JWK \
		--ca-url $(CA_URL) --root $(CA_CERT) \
		--public-key provisioner_public.json \
		--admin-provisioner admin \
		--admin-subject step \
		--admin-password-file root_ca_password.txt
	step ca provisioner list --ca-url $(CA_URL) --root $(CA_CERT)

clean-step:
	-step ca provisioner remove $(CA_PROVISIONER_NAME)  \
		--ca-url $(CA_URL) --root $(CA_CERT) \
		--admin-provisioner admin \
		--admin-subject step \
		--admin-password-file root_ca_password.txt
	step ca provisioner list --ca-url $(CA_URL) --root $(CA_CERT)

test: $(DEPENDS)
	poetry run pytest --ruff --ruff-format

coverage:
	poetry run coverage run -m pytest --verbose
	poetry run coverage html

lint:
	poetry run ruff check .

reformat:
	poetry run ruff check --select I --fix .
	poetry run ruff format .

clean:
	rm -f $(STEP_CA_FILES) $(CLIENT_FILES)
	rm -f $(BUILDINFO) $(OPENAPI)

realclean: clean
	poetry env remove --all
