CONTAINER=		ghcr.io/dnstapir/nodeman:latest
CONTAINER_BASE=		nodeman:latest
BUILDINFO=		nodeman/buildinfo.py
OPENAPI=		nodeman-api.yaml

DEPENDS=		$(BUILDINFO)


all: $(DEPENDS) $(PUBLIC_KEYS)

$(BUILDINFO):
	printf "__commit__ = \"`git rev-parse HEAD`\"\n__timestamp__ = \"`date +'%Y-%m-%d %H:%M:%S %Z'`\"\n" > $(BUILDINFO)

openapi: $(OPENAPI)

$(OPENAPI): $(DEPENDS)
	poetry run python tools/export_openapi_yaml.py > $@

container: $(DEPENDS)
	docker buildx build -t $(CONTAINER) -t $(CONTAINER_BASE) .

push-container:
	docker push $(CONTAINER)

server: $(DEPENDS) $($(PUBLIC_KEYS))
	poetry run nodeman_server --host 127.0.0.1 --port 8080 --debug

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
	rm -f $(PUBLIC_KEYS) $(PRIVATE_KEYS)
	rm -f $(BUILDINFO) $(OPENAPI)

realclean: clean
	poetry env remove --all
