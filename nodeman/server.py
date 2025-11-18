import argparse
import logging
from contextlib import asynccontextmanager
from datetime import timedelta

import mongoengine
import uvicorn
from fastapi import FastAPI
from jwcrypto.jwk import JWK, JWKSet
from opentelemetry import trace
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

import nodeman.extras
import nodeman.healthcheck
import nodeman.nodes
from dnstapir.logging import setup_logging
from dnstapir.opentelemetry import configure_opentelemetry
from dnstapir.starlette import LoggingMiddleware

from . import OPENAPI_METADATA, __verbose_version__
from .internal_ca import InternalCertificateAuthority
from .settings import InternalCaSettings, Settings, StepSettings
from .step import StepClient
from .x509 import CertificateAuthorityClient

logger = logging.getLogger(__name__)

tracer = trace.get_tracer("nodeman.tracer")


class NodemanServer(FastAPI):
    def __init__(self, settings: Settings):
        self.logger = logging.getLogger(__name__).getChild(self.__class__.__name__)
        self.settings = settings
        super().__init__(**OPENAPI_METADATA, lifespan=self.lifespan)

        self.add_middleware(LoggingMiddleware)
        self.add_middleware(ProxyHeadersMiddleware, trusted_hosts=[str(x) for x in self.settings.http.trusted_hosts])

        self.include_router(nodeman.nodes.router)
        self.include_router(nodeman.healthcheck.router)
        self.include_router(nodeman.extras.router)

        if self.settings.otlp:
            configure_opentelemetry(
                service_name="nodeman",
                settings=self.settings.otlp,
                fastapi_app=self,
            )
        else:
            self.logger.info("Configured without OpenTelemetry")

        self.trusted_jwks = JWKSet()
        if filename := self.settings.nodes.trusted_jwks:
            try:
                with open(filename) as fp:
                    self.trusted_jwks = JWKSet.from_json(fp.read())
            except OSError as exc:
                self.logger.error("Failed to read trusted keys from %s", filename)
                raise exc
            keys = self.trusted_jwks["keys"] if isinstance(self.trusted_jwks, dict) else []
            self.logger.info("Found %d trusted keys", len(keys))
        else:
            self.logger.warning("Starting without trusted keys")

        self.users = {entry.username: entry for entry in settings.users}
        if self.users:
            for username in self.users:
                self.logger.debug("Configured user '%s'", username)
            self.logger.info("Found %d users", len(self.users))
        else:
            self.logger.warning("Starting without users")

        self.ca_client: CertificateAuthorityClient | None

        if self.settings.internal_ca and self.settings.step:
            self.logger.warning("Multiple CAs configured, using internal CA")

        if self.settings.internal_ca:
            self.ca_client = self.get_internal_ca_client(self.settings.internal_ca)
        elif self.settings.step:
            self.ca_client = self.get_step_client(self.settings.step)
        else:
            self.ca_client = None

        self.generate_enrollment_key_kwargs = self.settings.enrollment.generate_kwargs()
        self.logger.debug("Enrollment key kwargs: %s", self.generate_enrollment_key_kwargs)

    def generate_enrollment_key(self, kid: str | None = None) -> JWK:
        """Generate enrollment key"""
        return JWK.generate(kid=kid, **self.generate_enrollment_key_kwargs)

    def get_internal_ca_client(self, settings: InternalCaSettings) -> InternalCertificateAuthority:
        res = InternalCertificateAuthority.load(
            issuer_ca_certificate_file=settings.issuer_ca_certificate,
            issuer_ca_private_key_file=settings.issuer_ca_private_key,
            root_ca_certificate_file=settings.root_ca_certificate,
            default_validity=timedelta(days=settings.validity_days),
            min_validity=timedelta(seconds=settings.min_validity_seconds) if settings.min_validity_seconds else None,
            max_validity=timedelta(seconds=settings.max_validity_seconds) if settings.max_validity_seconds else None,
            time_skew=timedelta(seconds=settings.time_skew_seconds),
        )
        self.logger.info("Configured Internal CA (%s)", res.ca_fingerprint)
        return res

    def get_step_client(self, settings: StepSettings) -> StepClient:
        if filename := settings.ca_fingerprint_file:
            try:
                with open(filename) as fp:
                    ca_fingerprint = fp.read().rstrip()
            except OSError as exc:
                self.logger.error("Failed to read CA fingerprint file from %s", filename)
                raise exc
        else:
            ca_fingerprint = settings.ca_fingerprint

        try:
            with open(str(settings.provisioner_private_key)) as fp:
                provisioner_jwk = JWK.from_json(fp.read())
        except OSError as exc:
            self.logger.error("Failed to read CA provisioner private key from %s", settings.provisioner_private_key)
            raise exc

        res = StepClient(
            ca_url=str(settings.ca_url),
            ca_fingerprint=ca_fingerprint,
            provisioner_name=settings.provisioner_name,
            provisioner_jwk=provisioner_jwk,
            ca_server_verify=settings.ca_server_verify,
        )
        self.logger.info("Connected to StepCA %s (%s)", res.ca_url, ca_fingerprint)
        return res

    def connect_mongodb(self):
        if mongodb_host := str(self.settings.mongodb.server):
            params = {"host": mongodb_host}
            if "host" in params and params["host"].startswith("mongomock://"):
                import mongomock

                params["host"] = params["host"].replace("mongomock://", "mongodb://")
                params["mongo_client_class"] = mongomock.MongoClient
            self.logger.info("Connecting to MongoDB %s", params)
            mongoengine.connect(**params, tz_aware=True)
            self.logger.info("MongoDB connected")

    @staticmethod
    @asynccontextmanager
    async def lifespan(app: "NodemanServer"):
        app.logger.debug("Lifespan startup")
        app.connect_mongodb()
        yield
        app.logger.debug("Lifespan ended")


def main() -> None:
    """Main function"""

    parser = argparse.ArgumentParser(description="Node Manager")

    parser.add_argument("--host", help="Host address to bind to", default="0.0.0.0")
    parser.add_argument("--port", help="Port to listen on", type=int, default=8080)
    parser.add_argument("--log-json", action="store_true", help="Enable JSON logging")
    parser.add_argument("--debug", action="store_true", help="Enable debugging")
    parser.add_argument("--version", action="store_true", help="Show version")

    args = parser.parse_args()

    if args.version:
        print(f"Node Manager version {__verbose_version__}")
        return

    setup_logging(json_logs=args.log_json, log_level="DEBUG" if args.debug else "INFO")

    logger.info("Starting Node Manager version %s", __verbose_version__)

    settings = Settings()
    app = NodemanServer(settings=settings)

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_config=None,
        log_level=None,
        headers=[("server", f"dnstapir-nodeman/{__verbose_version__}")],
    )


if __name__ == "__main__":
    main()
