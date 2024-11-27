import argparse
import json
import logging
from contextlib import asynccontextmanager

import mongoengine
import uvicorn
from fastapi import FastAPI
from opentelemetry import trace
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

import nodeman.extras
import nodeman.nodes
from dnstapir.logging import configure_json_logging
from dnstapir.opentelemetry import configure_opentelemetry

from . import OPENAPI_METADATA, __verbose_version__
from .settings import Settings

logger = logging.getLogger(__name__)

tracer = trace.get_tracer("nodeman.tracer")


class NodemanServer(FastAPI):
    def __init__(self, settings: Settings):
        self.logger = logging.getLogger(__name__).getChild(self.__class__.__name__)
        self.settings = settings
        super().__init__(**OPENAPI_METADATA, lifespan=self.lifespan)
        self.add_middleware(ProxyHeadersMiddleware)
        self.include_router(nodeman.nodes.router)
        self.include_router(nodeman.extras.router)
        if self.settings.otlp:
            configure_opentelemetry(
                service_name="nodeman",
                settings=self.settings.otlp,
                fastapi_app=self,
            )
        else:
            self.logger.info("Configured without OpenTelemetry")

        self.trusted_keys = []
        if self.settings.nodes.trusted_keys:
            with open(self.settings.nodes.trusted_keys) as fp:
                keys = json.load(fp)
                self.trusted_keys = keys.get("keys", [])

    def connect_mongodb(self):
        if mongodb_host := str(self.settings.mongodb.server):
            params = {"host": mongodb_host}
            if "host" in params and params["host"].startswith("mongomock://"):
                import mongomock

                params["host"] = params["host"].replace("mongomock://", "mongodb://")
                params["mongo_client_class"] = mongomock.MongoClient
            logger.info("Connecting to MongoDB %s", params)
            mongoengine.connect(**params, tz_aware=True)
            logger.info("MongoDB connected")

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
    parser.add_argument("--debug", action="store_true", help="Enable debugging")
    parser.add_argument("--version", action="store_true", help="Show version")

    args = parser.parse_args()

    if args.version:
        print(f"Node Manager version {__verbose_version__}")
        return

    logging_config = configure_json_logging()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        log_level = "debug"
    else:
        logging.basicConfig(level=logging.INFO)
        log_level = "info"

    logger.info("Starting Node Manager version %s", __verbose_version__)
    app = NodemanServer(settings=Settings())

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_config=logging_config,
        log_level=log_level,
        headers=[("server", f"dnstapir-nodeman/{__verbose_version__}")],
    )


if __name__ == "__main__":
    main()
