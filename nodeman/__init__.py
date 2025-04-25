from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("nodeman")
except PackageNotFoundError:
    __version__ = "0.0.0"

try:
    from .buildinfo import __commit__, __timestamp__

    __verbose_version__ = f"{__version__} ({__commit__})"
except ModuleNotFoundError:
    __verbose_version__ = __version__
    __commit__ = None
    __timestamp__ = None
    pass


OPENAPI_METADATA = {
    "title": "DNS TAPIR Node Manager",
    "description": "The DNS TAPIR Node Manager is a server component used for managing DNS TAPIR keys.",
    "version": __version__,
    "contact": {
        "name": "Jakob Schlyter",
        "email": "jakob@kirei.se",
    },
    "openapi_tags": [
        {"name": "client", "description": "Client operations"},
        {"name": "backend", "description": "Backend operations"},
    ],
}
