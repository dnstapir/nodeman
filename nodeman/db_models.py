import logging
from contextlib import suppress
from typing import Self

import bson
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
from fastapi import Request
from mongoengine import (
    DateTimeField,
    DictField,
    Document,
    EmbeddedDocument,
    EmbeddedDocumentField,
    IntField,
    SortedListField,
    StringField,
    ValidationError,
)
from mongoengine.errors import NotUniqueError

from . import TAG_CHARACTERS
from .names import get_deterministic_name
from .x509 import get_x509_extensions_hex

logger = logging.getLogger(__name__)


class TapirRequestMetadata(EmbeddedDocument):
    user_agent = StringField(max_length=1024)
    ip_address = StringField()
    port = IntField()

    @classmethod
    def from_request(cls, request: Request) -> Self:
        return cls(
            user_agent=(request.headers.get("user-agent") or "")[:1024] or None,
            ip_address=request.client.host if hasattr(request, "client") and request.client else None,
            port=request.client.port if hasattr(request, "client") and request.client else None,
        )


class TapirNode(Document):
    meta = {
        "collection": "nodes",
        "indexes": [
            {"fields": ["tags"]},
        ],
    }

    name = StringField(unique=True)
    domain = StringField()
    public_key = DictField()
    thumbprint = StringField()

    activated = DateTimeField()
    deleted = DateTimeField()

    tags = SortedListField(
        StringField(regex=rf"^{TAG_CHARACTERS}+$", min_length=1, max_length=100),
        max_length=100,
    )

    request_metadata = EmbeddedDocumentField(TapirRequestMetadata)

    @classmethod
    def create_next_node(cls, domain: str, tags: list[str] | None = None) -> Self:
        next_node_idx = len(cls.objects(domain=domain))
        while True:
            name = ".".join([get_deterministic_name(next_node_idx), domain])
            with suppress(NotUniqueError):
                return cls(name=name, domain=domain, tags=tags).save()
            next_node_idx += 1
            logging.debug("Name conflict, trying %d", next_node_idx)

    @classmethod
    def create_random_node(cls, domain: str, tags: list[str] | None = None) -> Self:
        name = ".".join([str(bson.ObjectId()), domain])
        return cls(name=name, domain=domain, tags=tags).save()


class TapirNodeEnrollment(Document):
    meta = {"collection": "enrollments"}

    name = StringField(unique=True)
    key = DictField()


class TapirCertificate(Document):
    meta = {
        "collection": "certificates",
        "indexes": [
            {"fields": ["name"]},
            {"fields": ["issuer", "serial"], "unique": True},
        ],
    }

    name = StringField(required=True)

    issuer = StringField(required=True)
    subject = StringField(required=True)
    serial = StringField(required=True)

    not_valid_before = DateTimeField(required=True)
    not_valid_after = DateTimeField(required=True)

    certificate = StringField(required=True)

    authority_key_identifier = StringField()
    subject_key_identifier = StringField()

    request_metadata = EmbeddedDocumentField(TapirRequestMetadata)

    @classmethod
    def from_x509_certificate(cls, name: str, x509_certificate: x509.Certificate) -> Self:
        return cls(
            name=name,
            issuer=x509_certificate.issuer.rfc4514_string(),
            subject=x509_certificate.subject.rfc4514_string(),
            certificate=x509_certificate.public_bytes(serialization.Encoding.PEM).decode(),
            serial=str(x509_certificate.serial_number),
            not_valid_before=x509_certificate.not_valid_before_utc,
            not_valid_after=x509_certificate.not_valid_after_utc,
            authority_key_identifier=get_x509_extensions_hex(x509_certificate, ExtensionOID.AUTHORITY_KEY_IDENTIFIER),
            subject_key_identifier=get_x509_extensions_hex(x509_certificate, ExtensionOID.SUBJECT_KEY_IDENTIFIER),
        )

    def clean(self):
        """Validate certificate field format"""
        try:
            x509.load_pem_x509_certificate(self.certificate.encode())
        except ValueError as exc:
            raise ValidationError("Invalid certificate PEM format") from exc
