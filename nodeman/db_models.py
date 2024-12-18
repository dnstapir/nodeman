import logging
from contextlib import suppress
from typing import Self

from mongoengine import DateTimeField, DictField, Document, StringField
from mongoengine.errors import NotUniqueError

from .names import get_deterministic_name, get_random_name

logger = logging.getLogger(__name__)


class TapirNode(Document):
    meta = {"collection": "nodes"}

    name = StringField(unique=True)
    domain = StringField()
    public_key = DictField()

    activated = DateTimeField()
    deleted = DateTimeField()

    @classmethod
    def create_random_node(cls, domain: str) -> Self:
        name = get_random_name() + "." + domain
        return cls(name=name)

    @classmethod
    def create_next_node(cls, domain: str) -> Self:
        next_node_idx = len(cls.objects(domain=domain))
        while True:
            name = ".".join([get_deterministic_name(next_node_idx), domain])
            with suppress(NotUniqueError):
                return cls(name=name, domain=domain).save()
            next_node_idx += 1
            logging.debug("Name conflict, trying %d", next_node_idx)


class TapirNodeEnrollment(Document):
    meta = {"collection": "enrollments"}

    name = StringField(unique=True)
    key = DictField()
