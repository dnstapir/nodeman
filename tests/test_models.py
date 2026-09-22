import random
import string

from requests import Request

from nodeman.db_models import TapirRequestMetadata

USER_AGENT = "pytest/0.0"


def test_request_metadata_ok():
    """Test that a valid user-agent is correctly parsed."""

    request = Request(
        method="GET",
        url="http://example.com",
        headers={"user-agent": USER_AGENT},
    )

    trm = TapirRequestMetadata.from_request(request)
    assert trm is not None
    assert trm.user_agent == USER_AGENT
    assert trm.ip_address is None
    assert trm.port is None


def test_request_metadata_missing_user_agent():
    """Test that a missing user-agent results in None."""

    request = Request(
        method="GET",
        url="http://example.com",
    )

    trm = TapirRequestMetadata.from_request(request)
    assert trm is not None
    assert trm.user_agent is None
    assert trm.ip_address is None
    assert trm.port is None


def test_request_metadata_truncated_user_agent():
    """Test that a user-agent longer than 1024 characters is truncated."""

    user_agent = random.choice(string.ascii_letters) * 2048

    request = Request(
        method="GET",
        url="http://example.com",
        headers={"user-agent": user_agent},
    )

    trm = TapirRequestMetadata.from_request(request)
    assert trm is not None
    assert trm.user_agent == user_agent[:1024]
    assert trm.ip_address is None
    assert trm.port is None
