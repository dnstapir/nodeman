import asyncio
import logging
import re
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

PASSWORD_VERIFIERS_LIMIT = 2

USERNAME_RE = re.compile(r"^[a-z0-9]{1,255}$")

logger = logging.getLogger(__name__)

security = HTTPBasic()

verify_password_semaphore = asyncio.Semaphore(PASSWORD_VERIFIERS_LIMIT)

# Set containing SHA-256 of verified credentials
# (username, password hash and plaintext password)
cached_credentials: set[bytes] = set()


async def get_current_username(
    request: Request,
    credentials: Annotated[HTTPBasicCredentials, Depends(security)],
):
    if not USERNAME_RE.match(credentials.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid username",
        )

    if user := request.app.users.get(credentials.username):
        # Accept already verified credentials
        credentials_hash = user.get_combined_hash(credentials.password)
        if credentials_hash in cached_credentials:
            return True

        # Limit number of concurrent password verifications using semaphore
        async with verify_password_semaphore:
            if user.verify_password(credentials.password):
                cached_credentials.add(credentials_hash)
                logger.debug("Verified password for user %s", credentials.username)
                return credentials.username
            else:
                logger.warning("Invalid password for user %s", credentials.username)
    else:
        logger.warning("Unknown user %s", credentials.username)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Basic"},
    )
