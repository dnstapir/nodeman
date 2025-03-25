import asyncio
import logging
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

PASSWORD_VERIFIERS_LIMIT = 2

logger = logging.getLogger(__name__)

security = HTTPBasic()

verify_password_semaphore = asyncio.Semaphore(PASSWORD_VERIFIERS_LIMIT)


async def get_current_username(
    request: Request,
    credentials: Annotated[HTTPBasicCredentials, Depends(security)],
):
    if user := request.app.users.get(credentials.username):
        async with verify_password_semaphore:
            if user.verify_password(credentials.password):
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
