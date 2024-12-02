import logging
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

logger = logging.getLogger(__name__)

security = HTTPBasic()


def get_current_username(
    request: Request,
    credentials: Annotated[HTTPBasicCredentials, Depends(security)],
):
    if user := request.app.users.get(credentials.username):
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
