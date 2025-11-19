import ipaddress
from contextlib import suppress

from fastapi import APIRouter, HTTPException, Request, status

from .db_models import TapirCertificate, TapirNode
from .models import HealthcheckResult

router = APIRouter()


@router.get(
    "/api/v1/healthcheck",
    tags=["backend"],
)
def healthcheck(
    request: Request,
) -> HealthcheckResult:
    """Perform healthcheck with database and S3 access"""

    if request.client and request.client.host:
        with suppress(ValueError):
            client_address = ipaddress.ip_address(request.client.host)
            for address in request.app.settings.http.healthcheck_hosts:
                if client_address in address:
                    break
            else:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You are not my physician",
                )

    try:
        node_count = TapirNode.objects().count()
        cert_count = TapirCertificate.objects().count()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to connect to MongoDB",
        ) from exc

    try:
        ca_fingerprint = request.app.ca_client.ca_fingerprint
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to connect to CA",
        ) from exc

    return HealthcheckResult(
        status="OK",
        node_count=node_count,
        cert_count=cert_count,
        ca_fingerprint=ca_fingerprint,
    )
