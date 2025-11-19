import ipaddress

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
    """Perform health check with database and S3 access"""

    if request.client and request.client.host:
        try:
            client_address = ipaddress.ip_address(request.client.host)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid client IP address: {request.client.host}",
            ) from exc

        for address in request.app.settings.http.healthcheck_hosts:
            if client_address in address:
                break
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not my physician",
            )
    else:
        # Always allow health check if no client IP is provided
        pass

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
