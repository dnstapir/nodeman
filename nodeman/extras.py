import functools
import io

import yaml
from fastapi import APIRouter, Request, Response

router = APIRouter()


@router.get("/openapi.yaml", include_in_schema=False)
@functools.lru_cache
def read_openapi_yaml(
    request: Request,
) -> Response:
    """Get OpenAPI as YAML"""

    openapi_json = request.app.openapi()
    yaml_s = io.StringIO()
    yaml.dump(openapi_json, yaml_s)
    return Response(yaml_s.getvalue(), media_type="text/yaml")
