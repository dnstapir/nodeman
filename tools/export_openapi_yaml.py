from fastapi.testclient import TestClient

from nodeman.server import NodemanServer
from nodeman.settings import Settings

settings = Settings()
app = NodemanServer(settings)

client = TestClient(app)
response = client.get("/openapi.yaml")
print(response.text)
