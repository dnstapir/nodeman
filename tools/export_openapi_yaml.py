from fastapi.testclient import TestClient
from pydantic_settings import SettingsConfigDict

from nodeman.server import NodemanServer
from nodeman.settings import Settings

Settings.model_config = SettingsConfigDict(toml_file="tests/test.toml")

settings = Settings()
app = NodemanServer(settings)

client = TestClient(app)
response = client.get("/openapi.yaml")
response.raise_for_status()
print(response.text)
