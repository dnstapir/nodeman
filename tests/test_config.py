import os

from nodeman.settings import ENV_PREFIX, Settings


def test_environment_variable_override():
    # Set environment variable
    test_domain_var = f"{ENV_PREFIX}NODES__DOMAIN"
    test_domain_value = "env-override.example.com"
    os.environ[test_domain_var] = test_domain_value

    # Create new settings instance
    Settings._toml_file = "tests/test.toml"
    settings = Settings()

    # Verify environment variable takes precedence
    assert settings.nodes.domain == test_domain_value

    # Unset environment variable
    del os.environ[test_domain_var]
