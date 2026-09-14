"""Shared pytest fixtures."""
import pytest

from takeover_hunter.app import create_app
from takeover_hunter.config import Config


@pytest.fixture
def open_config():
    """Config with auth off and rate limiting off (default test posture)."""
    return Config(api_key="", rate_limit_enabled=False)


@pytest.fixture
def app(open_config):
    application = create_app(open_config)
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def keyed_client():
    """Client for an app that requires the API key 'secret-key'."""
    application = create_app(Config(api_key="secret-key", rate_limit_enabled=False))
    application.config["TESTING"] = True
    return application.test_client()
