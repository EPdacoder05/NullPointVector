"""Focused tests for database and encryption runtime boundaries."""

from __future__ import annotations

import logging
import tomllib
from pathlib import Path

import pytest
import yaml
from cryptography.fernet import Fernet

from Autobot.VectorDB import NullPoint_Vector as vector_db


_ROOT = Path(__file__).resolve().parents[1]


_DB_ENV = (
    "DATABASE_URL",
    "DB_HOST",
    "DB_PORT",
    "DB_USER",
    "DB_PASSWORD",
    "DB_NAME",
    "DB_SSLMODE",
    "DB_CONNECT_TIMEOUT",
    "DB_POOL_MIN",
    "DB_POOL_MAX",
)


@pytest.fixture(autouse=True)
def clean_database_environment(monkeypatch):
    for name in _DB_ENV:
        monkeypatch.delenv(name, raising=False)
    yield
    vector_db._connection_pool = None


def test_database_url_is_authoritative_and_forces_tls(monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://runtime:fake-password@db.example.test:5432/nullpoint",
    )
    monkeypatch.setenv("DB_HOST", "wrong.example.test")

    params = vector_db._database_connection_params(production_like=True)

    assert params["host"] == "db.example.test"
    assert params["dbname"] == "nullpoint"
    assert params["sslmode"] == "require"
    assert params["application_name"] == "nullpoint"


def test_production_rejects_insecure_database_transport(monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://runtime:fake-password@db.example.test/nullpoint?sslmode=disable",
    )

    with pytest.raises(RuntimeError, match="must use TLS"):
        vector_db._database_connection_params(production_like=True)


def test_production_rejects_incomplete_database_configuration(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql:///nullpoint")

    with pytest.raises(RuntimeError, match="incomplete"):
        vector_db._database_connection_params(production_like=True)


def test_complete_production_db_values_are_supported(monkeypatch):
    values = {
        "DB_HOST": "db.example.test",
        "DB_PORT": "5432",
        "DB_USER": "runtime",
        "DB_PASSWORD": "fake-password",
        "DB_NAME": "nullpoint",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    params = vector_db._database_connection_params(production_like=True)

    assert params["host"] == "db.example.test"
    assert params["sslmode"] == "require"


def test_local_container_host_fallback_is_never_used_in_production():
    assert vector_db._candidate_db_hosts("db", production_like=False) == [
        "db", "localhost", "127.0.0.1",
    ]
    assert vector_db._candidate_db_hosts("db", production_like=True) == ["db"]


def test_pool_uses_thread_safe_implementation(monkeypatch):
    captured = {}
    sentinel = object()

    def fake_pool(*, minconn, maxconn, **kwargs):
        captured.update(minconn=minconn, maxconn=maxconn, **kwargs)
        return sentinel

    monkeypatch.setattr(vector_db, "_production_like", lambda: True)
    monkeypatch.setattr(
        vector_db,
        "_database_connection_params",
        lambda **_kwargs: {
            "host": "db.example.test",
            "dbname": "nullpoint",
            "user": "runtime",
            "password": "fake-password",
            "sslmode": "require",
        },
    )
    monkeypatch.setattr(vector_db.pool, "ThreadedConnectionPool", fake_pool)
    vector_db._connection_pool = None

    assert vector_db._init_pool() is sentinel
    assert captured["minconn"] == 1
    assert captured["maxconn"] == 10
    assert captured["sslmode"] == "require"


def test_invalid_encryption_key_is_never_silently_replaced(monkeypatch):
    monkeypatch.setattr(vector_db, "_production_like", lambda: False)
    monkeypatch.setenv("ENCRYPTION_KEY", "not-a-fernet-key")

    with pytest.raises(RuntimeError, match="valid Fernet"):
        vector_db.get_encryption_key()


def test_production_requires_persistent_encryption_key(monkeypatch):
    monkeypatch.setattr(vector_db, "_production_like", lambda: True)
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)

    with pytest.raises(RuntimeError, match="ENCRYPTION_KEY is not set"):
        vector_db.get_encryption_key()


def test_valid_encryption_key_is_preserved(monkeypatch):
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("ENCRYPTION_KEY", key)

    assert vector_db.get_encryption_key() == key


def test_database_failure_log_does_not_include_exception_text(caplog):
    vector_db._last_db_error_log = 0.0
    caplog.set_level(logging.ERROR)

    vector_db._safe_db_failure(
        "connection",
        RuntimeError("postgresql://runtime:do-not-log@db.example.test/nullpoint"),
    )

    assert "do-not-log" not in caplog.text
    assert "RuntimeError" in caplog.text


def test_fly_release_is_fail_closed_and_billing_disabled():
    with (_ROOT / "fly.toml").open("rb") as handle:
        config = tomllib.load(handle)

    assert config["deploy"]["release_command"] == "./start.sh migrate"
    assert config["processes"] == {"web": "./start.sh web"}
    assert config["http_service"]["processes"] == ["web"]
    assert config["env"]["ENV"] == "production"
    assert config["env"]["SIGNUP_OPEN"] == "false"
    assert config["env"]["BILLING_ENABLED"] == "false"
    assert config["env"]["BILLING_MOCK"] == "false"


@pytest.mark.parametrize("filename", ["docker-compose.yml", "docker-compose.prod.yml"])
def test_compose_routes_through_pgbouncer_and_gates_on_migration(filename):
    with (_ROOT / filename).open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)

    services = config["services"]
    app_env = services["app"]["environment"]
    assert "DB_HOST=pgbouncer" in app_env
    assert not any(value.startswith("DATABASE_URL=") for value in app_env)
    assert services["app"]["depends_on"]["migrate"]["condition"] == (
        "service_completed_successfully"
    )
    assert services["migrate"]["command"] == ["./start.sh", "migrate"]
    assert not services["pgbouncer"]["image"].endswith(":latest")
