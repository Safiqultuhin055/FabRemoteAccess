"""Environment-based configuration (FR_* variables, optionally from a .env file).

Validation enforces the project's safety rules at startup: no `sa`, certificate
validation and encryption stay on for any non-local database server, and secrets
are held as SecretStr so they never appear in reprs or logs.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

LOCAL_DB_HOSTS = ("localhost", "127.0.0.1", "::1", "(localdb)")
SUPPORTED_SCHEMA = "fr"


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FR_", env_file=".env", env_file_encoding="utf-8",
                                      extra="ignore", frozen=True)

    env: Environment = Environment.DEVELOPMENT
    log_level: str = "INFO"
    log_format: str = "json"                      # json | text
    expose_openapi: bool | None = None            # default: only in development
    cors_allowed_origins: Annotated[tuple[str, ...], NoDecode] = ()

    # Database (runtime login only; see docs/DATABASE_DESIGN.md)
    db_host: str | None = None                    # unset = database not configured
    db_port: int = Field(1433, ge=1, le=65535)
    db_name: str = "FabRemotesDB"
    db_schema: str = SUPPORTED_SCHEMA
    db_driver: str = "ODBC Driver 18 for SQL Server"
    db_user: str | None = None                    # unset = Windows authentication
    db_password: SecretStr | None = None
    db_encrypt: str = "yes"                       # yes | mandatory | strict | optional | no
    db_trust_server_cert: bool = False
    db_server_certificate: str | None = None
    db_host_name_in_certificate: str | None = None
    db_login_timeout_seconds: int = Field(5, ge=1, le=60)
    db_query_timeout_seconds: int = Field(10, ge=1, le=300)
    db_pool_size: int = Field(5, ge=1, le=50)
    db_max_overflow: int = Field(5, ge=0, le=50)

    jwt_signing_key: SecretStr | None = None      # mandatory outside development/test (else an ephemeral key)
    access_token_ttl_seconds: int = Field(600, ge=60, le=3600)
    refresh_token_ttl_days: int = Field(30, ge=1, le=90)
    web_session_idle_hours: int = Field(12, ge=1, le=72)
    web_session_absolute_days: int = Field(7, ge=1, le=30)
    login_lockout_threshold: int = Field(10, ge=3, le=50)
    login_lockout_minutes: int = Field(15, ge=1, le=1440)
    public_base_url: str | None = None            # used to build invitation links
    device_challenge_ttl_seconds: int = Field(120, ge=30, le=600)
    presence_ttl_seconds: int = Field(90, ge=30, le=3600)   # online only if a verified heartbeat is this recent
    max_devices_per_user: int = Field(10, ge=1, le=100)

    site_dir: str | None = None                   # folder with the landing page (web/site); unset = not served

    @field_validator("db_host", "db_user", "db_server_certificate", "db_host_name_in_certificate",
                     "jwt_signing_key", "db_password", "expose_openapi", "site_dir", "public_base_url",
                     mode="before")
    @classmethod
    def _blank_is_none(cls, value):
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def _split_origins(cls, value):
        if isinstance(value, str):
            return tuple(o.strip() for o in value.split(",") if o.strip())
        return value

    @field_validator("log_format")
    @classmethod
    def _check_log_format(cls, value: str) -> str:
        if value not in ("json", "text"):
            raise ValueError("must be 'json' or 'text'")
        return value

    @field_validator("db_encrypt")
    @classmethod
    def _check_encrypt(cls, value: str) -> str:
        value = value.lower()
        if value not in ("yes", "mandatory", "strict", "optional", "no"):
            raise ValueError("must be yes, mandatory, strict, optional or no")
        return value

    @model_validator(mode="after")
    def _check_safety_rules(self) -> Settings:
        if "*" in self.cors_allowed_origins:
            raise ValueError("FR_CORS_ALLOWED_ORIGINS must list explicit origins, not '*'")
        if self.db_schema != SUPPORTED_SCHEMA:
            raise ValueError(f"FR_DB_SCHEMA must be '{SUPPORTED_SCHEMA}'")
        if self.db_user and self.db_user.strip().lower() == "sa":
            raise ValueError("FR_DB_USER must not be 'sa'; use the least-privilege runtime login")
        if self.db_user and self.db_password is None:
            raise ValueError("FR_DB_PASSWORD is required when FR_DB_USER is set")
        relaxed_tls = self.db_trust_server_cert or self.db_encrypt in ("optional", "no")
        if relaxed_tls and not (self.env is Environment.DEVELOPMENT or self.env is Environment.TEST):
            raise ValueError("Relaxed database TLS settings are only allowed in development or test")
        if relaxed_tls and self.db_host and not self.db_is_local:
            raise ValueError("Relaxed database TLS settings (TrustServerCertificate or Encrypt=optional/no) "
                             "are only allowed for a local server")
        key = self.jwt_signing_key.get_secret_value() if self.jwt_signing_key else ""
        if key and len(key.encode()) < 32:
            raise ValueError("FR_JWT_SIGNING_KEY must be at least 32 bytes")
        if not key and self.env in (Environment.STAGING, Environment.PRODUCTION):
            raise ValueError("FR_JWT_SIGNING_KEY is required outside development and test")
        if self.site_dir and not (Path(self.site_dir) / "index.html").is_file():
            raise ValueError("FR_SITE_DIR must be a folder containing index.html")
        if self.public_base_url:
            local_dev = self.env in (Environment.DEVELOPMENT, Environment.TEST)
            if not (self.public_base_url.startswith("https://")
                    or (local_dev and self.public_base_url.startswith(("http://127.0.0.1", "http://localhost")))):
                raise ValueError("FR_PUBLIC_BASE_URL must use https (http only for localhost in development)")
        return self

    @property
    def db_configured(self) -> bool:
        return self.db_host is not None

    @property
    def db_is_local(self) -> bool:
        return bool(self.db_host) and self.db_host.lower().startswith(LOCAL_DB_HOSTS)

    @property
    def openapi_enabled(self) -> bool:
        return self.expose_openapi if self.expose_openapi is not None else self.env is Environment.DEVELOPMENT

    @property
    def db_connection_string(self) -> str:
        """ODBC connection string. Contains the password: never log or display it."""
        if not self.db_host:
            raise RuntimeError("Database is not configured (FR_DB_HOST is empty)")
        # LocalDB uses a named pipe instance name, not TCP host/port.
        server = self.db_host if self.db_host.lower().startswith("(localdb)") else f"tcp:{self.db_host},{self.db_port}"
        parts = {
            "DRIVER": "{" + self.db_driver + "}",
            "SERVER": server,
            "DATABASE": self.db_name,
            "Encrypt": self.db_encrypt,
            "TrustServerCertificate": "yes" if self.db_trust_server_cert else "no",
            "APP": "FabulousRemote",
        }
        if self.db_server_certificate:
            parts["ServerCertificate"] = "{" + self.db_server_certificate + "}"
        if self.db_host_name_in_certificate:
            parts["HostNameInCertificate"] = self.db_host_name_in_certificate
        if self.db_user:
            parts["UID"] = self.db_user
            parts["PWD"] = "{" + self.db_password.get_secret_value().replace("}", "}}") + "}"
        else:
            parts["Trusted_Connection"] = "yes"
        return ";".join(f"{k}={v}" for k, v in parts.items())

    def describe_database(self) -> str:
        """Safe, loggable description of the database target (no credentials)."""
        if not self.db_host:
            return "not configured"
        return f"{self.db_name} on {'local server' if self.db_is_local else 'remote server'}"
