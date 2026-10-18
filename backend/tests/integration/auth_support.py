"""Helpers for authentication integration tests (LocalDB scratch databases only)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.db.models import User
from app.domain.constants import Role, UserStatus
from app.main import create_app
from app.security.clock import FrozenClock
from app.security.passwords import PasswordHasher
from db_support import localdb_settings

PASSWORD = "Correct-Horse-Battery-9"
SIGNING_KEY = "integration-test-signing-key-0123456789"
# Argon2id with low cost for test speed; production parameters are asserted in unit tests.
FAST_HASHER = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)


@dataclass
class AuthEnv:
    app: FastAPI
    client: TestClient
    clock: FrozenClock
    db: object

    def account(self, *roles: Role, status: UserStatus = UserStatus.ACTIVE, password: str = PASSWORD):
        email = f"user.{uuid.uuid4().hex[:12]}@example.com"
        with self.db.unit_of_work() as uow:
            user = uow.users.add(User(
                email=email, display_name="Test User", status=status,
                password_hash=None if status is UserStatus.INVITED else FAST_HASHER.hash(password),
                email_verified_at=self.clock.now()))
            for role in sorted({Role.USER, *roles}):
                uow.users.grant_role(user.id, role)
            uow.commit()
        return Account(user.id, email, password)

    def login(self, account) -> dict:
        response = self.client.post("/api/v1/auth/token", json={"email": account.email, "password": account.password})
        assert response.status_code == 200, response.text
        return response.json()

    def bearer(self, account_or_tokens) -> dict:
        tokens = account_or_tokens if isinstance(account_or_tokens, dict) else self.login(account_or_tokens)
        return {"Authorization": f"Bearer {tokens['access_token']}"}


@dataclass(frozen=True)
class Account:
    id: uuid.UUID
    email: str
    password: str


def make_env(database, **settings) -> AuthEnv:
    clock = FrozenClock()
    values = {"jwt_signing_key": SIGNING_KEY, "public_base_url": "http://localhost:8765", **settings}
    app = create_app(localdb_settings("unused", **values), database, configure_logs=False, clock=clock,
                     password_hasher=FAST_HASHER)
    # https base URL so the Secure, __Host- prefixed session cookie is sent back by the client.
    return AuthEnv(app, TestClient(app, base_url="https://testserver"), clock, database)
