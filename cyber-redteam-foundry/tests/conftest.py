"""Shared pytest fixtures.

Two autouse fixtures keep the suite runnable without Backboard credentials while
ensuring the *runtime* code path never fabricates output:

1. ``_inject_fake_llm`` patches ``factory.get_llm`` to return an
   ObservableLLM wrapping the test-only ``FakeStructuredLLM``. Because
   ``get_llm_for_agent`` and the target adapters all call ``get_llm``
   internally, this covers every agent and the orchestrator.
2. ``_bypass_api_auth`` overrides ``require_auth``/``get_principal`` so the
   legacy v1 endpoint tests run as an admin. The WP8 tests clear both overrides
   and authenticate with real API keys and sessions.
"""

import pytest
from fixtures.fake_llm import FakeStructuredLLM

from cyberredteam.llm.observable import ObservableLLM


@pytest.fixture(autouse=True)
def _wandb_disabled(monkeypatch, tmp_path_factory):
    """Tests never talk to W&B unless they explicitly build an offline run."""
    monkeypatch.setenv("WANDB_MODE", "disabled")
    # Never write run files into the repo/CWD.
    monkeypatch.setenv("WANDB_DIR", str(tmp_path_factory.mktemp("wandb")))
    monkeypatch.delenv("WANDB_API_KEY", raising=False)


@pytest.fixture(autouse=True)
def _canary_env(monkeypatch):
    """Tests run as dev/test (Host-derived redirect_uri allowed); the legacy bypass
    admin is a platform admin so kill-switch tests can write."""
    monkeypatch.setenv("CANARY_ENV", "test")
    monkeypatch.setenv("CANARY_PLATFORM_ADMINS", "test-admin,admin@a.example")


@pytest.fixture(autouse=True)
def _inject_fake_llm(monkeypatch):
    def _fake_get_llm(model=None, agent_name="unknown", store=None, provider=None, temperature=None):
        return ObservableLLM(
            llm=FakeStructuredLLM(),
            agent_name=agent_name,
            deployment=model,
            store=store,
        )

    monkeypatch.setattr("cyberredteam.llm.factory.get_llm", _fake_get_llm)
    yield


@pytest.fixture(autouse=True)
def _bypass_api_auth():
    """Legacy endpoint tests run as a fixed admin principal. The WP8 API tests
    (``api_v2_support.v2``) remove both overrides and authenticate for real."""
    from cyberredteam.api import app, require_auth
    from cyberredteam.auth.deps import get_principal
    from cyberredteam.auth.principal import Principal, permissions_for

    admin = Principal(
        user_id="test-admin", org_id="test-org", role="admin", auth_method="api_key",
        permissions=permissions_for("admin"),
    )
    app.dependency_overrides[require_auth] = lambda: None
    app.dependency_overrides[get_principal] = lambda: admin
    yield
    app.dependency_overrides.pop(require_auth, None)
    app.dependency_overrides.pop(get_principal, None)


# WP7 jobs tests: shared DB fixture (SQLite, or Postgres when configured).
# WP8 API v2 tests: real auth (orgs, users, API keys, sessions) on db_factory.
from api_v2_support import v2  # noqa: E402, F401
from jobs_support import db_factory  # noqa: E402, F401
