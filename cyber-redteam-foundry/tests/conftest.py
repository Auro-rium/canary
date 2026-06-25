"""Shared pytest fixtures.

Two autouse fixtures keep the suite runnable without AWS credentials while
ensuring the *runtime* code path never fabricates output:

1. ``_inject_fake_llm`` patches ``factory.get_llm`` to return an
   ObservableLLM wrapping the test-only ``FakeStructuredLLM``. Because
   ``get_llm_for_agent`` and the target adapters all call ``get_llm``
   internally, this covers every agent and the orchestrator.
2. ``_bypass_api_auth`` overrides the FastAPI ``require_auth`` dependency so
   existing endpoint tests don't need to thread a bearer token through every
   request. ``test_auth.py`` clears this override to assert the gate itself.
"""

import pytest
from fixtures.fake_llm import FakeStructuredLLM

from cyberredteam.llm.azure_openai import ObservableLLM


@pytest.fixture(autouse=True)
def _inject_fake_llm(monkeypatch):
    def _fake_get_llm(model, agent_name="unknown", store=None):
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
    from cyberredteam.api import app, require_auth

    app.dependency_overrides[require_auth] = lambda: None
    yield
    app.dependency_overrides.pop(require_auth, None)
