import json

from cyberredteam.llm.backboard import BackboardObservableLLM
from cyberredteam.llm.schemas import AttackPlan


def test_backboard_structured_response_is_validated(monkeypatch):
    captured = {}

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"content": json.dumps({"categories": ["prompt_injection"], "priorities": ["high"], "rationale": "test"})}

    def post(url, **kwargs):
        captured.update(url=url, kwargs=kwargs)
        return Response()

    monkeypatch.setattr("httpx.post", post)
    llm = BackboardObservableLLM("secret", "strategist", "moonshotai/kimi-k2.6", "openrouter")
    result = llm.invoke_structured("system", "user", AttackPlan)

    assert isinstance(result, AttackPlan)
    assert captured["kwargs"]["headers"]["X-API-Key"] == "secret"
    assert captured["kwargs"]["json"]["json_output"] is True
    assert captured["kwargs"]["json"]["llm_provider"] == "openrouter"


def test_backboard_text_response(monkeypatch):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"content": "OK"}

    monkeypatch.setattr("httpx.post", lambda *args, **kwargs: Response())
    llm = BackboardObservableLLM("secret", "doctor", "moonshotai/kimi-k2.6", "openrouter")
    assert llm.invoke_text("system", "user") == "OK"
