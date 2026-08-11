import json

from cyberredteam.llm.nvidia import NvidiaObservableLLM
from cyberredteam.llm.schemas import AttackPlan


def test_nvidia_structured_response(monkeypatch):
    captured = {}

    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}, "choices": [{"message": {"content": json.dumps({
                "categories": ["prompt_injection"],
                "priorities": ["high"],
                "rationale": "test",
            })}}]}

    def post(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return Response()

    monkeypatch.setattr("httpx.post", post)
    llm = NvidiaObservableLLM("secret", "strategist", "nvidia/nemotron-3-ultra-550b-a55b")
    result = llm.invoke_structured("system", "user", AttackPlan)

    assert isinstance(result, AttackPlan)
    assert captured["url"].endswith("/chat/completions")
    assert captured["kwargs"]["headers"]["Authorization"] == "Bearer secret"
    assert captured["kwargs"]["json"]["model"].startswith("nvidia/")
    assert captured["kwargs"]["json"]["response_format"] == {"type": "json_object"}
    assert llm.last_status_code == 200
    assert llm.last_retry_count == 0
    assert llm.last_usage == {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
