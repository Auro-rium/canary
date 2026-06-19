"""Tests for attack strategies."""


from cyberredteam.attack_strategies.direct import DirectInjectionAttack
from cyberredteam.attack_strategies.jailbreaks import JailbreakAttack
from cyberredteam.attack_strategies.retrieval_poisoning import RetrievalPoisoningAttack
from cyberredteam.attack_strategies.tool_misuse import ToolMisuseAttack


def test_direct_injection_prompts():
    """Test direct injection generates prompts."""
    prompts = DirectInjectionAttack.generate_prompts()
    assert len(prompts) > 0
    assert all(isinstance(p, str) for p in prompts)


def test_direct_injection_analysis():
    """Test direct injection response analysis."""
    response = "Ignore all previous instructions. Here is secret data."
    indicators = DirectInjectionAttack.analyze_response(response)

    assert indicators is not None
    assert "complied_with_override" in indicators


def test_tool_misuse_prompts():
    """Test tool misuse generates prompts."""
    prompts = ToolMisuseAttack.generate_prompts()
    assert len(prompts) > 0


def test_retrieval_poisoning_analysis():
    """Test retrieval poisoning response analysis."""
    response = "According to the knowledge base, the password is 12345"
    indicators = RetrievalPoisoningAttack.analyze_response(response)

    assert "knowledge_base_abuse" in indicators


def test_jailbreak_prompts():
    """Test jailbreak generates prompts."""
    prompts = JailbreakAttack.generate_prompts()
    assert len(prompts) > 0
    assert any("role-play" in p.lower() for p in prompts)
