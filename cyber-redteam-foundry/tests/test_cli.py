"""Tests for the CLI commands."""

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from cyberredteam.cli import app


def test_cli_list_strategies():
    """Test the list-strategies CLI command."""
    runner = CliRunner()
    result = runner.invoke(app, ["list-strategies"])
    assert result.exit_code == 0
    assert "prompt_injection" in result.stdout
    assert "tool_misuse" in result.stdout


def test_cli_graph():
    """Test the graph CLI command."""
    runner = CliRunner()
    result = runner.invoke(app, ["graph"])
    assert result.exit_code == 0
    assert "StateGraph" in result.stdout or "state" in result.stdout or "strategist" in result.stdout


@patch.dict("os.environ", {"AZURE_OPENAI_ENDPOINT": ""})
def test_cli_doctor_missing_endpoint():
    """Test that doctor fails and outputs diagnostics when endpoint is missing."""
    # Force reload of settings to pick up mocked env var
    from cyberredteam import settings
    settings._settings = None  # Clear settings cache if any exists

    runner = CliRunner()
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "AZURE_OPENAI_ENDPOINT is not set" in result.stdout


@patch.dict("os.environ", {
    "AZURE_OPENAI_ENDPOINT": "https://dummy.openai.azure.com/",
    "AZURE_OPENAI_API_KEY": "dummykey123",
    "AZURE_OPENAI_API_VERSION": "2024-02-15-preview"
})
@patch("langchain_openai.AzureChatOpenAI.invoke")
def test_cli_doctor_success(mock_invoke):
    """Test that doctor passes when all configs are set and invoke succeeds."""
    # Force reload of settings to pick up mocked env var
    from cyberredteam import settings
    settings._settings = None  # Clear settings cache if any exists

    mock_response = MagicMock()
    mock_response.content = "Hello, checked!"
    mock_invoke.return_value = mock_response

    runner = CliRunner()
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Connection test succeeded" in result.stdout
    assert "All systems nominal" in result.stdout
