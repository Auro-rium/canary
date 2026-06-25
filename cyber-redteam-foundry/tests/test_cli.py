"""Tests for the CLI commands."""

from unittest.mock import patch

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


@patch.dict("os.environ", {"AWS_REGION": ""})
def test_cli_doctor_missing_region():
    """Doctor fails with diagnostics when AWS_REGION is missing."""
    runner = CliRunner()
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "AWS_REGION is not set" in result.stdout


@patch.dict("os.environ", {"AWS_REGION": "us-east-1"})
def test_cli_doctor_success():
    """Doctor passes when Bedrock is configured and connectivity succeeds.

    The conftest autouse fixture patches ``factory.get_llm`` to a fake, so
    the connectivity probe returns the fake's canned response.
    """
    runner = CliRunner()
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Connection test succeeded" in result.stdout
    assert "All systems nominal" in result.stdout
