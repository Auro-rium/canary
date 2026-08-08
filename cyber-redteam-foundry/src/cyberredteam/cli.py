"""CLI for the Cyber Red Team Framework.

Commands:
    init             — Initialise environment (dirs, db).
    run              — Execute a full attack-defend loop via LangGraph.
    list-strategies  — List available attack strategies.
    status           — Show status of last run.
    graph            — Display Mermaid graph visualisation.
"""

import uuid
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cyberredteam.langgraph.orchestrator import GraphOrchestrator
from cyberredteam.logging import setup_logging
from cyberredteam.schemas import RunConfig, StrategyType
from cyberredteam.settings import get_settings

logger = setup_logging()
console = Console()

app = typer.Typer(
    name="cyber-rt",
    help="Cybersecurity Red Team & Defense Framework",
)


# -------------------------------------------------------------------
# init
# -------------------------------------------------------------------

@app.command()
def init() -> None:
    """Initialize red team environment."""
    console.print("[bold blue]Initializing Cyber Red Team[/bold blue]")

    settings = get_settings()

    # Create necessary directories
    Path(settings.log_file).parent.mkdir(parents=True, exist_ok=True)
    Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
    Path(settings.report_output_dir).mkdir(parents=True, exist_ok=True)

    console.print(f"✓ Log directory: {settings.log_file.parent}")
    console.print(f"✓ Database: {settings.db_path}")
    console.print(f"✓ Reports: {settings.report_output_dir}")
    console.print("\n[bold green]Initialization complete![/bold green]")


# -------------------------------------------------------------------
# run
# -------------------------------------------------------------------

@app.command()
def run(
    target_id: str = typer.Option(..., help="Verified HTTP(S) agent endpoint"),
    strategies: str = typer.Option(
        "prompt_injection,indirect_injection,tool_misuse",
        help="Attack strategies (comma-separated)",
    ),
    max_attempts: int = typer.Option(5, help="Max attacks per strategy"),
    max_iterations: int = typer.Option(
        3, help="Max strategist→attacker→evaluator cycles",
    ),
    seed: int = typer.Option(None, help="Random seed for deterministic attacks"),
) -> None:
    """Execute a full red team attack and defense loop."""
    console.print("[bold blue]Starting Red Team Attack Loop[/bold blue]\n")

    settings = get_settings()
    run_id = str(uuid.uuid4())[:8]

    # Parse strategies
    strategy_list = [
        StrategyType(s.strip()) for s in strategies.split(",")
    ]

    # Create run config
    config = RunConfig(
        run_id=run_id,
        target_id=target_id,
        strategy_types=strategy_list,
        max_attempts=max_attempts,
        seed=seed,
        description=f"Attack on {target_id}",
    )

    if not target_id.startswith(("http://", "https://")):
        raise typer.BadParameter("target-id must be an http:// or https:// agent endpoint")

    logger.info(f"Starting run {run_id} against {target_id}")

    # Create graph orchestrator and run
    orchestrator = GraphOrchestrator(
        config=config,
        db_path=settings.database_location,
        report_dir=settings.report_output_dir,
        max_iterations=max_iterations,
    )

    result = orchestrator.run()

    # Display results
    console.print("\n[bold green]Run Complete[/bold green]\n")
    console.print(f"Run ID: [cyan]{result['run_id']}[/cyan]")
    console.print(f"Target: {result['target_id']}")
    console.print(f"Total Attacks: {result['total_attacks']}")
    console.print(f"Successful Attacks: {result['successful_attacks']}")
    console.print(f"Success Rate: {result['success_rate']:.1%}")
    console.print(f"Patches Applied: {result['patches_applied']}")
    console.print(f"Iterations: {result['iterations']}")
    console.print(f"Execution Time: {result['execution_time']:.1f}s")
    console.print(f"\n📋 Markdown Report: {result['markdown_report']}")
    console.print(f"📊 JSON Report: {result['json_report']}")

    # Display scores if available
    scores = result.get("scores", {})
    if scores:
        console.print("\n[bold yellow]Aggregate Scores[/bold yellow]")
        for key, value in scores.items():
            if isinstance(value, float):
                console.print(f"  {key}: {value:.3f}")
            else:
                console.print(f"  {key}: {value}")


# -------------------------------------------------------------------
# list-strategies
# -------------------------------------------------------------------

@app.command()
def list_strategies() -> None:
    """List available attack strategies."""
    console.print("[bold blue]Available Attack Strategies[/bold blue]\n")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Strategy", style="cyan")
    table.add_column("Description", style="green")
    table.add_column("Risk", style="yellow")

    for strategy_type in StrategyType:
        from cyberredteam.attack_strategies.registry import (
            get_risk_level,
            get_strategy_info,
        )

        info = get_strategy_info(strategy_type)
        risk = get_risk_level(strategy_type)

        table.add_row(
            strategy_type.value,
            info.get("description", "N/A"),
            risk.upper(),
        )

    console.print(table)


# -------------------------------------------------------------------
# status
# -------------------------------------------------------------------

@app.command()
def status() -> None:
    """Show status of last run."""
    console.print("[bold blue]Red Team Status[/bold blue]\n")

    settings = get_settings()

    # Check if database exists
    if not Path(settings.db_path).exists():
        console.print("[yellow]No runs recorded yet[/yellow]")
        return

    console.print(f"Database: {settings.db_path}")
    console.print(f"Reports: {settings.report_output_dir}")


# -------------------------------------------------------------------
# graph
# -------------------------------------------------------------------

@app.command()
def graph(
    save: bool = typer.Option(False, help="Save Mermaid to reports dir"),
) -> None:
    """Display the LangGraph workflow as a Mermaid diagram."""
    mermaid = GraphOrchestrator.get_graph_visualization()

    console.print(
        Panel(mermaid, title="RedTeam LangGraph", border_style="cyan")
    )

    if save:
        settings = get_settings()
        out = Path(settings.report_output_dir) / "graph.mmd"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(mermaid)
        console.print(f"\n[green]Saved to {out}[/green]")


# -------------------------------------------------------------------
# doctor
# -------------------------------------------------------------------

@app.command()
def doctor() -> None:
    """Verify environment variables and test AWS Bedrock connectivity."""
    console.print("[bold blue]Running Diagnostics / Doctor Command[/bold blue]\n")
    settings = get_settings()
    from cyberredteam.llm.factory import get_model_for_agent

    errors = []

    # Check AWS Bedrock configuration
    console.print("[bold]Checking AWS Bedrock Configuration...[/bold]")
    if not settings.aws_region:
        console.print("[red]✗ AWS_REGION is not set.[/red]")
        errors.append("AWS_REGION missing")
    else:
        console.print(f"✓ AWS_REGION: {settings.aws_region}")

    console.print(
        "  (AWS credentials are resolved via the standard boto3 chain: "
        "env vars, shared config, or instance/role profile.)"
    )

    # Show per-agent model assignment
    console.print("\n[bold]Model assignment per agent:[/bold]")
    for agent in ("strategist", "attacker", "evaluator", "reporter"):
        console.print(f"✓ {agent}: {get_model_for_agent(agent)}")

    # Check API auth configuration
    console.print("\n[bold]Checking API Authentication...[/bold]")
    if not settings.api_secret_key:
        console.print("[yellow]! API_SECRET_KEY is not set — the API will refuse all requests.[/yellow]")
    else:
        console.print("✓ API_SECRET_KEY is set.")

    if errors:
        console.print("\n[bold red]Diagnostics failed. Please set required variables in your .env file.[/bold red]")
        raise typer.Exit(code=1)

    # Test actual connectivity
    console.print("\n[bold]Testing connectivity to AWS Bedrock...[/bold]")
    try:
        from langchain_core.messages import HumanMessage

        from cyberredteam.llm.factory import get_llm

        llm = get_llm(get_model_for_agent("evaluator"), agent_name="doctor")
        response = llm.llm.invoke([HumanMessage(content="Hello, connection check.")])
        console.print("[green]✓ Connection test succeeded![/green]")
        console.print(f"Response: {response.content.strip()}")
    except Exception as e:
        console.print(f"[red]✗ Connection test failed: {e}[/red]")
        console.print(
            "\n[bold red]Verify AWS_REGION, AWS credentials, that the configured "
            "Bedrock model/inference-profile IDs exist in the region, and that your "
            "IAM principal has bedrock:InvokeModel on them.[/bold red]"
        )
        raise typer.Exit(code=1)

    console.print("\n[bold green]All systems nominal. Doctor check passed successfully![/bold green]")


# -------------------------------------------------------------------
# server
# -------------------------------------------------------------------

@app.command()
def server(
    host: str = typer.Option("0.0.0.0", help="Bind socket to this host"),
    port: int = typer.Option(8000, help="Bind socket to this port"),
) -> None:
    """Start the FastAPI backend server for the React frontend."""
    console.print(f"[bold green]Starting Agent Canary API server on {host}:{port}...[/bold green]")
    import uvicorn
    uvicorn.run("cyberredteam.api:app", host=host, port=port, reload=True)


# -------------------------------------------------------------------
# App setup callback
# -------------------------------------------------------------------

@app.callback()
def setup() -> None:
    """Setup logging and configuration."""
    settings = get_settings()
    setup_logging(
        log_level=settings.log_level,
        log_file=settings.log_file,
    )


if __name__ == "__main__":
    app()
