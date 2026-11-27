from pathlib import Path

import click
import uvicorn

from cairn.dispatcher.logging import configure_logging
from cairn.dispatcher.scheduler.loop import DispatcherLoop
from cairn.server import db


@click.group()
def main():
    """Cairn - Fact-graph based collaborative exploration protocol."""


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind host")
@click.option("--port", default=8000, show_default=True, help="Bind port")
@click.option(
    "--db-path",
    type=click.Path(),
    default=str(db.DEFAULT_DB),
    show_default=True,
    help="SQLite database path",
)
@click.option("--log-level", default="info", show_default=True, help="Uvicorn log level")
@click.option("--access-log/--no-access-log", default=True, show_default=True, help="Enable Uvicorn access log")
def serve(host: str, port: int, db_path: str, log_level: str, access_log: bool):
    """Start the Cairn API server."""
    db.configure(Path(db_path))
    from cairn.server.app import app

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=log_level.lower(),
        access_log=access_log,
    )


@main.command()
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Dispatcher config path",
)
@click.option("--once", is_flag=True, help="Run one scheduling iteration and exit")
@click.option(
    "--startup-healthcheck-only",
    is_flag=True,
    help="Run startup worker healthchecks and exit",
)
@click.option("--log-level", default="INFO", show_default=True, help="Log level")
def dispatch(config_path: Path, once: bool, startup_healthcheck_only: bool, log_level: str):
    """Run the Cairn dispatcher."""
    configure_logging(log_level, bare=startup_healthcheck_only)
    loop = DispatcherLoop(config_path)
    try:
        if startup_healthcheck_only:
            loop.run_startup_healthchecks_only()
            return
        loop.run(once=once)
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc


@main.command()
@click.option("--race-base-url", envvar="RACE_BASE_URL", required=True, help="Official AI-Race base URL")
@click.option("--agent-token", envvar="RACE_AGENT_TOKEN", required=True, help="Team Agent Token (kept on host only)")
@click.option("--cairn-url", envvar="CAIRN_URL", default="http://127.0.0.1:8000", show_default=True)
@click.option("--cairn-admin-token", envvar="CAIRN_ADMIN_TOKEN", default=None)
@click.option("--bridge-host", envvar="BRIDGE_HOST", default="127.0.0.1", show_default=True)
@click.option("--bridge-port", envvar="BRIDGE_PORT", default=8098, type=int, show_default=True)
@click.option("--max-scenes", envvar="MAX_SCENES", default=2, type=int, show_default=True)
@click.option("--max-attachments", envvar="MAX_ATTACHMENTS", default=2, type=int, show_default=True)
@click.option("--poll-interval", envvar="POLL_INTERVAL", default=30.0, type=float, show_default=True)
@click.option("--start-at", envvar="RACE_START_AT", default=None, help="ISO-8601 scheduled start time")
@click.option("--end-at", envvar="RACE_END_AT", default=None, help="ISO-8601 hard stop time")
@click.option("--state-file", default="runtime/race-orchestrator-state.json", show_default=True)
@click.option("--log-level", default="INFO", show_default=True)
def race(
    race_base_url: str,
    agent_token: str,
    cairn_url: str,
    cairn_admin_token: str | None,
    bridge_host: str,
    bridge_port: int,
    max_scenes: int,
    max_attachments: int,
    poll_interval: float,
    start_at: str | None,
    end_at: str | None,
    state_file: str,
    log_level: str,
):
    """Run the official AI-Race master orchestrator and zero-leak submission bridge."""
    from cairn.race.orchestrator import OrchestratorConfig, RaceOrchestrator

    configure_logging(log_level)
    cfg = OrchestratorConfig(
        race_base_url=race_base_url,
        agent_token=agent_token,
        cairn_url=cairn_url,
        cairn_admin_token=cairn_admin_token,
        bridge_host=bridge_host,
        bridge_port=bridge_port,
        max_scenes=max_scenes,
        max_attachments=max_attachments,
        poll_interval_sec=poll_interval,
        start_at=start_at,
        end_at=end_at,
        state_file=state_file,
    )
    RaceOrchestrator(cfg).run()
