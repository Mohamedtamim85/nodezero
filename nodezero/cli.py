"""Command-line interface for nodezero-lite.

Typical flow:

    nodezero init-engagement engagement.json      # interactive authorization setup
    nodezero run engagement.json --target example.internal.test
    nodezero run engagement.json --target 10.0.5.0/24 --format json -o report.json
"""

from __future__ import annotations

import datetime as _dt
import ipaddress

import click
from rich.console import Console
from rich.table import Table

from nodezero.authorization import REQUIRED_ATTESTATION, EngagementAuthorization
from nodezero.engine import Engagement
from nodezero.modules import ALL_MODULES
from nodezero.reporting import render_json, render_markdown, save_report
from nodezero.scope import Scope

console = Console()


def _expand_cidr_targets(targets: list[str], max_hosts: int = 4096) -> list[str]:
    """Expand any CIDR entries in ``targets`` into individual host addresses.

    Bare hostnames/IPs pass through unchanged. Refuses to expand a network
    larger than ``max_hosts`` so a typo (e.g. a /8) can't silently queue
    millions of probes.
    """
    expanded: list[str] = []
    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            expanded.append(t)
            continue
        hosts = list(net.hosts()) or [net.network_address]
        if len(hosts) > max_hosts:
            raise click.ClickException(
                f"Target network {t} expands to {len(hosts)} hosts, which exceeds "
                f"the safety limit of {max_hosts}. Narrow the range or raise "
                f"--max-hosts explicitly."
            )
        expanded.extend(str(h) for h in hosts)
    return expanded


@click.group()
def main():
    """nodezero-lite: a local, authorization-gated AI-assisted pentest console."""


@main.command("init-engagement")
@click.argument("output_path", type=click.Path())
def init_engagement(output_path: str):
    """Interactively create and save an engagement authorization file."""
    console.print("[bold]New engagement authorization[/bold]\n")
    name = click.prompt("Engagement name")
    authorized_by = click.prompt("Authorized by (name, role, organization)")
    allow_raw = click.prompt("In-scope targets (comma-separated hosts/IPs/CIDRs)")
    deny_raw = click.prompt("Excluded targets (comma-separated, optional)", default="")
    days = click.prompt("Engagement duration in days", type=int, default=7)
    notes = click.prompt("Rules of engagement notes (optional)", default="")

    allow = [a.strip() for a in allow_raw.split(",") if a.strip()]
    deny = [d.strip() for d in deny_raw.split(",") if d.strip()]

    try:
        scope = Scope(allow=allow, deny=deny)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    console.print(f"\n[yellow]{REQUIRED_ATTESTATION}[/yellow]\n")
    accepted = click.confirm("Do you accept this attestation?", default=False)
    if not accepted:
        raise click.ClickException("Attestation not accepted. No engagement file was created.")

    now = _dt.datetime.utcnow()
    authorization = EngagementAuthorization(
        engagement_name=name,
        authorized_by=authorized_by,
        scope=scope,
        starts_at=now,
        ends_at=now + _dt.timedelta(days=days),
        attestation_accepted=True,
        notes=notes,
    )
    authorization.save(output_path)
    console.print(f"\n[green]Saved engagement authorization to {output_path}[/green]")
    console.print(f"Scope: {scope.describe()}")


@main.command("list-modules")
def list_modules():
    """List available assessment modules."""
    table = Table(title="Available modules")
    table.add_column("Name")
    table.add_column("Intrusive?")
    table.add_column("Description")
    for name, cls in ALL_MODULES.items():
        table.add_row(name, "yes" if cls.intrusive else "no", cls.description)
    console.print(table)


@main.command("run")
@click.argument("engagement_path", type=click.Path(exists=True))
@click.option(
    "--target",
    "-t",
    "targets",
    multiple=True,
    required=True,
    help="Target host/IP/CIDR. Repeatable.",
)
@click.option(
    "--module",
    "-m",
    "modules",
    multiple=True,
    help="Module name to run (repeatable). Default: all non-intrusive modules.",
)
@click.option("--format", "fmt", type=click.Choice(["markdown", "json"]), default="markdown")
@click.option("--output", "-o", "output_path", type=click.Path(), default=None)
@click.option("--max-hosts", type=int, default=4096, help="Safety cap on CIDR expansion.")
@click.option("--no-ai", is_flag=True, help="Force the offline heuristic advisor.")
@click.option("--audit-log", default="nodezero_audit.jsonl", help="Path to the audit log.")
@click.option(
    "--reports-dir",
    default="nodezero_reports",
    type=click.Path(),
    help="Every run is also saved here as JSON, for 'nodezero serve' to list. "
    "Pass an empty string to skip saving.",
)
def run(
    engagement_path, targets, modules, fmt, output_path, max_hosts, no_ai, audit_log, reports_dir
):
    """Run an authorized engagement against TARGETS using ENGAGEMENT_PATH."""
    authorization = EngagementAuthorization.load(engagement_path)

    try:
        authorization.validate()
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc

    try:
        expanded_targets = _expand_cidr_targets(list(targets), max_hosts=max_hosts)
    except click.ClickException:
        raise

    out_of_scope = [t for t in expanded_targets if not authorization.scope.is_in_scope(t)]
    if out_of_scope:
        preview = ", ".join(out_of_scope[:10])
        more = f" (+{len(out_of_scope) - 10} more)" if len(out_of_scope) > 10 else ""
        raise click.ClickException(
            f"Refusing to run: {len(out_of_scope)} target(s) are outside the "
            f"authorized scope: {preview}{more}\nScope: {authorization.scope.describe()}"
        )

    console.print(
        f"[bold]{authorization.engagement_name}[/bold]  "
        f"(authorized by {authorization.authorized_by})"
    )
    module_label = ", ".join(modules) or "all (non-intrusive)"
    console.print(f"Targets: {len(expanded_targets)}  |  Modules: {module_label}")

    engagement = Engagement(authorization, audit_path=audit_log)

    unknown = [m for m in modules if m not in ALL_MODULES]
    if unknown:
        raise click.ClickException(f"Unknown module(s): {', '.join(unknown)}")

    with console.status("[bold green]Running assessment..."):
        result = engagement.run(
            expanded_targets,
            module_names=list(modules) or None,
            use_ai=not no_ai,
        )

    console.print(
        f"[green]Done.[/green] {len(result.findings)} findings collected "
        f"(advisory: {result.advisory.generated_by})."
    )

    if fmt == "json":
        report = render_json(authorization, result)
    else:
        report = render_markdown(authorization, result)
    if output_path:
        with open(output_path, "w") as f:
            f.write(report)
        console.print(f"Report written to {output_path}")
    else:
        console.print(report)

    if reports_dir:
        saved_path = save_report(reports_dir, authorization, result)
        console.print(
            f"Saved to {saved_path} (view with: nodezero serve --reports-dir {reports_dir})"
        )


@main.command("serve")
@click.option(
    "--reports-dir",
    default="nodezero_reports",
    type=click.Path(),
    help="Directory of saved JSON reports to serve (written by 'nodezero run').",
)
@click.option("--host", default="127.0.0.1", help="Bind address. Defaults to localhost only.")
@click.option("--port", default=8765, type=int)
def serve(reports_dir, host, port):
    """Serve a local, read-only web viewer over saved reports.

    This only renders report files 'nodezero run' already wrote to
    REPORTS-DIR — it cannot start a scan or change any authorization.
    """
    try:
        from nodezero.webui.app import create_app
    except ImportError as exc:
        raise click.ClickException(
            "The web UI needs the 'web' extra. Install with: pip install -e '.[web]'"
        ) from exc

    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print(
            "[yellow]Warning:[/yellow] binding to a non-local host exposes report "
            "data (target lists, findings) to anyone who can reach it on your "
            "network. This viewer has no authentication of its own."
        )

    app = create_app(reports_dir)
    console.print(f"[green]Serving reports from {reports_dir} at http://{host}:{port}[/green]")
    console.print("Press CTRL+C to stop.")
    app.run(host=host, port=port)


if __name__ == "__main__":
    main()
