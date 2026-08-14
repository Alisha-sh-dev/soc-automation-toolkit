"""
SOC Automation Toolkit - CLI Interface

Provides command-line access to:
  - IOC Enrichment
  - Log Triage
  - Phishing Analysis

Usage:
    python -m src.cli ioc-enrich 8.8.8.8
    python -m src.cli log-triage /var/log/apache2/access.log --type apache
    python -m src.cli phishing-analyze suspicious_email.eml
"""

import json
import sys
from pathlib import Path

import click

from src.ioc_enricher import IOCEnricher
from src.log_triage import LogTriageEngine
from src.phishing_analyzer import PhishingAnalyzer


@click.group()
@click.version_option(version="1.0.0", prog_name="soc-toolkit")
@click.option("--config", "-c", default="config.yaml", help="Path to config file.")
@click.pass_context
def cli(ctx: click.Context, config: str) -> None:
    """SOC Automation Toolkit - Automate Tier-1 analyst workflows."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = config

    # Validate config exists
    if not Path(config).exists():
        click.echo(f"Error: Config file not found: {config}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("ioc")
@click.option("--output", "-o", default="-", help="Output file (default: stdout).")
@click.option("--format", "fmt", type=click.Choice(["json", "table"]), default="json")
@click.pass_context
def ioc_enrich(ctx: click.Context, ioc: str, output: str, fmt: str) -> None:
    """Enrich a single IOC (IP, hash, or domain)."""
    config = ctx.obj["config"]
    enricher = IOCEnricher(config)

    click.echo(f"Enriching IOC: {ioc}...", err=True)
    result = enricher.enrich(ioc)

    if fmt == "json":
        output_text = result.to_json()
    else:
        # Simple table format
        lines = [
            f"IOC:          {result.ioc}",
            f"Type:         {result.ioc_type.value}",
            f"Risk Score:   {result.risk_score:.1f}/100",
            f"Risk Level:   {result.risk_level.value.upper()}",
            f"Sources:      {', '.join(result.sources.keys())}",
        ]
        if result.errors:
            lines.append(f"Errors:       {', '.join(result.errors)}")
        output_text = "\n".join(lines)

    if output == "-":
        click.echo(output_text)
    else:
        with open(output, "w") as f:
            f.write(output_text)
        click.echo(f"Report saved to {output}", err=True)


@cli.command("ioc-enrich-batch")
@click.argument("file", type=click.Path(exists=True))
@click.option("--output", "-o", default="-", help="Output file (default: stdout).")
@click.pass_context
def ioc_enrich_batch(ctx: click.Context, file: str, output: str) -> None:
    """Enrich multiple IOCs from a file (one per line)."""
    config = ctx.obj["config"]
    enricher = IOCEnricher(config)

    with open(file, "r") as f:
        iocs = [line.strip() for line in f if line.strip()]

    click.echo(f"Enriching {len(iocs)} IOCs...", err=True)
    results = enricher.enrich_batch(iocs)

    report = {
        "total": len(results),
        "results": [r.to_dict() for r in results],
    }
    output_text = json.dumps(report, indent=2)

    if output == "-":
        click.echo(output_text)
    else:
        with open(output, "w") as f:
            f.write(output_text)
        click.echo(f"Report saved to {output}", err=True)


@cli.command("log-triage")
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--type", "log_type", type=click.Choice(["apache", "windows", "auto"]), default="auto",
              help="Log type (default: auto-detect).")
@click.option("--output", "-o", default="-", help="Output file (default: stdout).")
@click.pass_context
def log_triage(ctx: click.Context, logfile: str, log_type: str, output: str) -> None:
    """Analyze log files for anomalies and security events."""
    config = ctx.obj["config"]
    engine = LogTriageEngine(config)

    detected_type = None if log_type == "auto" else log_type

    click.echo(f"Analyzing {logfile}...", err=True)
    report = engine.analyze_file(logfile, detected_type)

    output_text = report.to_json()

    if output == "-":
        click.echo(output_text)
    else:
        with open(output, "w") as f:
            f.write(output_text)
        click.echo(f"Report saved to {output}", err=True)

    # Summary to stderr
    click.echo(f"\nSummary: {report.total_events} events, {len(report.anomalies)} anomalies detected", err=True)
    for anomaly in report.anomalies:
        click.echo(f"  [!] {anomaly.severity.upper()}: {anomaly.description}", err=True)


@cli.command("phishing-analyze")
@click.argument("emlfile", type=click.Path(exists=True))
@click.option("--output", "-o", default="-", help="Output file (default: stdout).")
@click.pass_context
def phishing_analyze(ctx: click.Context, emlfile: str, output: str) -> None:
    """Analyze an .eml file for phishing indicators."""
    config = ctx.obj["config"]
    analyzer = PhishingAnalyzer(config)

    click.echo(f"Analyzing {emlfile}...", err=True)
    report = analyzer.analyze(emlfile)

    output_text = report.to_json()

    if output == "-":
        click.echo(output_text)
    else:
        with open(output, "w") as f:
            f.write(output_text)
        click.echo(f"Report saved to {output}", err=True)

    # Summary to stderr
    verdict = "SUSPICIOUS" if report.is_suspicious else "CLEAN"
    click.echo(f"\nVerdict: {verdict} (Risk Score: {report.risk_score:.1f}/100)", err=True)
    click.echo(f"URLs Found: {len(report.extracted_urls)}", err=True)
    if report.indicators:
        click.echo("Indicators:", err=True)
        for ind in report.indicators:
            click.echo(f"  - {ind}", err=True)


if __name__ == "__main__":
    cli()
