"""Command-line interface for Persispector."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
import yaml

from persispector.generator import generate_openapi

app = typer.Typer(add_completion=False, help="Generate OpenAPI from a Java REST API project.")


@app.command()
def generate(
    project: Annotated[Path, typer.Argument(help="Java project source root.")],
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output .json/.yaml file.")] = None,
    title: Annotated[str | None, typer.Option(help="OpenAPI info.title (defaults to directory name).")] = None,
    version: Annotated[str, typer.Option(help="OpenAPI info.version.")] = "0.0.0",
    analysis_cache: Annotated[Path | None, typer.Option(help="Directory for CLDK's analysis.json cache.")] = None,
    eager: Annotated[bool, typer.Option(help="Refresh a cached CLDK analysis.")] = False,
) -> None:
    """Analyze PROJECT and emit an OpenAPI 3 document."""

    document = generate_openapi(
        project, title=title, version=version,
        analysis_json_path=analysis_cache, eager=eager,
    )
    if output and output.suffix.lower() in {".yaml", ".yml"}:
        rendered = yaml.safe_dump(document, sort_keys=False)
    else:
        rendered = json.dumps(document, indent=2) + "\n"
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        typer.echo(rendered, nl=False)


if __name__ == "__main__":
    app()
