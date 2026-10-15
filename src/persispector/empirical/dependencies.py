"""Load and flatten LlamaRestTest-style IPD files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from persispector.empirical.models import IPDRecord


def load_ipd_records(
    dependency_file: str | Path, application: str | None = None
) -> list[IPDRecord]:
    path = Path(dependency_file)
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    applications = [application] if application else list(data)
    records: list[IPDRecord] = []
    for app in applications:
        if app not in data:
            raise KeyError(f"Application {app!r} is not present in {path}.")
        for api_path, methods in data[app].items():
            for http_method, dependencies in methods.items():
                for dependency in dependencies:
                    records.append(
                        IPDRecord(
                            application=app,
                            path=api_path,
                            http_method=http_method.upper(),
                            dependency=dependency.strip(),
                            source_file=str(path),
                        )
                    )
    return records

