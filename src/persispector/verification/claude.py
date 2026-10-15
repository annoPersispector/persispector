"""Non-interactive Claude Code adapter used by the verification supervisor."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import uuid
from typing import Any

from persispector.verification.models import (
    AgentCompletion,
    AgentRunRecord,
    AgentRunExecutionStatus,
    AgentState,
    VerificationPolicy,
    VerificationTaskManifest,
)


_FUNDS_PATTERNS = (
    "credit balance",
    "credits exhausted",
    "insufficient credits",
    "billing error",
    "payment required",
    "spending limit",
)
_CREDENTIAL_PATTERNS = (
    "authentication failed",
    "not logged in",
    "invalid api key",
    "authentication_error",
    "please run /login",
)
_RATE_LIMIT_PATTERNS = (
    "rate limit",
    "rate_limit",
    "too many requests",
    "session limit",
    "usage limit",
    "you've hit your limit",
    "you have hit your limit",
)


class ClaudeCodeBackend:
    """Launch and resume one Claude Code session for one application."""

    def __init__(
        self,
        *,
        command: str = "claude",
        model: str | None = None,
        allowed_tools: list[str] | None = None,
        timeout_seconds: float | None = None,
        max_turns: int | None = None,
        max_budget_usd: float | None = None,
        permission_mode: str = "dontAsk",
    ) -> None:
        resolved = shutil.which(command)
        if resolved is None:
            candidate = Path(command).expanduser()
            if not candidate.is_file():
                raise ValueError(f"Claude Code executable was not found: {command}")
            resolved = str(candidate.resolve())
        self.command = resolved
        self.model = model
        self.allowed_tools = allowed_tools or [
            "Read",
            "Write",
            "Edit",
            "Glob",
            "Grep",
            "Bash",
        ]
        self.timeout_seconds = timeout_seconds
        self.max_turns = max_turns
        self.max_budget_usd = max_budget_usd
        self.permission_mode = permission_mode

    def start(self, task: VerificationTaskManifest) -> AgentRunRecord:
        prompt = Path(task.instructions_file).read_text(encoding="utf-8")
        return self._run(task, prompt=prompt, resume_session=None)

    def resume(
        self,
        task: VerificationTaskManifest,
        session_id: str,
        feedback: str,
    ) -> AgentRunRecord:
        prompt = (
            "Continue the Persispector verification assignment. Preserve all valid existing "
            "artifacts, correct the issues below, revalidate the complete target inventory, "
            "and return a fresh schema-conforming completion object.\n\n"
            + feedback
        )
        return self._run(task, prompt=prompt, resume_session=session_id)

    def _run(
        self,
        task: VerificationTaskManifest,
        *,
        prompt: str,
        resume_session: str | None,
    ) -> AgentRunRecord:
        policy = VerificationPolicy.model_validate_json(
            Path(task.policy_file).read_text(encoding="utf-8")
        )
        timeout = self.timeout_seconds or float(policy.max_runtime_seconds)
        max_turns = self.max_turns or policy.max_agent_turns
        max_budget = (
            self.max_budget_usd
            if self.max_budget_usd is not None
            else policy.max_budget_usd
        )
        schema = json.loads(Path(task.result_schema_file).read_text(encoding="utf-8"))
        command = [
            self.command,
            "--print",
            "--safe-mode",
            "--output-format",
            "stream-json",
            "--verbose",
            "--json-schema",
            json.dumps(schema, separators=(",", ":")),
            "--permission-mode",
            self.permission_mode,
            "--permission-prompts",
            "none",
            "--allowedTools",
            ",".join(self.allowed_tools),
            "--max-turns",
            str(max_turns),
            "--add-dir",
            str(Path(task.constraint_report).parent),
            "--add-dir",
            task.output_directory,
        ]
        if self.model:
            command.extend(["--model", self.model])
        if max_budget is not None:
            command.extend(["--max-budget-usd", str(max_budget)])
        if resume_session:
            command.extend(["--resume", resume_session])

        run_id = uuid.uuid4().hex[:12]
        agent_dir = Path(task.supervisor_directory) / "agent"
        agent_dir.mkdir(parents=True, exist_ok=True)
        events_path = agent_dir / f"{run_id}.jsonl"
        stderr_path = agent_dir / f"{run_id}.stderr.log"
        started = datetime.now(timezone.utc)
        exit_code: int | None = None
        timed_out = False
        launch_error: str | None = None
        env = os.environ.copy()
        env.update(
            {
                "PERSISPECTOR_VERIFICATION_TASK_ID": task.task_id,
                "PERSISPECTOR_VERIFICATION_OUTPUT": task.output_directory,
            }
        )
        try:
            with events_path.open("w", encoding="utf-8") as events, stderr_path.open(
                "w", encoding="utf-8"
            ) as stderr:
                process = subprocess.Popen(
                    command,
                    cwd=task.application_directory,
                    stdin=subprocess.PIPE,
                    stdout=events,
                    stderr=stderr,
                    text=True,
                    env=env,
                    start_new_session=True,
                )
                try:
                    process.communicate(input=prompt, timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    self._signal_group(process.pid, signal.SIGTERM)
                    try:
                        process.communicate(timeout=15)
                    except subprocess.TimeoutExpired:
                        self._signal_group(process.pid, signal.SIGKILL)
                        process.communicate()
                finally:
                    # Claude is expected to clean up the application. This also
                    # terminates forgotten background descendants in its process group.
                    self._signal_group(process.pid, signal.SIGTERM)
                exit_code = process.returncode
        except OSError as error:
            launch_error = str(error)
            stderr_path.write_text(launch_error + "\n", encoding="utf-8")
            events_path.touch()

        finished = datetime.now(timezone.utc)
        event_data = self._read_events(events_path)
        completion = self._completion(event_data)
        session_id = self._session_id(event_data) or resume_session
        stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
        combined_error = "\n".join(
            [stderr_text, self._event_error_text(event_data), launch_error or ""]
        ).strip()
        execution_status = self._execution_status(
            completion=completion,
            exit_code=exit_code,
            timed_out=timed_out,
            error_text=combined_error,
        )
        record = AgentRunRecord(
            run_id=run_id,
            application=task.application,
            execution_status=execution_status,
            coverage_status=(
                completion.coverage_status if completion is not None else "none"
            ),
            started_at=started,
            finished_at=finished,
            command=self._display_command(command),
            working_directory=task.application_directory,
            session_id=session_id,
            resumed_from=resume_session,
            exit_code=exit_code,
            total_cost_usd=self._number(event_data, "total_cost_usd"),
            turns=self._integer(event_data, "num_turns"),
            events_file=str(events_path),
            stderr_file=str(stderr_path),
            completion=completion,
            error=combined_error or None,
        )
        self._append_state(task, record)
        return record

    @staticmethod
    def load_state(task: VerificationTaskManifest) -> AgentState:
        path = Path(task.supervisor_directory) / "agent-state.json"
        if not path.exists():
            return AgentState(application=task.application, task_id=task.task_id)
        return AgentState.model_validate_json(path.read_text(encoding="utf-8"))

    @staticmethod
    def _append_state(
        task: VerificationTaskManifest, record: AgentRunRecord
    ) -> None:
        state = ClaudeCodeBackend.load_state(task)
        state.runs.append(record)
        path = Path(task.supervisor_directory) / "agent-state.json"
        path.write_text(state.model_dump_json(indent=2) + "\n", encoding="utf-8")

    @staticmethod
    def _read_events(path: Path) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                events.append(value)
        return events

    @staticmethod
    def _completion(events: list[dict[str, Any]]) -> AgentCompletion | None:
        for event in reversed(events):
            for candidate in ClaudeCodeBackend._candidate_objects(event):
                if isinstance(candidate, str):
                    try:
                        candidate = json.loads(candidate)
                    except json.JSONDecodeError:
                        continue
                if not isinstance(candidate, dict):
                    continue
                try:
                    return AgentCompletion.model_validate(candidate)
                except ValueError:
                    continue
        return None

    @staticmethod
    def _candidate_objects(value: Any):
        """Yield likely structured completions from evolving CLI event shapes."""

        if isinstance(value, dict):
            if (
                "status" in value or "execution_status" in value
            ) and "application" in value:
                yield value
            for key in ("structured_output", "result", "output", "content"):
                if key in value:
                    yield from ClaudeCodeBackend._candidate_objects(value[key])
        elif isinstance(value, list):
            for item in value:
                yield from ClaudeCodeBackend._candidate_objects(item)
        elif isinstance(value, str):
            yield value

    @staticmethod
    def _session_id(events: list[dict[str, Any]]) -> str | None:
        for event in reversed(events):
            value = event.get("session_id")
            if isinstance(value, str) and value:
                return value
        return None

    @staticmethod
    def _number(events: list[dict[str, Any]], key: str) -> float | None:
        for event in reversed(events):
            value = event.get(key)
            if isinstance(value, (int, float)):
                return float(value)
        return None

    @staticmethod
    def _integer(events: list[dict[str, Any]], key: str) -> int | None:
        for event in reversed(events):
            value = event.get(key)
            if isinstance(value, int):
                return value
        return None

    @staticmethod
    def _event_error_text(events: list[dict[str, Any]]) -> str:
        parts: list[str] = []
        for event in events:
            if event.get("is_error") or event.get("type") == "error":
                for key in ("error", "message", "result"):
                    value = event.get(key)
                    if isinstance(value, str):
                        parts.append(value)
                    elif isinstance(value, dict):
                        parts.append(json.dumps(value, sort_keys=True))
        return "\n".join(parts)

    @staticmethod
    def _execution_status(
        *,
        completion: AgentCompletion | None,
        exit_code: int | None,
        timed_out: bool,
        error_text: str,
    ) -> AgentRunExecutionStatus:
        if timed_out:
            return "timed-out"
        lowered = error_text.lower()
        if any(pattern in lowered for pattern in _FUNDS_PATTERNS):
            return "needs-funds"
        if any(pattern in lowered for pattern in _CREDENTIAL_PATTERNS):
            return "needs-credentials"
        if any(pattern in lowered for pattern in _RATE_LIMIT_PATTERNS):
            return "rate-limited"
        if completion is not None:
            return completion.execution_status
        if exit_code == 0:
            return "invalid-output"
        return "failed"

    @staticmethod
    def _display_command(command: list[str]) -> list[str]:
        result = list(command)
        try:
            index = result.index("--json-schema") + 1
            result[index] = "<agent-result-schema>"
        except (ValueError, IndexError):
            pass
        return result

    @staticmethod
    def _signal_group(pid: int, requested_signal: signal.Signals) -> None:
        try:
            os.killpg(pid, requested_signal)
        except ProcessLookupError:
            pass
