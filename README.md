# Persispector Artifact

## Environment setup

The artifact requires Python 3.11. The complete workflow also requires the
CodeQL CLI and a Java toolchain compatible with the application being analyzed.
Runtime verification additionally requires an authenticated Claude Code CLI.

The paper used CodeQL 2.26.4, `deepseek/deepseek-v4-pro-0813` for residual
static analysis, and `claude-opus-5-5` for runtime verification.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Copy the environment template and set the model-provider credentials:

```bash
cp .env.example .env
```

At minimum, set the following values in `.env`:

```dotenv
API_KEY=YOUR_API_KEY
BASE_URL=https://openrouter.ai/api/v1
PERSISTENCE_MODEL=deepseek/deepseek-v4-pro-0813
CODEQL_COMMAND=codeql
```

Do not commit `.env` or any credentials.

## Run the static-analysis pipeline

Run the complete pipeline, including CodeQL endpoint reachability and taint
analysis, on a Java application:

```bash
persispector-persistence run /path/to/java-project \
  --output-dir persistence-output \
  --codeql-taint
```

The command produces:

- `persistence-evidence.json`
- `persistence-taint.json`
- `persistence-constraints.json`
- `persistence-report.md`

Production source and resource files are analyzed by default; test and build
directories are excluded. Use `persispector-persistence run --help` for options
such as reusing a CodeQL database or selecting CodeQL's `autobuild` mode.

## Run runtime verification

Prepare and run an isolated verification task for an application:

```bash
persispector-verify delegate \
  /path/to/java-project \
  persistence-output/persistence-constraints.json \
  --taint-report persistence-output/persistence-taint.json \
  --application APPLICATION \
  --allowed-port PORT \
  --model claude-opus-5-5
```

Add `--allow-dependency-downloads` if deployment requires downloading build
dependencies. Use `--target-id TARGET_ID` to verify selected findings instead
of the entire report.

To inspect the generated task before invoking Claude Code, run
`persispector-verify prepare` first and then pass the printed task directory to
`persispector-verify run`.
