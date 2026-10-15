# Persispector Artifact

## Environment setup

The artifact requires Python 3.11. The complete workflow also requires the
CodeQL CLI and a Java toolchain compatible with the application being analyzed.
Runtime verification additionally requires an authenticated Claude Code CLI.

The paper used CodeQL 2.26.4, `deepseek/deepseek-v4-pro-0813` for residual
static analysis, and `claude-opus-5-5` for runtime verification.

```bash
python -m venv .venv
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


## Prepare the subject applications

The ten-application bundles are distributed separately as a dataset [(Zenodo)](https://doi.org/10.5281/zenodo.23388151). Download and extract that archive so that this repository has the following layout:

```text
dataset/
  APPLICATION/
    APPLICATION-TASK-ID/
      application/
      inputs/
      output/
      supervisor/
      task.json
```

The dataset preserves the deployment bundles' file contents and original path metadata. It omits generated `build/` and `target/` directories; Maven/Gradle build files, wrappers, source files, compatibility code, and generated runtime harnesses remain. Build an application with its included wrapper before running it when compiled outputs are required.

For exact replay, the Eventuate bundle retains its generated MySQL `data/` and `run/` state, including MySQL-generated CA, server, and client private keys. These keys are intentionally disclosed test-only material. The recorded MySQL instance uses a local Unix socket with `skip-networking`, and the application uses `sslMode=DISABLED`. Do not reuse these keys or expose this database state on a network. Stored configuration still contains original absolute paths, so reviewers must either reproduce that layout, update those paths locally, or initialize a fresh database.

Some stored task manifests contain absolute paths from the original execution environment. They are provenance records, not portable launchers. For a fresh run, pass the extracted `application/` directory to Persispector as shown below and write new outputs under `reproduced/`.

The dataset is not needed to read the supplied results or regenerate the paper tables.

## Run the static-analysis pipeline

List the available application identifiers:

```bash
./scripts/run_persistence.sh --list
```

Run the complete pipeline, including CodeQL endpoint reachability and taint analysis, for one application:

```bash
./scripts/run_persistence.sh APPLICATION
```

Run it sequentially for all ten applications:

```bash
./scripts/run_persistence_all.sh
```

The batch script asks for confirmation because it invokes CodeQL and the model provider ten times. Use `--dry-run` to print commands without executing them, or `--yes` for confirmed non-interactive execution. Additional CLI options can be passed after `--`, for example:

```bash
./scripts/run_persistence.sh APPLICATION -- --codeql-build-mode autobuild
```

Each run writes to `reproduced/APPLICATION/static/` and produces:

- `persistence-evidence.json`
- `persistence-taint.json`
- `persistence-constraints.json`
- `persistence-report.md`

Production source and resource files are analyzed by default; test and build directories are excluded. Use `persispector-persistence run --help` for options such as reusing a CodeQL database or selecting CodeQL's `autobuild` mode.

## Run runtime verification

First run static analysis for the selected application. Then start runtime verification with:

```bash
./scripts/run_verification.sh APPLICATION
```

Run verification sequentially for all applications after all static reports have been generated:

```bash
./scripts/run_verification_all.sh
```

The runners supply the paper's application labels, model, and allowed ports, including secondary local-service ports. Dependency downloads are enabled because compiled build outputs are not distributed. Runtime tasks are written to `reproduced/APPLICATION/runtime-RUN_ID/`. The all-app runner is sequential to avoid port conflicts and asks for confirmation because it can take several hours and incur substantial model cost.

Use `--dry-run` to inspect commands, `--yes` for confirmed non-interactive batch execution, and pass additional verification options after `--`. For example:

```bash
./scripts/run_verification.sh APPLICATION -- --target-id TARGET_ID
```

Set `PERSISPECTOR_RUN_ID` to name a runtime run and `PERSISPECTOR_VERIFY_MODEL` to override `claude-opus-5-5`. Set `PERSISPECTOR_DATASET_DIR` or `PERSISPECTOR_REPRODUCED_DIR` to override the default `dataset/` and `reproduced/` locations.

To inspect the generated task before invoking Claude Code, run `persispector-verify prepare` first and then pass the printed task directory to `persispector-verify run`.

## Read the stored results and reproduce the paper tables

The commands in this section aggregate files under `results/` only. They do not use `dataset/`, rerun static analysis, deploy an application, contact a model provider, or send runtime requests.

### RQ1: Constraints not enforced in application code

`results/RQ1/` contains compact runtime-verification results for the ten applications. Each application directory contains:

- `output/verification-results.json` and `.csv`, with the finding-level runtime
  classifications;
- `output/verification-report.md`, the corresponding readable report;
- `output/raw/`, `output/logs/`, and (where present) `output/source/`, containing evidence cited by the results; and
- `inputs/persistence-constraints.json`, which supplies the static finding kind and metadata used in aggregation.

No manual-review CSV is included or used. Tables 2 and 3 are derived directly from exact-predicate-confirmed runtime results whose outcome is `DATABASE_ENFORCED_HANDLED` or `DATABASE_ENFORCED_UNHANDLED`.

Reproduce Tables 2 and 3 with:

```bash
python results/RQ1/generate_tables.py
```

### RQ2: Types of inferred constraints and dependences

`results/RQ2/reports/` contains the static `persistence-constraints.json` report for each application. `results/RQ2/reviewed-findings.csv` is the consolidated finding inventory used for aggregation. Rows marked `incorrect` in `review_decision` are excluded from the verified source inventory. The `Active` column in Table 5 excludes rows whose runtime outcome is `VARIANT_NOT_DEPLOYED`.

Reproduce Tables 4 and 5 with:

```bash
python results/RQ2/generate_tables.py
```

### RQ3: Accuracy of inferred constraints and dependences

`results/RQ3/persispector_corpus_10.xlsx` contains one worksheet per application. The `origin` column identifies deterministic, LLM-generated, and modeled findings. For LLM-generated findings, `manual_review_status` is `1` for a correct finding and `0` for an incorrect finding; `manual_review_notes` records review notes where applicable. The four foreign-key dependences derived from the reviewed LLM join-table declarations are attributed to the LLM-assisted component, as in the paper.

Reproduce Table 6 with:

```bash
python results/RQ3/generate_tables.py
```
