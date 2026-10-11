# ReportForge

Self-hosted security report generator. Turn findings from a pentest / bug
bounty workflow into a clean, branded report in minutes: no LLM required,
no Docker, no external services.

Built for the way a solo pentester actually works: import what you already
have, add a small amount of context, export.

## Status

v0.2 (working build): local FastAPI app + Jinja2 web UI **plus a headless
CLI**. Ingests findings, computes a rule-based smart context, renders a
pentest report, exports to HTML / PDF / DOCX / Markdown.

## Stack

- FastAPI + Jinja2 SSR (web UI and the report template render server-side)
- SQLite (single file in `data/`): no server, no Docker
- WeasyPrint for PDF, python-docx for DOCX, native Markdown writer
- Rule-based smart context (no LLM calls in the happy path)

## Quick start

The virtualenv lives at the project root (`.venv/`), same level as `backend/`
and `data/`. Start from the project root:

```bash
cd backend
../.venv/bin/uvicorn app.main:app --reload
```

Or, with the helper script:

```bash
./run.sh
```

Open http://127.0.0.1:8000/

> Local-only by default: bind explicitly to the loopback interface
> (`uvicorn app.main:app --host 127.0.0.1`) for personal use. If you must
> expose the API to another origin, set `REPORTFORGE_ORIGINS` to a
> comma-separated allowlist (default is `http://127.0.0.1:8000`).

Tests (run from the project root):

```bash
.venv/bin/python -m pytest backend/tests -q
```

## Headless CLI

A CLI talks directly to the same services the web app uses — no HTTP server
needed. Installed as a symlink in `~/.local/bin/` via `bin/reportforge`, so it
works from any directory:

```bash
reportforge list                          # list reports + severity counts
reportforge create --title "Pentest ACME" --client ACME --scope https://acme.example.com/
reportforge import --report 1 --src yaml --file findings.yaml --dedupe
reportforge smart --report 1              # compute + cache smart context
reportforge export --report 1 --format md --out report.md
reportforge export --report 1 --format pdf --out report.pdf
```

`import` reads from `--file` or stdin; `--src` accepts `auto` (default) or an
explicit `yaml|nuclei|bb_workflow|burp`.

## Workflow (4 clicks, or 4 CLI commands)

1. Create a report (title, client, scope, template type)
2. Import findings: paste `bb_workflow` `report.json`, nuclei JSONL output,
   Burp Suite XML, or a manual YAML list (auto-detected)
3. Generate Smart Context (rule-based: dominant vector, insight, CVE trends,
   top CWEs)
4. Export: HTML, PDF, DOCX, or Markdown

## Import formats

| Source | Shape | Notes |
|---|---|---|
| bb_workflow | `report.json` | Machine-owned: target, live hosts, tech, vulns |
| nuclei | JSONL (`-jsonl -o`) | Per-line JSON, `info` object |
| Burp Suite | XML export | Namespaced and plain `<issue>` handled |
| Manual | YAML list | `title`, `severity`, `description`, `recommendation` |

Severity is canonicalized (informational/info/none → info, moderate → medium,
severe → critical, unknown → medium) and never silently dropped. CVSS vectors
and scores imported from YAML or nuclei (`cvss-metrics`) are stored on the
finding. Import dedupe (by title+asset) is available in both web (`dedupe`
checkbox, the CLI `--dedupe` flag) and API (`"dedupe": true`).

## Smart Context

Rule-based only: findings are matched (by keyword over title/CWE/CVE/asset)
against vectors in `data/insights/vectors.yaml`: webapp, AD, cloud,
infrastructure, supply chain, process. The result drives:

- dominant theme paragraph in the executive summary
- CVE year trend + top CWE list in the editor **and in the rendered report**
- persisted per report as `smart_context_json` (recomputed on demand)

Ollama/mistral summarization is a possible improvement, tracked in the
project `TODO.md`: not wired in.

## Custom branding

Per-client theming is a YAML file in `data/branding/`:

1. Drop `data/branding/<client>.yaml` with any of these keys:
   `company`, `analyst`, `logo`, `accent_color`, `address`, `website`,
   `disclaimer`
2. Missing keys auto-merge from `data/branding/default.yaml`
3. Select the profile on the report form / API (`branding_ref`), or pass
   `--branding <client>` to the CLI

Two ready-made themes ship: `default` (dark red accent) and `consulting`
(navy/teal `#1F4E5F`).

## Layout

```
backend/
  app/
    main.py            # FastAPI entrypoint (api + web routers)
    cli.py             # headless CLI (python -m app.cli)
    api/               # JSON API (CRUD, import, export)
    core/              # config paths, SQLAlchemy engine/session
    models/            # Report, Finding ORM + severity vocab
    services/          # ingest, renderer, exporter, smart_context, branding
    templates/
      render/          # report templates (pentest anchor, va variant)
      web/             # web UI pages
    web.py             # web UI routes (server-side forms)
    tests/             # pytest suite (35 tests)
bin/
  reportforge          # CLI launcher (resolves the repo + venv through symlinks)
data/
  branding/            # default.yaml + per-client overrides
  insights/            # rule-based vector definitions
  findings_library/    # reusable finding YAML you can copy-paste import
```

## Roadmap

- Phase 1-4 (ingest, render/export, smart context, API+UI): done
- v0.2: headless CLI, native Markdown export, CVSS passthrough, shared
  import dedupe, persisted smart context, env-driven CORS, ready-made
  branding packs, TODO.md
- Drag-and-drop evidence screenshots into DOCX/PDF
- Optional Ollama summarization behind a config flag

Plans live in `TODO.md`; the repo contains **no client data** — the runtime
DB (`data/reportforge.db`) and generated `exports/` are git-ignored.