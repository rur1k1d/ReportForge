# ReportForge

Self-hosted security report generator. Turn findings from a pentest / bug
bounty workflow into a clean, branded report in minutes: no LLM required,
no Docker, no external services.

Built for the way a solo pentester actually works: import what you already
have, add a small amount of context, export.

## Status

v0.1 (working build): local FastAPI app + Jinja2 web UI. Ingests findings,
computes a rule-based smart context, renders a pentest report, exports to
HTML / PDF / DOCX.

## Stack

- FastAPI + Jinja2 SSR (web UI and the report template render server-side)
- SQLite (single file in `data/`): no server, no Docker
- WeasyPrint for PDF, python-docx for DOCX, pandoc-compatible HTML
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

Tests (run from the project root):

```bash
.venv/bin/python -m pytest backend/tests -q
```

## Workflow (4 clicks)

1. Create a report (title, client, scope, template type)
2. Import findings: paste `bb_workflow` `report.json`, nuclei JSONL output,
   Burp Suite XML, or a manual YAML list (auto-detected)
3. Generate Smart Context (rule-based: dominant vector, insight, CVE trends)
4. Export: HTML, PDF, or DOCX

## Import formats

| Source | Shape | Notes |
|---|---|---|
| bb_workflow | `report.json` | Machine-owned: target, live hosts, tech, vulns |
| nuclei | JSONL (`-jsonl -o`) | Per-line JSON, `info` object |
| Burp Suite | XML export | Namespaced and plain `<issue>` handled |
| Manual | YAML list | `title`, `severity`, `description`, `recommendation` |

Severity is canonicalized (informational/info/none → info, moderate → medium,
severe → critical, unknown → medium) and never silently dropped.

## Smart Context

Rule-based only in v1: findings are matched (by keyword over title/CWE/CVE/
asset) against vectors in `data/insights/vectors.yaml`: webapp, AD, cloud,
infrastructure, supply chain, process. The result drives:

- dominant theme paragraph in the executive summary
- CVE year trend + top CWE list in the editor

Ollama/mistral summarization is a possible improvement, tracked in the
project TODO: not wired in.

## Layout

```
backend/
  app/
    main.py            # FastAPI entrypoint (api + web routers)
    api/               # JSON API (CRUD, import, export)
    core/              # config paths, SQLAlchemy engine/session
    models/            # Report, Finding ORM + severity vocab
    services/          # ingest, renderer, exporter, smart_context, branding
    templates/
      render/          # report templates (pentest anchor, va variant)
      web/             # web UI pages
    web.py             # web UI routes (server-side forms)
    tests/             # pytest suite (26 tests)
data/
  branding/            # default.yaml + per-client overrides
  insights/            # rule-based vector definitions
  findings_library/    # reusable finding YAML you can copy-paste import
```

## Roadmap

- Phase 1-4 (ingest, render/export, smart context, API+UI): **done**
- Markdown export via pandoc path
- Drag-and-drop evidence screenshots into DOCX/PDF
- Client branding packs (2-3 ready-made themes)

See `TODO.md` (project) for the full queue.