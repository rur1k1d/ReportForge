# ReportForge — v0.2 Improvement Plan (executed via /goal)

Status: **DONE — implemented 2026-10-11, released as v0.2.0, repo is now PUBLIC
(`rur1k1d/ReportForge`).** The file stays as the provenance record.
Language: all files, code, comments, and this document in English.

## Objective

Turn ReportForge v0.1 (web-only, correct for solo use) into v0.2: a headless-first
tool with real correctness fixes, native Markdown export, persisted smart context,
hardened defaults, and a complete project file. Then push it PUBLIC
(`rur1k1d/ReportForge`).

## Current state (verified from code, do not re-derive)

- Stack: FastAPI + Jinja2 SSR, SQLite (`data/reportforge.db`), WeasyPrint PDF,
  python-docx DOCX, rule-based SmartContext. 28 backend tests.
- Layout: `backend/app/{main,web,api,core,models,services}/...`, templates in
  `backend/app/templates/{render,web}/`, data in `data/{branding,insights,
  findings_library}/`.
- Working: reports CRUD, findings CRUD, import (yaml | nuclei jsonl |
  bb_workflow | burp xml, `auto` detect), export html/pdf/docx, smart context
  (dominant vector + CVE trends), branding with defaults merge.
- Repo: `git@github.com:rur1k1d/ReportForge.git`, branch main, 1 commit
  (`21ac713`), visibility PRIVATE, identity local `commander@clevertrap.local`.
- README says "26 tests" (real: 28) and links to `TODO.md` which does NOT exist.

## Bugs / correctness fixes (do these first, with tests)

1. CVSS is parsed into `RawFinding.extra["cvss"]` but NEVER written to the
   `finding.cvss` column. Root cause: `backend/app/api/routes.py` (`import_findings`,
   ~line 131) and `backend/app/web.py` (`import_page`, ~line 194) build `Finding(...)`
   without `cvss=rf.extra.get("cvss")`. Also `FindingIn` schema has no `cvss` field.
   Fix: add `cvss` to `FindingIn`, map it on BOTH import paths, also from
   `from_yaml`/nuclei where available.

   DONE: `cvss` added to RawFinding + FindingIn; both import paths + web
   add/update forms write it; yaml/nuclei/bb_workflow fill it (nuclei uses
   `classification.cvss-metrics`). Tests: test_yaml_cvss_passthrough,
   test_add_finding_with_cvss.

2. API import has no dedupe while the web import form does. Fix: add a `dedupe`
   bool to `ImportRequest` and honor it in `/api/reports/{id}/import` exactly like
   `web.import_page`. Extract a single shared `dedupe_findings(existing_keys, raw)`
   helper used by both paths (single source of truth).

   DONE: `existing_keys` + `dedupe_raw` helpers in ingest.py, used by API + web;
   `ImportRequest.dedupe`. Tests: test_import_dedupe_api, test_dedupe_helper.

3. Dead code: `SmartContextRequest` schema in `backend/app/api/schemas.py` is
   unused. Remove it.

   DONE: removed.

4. `smart_context_json` column on `Report` is declared but never persisted. Decide:
   persist the SmartContext result there on regeneration (cache), so the API
   `/smart-context` can return stored value (still recompute to keep fresh).

   DONE: `SmartContext.build_and_persist()` (serializes + commit); used by API
   GET and web POST /smart-context. Test: test_smart_context_web persistence
   assertion.

## Headless CLI (new capability, main differentiator)

- New `bin/reportforge` launcher script (bash) resolving repo root through
  symlinks, then `exec <repo>/.venv/bin/python -m reportforge "$@"` (or pytest-style
  fallback to system python if venv absent).
- New package command module `backend/app/cli.py` with `python -m reportforge`
  entry (add `backend/app/__main__.py`). Commands:
  - `list [--status X]`
  - `create --title T --client C [--template pentest|va] [--branding B]`
  - `import --report ID --src yaml|nuclei|bb_workflow|burp|auto [--file PATH|
    --stdin] [--label L] [--dedupe]`
  - `render --report ID [--branding B]` (print HTML to stdout)
  - `export --report ID --format html|pdf|docx|md --out PATH`
- Symlink `~/.local/bin/reportforge` -> `bin/reportforge` (pattern mirrors
  ShadowReap). Verify from any cwd.
- Trade-off note: CLI talks directly to the same services (exporter, ingest,
  smart_context) + SQLAlchemy session, NOT over HTTP. Keep logic shared.

  DONE: `backend/app/cli.py` (commands list/create/import/render/export/smart) +
  `__main__.py` (`python -m app.cli`), `bin/reportforge` launcher resolves the
  repo root through symlinks, runs `.venv` python with `backend/` on PYTHONPATH,
  falls back to `python3` if venv missing. `~/.local/bin/reportforge` symlink
  installed. Smoke from `/tmp` passes (create/import/smart/export all four
  formats).

## Native Markdown export (no pandoc dependency)

- New `exporter.markdown(report, findings, branding_ref) -> str`.
  Structure: `# title`, meta block (client, scope, template, version, date),
  `## Executive Summary`, severity counts table (markdown pipe table),
  per-finding sections grouped by severity (title, tags, asset, description,
  impact, evidence fenced code block, recommendation).
- Wire into API `/export?format=md` (extend the `pattern` today strictly
  `html|pdf|docx`) and web export (`fmt=md`). `media_type: text/markdown`.
- Test: `test_export_markdown` asserting the 5 structural sections exist and
  severity table renders.

  DONE: `exporter.render_markdown()` (native writer, no pandoc), wired into API
  `?format=md`, web `fmt=md`, CLI `export --format md`. Tests:
  test_export_markdown (+ API variant).

## Smart context -> report

- `top_cwes` is computed but never shown in the rendered report. Add a
  "Common weaknesses" list to `backend/app/templates/render/pentest/report.html.j2`
  near the existing `smart.trends` block (only when non-empty).
- Persist `smart_context_json` on regeneration (see fix #4). Test: recompute +
  assert column non-empty after `POST /smart-context`.

  DONE: "Common weaknesses" block in pentest template (renders when non-empty);
  persistence via build_and_persist (item 1-4 above). Test:
  test_render_html_top_cwes.

## Branding

- Add second ready-made theme `data/branding/consulting.yaml` (light neutral
  palette, e.g. accent `#1F4E5F` / navy-teal), minimal keys only (rest merges
  from default).
- README: short "Custom branding" section: drop `data/branding/<client>.yaml`,
  select via report form/API, keys listed.

  DONE: `data/branding/consulting.yaml` (navy/teal #1F4E5F, defaults merge
  verified); README "Custom branding" section added.

## Hardening

- CORS: `allow_origins` from env var `REPORTFORGE_ORIGINS` (comma-separated),
  default `http://127.0.0.1:8000`. No bare `*` by default.
- README Quick start: explicit note to bind `--host 127.0.0.1` for local-only use.
- Add `exports/` + `/data/reportforge.db*` are already ignored; also add
  `*.html`/`*.pdf`/`*.docx`/`*.md` under `exports/` via a `.gitignore` entry.
- Secret sweep before push: `grep -rniE "api[_-]?key|secret|password|token"`.

  DONE: CORS from `config.CORS_ORIGINS` (env, default 127.0.0.1:8000, no
  wildcard); bind note in README Quick start; `exports/` in .gitignore (checked
  with `git check-ignore`, README/TODO stay tracked).

## Housekeeping / docs

- Bump version: `backend/app/main.py` `version="0.2.0"`, model default `v0.1` ->
  `v0.2`, `web.py`/`schemas.py` defaults.
- `generator` string in `renderer.build_context`: drop "legacy build".
- README: real test count (28 -> whatever green), CLI section, exports list
  (html/pdf/docx/md), Roadmap updated to v0.2, note about no client data in repo.
- Commit message style: `feat:` semantic prefix (house rule).
- GitHub after push: repo PUBLIC, set description ("Self-hosted security report
  generator — headless CLI + web, HTML/PDF/DOCX/Markdown export") and topics
  (python, fastapi, pentest, report-generator, security-tooling).

  DONE: version 0.2.0 everywhere; generator "ReportForge v0.2"; README synced
  (35 tests, Headless CLI section, markdown in exports, Custom branding,
  Roadmap v0.2, no-client-data note); TODO.md carries provenance.

## Verification (must pass before release)

- `cd backend && ../.venv/bin/python -m pytest tests/ -q` all green (or
  `.venv/bin/python -m pytest backend/tests -q` from project root).
- CLI smoke from a DIFFERENT directory: `reportforge list`, then
  `reportforge create ...`, `reportforge import ...`, `reportforge export
  --format md|pdf|docx|html` and confirm files exist and open.
- API smoke: report CRUD + import + `?format=md` export via curl/httpx.
- Secret + data sweep: no client PII, no `reportforge.db` in tree, `exports/`
  ignored.
- `git status` clean of junk (`__pycache__`, venv, db, preview artifacts).

  DONE: 35/35 pytest green; CLI smoke from /tmp; API smoke in test suite
  (CRUD, import, format=md, format=html, smart-context persistence);
  secret sweep clean; exports/ ignored; git status clean.

## Deliverables

- `backend/app/cli.py`, `backend/app/__main__.py`, `bin/reportforge` +
  `~/.local/bin/reportforge` symlink.
- `exporter.markdown` + API/web wiring + test.
- CVSS + API dedupe fixes + shared helper + tests.
- `data/branding/consulting.yaml`, env-driven CORS, updated templates.
- `README.md` and this `TODO.md` kept in sync (README already links it — it now
  exists).
- Repo pushed PUBLIC, description + topics set, semantic commit.