#!/usr/bin/env bash
# ReportForge quick start: runs the FastAPI dev server with --reload.
# The virtualenv lives in the project root, so we resolve paths from here.
set -euo pipefail

cd "$(dirname "$0")/backend"
exec ../.venv/bin/uvicorn app.main:app --reload