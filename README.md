# ARGUS

**AI-Driven Network Guard & Unified Security**

ARGUS is an early-stage network security analytics project. It currently provides a Python API and an offline ingestion pipeline for normalizing Zeek and Suricata events into a shared schema and storing them in PostgreSQL.

> **Work in progress:** ARGUS is not a complete or production-ready security platform. ML-based analysis, live ingestion, deployment hardening, and broader operational documentation are still in development. Treat current analysis responses as placeholders.

## Current capabilities

- Parse Zeek tab-separated logs and Suricata EVE JSON.
- Normalize supported records into a common event model.
- Store and query events in PostgreSQL.
- Expose health and event endpoints through FastAPI.
- Run the API with Docker Compose.

## Project layout

```text
config/                 Application configuration
docker/                 Supporting container configuration
logs/                   Local Zeek and Suricata input logs (not committed)
models/                 Future model artifacts (not committed)
pcaps/                  Local packet captures (not committed)
src/argus/api/          FastAPI application and routes
src/argus/database/     SQLAlchemy models and persistence
src/argus/parsers/      Zeek and Suricata parsers
src/argus/schemas/      Shared event schemas
src/argus/services/     Ingestion and normalization
tests/                  Automated tests
```

## Requirements

- Python 3.10 or later
- PostgreSQL 14 or later, locally or hosted
- Docker and Docker Compose (optional)

## Local setup

Create and activate a virtual environment, then install the pinned dependencies:

```bash
python -m venv .venv
```

On macOS/Linux:

```bash
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Then install dependencies and configure the database:

```bash
python -m pip install -r requirements.txt
cp .env.example .env
```

Set `DATABASE_URL` in `.env` to a PostgreSQL connection string available to the API. The example value is a placeholder and requires a matching local database and credentials.

Start the API from the project root:

```bash
uvicorn argus.api.main:app --app-dir src --reload --host 127.0.0.1 --port 8001
```

Interactive API documentation is available at `http://127.0.0.1:8001/docs`; the health endpoint is `http://127.0.0.1:8001/health`.

## Ingesting logs

The ingestion command parses, normalizes, and stores one log file. PostgreSQL must be available through `DATABASE_URL`.

```bash
# macOS/Linux
PYTHONPATH=src python -m argus.services.ingestion --source zeek --file logs/zeek/conn.log
```

```powershell
# Windows PowerShell
$env:PYTHONPATH = "src"
python -m argus.services.ingestion --source suricata --file logs/suricata/eve.json
```

## Docker Compose

Copy `.env.example` to `.env`, set `DATABASE_URL` to a database reachable from inside the container, then run:

```bash
docker compose up --build
```

The API listens on port `8001`. The Compose setup starts only the API; it does not provision PostgreSQL. A database running on the host may need a Docker-reachable hostname rather than `localhost`.

## Tests

Run the test suite from the project root:

```bash
python -m pytest
```

## Development status

This repository is a working foundation, not a finished product. Planned work includes completing and validating analysis functionality, adding live or scheduled ingestion, improving database migrations and operational setup, and expanding security and deployment guidance. Interfaces and behavior may change as development continues.

## Security and data handling

- Keep credentials and tokens in your local `.env`; never commit that file.
- Do not commit real network captures or sensitive production logs.
- Use synthetic or sanitized input data when sharing examples.

