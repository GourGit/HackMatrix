# TrustLens Deployment and Production Operations Guide

This guide details the deployment architecture, configuration requirements, database migration workflow, security guardrails, and container deployment for TrustLens.

---

## 1. Architecture Overview

TrustLens is architected as an isolated multi-service application consisting of:

* **Backend API (`backend`)**: Python 3.11+ ASGI application powered by FastAPI and Uvicorn. Exposes `/v1` endpoints, `/health` (liveness), and `/ready` (readiness).
* **Database (`db`)**: PostgreSQL 16 relational database with UUID primary keys, foreign keys, and indexes. Isolated to the internal Docker bridge network (public port 5432 is disabled).
* **Cache & Shared State (`redis`)**: Redis 7 shared store used for production rate limiting and inter-worker state.
* **Frontend (`frontend`)**: React / Vite / Tailwind SPA served via an NGINX container on port 3000.
* **Evidence Storage (`evidence_store`)**: Local or mounted storage for encrypted and redacted forensic evidence artifacts. Excluded from version control.

---

## 2. Production Security Hardening & Fail-Safe Startup

In `APP_ENV=production`, the application performs fail-safe startup checks inside `app.config.Settings.validate_production_security()`. If any safety check fails, application startup terminates immediately with a descriptive `ValueError` (or Pydantic `ValidationError`):

1. **Application Secret (`APP_SECRET_KEY`)**:
   - Must be configured and be at least 32 characters in length.
   - Default/insecure values (e.g. `change-me-to-a-random-secret`, `secret`, `changeme`, `password`) are strictly forbidden.
2. **Database Credentials (`DATABASE_URL`)**:
   - Must not contain default or example credentials (`:trustlens@`, `:trustlens_password@`, `:password@`, `:secret@`, `:root@`, `:admin@`, `:user:pass@`).
3. **JWT Authentication Secret (`JWT_SECRET_KEY`)**:
   - Must be configured and be at least 32 characters in length.
   - Example/default passwords are rejected.
4. **CORS Allowlist (`CORS_ORIGINS`)**:
   - Must contain an explicit list of allowed domains (e.g. `https://trustlens.yourdomain.com`).
   - Wildcards (`*`) and empty configurations are strictly rejected in production.
5. **Rate Limiting**:
   - Configured via Redis (`REDIS_URL`) in production to coordinate request quotas across multiple worker instances. In-memory storage is retained exclusively for local development and test suites.

---

## 3. Environment Variables Reference

| Variable | Required in Prod | Default / Example | Purpose |
|---|---|---|---|
| `APP_ENV` | Yes | `production` | Environment mode (`production`, `development`, `testing`) |
| `APP_DEBUG` | Yes | `false` | Must be `false` in production (disables `/docs` and debug traces) |
| `APP_SECRET_KEY` | Yes | *>= 32 random chars* | Cryptographic application secret key |
| `JWT_SECRET_KEY` | Yes | *>= 32 random chars* | JWT signing secret key |
| `DATABASE_URL` | Yes | `postgresql+asyncpg://...` | Connection URI for PostgreSQL with asyncpg |
| `REDIS_URL` | Yes | `redis://redis:6379/0` | Shared storage URI for production rate limiting |
| `CORS_ORIGINS` | Yes | `https://app.trustlens.io` | Comma-delimited list of allowed origin URLs (no wildcard `*`) |
| `EVIDENCE_STORAGE_PATH` | No | `./evidence_store` | Path to persistent evidence directory |
| `EVIDENCE_RETENTION_DAYS` | No | `90` | Default retention period for evidence |
| `RATE_LIMIT_PER_MINUTE` | No | `30` | Default request quota per client IP |
| `SCAN_CONCURRENCY_LIMIT` | No | `5` | Maximum concurrent background scans |
| `SAFE_SCAN_ENABLED` | No | `false` | Strict gate for safe active surface scanning |

---

## 4. Database Migrations (Alembic)

Database schema versioning is managed via Alembic located in `backend/migrations`.

### Applying Migrations to a Live Database
For container deployments where PostgreSQL is isolated on the internal Docker network, execute migrations within the Compose environment:
```bash
docker compose run --rm backend alembic upgrade head
```

For direct local development with a locally reachable PostgreSQL instance:
```bash
cd backend
alembic upgrade head
```

### Dry-Run / Offline SQL Generation
To inspect or export the exact PostgreSQL DDL generated for an empty database to `head` without connecting to a live database:
```bash
cd backend
alembic upgrade head --sql
```

### Rollback
To roll back the most recent migration:
```bash
cd backend
alembic downgrade -1
```

### Automated Migration Verification
The migration test suite verifies that Alembic can generate valid transactional DDL for every table and relationship:
```bash
cd backend
pytest tests/test_deployment_and_migrations.py -k test_alembic_migration_sql_generation -v
```

---

## 5. Docker Compose Deployment

The project includes a production-ready `docker-compose.yml` with health checks, internal networking, and secret separation.

### Quick Start
1. Create a `.env` file from `.env.example`:
   ```bash
   cp backend/.env.example .env
   ```
2. Populate `.env` with strong random secrets (generate via `openssl rand -hex 32` and paste the literal values):
   ```bash
   POSTGRES_USER=trustlens_admin
   POSTGRES_PASSWORD=c4a1793fbbd0295ec6d0294191c98ae8b51c8651a2491bb4
   POSTGRES_DB=trustlens_prod
   APP_SECRET_KEY=e83a7c64264771c5031bdfad0f413988629b35bc4079815bbecf2134a9b6ff81
   JWT_SECRET_KEY=94b407b7156942ad8d39fdf7b856da1cb61d9a56c429ebae31d37e6f98797f10
   CORS_ORIGINS=https://trustlens.yourdomain.com
   ```
3. Run the container cluster:
   ```bash
   docker-compose up -d --build
   ```
4. Verify container health status:
   ```bash
   docker-compose ps
   ```

### Network Isolation
- PostgreSQL container (`db`) has no exposed public host ports. It is reachable strictly across the internal Docker bridge network by `backend:5432`.
- Redis container (`redis`) is similarly restricted to the internal network.
- The backend (`backend`) is exposed on port 8000 (or placed behind an ingress reverse proxy / API gateway with TLS).
- The frontend (`frontend`) is exposed on port 3000.

---

## 6. Health & Readiness Probes

The API exposes two diagnostic endpoints designed for Kubernetes, Docker Compose, and load-balancer probes:

### 1. Liveness Probe (`GET /health`)
Verifies that the ASGI application process is running and responsive.
- **HTTP 200 OK**:
  ```json
  {
    "status": "healthy",
    "service": "trustlens-api",
    "version": "0.1.0",
    "environment": "production"
  }
  ```

### 2. Readiness Probe (`GET /ready`)
Performs active validation of all backing dependencies:
- **Database**: Executes a test query (`SELECT 1`) on the async connection pool.
- **Evidence Storage**: Validates that `EVIDENCE_STORAGE_PATH` exists or is writable.
- **Redis (when configured)**: Sends a `PING` command to verify cache reachability.

- **HTTP 200 OK** (All dependencies healthy):
  ```json
  {
    "status": "ready",
    "checks": {
      "database": "connected",
      "storage": "available",
      "redis": "connected"
    }
  }
  ```
- **HTTP 503 Service Unavailable** (Dependency failure):
  ```json
  {
    "status": "not_ready",
    "checks": {
      "database": "unavailable",
      "storage": "available",
      "redis": "unavailable"
    }
  }
  ```

---

## 7. Version Control Exclusions

The repository enforces strict `.gitignore` rules at both repository root and backend levels to prevent secret leakage and unintended artifacts:
- Version control files (`.git/`)
- Dependencies (`node_modules/`, Python virtual environments)
- Caches (`__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`)
- Bytecode (`*.pyc`, `*.pyo`)
- Environment files (`.env`, `.env.*`, except `.env.example`)
- Keys & certificates (`*.pem`, `*.key`, `*.cert`)
- Evidence artifacts (`evidence_store/`, `*.evidence`)
- Build outputs (`dist/`, `build/`)

