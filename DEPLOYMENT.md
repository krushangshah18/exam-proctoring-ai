# Exam Proctoring AI — Deployment Documentation

**Last updated:** April 2026  
**Stack:** FastAPI · Next.js 16 · PostgreSQL (RDS) · Redis · Docker · Nginx · Netlify · AWS EC2 · AWS ECR · AWS S3

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Infrastructure Summary](#2-infrastructure-summary)
3. [Server (FastAPI) — EC2 + Docker](#3-server-fastapi--ec2--docker)
4. [Proctor Engine — GPU EC2](#4-proctor-engine--gpu-ec2)
5. [Client (Next.js) — Netlify](#5-client-nextjs--netlify)
6. [Database — AWS RDS PostgreSQL](#6-database--aws-rds-postgresql)
7. [File Storage — AWS S3](#7-file-storage--aws-s3)
8. [Nginx Reverse Proxy](#8-nginx-reverse-proxy)
9. [CI/CD — GitHub Actions](#9-cicd--github-actions)
10. [Environment Variables Reference](#10-environment-variables-reference)
11. [Deployment Runbook](#11-deployment-runbook)
12. [Operational Procedures](#12-operational-procedures)
13. [Security Notes](#13-security-notes)
14. [Known Constraints](#14-known-constraints)

---

## 1. Architecture Overview

```
Browser (Netlify)
    │
    │  HTTPS
    ▼
Netlify CDN ──── Next.js 16 App (proctor-it.netlify.app)
    │
    │  HTTPS API calls (axios)
    ▼
Nginx (3-6-8-253.sslip.io:443)
    │
    │  HTTP proxy (127.0.0.1:8000)
    ▼
FastAPI Server (Docker, single uvicorn worker)
    ├── PostgreSQL RDS  (SQLAlchemy ORM)
    ├── Redis           (Docker, 127.0.0.1:6379)
    ├── S3              (profile images, boto3)
    └── Proctor Engine  (HTTP, private VPC IP)
            │
            │  WebRTC (from browser direct)
            ▼
        Engine EC2 (GPU) — YOLO · MediaPipe · FaceNet
            ├── PostgreSQL RDS  (raw psycopg2 writes)
            └── S3              (evidence proof files)
```

**Request paths:**
- Student/Teacher browser → Netlify (page load) → API calls → Nginx → FastAPI
- Student browser → Engine EC2 directly via WebRTC (video/audio stream)
- FastAPI → Engine EC2 via private VPC IP (session management, risk events)

---

## 2. Infrastructure Summary

| Component | Service | Details |
|-----------|---------|---------|
| Frontend | Netlify | `https://proctor-it.netlify.app` |
| API Server | AWS EC2 (t-series) | `https://3-6-8-253.sslip.io` (IP: 3.6.8.253) |
| Proctor Engine | AWS EC2 (GPU) | Private IP: `172.31.44.157`, Ports 8000 & 8001 |
| Database | AWS RDS PostgreSQL | `database-1.cpcayiqmocey.ap-south-1.rds.amazonaws.com:5432` |
| Cache | Redis 7 (Docker) | `127.0.0.1:6379` on server EC2 |
| Container Registry | AWS ECR (ap-south-1) | `687159379171.dkr.ecr.ap-south-1.amazonaws.com` |
| File Storage | AWS S3 | Profile images + exam evidence proofs |
| Region | ap-south-1 (Mumbai) | All AWS resources |
| SSL | Let's Encrypt (certbot) | Auto-renews, expires 2026-07-05 |

---

## 3. Server (FastAPI) — EC2 + Docker

### 3.1 Docker Image

**ECR Repository:** `687159379171.dkr.ecr.ap-south-1.amazonaws.com/proctorapi`

The Dockerfile uses a **two-stage build** to keep the final image lean:

**Stage 1 — Builder (`python:3.12-slim`)**
- Installs build tools and `uv` package manager
- Runs `uv sync --frozen --no-dev` to install all Python dependencies into `.venv`
- Only runs when `pyproject.toml` or `uv.lock` changes (Docker layer caching)

**Stage 2 — Runtime (`python:3.12-slim`)**
- Copies only `.venv` from builder (no build tools in final image)
- Runtime system libraries: `libgl1`, `libglib2.0-0` (OpenCV), `libpq5` (psycopg2), `curl` (healthcheck)
- Includes: application code (`app/`), migrations (`alembic/`, `alembic.ini`), YOLO fallback model (`finalBestV5.pt` — 18 MB)
- Pre-creates runtime dirs: `storage/{profiles,evidence,audio,temp}`, `logs/`

**Environment variables baked into image:**
```
PATH=/app/.venv/bin:$PATH
PYTHONPATH=/app
PYTHONDONTWRITEBYTECODE=1
PYTHONUNBUFFERED=1
```

**Health check:**
```
curl -sf http://localhost:8000/health | grep -q "ok"
Interval: 30s | Timeout: 10s | Start period: 90s | Retries: 3
```
The 90-second start period exists because FaceNet and YOLO models are lazy-loaded on first request and take time to warm up.

**Startup command:**
```bash
uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --loop uvloop \
  --http httptools \
  --timeout-keep-alive 120
```

> **Critical:** Only **one worker** is ever run. The server uses in-memory SSE queues (`_queues`), in-memory identity check tasks (`_identity_tasks`), and an in-process exam scheduler. Multiple workers would break SSE event delivery and session state.

---

### 3.2 Docker Compose

**File location on EC2:** `/srv/proctorapi/docker-compose.yml`

```yaml
services:
  server (proctorapi):
    image: 687159379171.dkr.ecr.ap-south-1.amazonaws.com/proctorapi:latest
    container_name: proctorapi
    restart: unless-stopped
    env_file: /srv/proctorapi/.env
    ports: [127.0.0.1:8000:8000]        # localhost only — nginx reaches it
    volumes:
      - /srv/proctorapi/storage:/app/storage
      - /srv/proctorapi/logs:/app/logs
    depends_on:
      redis: { condition: service_healthy }

  redis:
    image: redis:7-alpine
    container_name: proctorapi-redis
    restart: unless-stopped
    ports: [127.0.0.1:6379:6379]        # localhost only
    volumes: [redis_data:/data]
    command: >
      redis-server
        --save 60 1                      # persist to disk every 60s
        --maxmemory 256mb
        --maxmemory-policy allkeys-lru
```

**Volume mounts:**

| Host path | Container path | Purpose |
|-----------|---------------|---------|
| `/srv/proctorapi/storage` | `/app/storage` | Profile images, evidence files |
| `/srv/proctorapi/logs` | `/app/logs` | Application logs |
| `redis_data` (named volume) | `/data` | Redis persistence |

---

### 3.3 Application Startup Validation

On startup, `main.py` validates the environment before accepting traffic:

1. Checks `JWT_SECRET_KEY` is set and not empty
2. Checks `DATABASE_URL` is set
3. Checks `PROCTOR_ENGINE_URLS` is set and not empty
4. Pings Redis — fails hard if unreachable
5. Calls `proctor_startup()` — seeds engine containers from `PROCTOR_ENGINE_URLS`, deactivates stale engines from DB

If any check fails, the process exits immediately with a clear error message.

---

### 3.4 Exam Status Scheduler

Runs every 60 seconds in a background thread (`APScheduler`). Handles:

| Transition | Condition |
|-----------|-----------|
| `SCHEDULED` → `LIVE` | Current time ≥ `start_window` |
| `LIVE` → `ENDED` | Current time ≥ `end_window` |
| `ACTIVE` session → `DISCONNECTED` | No heartbeat for > 90 seconds |
| `DISCONNECTED` session → `TERMINATED` | Disconnected for > 5 minutes |
| Extended sessions | Students with admin-granted extra time are not ended early |

All scheduler exceptions are logged via `system_logger` with full stack traces.

---

### 3.5 Middleware Stack

Middleware is applied in this order (outermost first):

1. **CORSMiddleware** — allows `FRONTEND_URL` origin only, credentials enabled
2. **add_security_headers** — adds CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy

**CSP for API routes:**
```
default-src 'self';
script-src 'self';
style-src 'self';
img-src 'self';
connect-src 'self' {FRONTEND_URL};
frame-ancestors 'none';
```

---

### 3.6 Python Dependencies (key packages)

| Package | Purpose |
|---------|---------|
| `fastapi`, `uvicorn[standard]` | Web framework + ASGI server |
| `uvloop`, `httptools` | High-performance async I/O |
| `sqlalchemy`, `psycopg2-binary` | ORM + PostgreSQL driver |
| `alembic` | Database migrations |
| `redis[hiredis]` | Redis client with C extension |
| `facenet-pytorch` | Face embedding extraction |
| `torch`, `torchvision` | Deep learning runtime |
| `opencv-python-headless` | Image processing |
| `ultralytics` | YOLO fallback object detection |
| `boto3` | AWS S3 (profile images) |
| `python-jose[cryptography]` | JWT tokens |
| `argon2-cffi` | Password hashing |
| `passlib` | Auth utilities |
| `python-multipart` | File upload support |
| `httpx` | Async HTTP client (engine proxying) |

---

## 4. Proctor Engine — GPU EC2

### 4.1 Overview

The engine runs on a dedicated GPU EC2 instance and handles all real-time AI inference. It is **completely separate** from the API server.

**Elastic IP:** `35.154.222.102` (public)  
**Private IP:** `172.31.44.157` (used by API server for internal communication)  
**Ports:** 8000, 8001 (two engine instances for parallel sessions)  
**Max sessions per instance:** 3 (configurable via `MAX_SESSIONS`)

> **Important:** The API server always communicates with the engine via the **private VPC IP** (`172.31.44.157`), never the public elastic IP. This avoids internet routing, reduces latency, and eliminates data transfer costs.

### 4.2 Docker Image

**Base:** `nvidia/cuda:12.4.1-cudnn-runtime-ubuntu22.04`

**Build layers (optimized for cache):**
1. System dependencies (OpenCV runtime, Python 3.11)
2. PyTorch with CUDA 12.4 (from pytorch.org/whl — ~2.5 GB, rarely changes)
3. Python requirements (from `requirements.txt`)
4. YOLO model weights (`finalBestV5.pt` — 18 MB)
5. Application source code

**Startup command:**
```bash
python main.py --half --warmup 3
```
- `--half`: FP16 precision (~2× throughput, ~½ VRAM usage)
- `--warmup 3`: Runs 3 YOLO inference passes at startup to pre-compile CUDA kernels

### 4.3 Engine Architecture

The engine exposes a **FastAPI HTTP + WebRTC** server:

**WebRTC flow:**
1. Browser negotiates SDP offer/answer via `/session/{session_id}/offer`
2. ICE candidates exchanged via Google STUN servers
3. Browser streams video + audio directly to engine via WebRTC DataChannel
4. Engine processes frames in real-time (YOLO + MediaPipe + FaceNet)

**Detection pipeline (per frame):**
- Head pose estimation (MediaPipe FaceMesh)
- Gaze direction (iris landmarks)
- Object detection (YOLO: phone, book, headphone, earbud, multiple people)
- Fake presence / liveness detection (FaceNet + blink + motion analysis)
- Speaker audio detection (Silero VAD + lip movement)

**Data flow:**
- Alerts/warnings → written directly to RDS PostgreSQL (raw psycopg2, not ORM)
- Evidence proof files (JPEG/WAV) → uploaded to S3, then deleted locally
- Risk scores → sent back to API server via HTTP callbacks

### 4.4 Risk Scoring System

**Score thresholds:**

| State | Score |
|-------|-------|
| Normal | 0–29 |
| Warning | 30–59 |
| High Risk | 60–99 |
| Admin Review | 100+ |

**Score categories:**

| Event | Score | Notes |
|-------|-------|-------|
| Phone detected (1st) | Warning only | Grace occurrence |
| Phone detected (2nd) | 25.0 | Fixed (no decay) |
| Phone detected (3rd+) | 50.0 | Fixed |
| Book detected | 20.0 | Decaying |
| Multiple people (2nd) | 20.0 | Fixed |
| Multiple people (3rd+) | 50.0 | Fixed |
| Fake presence (10s) | 30.0 | Fixed |
| Fake presence (25s) | 60.0 | Fixed |
| No person (5s) | 25.0 | Fixed |
| No person (10s) | 50.0 | Fixed |
| Gaze event | 5.0 | Decaying |
| Speaker audio (3s) | 10.0 | Decaying |

**Auto-termination triggers:**
- Multiple people detected for > 20s continuously
- No person detected for > 20s continuously
- Tab switching 3 times consecutively

### 4.5 Engine Environment Variables

```env
DATABASE_URL=postgresql://...rds.amazonaws.com:5432/exam_proctoring
S3_BUCKET=exam-proctoring-proofs-23ceuod010
AWS_REGION=ap-south-1
AWS_ACCESS_KEY_ID=<key>
AWS_SECRET_ACCESS_KEY=<secret>
SAVE_REPORT=false       # writes to DB instead of local files
```

---

## 5. Client (Next.js) — Netlify

### 5.1 Build Configuration

**File:** `netlify.toml` (repo root)

```toml
[build]
  base    = "client"
  command = "npm install && npm run build"
  publish = ".next"

[[plugins]]
  package = "@netlify/plugin-nextjs"
```

**Netlify build settings:**
- Base directory: `client`
- Build command: `npm install && npm run build`
- Publish directory: `client/.next`
- Plugin: `@netlify/plugin-nextjs` (auto-detected, enables SSR + ISR on Netlify)
- Node version: 22.x (Netlify default)

### 5.2 Environment Variables (set in Netlify dashboard)

| Variable | Value |
|----------|-------|
| `NEXT_PUBLIC_API_URL` | `https://3-6-8-253.sslip.io` |

> **Important:** `NEXT_PUBLIC_*` variables are **baked into the JS bundle at build time**. Changing the value in Netlify requires a new build to take effect. Simply redeploying with "Clear cache and deploy" will not help — the variable must be set before the build runs.

### 5.3 Next.js Configuration

```typescript
// client/next.config.ts
const nextConfig: NextConfig = {
  reactStrictMode: false,   // disabled to prevent double-render side effects
};
```

React Strict Mode is disabled because the app makes real-time WebRTC connections and SSE subscriptions that would be disrupted by double-mounting in development.

### 5.4 Frontend Stack

| Package | Version | Purpose |
|---------|---------|---------|
| `next` | 16.1.6 | Framework |
| `react` | 19.2.3 | UI library |
| `tailwindcss` | 4.x | Styling |
| `radix-ui` | 1.4.x | Accessible UI primitives |
| `shadcn` | 3.8.x | Component library |
| `axios` | 1.13.5 | HTTP client |
| `react-hook-form` | 7.x | Form management |
| `zod` | 4.x | Schema validation |
| `react-webcam` | 7.x | Camera access |
| `@tanstack/react-table` | 8.x | Data tables |
| `jwt-decode` | 4.x | Token decoding |
| `sonner` | 2.x | Toast notifications |
| `date-fns` | 4.x | Date utilities |

### 5.5 API Client

**File:** `client/src/lib/axios.ts`

```typescript
const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
  headers: { 'Content-Type': 'application/json' },
});
```

**Request interceptor:** Attaches `Authorization: Bearer <token>` from `localStorage` on every request.

**Response interceptor (token refresh):**
- On 401, silently calls `/auth/refresh` with the stored refresh token
- Queues concurrent requests during refresh to prevent multiple simultaneous refresh calls
- On refresh failure, clears tokens and redirects to `/auth/login`
- Does NOT attempt refresh for auth endpoints (`/auth/*`)
- Does NOT redirect if the user is on an active exam page

---

## 6. Database — AWS RDS PostgreSQL

**Endpoint:** `database-1.cpcayiqmocey.ap-south-1.rds.amazonaws.com`  
**Port:** 5432  
**Database:** `exam_proctoring`  
**Region:** ap-south-1

**Access:**
- Server EC2 → RDS: via VPC (private, no internet routing)
- Engine EC2 → RDS: via VPC (private, raw psycopg2 writes)
- Local machine → RDS: **blocked by security group** (not allowed from outside VPC)

**Running migrations:**

Migrations must be run from **inside the server Docker container** (which is in the VPC):

```bash
# On the server EC2
docker exec -it proctorapi alembic upgrade head
```

**Migration history:** Managed by Alembic. Migration files in `server/alembic/versions/`.

---

## 7. File Storage — AWS S3

**Two buckets:**

| Bucket | Contents | Managed by |
|--------|----------|-----------|
| (server bucket) | Profile photos (face embeddings reference) | Server (boto3) |
| `exam-proctoring-proofs-23ceuod010` | Evidence proof files (JPEG frames, WAV audio clips) | Engine (boto3) |

**Profile images:** Uploaded during registration/reactivation. Stored as `profiles/{user_id}.jpg`. URL generated server-side as presigned S3 URL.

**Evidence proofs:** Uploaded by engine when an alert is triggered. Format: `{session_id}/{timestamp}_{event_type}.jpg` and `.wav`. S3 object key stored in the `proctor_alerts` table for later presigned URL generation.

**IAM:** The server EC2 has an **instance role** that grants S3 access — no AWS keys are stored in the server's `.env`. The engine EC2 uses explicit `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`.

---

## 8. Nginx Reverse Proxy

**Config file on EC2:** `/etc/nginx/sites-available/proctorapi`  
**Symlinked to:** `/etc/nginx/sites-enabled/proctorapi`  
**SSL managed by:** certbot (auto-renews)  
**Certificate expires:** 2026-07-05

### 8.1 HTTP → HTTPS Redirect

All HTTP traffic on port 80 is redirected to HTTPS. Certbot's ACME challenge at `/.well-known/acme-challenge/` is excluded from redirect.

### 8.2 Standard API Routes (`location /`)

```nginx
location / {
    # OPTIONS preflight — handled entirely by nginx
    if ($request_method = OPTIONS) {
        add_header 'Access-Control-Allow-Origin' 'https://proctor-it.netlify.app' always;
        add_header 'Access-Control-Allow-Credentials' 'true' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, PATCH, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'Authorization, Content-Type, Accept' always;
        add_header 'Access-Control-Max-Age' 86400 always;
        return 204;
    }

    # Strip FastAPI's CORS headers to prevent duplicates
    proxy_hide_header Access-Control-Allow-Origin;
    proxy_hide_header Access-Control-Allow-Credentials;
    proxy_hide_header Vary;

    # Add nginx's CORS headers
    add_header 'Access-Control-Allow-Origin' 'https://proctor-it.netlify.app' always;
    add_header 'Access-Control-Allow-Credentials' 'true' always;

    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_connect_timeout 10s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;
}
```

**Why CORS is handled at nginx level:** The FastAPI container's image may not always be up-to-date with the latest `FRONTEND_URL`. Nginx handles CORS at the proxy layer for reliability. `proxy_hide_header` removes FastAPI's CORS headers to prevent duplicate `Access-Control-Allow-Origin` headers (browsers reject responses with multiple CORS headers).

### 8.3 SSE Streaming Routes (`location ~* ^/exam/(events|.*stream)`)

```nginx
location ~* ^/exam/(events|.*stream) {
    proxy_buffering off;          # critical — SSE must stream without buffering
    proxy_cache off;
    proxy_read_timeout 3600s;    # 1 hour — full exam duration
    proxy_send_timeout 3600s;
    proxy_set_header Connection "";
    chunked_transfer_encoding on;
}
```

SSE (Server-Sent Events) requires `proxy_buffering off` — without it, nginx buffers the entire response and events never reach the browser in real-time.

### 8.4 Security Headers

Applied globally on the HTTPS server block:
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000
```

---

## 9. CI/CD — GitHub Actions

**Workflow file:** `.github/workflows/server-deploy.yml`  
**Trigger:** Push to `main` branch with changes under `server/**` or the workflow file itself

### 9.1 Required GitHub Secrets

| Secret | Value |
|--------|-------|
| `AWS_ACCESS_KEY_ID` | IAM user access key (ECR push + SSM) |
| `AWS_SECRET_ACCESS_KEY` | IAM user secret key |
| `SERVER_INSTANCE_ID` | `i-0787192936857485f` |

### 9.2 Workflow Steps

```
1. Checkout code
2. Configure AWS credentials (from secrets)
3. Login to ECR
4. Build Docker image (from server/ directory)
   - Tagged with commit SHA: proctorapi:{sha}
   - Tagged with: proctorapi:latest
5. Push both tags to ECR
6. Deploy via AWS SSM (no SSH needed):
   - ECR login on EC2
   - docker pull proctorapi:latest
   - docker compose up -d --remove-orphans
   - docker image prune -f
7. Poll SSM command status (every 5s, max 3 min)
8. Smoke test: curl https://3-6-8-253.sslip.io/health
   - Expects HTTP 200
   - Wait 10s after deploy before testing
```

### 9.3 SSM vs SSH

The deployment uses **AWS Systems Manager (SSM) Send Command** instead of SSH. This was chosen because:
- The office network blocks outbound port 22
- SSM requires only an IAM role on the EC2 instance (already configured)
- No SSH key management needed in CI/CD

**Manual access to EC2:** Use **EC2 Instance Connect** in the AWS console (works without port 22 from the browser).

### 9.4 Build Configuration

| Setting | Value |
|---------|-------|
| AWS Region | `ap-south-1` |
| ECR Registry | `687159379171.dkr.ecr.ap-south-1.amazonaws.com` |
| ECR Repository | `proctorapi` |
| Image tags | `{github.sha}` + `latest` |

---

## 10. Environment Variables Reference

### 10.1 Server `.env` (at `/srv/proctorapi/.env` on EC2)

```env
# ── Database
DATABASE_URL=postgresql+psycopg2://postgres:<password>@database-1.cpcayiqmocey.ap-south-1.rds.amazonaws.com:5432/exam_proctoring

# ── JWT
JWT_SECRET_KEY=<long-random-string>          # REQUIRED — app won't start without this
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# ── Redis (use service name from docker-compose)
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_DB=0

# ── Email (Gmail SMTP)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=<gmail-address>
SMTP_PASSWORD=<gmail-app-password>           # NOT your Gmail password — use App Password
SMTP_TLS=true
EMAIL_FROM=Exam Proctoring System <noreply@examai.com>

# ── Frontend (for CORS + email links)
FRONTEND_URL=https://proctor-it.netlify.app

# ── Proctor Engine (private VPC IPs only)
PROCTOR_ENGINE_URLS=http://172.31.44.157:8000,http://172.31.44.157:8001
PROCTOR_ENGINE_MAX_SESSIONS=3

# ── AWS (NOT needed — EC2 instance role handles ECR + S3)
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=ap-south-1

# ── S3 (profile images)
S3_BUCKET_NAME=<bucket-name>

# ── Security settings
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCK_FAILED_LOGIN_MINUTES=15
MAX_TRUSTED_DEVICES=3
OTP_EXPIRE_MINUTES=10
OTP_SECRET=<random-secret>                   # REQUIRED
MAX_OTP_ATTEMPTS=3
MAX_UNLOCK_REQUESTS=2
PROFILE_IMAGE_UPDATE_DAYS=30
```

### 10.2 Engine `.env` (on GPU EC2)

```env
DATABASE_URL=postgresql://postgres:<password>@database-1.cpcayiqmocey.ap-south-1.rds.amazonaws.com:5432/exam_proctoring
S3_BUCKET=exam-proctoring-proofs-23ceuod010
AWS_REGION=ap-south-1
AWS_ACCESS_KEY_ID=<key>
AWS_SECRET_ACCESS_KEY=<secret>
SAVE_REPORT=false
```

### 10.3 Netlify Environment Variables

Set in Netlify dashboard → Site configuration → Environment variables:

| Variable | Value |
|----------|-------|
| `NEXT_PUBLIC_API_URL` | `https://3-6-8-253.sslip.io` |

---

## 11. Deployment Runbook

### 11.1 First-Time Server EC2 Setup

```bash
# 1. Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker ubuntu

# 2. Install AWS CLI
sudo apt-get install -y awscli

# 3. Create app directory
sudo mkdir -p /srv/proctorapi/storage /srv/proctorapi/logs
sudo chown ubuntu:ubuntu /srv/proctorapi

# 4. Copy docker-compose.yml from repo
cp server/deploy/docker-compose.yml /srv/proctorapi/

# 5. Create .env from template
cp server/deploy/.env.example /srv/proctorapi/.env
nano /srv/proctorapi/.env   # fill in all values

# 6. Install nginx + certbot
sudo apt-get install -y nginx certbot python3-certbot-nginx

# 7. Create nginx config
sudo nano /etc/nginx/sites-available/proctorapi
sudo ln -sf /etc/nginx/sites-available/proctorapi /etc/nginx/sites-enabled/proctorapi
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t

# 8. Get SSL certificate
sudo certbot --nginx -d 3-6-8-253.sslip.io

# 9. Login to ECR and pull image
aws ecr get-login-password --region ap-south-1 | \
  docker login --username AWS --password-stdin \
  687159379171.dkr.ecr.ap-south-1.amazonaws.com

# 10. Start containers
cd /srv/proctorapi && docker compose up -d

# 11. Run database migrations
docker exec -it proctorapi alembic upgrade head

# 12. Verify
curl https://3-6-8-253.sslip.io/health   # should return {"status":"ok"}
```

### 11.2 Manual Server Redeploy (without CI/CD)

```bash
# On server EC2:
cd /srv/proctorapi

# Pull latest image
aws ecr get-login-password --region ap-south-1 | \
  docker login --username AWS --password-stdin \
  687159379171.dkr.ecr.ap-south-1.amazonaws.com
docker compose pull

# Restart
docker compose down && docker compose up -d

# Clean old images
docker image prune -f

# Verify
curl https://3-6-8-253.sslip.io/health
```

### 11.3 Update Environment Variable

```bash
# On server EC2:
sudo nano /srv/proctorapi/.env
# Make changes, save

# Full restart (not just restart — env_file is read on container create)
cd /srv/proctorapi && docker compose down && docker compose up -d

# Verify the change was picked up
docker exec proctorapi env | grep <VARIABLE_NAME>
```

> **Note:** `docker compose restart` does NOT re-read the `.env` file for existing containers. Always use `down && up` when changing environment variables.

### 11.4 Run Database Migrations

```bash
# From server EC2 (inside the VPC, has RDS access)
docker exec -it proctorapi alembic upgrade head

# Check current revision
docker exec -it proctorapi alembic current

# Rollback one revision
docker exec -it proctorapi alembic downgrade -1
```

### 11.5 Deploy Frontend Changes

Frontend deploys automatically when changes are pushed to `main` (Netlify watches the GitHub repo). To trigger manually:

1. Go to Netlify dashboard → `proctor-it` site
2. Deploys → Trigger deploy → "Deploy site"

Or via Netlify CLI:
```bash
cd client && netlify deploy --prod
```

---

## 12. Operational Procedures

### 12.1 Check System Status

```bash
# Container status
docker compose ps

# Server logs (live)
docker compose logs -f server --tail=50

# Redis logs
docker compose logs redis --tail=20

# Health check
curl https://3-6-8-253.sslip.io/health

# Disk usage
df -h /

# Docker image sizes
docker images
```

### 12.2 Free Disk Space (if disk is full)

```bash
# Remove unused Docker images/containers/networks
docker system prune -af

# Truncate nginx logs
sudo truncate -s 0 /var/log/nginx/access.log
sudo truncate -s 0 /var/log/nginx/error.log

# Vacuum journal logs
sudo journalctl --vacuum-size=100M

# Check what's using space
sudo du -sh /* 2>/dev/null | sort -rh | head -20
```

> **Warning:** The server image is ~13 GB uncompressed. If disk is full when pulling a new image, remove the old image first:
> ```bash
> docker rmi 687159379171.dkr.ecr.ap-south-1.amazonaws.com/proctorapi:latest
> docker compose pull && docker compose down && docker compose up -d
> ```

### 12.3 Nginx Operations

```bash
# Test config
sudo nginx -t

# Reload config (no downtime)
sudo systemctl reload nginx

# Full restart
sudo systemctl restart nginx

# View config
sudo nginx -T

# Renew SSL manually
sudo certbot renew
```

### 12.4 Redis Operations

```bash
# Check if Redis is responding
docker exec proctorapi-redis redis-cli ping   # should return PONG

# Check memory usage
docker exec proctorapi-redis redis-cli info memory | grep used_memory_human

# Flush all data (WARNING: clears all session state)
docker exec proctorapi-redis redis-cli flushall
```

### 12.5 View Application Logs

```bash
# Live server logs
docker compose -f /srv/proctorapi/docker-compose.yml logs -f server

# Specific time range
docker compose logs server --since="1h"

# Application log files (on host, via volume mount)
tail -f /srv/proctorapi/logs/app.log
```

---

## 13. Security Notes

### 13.1 Network Security

- **RDS:** Security group only allows inbound 5432 from within VPC. Not accessible from internet.
- **Engine:** Elastic IP accessible publicly (WebRTC needs direct connection from browser). Only ports 8000-8001 open.
- **Server:** Port 8000 bound to `127.0.0.1` only. Only nginx (443/80) is public-facing.
- **Redis:** Port 6379 bound to `127.0.0.1` only. No external access.
- **SSH:** Port 22 not used. Access via EC2 Instance Connect only.

### 13.2 Credentials

- **Server EC2:** No AWS keys in `.env`. An IAM instance role provides ECR pull and S3 access.
- **Engine EC2:** AWS keys in `.env` for S3 proof uploads (no instance role was configured).
- **GitHub Secrets:** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `SERVER_INSTANCE_ID` — used only for CI/CD.
- **JWT Secret:** Must be a cryptographically random string of at least 32 characters.
- **OTP Secret:** Must be a cryptographically random string.

### 13.3 CORS Policy

The server only allows requests from `FRONTEND_URL` (configured per-environment). The nginx layer also enforces this via `Access-Control-Allow-Origin`. The CORS `Access-Control-Allow-Origin` header must be a specific origin (not `*`) because `credentials: true` is used.

### 13.4 Corporate Firewall Note

`sslip.io` is a free Dynamic DNS service. Corporate firewalls (e.g., FortiGuard) categorize it as "Dynamic DNS" and may block it. If users are on a corporate network that blocks `sslip.io`, they will receive CORS errors (actually a 403 from the firewall). **This is a network-level block, not a server bug.** To resolve: purchase a proper domain and point it to the EC2 elastic IP.

---

## 14. Known Constraints

| Constraint | Reason | Impact |
|-----------|--------|--------|
| Single uvicorn worker | In-memory SSE queues + exam scheduler | Cannot horizontally scale the API server process |
| RDS not accessible from local machine | VPC security group restricts to VPC CIDR | Must run Alembic migrations from inside Docker container on EC2 |
| Engine uses public elastic IP for WebRTC | Browser needs routable IP for WebRTC ICE | Engine's public IP must remain static (elastic IP) |
| `NEXT_PUBLIC_API_URL` baked at build time | Next.js design | Changing the API URL requires a full Netlify rebuild |
| `docker compose down && up` required for env changes | Docker container recreation | Cannot use `restart` alone when changing `.env` |
| 20 GB EC2 disk | Default EBS volume | Large Docker images (13 GB uncompressed) leave ~4 GB free; pull requires removing old image first |
| sslip.io blocked by corporate firewalls | Dynamic DNS categorization | Users on restricted networks cannot reach the API |

---

*This document covers the complete deployment as of April 2026. The system is deployed to AWS ap-south-1 (Mumbai) region.*
