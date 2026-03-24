# Proctor AI — Session Context & Handover Document

> **Written:** 2026-03-24
> **Branch:** `develop`
> **Last commit:** `61cdd5c` — "exam creation from exam admin and students exam flow"
> **Purpose:** Complete handover context for continuing work on the office desktop after pulling from GitHub.

---

## ⚠️ CRITICAL — Changes NOT Yet Run / Tested

All changes listed in this document are **uncommitted and untested**. They exist only as working-tree modifications on the home laptop. After pulling on the office desktop you must:

1. **Start Docker containers** (Postgres + Redis) before starting the server — see [Infrastructure Setup](#infrastructure-setup)
2. **Run the DB migration** for the new engine tables — see [Database Migration](#database-migration)
3. **Start the proctor engine** separately — see [Proctor Engine Setup](#proctor-engine-setup)
4. **Test each phase** before considering it done

The following specific changes were made **at the very end of the last session** and have **never been run even once**:

| File | Change | Tested? |
|------|--------|---------|
| `client/src/app/admin/dashboard/exams/[id]/monitor/page.tsx` | Fixed SSE handler bug (see Phase 11 fix) | ❌ NOT TESTED |
| `client/src/app/student/exam/[id]/active/page.tsx` | Added DISCONNECTED/CREATED redirect guards + heartbeat 403 redirect | ❌ NOT TESTED |

All other changes in this document were coded but also **not fully integration-tested end-to-end** — partial testing was done by the user on the home machine, bugs were found, and fixes were applied. The tested/untested column below tracks what was at least manually verified.

---

## Project Overview

**Proctor AI** is a full-stack AI-powered online exam proctoring system.

- **Frontend:** Next.js 14 (App Router), TypeScript, Tailwind, shadcn/ui — at `client/`
- **Backend:** FastAPI (Python 3.11), SQLAlchemy, PostgreSQL, Redis — at `server/`
- **Proctor Engine:** Separate FastAPI service (Python), YOLO + MediaPipe, WebRTC — at `engine/`
- **Database:** PostgreSQL on port **5433** (not default 5432) via Docker
- **Cache/Sessions:** Redis on port **6379** via Docker

### User Roles
- `STUDENT` — takes exams
- `TEACHER` (admin) — creates/manages exams, monitors live sessions
- `SYSADMIN` — system-wide settings, engine config, teacher application approvals

---

## Infrastructure Setup

### Docker Containers (MUST be running before server start)

```bash
docker start exam_proctoring_postgres exam_proctoring_redis
```

Check they're up:
```bash
docker ps
```
Expected: two containers running — `exam_proctoring_postgres` (port 5433) and `exam_proctoring_redis` (port 6379).

If containers don't exist (new machine), create them:
```bash
docker run -d --name exam_proctoring_postgres \
  -e POSTGRES_PASSWORD=yourpassword \
  -e POSTGRES_DB=exam_proctoring \
  -p 5433:5432 postgres:15

docker run -d --name exam_proctoring_redis \
  -p 6379:6379 redis:7
```

### Server `.env` (at `server/.env`)

The server reads from `server/.env`. Make sure these exist:
```env
DATABASE_URL=postgresql://postgres:yourpassword@localhost:5433/exam_proctoring
REDIS_URL=redis://localhost:6379
SECRET_KEY=your-secret-key
PROCTOR_ENGINE_URLS=http://localhost:8001   # comma-separated if multiple
```

`PROCTOR_ENGINE_URLS` is the new env var added in this session — it tells the backend where to find the AI proctoring engine.

### Frontend `.env.local` (at `client/.env.local`)

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

---

## Database Migration

A new Alembic migration was added in this session:

```
server/alembic/versions/c1d2e3f4a5b6_add_proctor_engine_tables.py
```

This migration adds:
- `proctor_engine_containers` table — tracks engine instances
- `exam_engine_assignments` junction table — maps exams to engines
- New columns on `exam_sessions`: `proctor_engine_url`, `proctor_pc_id`
- New columns on `exams`: `detection_config` (JSONB)
- `engine_settings` table — system-wide AI threshold config

**Run this after pulling:**
```bash
cd server
.venv/Scripts/activate   # Windows
alembic upgrade head
```

---

## Proctor Engine Setup

The engine is a **separate FastAPI process** at `engine/`. It must be running for WebRTC proctoring to work. It is NOT containerized yet for local dev.

```bash
cd engine
pip install -r requirements.txt    # first time only
python -m uvicorn main:app --port 8001 --reload
```

**You do NOT need to build/push a Docker image for local development.** Docker image is only needed for EC2 deployment.

The engine exposes:
- `POST /offer` — WebRTC SDP offer (called by backend proxy)
- `POST /ice/{pc_id}` — ICE candidates (called by backend proxy)
- `GET /stream/{pc_id}` — SSE alert stream (proxied to student & admin)
- `GET /frame/{pc_id}` — latest JPEG frame (proxied to admin monitor)
- `POST /debug/{pc_id}` — toggle debug overlay
- `POST /close/{pc_id}` — end session

The backend allocates engine containers via `server/app/exam/engine_allocator.py` and proxies all calls via `server/app/exam/proctor_proxy.py`.

---

## What Was Built in These Sessions (Phases 1–11)

### Phase 1–3: Engine Infrastructure (Server)
**Files:**
- `server/app/db/models.py` — Added `ProctorEngineContainer`, `ExamEngineAssignment` models; added `proctor_engine_url`, `proctor_pc_id` to `ExamSession`; added `detection_config` JSONB to `Exam`; added `EngineSettings` table
- `server/app/core/config.py` — Added `PROCTOR_ENGINE_URLS` setting (reads from env, splits comma-separated)
- `server/alembic/versions/c1d2e3f4a5b6_...py` — Migration for all above

### Phase 4–5: Engine Proxy & Allocator (Server)
**Files (NEW — untracked):**
- `server/app/exam/proctor_proxy.py` — Async HTTP proxy functions: `send_offer()`, `send_ice()`, `fetch_frame()`, `fetch_session_log()`, `close_session()`
- `server/app/exam/engine_allocator.py` — `allocate_for_exam()` / `release_for_exam()` — picks least-loaded engine container from DB
- `server/app/exam/proctor_startup.py` — Seeds engine containers into DB on startup from `PROCTOR_ENGINE_URLS`

### Phase 6: Backend Routes (Server)
**File:** `server/app/exam/routes.py`

Added to existing routes file:
- `POST /exam/{exam_id}/proctor-connect` — receives WebRTC offer from student, proxies to engine, returns answer SDP + `pc_id`
- `POST /exam/{exam_id}/proctor-ice` — trickle ICE candidates from student to engine
- `GET /exam/{exam_id}/proctor-events` — SSE proxy from engine to student browser (alert stream)
- `POST /exam/{exam_id}/proctor-violation` — student-side violation events (tab switch etc.) logged and forwarded to engine
- `GET /{exam_id}/session-active` updated to return `title`, `flag_threshold`, `config` (these were missing, causing tab-switch monitoring to silently fail)

**File:** `server/app/exam/admin_routes.py`

Added:
- `GET /admin/exams/{exam_id}/sessions/{session_id}/live-frame` — proxies JPEG frame from engine
- `GET /admin/exams/{exam_id}/sessions/{session_id}/live-stream` — SSE proxy from engine to admin monitor
- `POST /admin/exams/{exam_id}/sessions/{session_id}/debug-mode` — toggle engine debug overlay
- `GET /admin/system-settings` — returns `EngineSettings` row (creates defaults if none exist)
- `POST /admin/system-settings` — saves `EngineSettings`
- `detection_config` wired into `create_exam` and `update_exam`

**File:** `server/app/main.py` — `proctor_startup.py` called on app startup to seed engine containers

### Phase 7: Exam Schemas (Server)
**File:** `server/app/exam/schemas.py`

Added `DetectionConfig` Pydantic model with 13 boolean fields:
```
DETECT_LOOKING_AWAY, DETECT_LOOKING_DOWN, DETECT_LOOKING_UP, DETECT_LOOKING_SIDE,
DETECT_FACE_HIDDEN, DETECT_PARTIAL_FACE, DETECT_FAKE_PRESENCE, DETECT_SPEAKER_AUDIO,
DETECT_PHONE, DETECT_BOOK, DETECT_HEADPHONE, DETECT_EARBUD, DETECT_MULTIPLE_PEOPLE
```

### Phase 8: Admin Exam Forms — Detection Toggles (Frontend)
**Files:**
- `client/src/app/admin/dashboard/exams/new/page.tsx` — Added `detection_config` zod schema, default values (all `true`), toggle grid UI in Proctoring card
- `client/src/app/admin/dashboard/exams/[id]/edit/page.tsx` — Same additions; loads `detection_config` from API with all-true fallback

### Phase 9: System Admin Engine Settings Page (Frontend)
**File (NEW — untracked):** `client/src/app/sys/dashboard/system-settings/page.tsx`

Full SYSADMIN settings page for `EngineSettings` — 30+ numeric thresholds grouped into cards:
- Head Pose Thresholds
- Duration Gates
- Risk Scores
- State Thresholds
- Termination Rules
- YOLO Confidence

Uses `GET /admin/system-settings` and `POST /admin/system-settings`.

**File:** `client/src/app/sys/dashboard/layout.tsx` — Added "Engine Settings" nav item with `SlidersHorizontal` icon pointing to `/sys/dashboard/system-settings`

### Phase 10: WebRTC Proctor Integration — Student Active Exam (Frontend)
**File:** `client/src/app/student/exam/[id]/active/page.tsx`

This was the largest change. Added:
- `pcRef`, `proctorPcIdRef`, `proctorSseCloseRef` refs
- `setupProctor()` useCallback:
  - Creates `RTCPeerConnection` and adds camera/mic tracks
  - Trickle ICE to `POST /exam/{examId}/proctor-ice`
  - Waits up to 3s for ICE gathering then posts offer to `POST /exam/{examId}/proctor-connect`
  - Sets remote description from engine's answer
  - Opens SSE to `GET /exam/{examId}/proctor-events` with `message` handler dispatching by `data.type`
- Tab switch handler also posts `POST /exam/{examId}/proctor-violation`
- `executeSubmit` and cleanup close PC + proctor SSE
- Fixed `parseUTCDate()` to handle both `+00:00` and naive ISO strings without NaN
- Added session status guards (DISCONNECTED → reconnect, CREATED → info page)
- Heartbeat 403 now redirects to `system?reconnect=true` instead of silently failing

### Phase 11: Live Admin Monitor — Engine Integration (Frontend)
**File:** `client/src/app/admin/dashboard/exams/[id]/monitor/page.tsx`

Replaced stub `LiveMonitorPanel` with live implementation:
- Polls `GET /admin/exams/{examId}/sessions/{session_id}/live-frame` every 2s → blob URL → `<img>`
- Opens SSE to `GET /admin/exams/{examId}/sessions/{session_id}/live-stream`
- Debug toggle button → `POST /admin/exams/{examId}/sessions/{session_id}/debug-mode`
- Live alerts list (max 50, newest first)
- **SSE handler fixed** (end of last session, UNTESTED): Changed named handlers `alert`/`risk_update` to single `message` handler dispatching by `data.type` — because the engine sends bare `data:` SSE lines with no `event:` prefix

### UTC Date/Time Fix (Frontend — Multiple Files)
**File (NEW — untracked):** `client/src/lib/fmt-date.ts`

```ts
export function parseUTC(iso: string): Date   // handles Z, +00:00, naive
export function fmtDate(iso: string): string  // "Jan 5, 2025" local TZ
export function fmtTime(iso: string): string  // "02:30 PM" local TZ
export function fmtDateTime(iso: string): string
```

**Files updated to use `parseUTC` instead of `new Date(str)` or `date-fns`:**
- `client/src/app/admin/dashboard/exams/page.tsx` — removed `date-fns`
- `client/src/app/admin/dashboard/exams/[id]/page.tsx` — removed `date-fns`
- `client/src/app/sys/dashboard/applications/page.tsx`
- `client/src/app/student/dashboard/page.tsx`
- `client/src/app/student/history/page.tsx`
- `client/src/app/student/exam/[id]/system/page.tsx`

### Countdown Timer Fix — System Check Page
**File:** `client/src/app/student/exam/[id]/system/page.tsx`

Old code used `time_until_open_ms` (which counts down to 15 min BEFORE start — the early-enter window, not actual start). Fixed to compute countdown from actual `start_window` using `parseUTC`. Also fixed interval leak — old code created a new `setInterval` every second via a `useEffect` dependency on `countdown`. Fixed by using `useRef` for interval, starting once inside `initSystem`.

---

## Bug Log — Fixed in These Sessions

| Bug | Root Cause | Fix | Tested? |
|-----|-----------|-----|---------|
| CORS error on login | Docker containers were stopped | `docker start exam_proctoring_postgres exam_proctoring_redis` | ✅ |
| Times displayed as UTC | `new Date("+00:00 string")` → invalid; `date-fns` didn't TZ-convert | Created `fmt-date.ts` with `parseUTC()` | ✅ |
| Countdown NaN on system page | Used `time_until_open_ms` (early-enter window, not start); interval recreated every second | Compute from `start_window`; use `useRef` for interval | ✅ |
| Timer NaN on active exam page | `parseUTCDate` appended `Z` to already-TZ-aware string | Check for existing TZ info before appending `Z` | ✅ |
| Tab switch / FS exit alerts silent | `session-active` didn't return `config` or `flag_threshold`; active page check `if (!exam?.config?.tab_switching)` always returned early | Added `title`, `flag_threshold`, `config` to `get_session_active` response | ✅ (partial) |
| Engine alerts not showing on student page | Engine sends bare `data:` SSE without `event:` prefix; handlers were registered as `alert`/`risk_update` keys | Changed to `message` handler dispatching by `data.type` | ✅ (partial) |
| Engine alerts not showing on admin monitor | Same SSE bug as above | Fixed `monitor/page.tsx` SSE handler | ❌ NOT TESTED |
| Heartbeat 403 Forbidden | Session not ACTIVE when heartbeat called; errors silently swallowed | Added status guards in active page init; heartbeat 403 now redirects to reconnect | ❌ NOT TESTED |

---

## SSE Event Format (Critical — Engine-Specific)

The proctor engine (`engine/`) sends SSE in this format:
```
data: {"type": "alert", "alert_type": "LOOKING_AWAY", "message": "...", "risk_delta": 5}
data: {"type": "risk_update", "score": 42}
data: {"type": "warning", "message": "..."}
```

**There is NO `event:` line.** All events arrive on the browser's default `message` event. Both the student active page and admin monitor use a custom `openSSE()` fetch-based helper (needed because `EventSource` doesn't support `Authorization` headers). That helper defaults `ev = 'message'` when no `event:` line is present. So handlers must be registered under the `message` key, and dispatch by `data.type` inside the handler:

```ts
openSSE(url, token, {
  message: (data: any) => {
    if (data?.type === 'alert' || data?.type === 'warning') { /* show toast */ }
    else if (data?.type === 'risk_update') { /* update score */ }
  },
});
```

---

## Architecture: WebRTC Flow

```
Student Browser
  │
  │  1. POST /exam/{id}/proctor-connect  (SDP offer)
  ▼
Proctor AI Backend  ──────────────────►  Engine FastAPI
  │                  POST /offer              │
  │◄─────────────── SDP answer ◄─────────────┘
  │
  │  2. POST /exam/{id}/proctor-ice  (ICE candidates)
  │─────────────► Engine POST /ice/{pc_id}
  │
  │  WebRTC media (video/audio) flows DIRECTLY:
  │  Student Browser ◄──────── UDP ──────────► Engine
  │
  │  3. GET /exam/{id}/proctor-events  (SSE alerts)
  │◄────── Backend proxies Engine GET /stream/{pc_id}
```

---

## File Change Map — Everything Modified in This Session

### NEW Files (untracked in git)

| File | Purpose |
|------|---------|
| `engine/` | Proctor engine (YOLO + MediaPipe WebRTC service) — copied from Proctor-webRTC repo |
| `server/alembic/versions/c1d2e3f4a5b6_add_proctor_engine_tables.py` | DB migration for engine tables |
| `server/app/exam/engine_allocator.py` | Engine container selection / load balancing |
| `server/app/exam/proctor_proxy.py` | Async HTTP proxy functions to engine |
| `server/app/exam/proctor_startup.py` | Seeds engine URLs into DB on startup |
| `client/src/lib/fmt-date.ts` | UTC-safe date formatting utilities |
| `client/src/app/sys/dashboard/system-settings/page.tsx` | SYSADMIN engine threshold settings page |

### Modified Files

| File | What Changed |
|------|-------------|
| `server/app/db/models.py` | `ProctorEngineContainer`, `ExamEngineAssignment`, `EngineSettings` models; new columns on `ExamSession` and `Exam` |
| `server/app/core/config.py` | `PROCTOR_ENGINE_URLS` setting |
| `server/app/exam/schemas.py` | `DetectionConfig` Pydantic model (13 bool fields) |
| `server/app/exam/routes.py` | Added proctor-connect, proctor-ice, proctor-events, proctor-violation routes; fixed `session-active` to return `title`/`flag_threshold`/`config` |
| `server/app/exam/admin_routes.py` | Added live-frame, live-stream, debug-mode, system-settings routes; wired `detection_config` into create/update exam |
| `server/app/main.py` | Calls `proctor_startup` on startup |
| `server/pyproject.toml` / `server/uv.lock` | Added `httpx` dependency (used by proctor proxy) |
| `client/src/app/admin/dashboard/exams/new/page.tsx` | Detection config toggles (13 bool fields) |
| `client/src/app/admin/dashboard/exams/[id]/edit/page.tsx` | Same detection config toggles |
| `client/src/app/admin/dashboard/exams/[id]/page.tsx` | `date-fns` → `fmt-date` |
| `client/src/app/admin/dashboard/exams/page.tsx` | `date-fns` → `fmt-date` |
| `client/src/app/admin/dashboard/exams/[id]/monitor/page.tsx` | Full live monitor (frame polling, SSE, debug toggle, alerts list); SSE handler bug fix |
| `client/src/app/sys/dashboard/layout.tsx` | Added "Engine Settings" nav item |
| `client/src/app/sys/dashboard/applications/page.tsx` | `date-fns` → `fmt-date` |
| `client/src/app/student/dashboard/page.tsx` | `parseUTC` for exam dates |
| `client/src/app/student/history/page.tsx` | `parseUTC` for exam dates |
| `client/src/app/student/exam/[id]/system/page.tsx` | Fixed countdown (start_window based, useRef interval) |
| `client/src/app/student/exam/[id]/active/page.tsx` | WebRTC proctor setup, SSE alerts, tab-switch violations, `parseUTCDate` fix, session status guards, heartbeat 403 redirect |

---

## Remaining TODOs / Next Steps

### High Priority

1. **Test all Phase 10–11 changes end-to-end:**
   - Start Docker + server + engine + frontend
   - Create an exam with detection config
   - Take exam as student: verify WebRTC connects, timer works, tab-switch alert shows, engine alerts appear as toasts
   - Monitor as admin: verify live frame updates, SSE alerts appear in monitor panel

2. **Verify heartbeat 403 fix works:**
   - Start exam, check server logs for heartbeat calls — should see `200` not `403`
   - Simulate disconnected session (wait 6 min with page open, or manually update DB) → verify redirect to reconnect page

3. **Phase 12 — Exam Completion Page:**
   - After submit, show detailed violation/risk breakdown
   - Calls `GET /exam/{id}/session-summary` which returns `proctor_report_id` and engine log data
   - Currently just shows a basic "submitted" screen

### Medium Priority

4. **Admin monitor — terminate student:**
   - Currently no "Terminate" button on the monitor page, only time extension and appeals
   - Add `POST /admin/exams/{examId}/sessions/{session_id}/terminate` button

5. **SYSADMIN system-settings page — test:**
   - Verify `GET /admin/system-settings` creates default `EngineSettings` row on first call
   - Verify `POST /admin/system-settings` updates and persists

6. **Detection config display:**
   - In exam detail page (`/admin/dashboard/exams/[id]`) show the saved detection toggles

### Low Priority

7. **EC2 Deployment:**
   - Build engine Docker image from `engine/` directory
   - Push to ECR or DockerHub
   - Deploy engine on EC2, update `PROCTOR_ENGINE_URLS` in production `.env`
   - Add `ProctorEngineContainer` row to production DB pointing to engine EC2 instance

---

## How to Start Everything Locally (Office Desktop)

```bash
# 1. Pull latest code
git pull origin develop

# 2. Start Docker containers
docker start exam_proctoring_postgres exam_proctoring_redis
# If containers don't exist: see Infrastructure Setup above

# 3. Run DB migration
cd server
.venv/Scripts/activate
alembic upgrade head

# 4. Start backend
uvicorn app.main:app --reload --port 8000
# Keep this terminal open

# 5. Start proctor engine (new terminal)
cd engine
pip install -r requirements.txt   # first time only
python -m uvicorn main:app --port 8001 --reload
# Keep this terminal open

# 6. Start frontend (new terminal)
cd client
npm install   # first time only
npm run dev
# Opens at http://localhost:3000
```

---

## Key Notes for Claude in Next Session

- All code changes from these sessions are in git working tree (uncommitted) — commit them once tested
- The SSE handler pattern (`message` key + dispatch by `data.type`) must be used consistently — **never** use named event handlers like `alert:` or `risk_update:` with this engine
- `parseUTC()` from `client/src/lib/fmt-date.ts` must be used everywhere dates from the API are displayed — never use `new Date(isoString)` directly or `date-fns format()` on raw API strings
- The `exam_guard` FastAPI dependency only allows `ACTIVE` sessions — any protected route (heartbeat, submit, end) will 403 if session is not exactly ACTIVE
- Engine URL is configured via `PROCTOR_ENGINE_URLS` env var (comma-separated), seeded into `proctor_engine_containers` table on startup via `proctor_startup.py`
- The heartbeat interval on the active page is 15 seconds; the scheduler marks sessions DISCONNECTED after 5 minutes of no heartbeat; the scheduler runs every 60 seconds
