# Proctor AI Client and Server Reference

## 1. Purpose of This Document

This document is the working reference for the main Proctor AI application codebase, focused on:

- `client/`
- `server/`

It intentionally does **not** explain how the separate AI `engine/` works internally. Instead, it documents:

- how the client and server are structured
- how the engine is integrated into the main system
- what each role can do
- how exam flow works
- what security controls exist in the product
- what policies are enforced in code today

This file should be treated as a practical implementation reference, not just a product vision note.

---

## 2. What This Project Is

Proctor AI is a full-stack online exam proctoring platform with three user roles:

- `STUDENT`
- `ADMIN`
- `SYSADMIN`

At a high level:

- the `client` provides the full web interface for registration, login, dashboards, exam flow, monitoring, and settings
- the `server` owns authentication, authorization, user/device management, exam scheduling, session state, appeals, time extensions, and proxy communication with the proctoring engine
- the `engine` is a separate real-time monitoring service used during active exams, but its internals are outside the scope of this document

Core system goals:

- secure exam participation
- identity verification
- trusted-device enforcement
- explainable session state transitions
- live proctoring integration
- admin review and recovery workflows

---

## 3. High-Level Architecture

### 3.1 Main application layers

1. `client/`
   - Next.js App Router frontend
   - role-based dashboards and exam UX

2. `server/`
   - FastAPI backend
   - SQLAlchemy models
   - PostgreSQL persistence
   - Redis for OTP and rate limiting

3. `engine/`
   - separate AI/WebRTC service
   - integrated through backend proxy endpoints

### 3.2 Runtime data flow

Typical exam runtime flow:

1. student authenticates through the backend
2. backend validates role, token, and trusted device
3. student enters pre-exam flow on the client
4. backend creates or resumes an `ExamSession`
5. client starts exam and asks backend to connect to the proctor engine
6. backend selects an engine container and proxies WebRTC signaling
7. browser media streams directly to the engine
8. engine events are proxied back through backend SSE endpoints
9. backend remains the source of truth for exam status, appeals, and session records

### 3.3 Important boundary

The engine is **not** the main system of record.

The backend remains the authoritative source for:

- users
- devices
- exams
- invites
- exam sessions
- appeal/resume decisions
- time extension decisions
- final session status

---

## 4. Current Folder-Level Overview

## 4.1 Client folder

`client/src/app/` currently contains these route groups:

- public and auth:
  - `/`
  - `/auth/login`
  - `/auth/register`
  - `/auth/verify-otp`
  - `/auth/forgot-password`
  - `/auth/reset-password`
  - `/auth/unlock-account`
  - `/auth/setup-password`
  - `/auth/teacher-apply`

- student:
  - `/student/dashboard`
  - `/student/history`
  - `/student/profile`
  - `/student/exam/[id]/info`
  - `/student/exam/[id]/device`
  - `/student/exam/[id]/environment`
  - `/student/exam/[id]/system`
  - `/student/exam/[id]/active`
  - `/student/exam/[id]/terminated`
  - `/student/exam/[id]/completion`

- admin:
  - `/admin/dashboard`
  - `/admin/dashboard/exams`
  - `/admin/dashboard/exams/new`
  - `/admin/dashboard/exams/[id]`
  - `/admin/dashboard/exams/[id]/edit`
  - `/admin/dashboard/exams/[id]/monitor`

- sysadmin:
  - `/sys/dashboard`
  - `/sys/dashboard/applications`
  - `/sys/dashboard/engine`
  - `/sys/dashboard/sessions`
  - `/sys/dashboard/system-settings`

Supporting client modules include:

- role guard
- device management UI
- shared data table/search/status components
- API client and token refresh logic
- UTC/local time formatting helpers

## 4.2 Server folder

`server/app/` is organized into:

- `auth/`
  - login, registration, OTP, password reset, device verification, admin application review

- `core/`
  - config, email, Redis, rate limiting, device fingerprinting, face utilities, storage

- `db/`
  - SQLAlchemy session, enums, models, mixins

- `exam/`
  - student exam routes
  - admin exam routes
  - SSE event handling
  - engine proxying
  - engine startup/container seeding
  - exam guard logic

- `main.py`
  - FastAPI app bootstrap
  - CORS
  - security headers
  - router registration
  - background scheduler for exam/session transitions

---

## 5. Tech Stack

## 5.1 Client

- Next.js 16 App Router
- React 19
- TypeScript
- Tailwind CSS
- shadcn/ui style component structure
- Axios
- React Hook Form
- Zod
- Sonner toasts

## 5.2 Server

- FastAPI
- SQLAlchemy
- Alembic
- PostgreSQL
- Redis
- Argon2 password hashing
- JWT access tokens
- UUID refresh tokens
- FaceNet via `facenet-pytorch`
- OpenCV and PIL for image processing

## 5.3 Engine integration dependencies

On the main system side, integration is handled with:

- `httpx` for engine HTTP proxying
- SSE streaming from backend to client
- WebRTC signaling proxied through backend endpoints

---

## 6. Role Model and Real Use Cases

## 6.1 Student

Student capabilities:

- register with selfie and consent
- login from trusted devices
- verify a new device through email OTP
- view upcoming exams
- complete pre-exam checks
- start, reconnect, or continue an exam depending on session state
- receive real-time exam events and warnings
- submit the exam
- see exam history
- update profile and password
- update profile image under policy rules
- appeal late join or termination in allowed cases
- manage own active devices

Student restrictions:

- cannot access admin or sysadmin areas
- cannot update selfie during an active exam
- cannot update selfie more than once every 30 days
- cannot enter an exam from an untrusted or revoked device

## 6.2 Admin

Admin capabilities:

- create and update exams
- invite students by email
- configure monitoring options
- configure exam-level detection toggles sent to the engine
- view exam lists and exam details
- monitor live sessions
- see live frames and alert streams
- toggle debug mode on a monitored session
- manually terminate a session
- extend time for one student or all active students in an exam
- review appeal/resume requests
- approve or deny appeals
- optionally restore time on approved reconnect-type appeals
- unsubmit an ended session to allow a controlled resume

Admin restrictions:

- admin routes are role-protected
- most exam admin actions are scoped to exams created by that admin

## 6.3 Sysadmin

Sysadmin capabilities:

- review and approve/reject teacher/admin applications
- create or reactivate admin users indirectly through application approval
- unlock user accounts
- revoke devices
- kill active exam sessions
- inspect active sessions globally
- monitor engine container health and usage through backend proxy endpoints
- view live sessions across exams
- manage global engine settings used during engine connection

Sysadmin use case in this project is platform control, not day-to-day invigilation.

---

## 7. Client Application Reference

## 7.1 Public and authentication pages

### `/auth/register`

Student registration page:

- collects full name, email, password, privacy consent
- captures/uploads a selfie
- sends multipart registration request to backend
- backend validates image, face presence, and generates face embedding
- allowed image MIME types are `image/jpeg`, `image/png`, and `image/jpg`
- registration is rejected if consent is not given
- if the email already belongs to an active account, registration is rejected
- if the email belongs to an inactive account, the backend reactivates that account instead of creating a duplicate user

### `/auth/login`

Login behavior:

- sends email/password to `/auth/login`
- if login succeeds directly, stores access and refresh tokens
- fetches `/auth/me`
- routes users by role:
  - `STUDENT` -> student dashboard
  - `ADMIN` -> admin dashboard
  - `SYSADMIN` -> sysadmin dashboard
- if device OTP is required, redirects to `/auth/verify-otp`
- OTP is required only for student logins when:
  - the fingerprint does not match an already trusted, non-revoked device, and
  - this is not the student's first ever active device
- first student device is auto-trusted
- admin and sysadmin logins currently bypass device OTP and auto-trust their device

### `/auth/verify-otp`

Used for new device verification:

- student receives device OTP by email
- client posts OTP to `/auth/device/verify`
- backend marks device as trusted and returns tokens
- backend only accepts this if there is a matching pending, non-revoked device record for the current fingerprint
- if the student's trusted-device limit is already reached, the oldest trusted device is revoked before trusting the new one

### `/auth/forgot-password` and `/auth/reset-password`

Password reset flow:

- request reset
- receive email link
- submit reset token and new password

### `/auth/unlock-account`

Used when account lockout is triggered after repeated failed login attempts.

### `/auth/setup-password`

Used mainly for newly approved admins or reactivated admins who must set an initial password.

### `/auth/teacher-apply`

Public application form for users who want admin/teacher privileges.

## 7.2 Student pages

### Student dashboard

Primary student home page:

- fetches `/auth/me`
- fetches `/exam/upcoming`
- shows live and upcoming exams
- links to history and profile
- includes device management UI

### Student history

Shows completed or otherwise historical exam attempts, including:

- exam timing
- session status
- risk score
- violation count
- termination reason if applicable

### Student profile

Supports:

- full name update
- password change
- profile image update through webcam capture

The UI explicitly tells the user that selfie update is limited to once every 30 days.

## 7.3 Student exam flow pages

### `/student/exam/[id]/info`

Entry gateway for a specific exam. This page decides what the student is allowed to do based on:

- exam timing
- invite existence
- session status
- late-join state
- appeal/resume state

It can:

- allow entry into pre-exam flow
- redirect back to active exam
- show late join appeal controls
- redirect to terminated flow
- block resubmission when already ended
- poll more frequently when waiting on appeal or reconnect state
- allow practical pre-exam entry when session is:
  - not yet started
  - `DISCONNECTED`
  - approved for re-entry and moved back toward `CREATED`
- block normal entry when session is:
  - `ACTIVE` on the same or another device
  - `TERMINATED` without approval
  - `ENDED`

### `/student/exam/[id]/device`

Hardware selection step:

- requests camera and microphone permissions
- enumerates devices
- previews camera
- measures mic level
- stores selected camera and microphone IDs in local storage

### `/student/exam/[id]/environment`

Environment and identity validation:

- opens selected camera/mic
- performs lighting check
- performs background noise check
- captures a face image
- sends captured image to `/exam/{examId}/verify-face`
- requires all checks to pass before continuing

### `/student/exam/[id]/system`

Final system lock step before exam start or reconnect:

- locks out other devices using `/exam/{examId}/lock-session`
- checks fullscreen support
- checks engine availability using `/exam/{examId}/engine-status`
- waits for actual exam start time if the student is early
- starts or reconnects exam using `/exam/start/{examId}`
- if another device already has an `ACTIVE` session for the same exam, backend returns `409` and the student cannot continue from this device
- if the exam is late and policy requires review, start is blocked until an approved appeal exists
- if the session is terminated and not approved for return, start is blocked

### `/student/exam/[id]/active`

Active exam page responsibilities:

- fetches authoritative session state from `/exam/{examId}/session-active`
- computes timer from server-side timestamps
- restores selected camera/mic
- starts backend SSE for exam events
- starts WebRTC proctor connection through backend
- sends heartbeat every few seconds
- watches fullscreen state
- tracks tab switching
- proxies tab-switch violations to backend
- handles time extension events
- redirects on termination or disconnect
- submits and ends the exam

This page is the core runtime page for a student.

### `/student/exam/[id]/terminated`

Termination handling page:

- fetches session status and resume state
- keeps polling for appeal review updates
- opens backend SSE to receive resume approval or denial
- lets the student:
  - appeal once when allowed
  - dismiss the appeal opportunity
  - return to dashboard when closed
- has different UI for:
  - `CAN_APPLY`
  - `PENDING`
  - `DENIED`
  - `NOT_APPLIED`
  - `AGAIN`
- automatically dismisses the appeal opportunity on page unload when the student leaves without filing, so the system can remember that they chose not to appeal
- redirects back into the pre-exam flow if an approved recovery moves the session back into a resumable state

### `/student/exam/[id]/completion`

Used after a normal submit or auto-submit.

## 7.4 Admin client pages

Admin UI supports:

- dashboard
- exam list
- exam creation
- exam editing
- exam detail view
- live monitor page

Important implemented admin UI features:

- exam schedule and invite management
- monitoring config selection
- exam-level detection toggles
- live session cards
- live frame polling
- live SSE alert feed
- debug toggle
- appeal review controls
- time extension controls
- manual session termination controls

## 7.5 Sysadmin client pages

Sysadmin UI supports:

- dashboard
- application review page
- engine monitor page
- live sessions page
- engine settings page

These pages mostly consume backend admin/system endpoints and expose platform-wide controls.

## 7.6 Shared client guards and utilities

### RoleGuard

`client/src/components/auth/role-guard.tsx`:

- checks token presence
- decodes JWT on client
- rejects expired tokens
- redirects users away from unauthorized route groups

### Axios client

`client/src/lib/axios.ts`:

- attaches `Authorization: Bearer ...`
- refreshes tokens automatically on backend `401`
- retries queued requests after refresh
- clears tokens and redirects to login on refresh failure

### Time formatting

`client/src/lib/fmt-date.ts`:

- normalizes UTC parsing
- formats dates and times in local browser timezone
- reduces frontend timezone inconsistencies

---

## 8. Server Application Reference

## 8.1 `main.py`

Backend bootstrap responsibilities:

- creates the FastAPI app
- mounts `/storage`
- applies CORS
- adds security headers
- includes routers
- runs startup tasks
- starts the background scheduler

### Implemented security headers

For application routes, backend sets:

- `Content-Security-Policy`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`

### Background scheduler behavior

Every 60 seconds the backend:

- moves exams from `SCHEDULED` to `LIVE`
- moves exams from `LIVE` to `ENDED`
- marks stale active sessions as `DISCONNECTED` after heartbeat loss
- auto-terminates disconnected sessions after 5 minutes
- ends sessions whose personal deadline has passed

## 8.2 `auth/` module

This module handles:

- student registration
- login
- password changes
- forced first-time password setup
- token refresh
- forgot/reset password
- logout
- account deletion
- profile updates
- profile image updates
- account unlock flow
- device verification
- device listing and revocation
- admin application submission and review

## 8.3 `core/` module

Key pieces:

- `config.py`
  - environment-driven settings
- `email.py`
  - SMTP email sending
- `redis.py`
  - Redis connection
- `rate_limiter.py`
  - Redis-based rate limiter
- `device.py`
  - request-based device fingerprint generation
- `otp.py`
  - hashed OTP storage and verification
- `device_otp.py`
  - dedicated device OTP helper
- `face_utils.py`
  - face validation, embedding comparison, profile image update cooldown check
- `embedding.py`
  - generates face embeddings
- `storage.py`
  - stores profile images in local storage path
- `exam_guard.py`
  - protects active exam actions

## 8.4 `db/` module

Contains:

- SQLAlchemy engine/session setup
- enums for roles, exam states, session states, resume states, policies
- ORM models for users, exams, sessions, devices, violations, risk, applications, and engine integration metadata

## 8.5 `exam/` module

Contains the operational exam system:

- student exam routes
- admin monitoring and control routes
- session event queues
- engine selection and proxy logic
- startup seeding of engine metadata

---

## 9. Core Data Model

This section focuses on the most important server-side entities.

## 9.1 Users

`users` stores:

- full name
- email
- password hash
- role
- profile image path
- face embedding
- account activity state
- password setup requirements
- login lockout fields
- privacy consent fields

## 9.2 User devices

`user_devices` stores:

- device fingerprint
- user agent
- IP
- last seen timestamp
- `trusted`
- `pending`
- `revoked`

This table is central to trusted device security.

### What the device fingerprint is

In the current backend implementation, the device fingerprint is a deterministic hash created from:

- the request `User-Agent` header
- the client IP address

The backend concatenates those values and generates a SHA-256 hash.

Practical meaning:

- it is not a browser-grade hardware fingerprint
- it is a backend-generated identity token for "this request environment"
- if user agent or client IP changes, the fingerprint can change too

This fingerprint is then reused in:

- `user_devices`
- JWT access token payloads
- refresh token binding
- exam session device binding
- device OTP verification

## 9.3 Refresh tokens

`refresh_tokens` stores:

- token value
- user
- bound device fingerprint
- expiry
- revoked flag

## 9.4 Exams

`exams` stores:

- title
- creator
- exam mode
- status
- start and end windows
- hard join deadline
- duration
- flag threshold
- late join policy
- late extension settings
- regular monitoring config
- engine-facing `detection_config`

## 9.5 Exam invites

`exam_invites` stores:

- invited email
- token
- expiration
- `used` flag

## 9.6 Exam sessions

`exam_sessions` stores:

- user and exam linkage
- session status
- start and end timestamps
- risk score
- last heartbeat
- termination metadata
- time extensions
- device binding
- IP and user agent
- engine integration fields:
  - `proctor_pc_id`
  - `proctor_engine_url`
  - `proctor_report_id`

## 9.7 Resume requests

`resume_requests` stores appeal/rejoin workflow state:

- student reason
- review decision
- admin review note
- time extension granted
- review timestamps and reviewer

## 9.8 Audit logs

`audit_logs` store security and administrative traceability.

Examples recorded in code:

- account lock
- profile update
- profile image update
- device verification
- device revocation
- admin application approval or rejection
- unlock actions

## 9.9 Engine integration metadata

The main system stores engine integration metadata in:

- `engine_containers`
- `exam_engine_assignments`
- `engine_settings`

This allows the backend to manage engine availability and pass configuration without embedding engine logic into the client.

---

## 10. Authentication, Session, and Device Security

This is one of the most important parts of the project.

## 10.1 Password security

Passwords are hashed with `Argon2`.

Implemented in:

- `server/app/auth/security.py`

The system never stores plain-text passwords.

## 10.2 Access token model

Access tokens are:

- JWT-based
- short-lived
- signed with configured secret and algorithm
- tagged with:
  - `sub`
  - `device`
  - `role`
  - token `type`

The backend rejects tokens that are:

- invalid
- expired
- not of access-token type

## 10.3 Refresh token model

Refresh tokens are:

- persistent DB records
- bound to a specific device fingerprint
- checked for revocation
- checked for expiry
- rotated on refresh

Refresh flow protection includes:

- rejecting refresh from a different device
- revoking the old refresh token when a new one is issued

## 10.4 Trusted device enforcement

This system does not treat password-only login as sufficient for students.

### How device fingerprint is generated

Current implementation in `server/app/core/device.py`:

1. backend reads `User-Agent`
2. backend reads client IP from `request.client.host`
3. backend concatenates those values
4. backend computes SHA-256
5. resulting hex digest becomes the device fingerprint

Student login behavior:

1. if the student has zero active non-revoked devices, the first device is auto-trusted
2. if the fingerprint already belongs to an existing trusted, non-pending, non-revoked device, login succeeds directly
3. if the fingerprint is new or still pending, backend creates a pending device record and sends an OTP email
4. OTP verification is required before that device becomes trusted
5. if the number of trusted devices has reached the configured `MAX_TRUSTED_DEVICES`, the oldest trusted device is revoked to make room

Admin and sysadmin devices are currently auto-trusted on successful login.

## 10.5 Device states

Device lifecycle fields:

- `trusted`
- `pending`
- `revoked`

This supports:

- staged verification
- invalidation of compromised devices
- exam-only device control

## 10.6 Account lockout and unlock

After repeated failed logins:

- `failed_login_attempts` increases
- `locked_until` is set
- account login is blocked
- lock email is sent
- audit log is created

Unlock flow:

- user requests unlock OTP
- OTP is sent by email
- unlock OTP is verified
- failed attempts and lock state are cleared

## 10.7 OTP security

OTP values are:

- 6-digit numeric codes
- hashed before storage
- stored in Redis
- time-limited
- attempt-limited

This applies to:

- device verification
- account unlock
- device trust approval for students is therefore tied both to email possession and the exact request fingerprint

### How OTP is generated

Current implementation in `server/app/core/otp.py`:

- OTP is generated as a random 6-digit number
- before storage, the OTP is combined with `OTP_SECRET`
- the combined value is hashed with SHA-256
- only the hash is stored, not the plain OTP

Stored OTP records also track:

- attempt count
- expiry TTL in Redis

If attempts exceed the configured maximum, the OTP record is deleted and verification fails.

### Device OTP flow

The new-device verification flow for students is:

1. student submits email and password to `/auth/login`
2. backend authenticates credentials
3. backend generates current request fingerprint from `User-Agent + IP`
4. backend checks whether this fingerprint already exists as a trusted, non-revoked device
5. if not trusted and not first-device case:
   - backend creates or refreshes a `user_devices` row with:
     - `trusted = false`
     - `pending = true`
     - `revoked = false`
   - backend generates a 6-digit OTP
   - backend stores OTP in Redis keyed by user and fingerprint
   - backend emails the OTP to the user's registered email
   - backend returns an OTP-required response instead of tokens

6. client redirects to `/auth/verify-otp`
7. student submits OTP to `/auth/device/verify`
8. backend regenerates the fingerprint from the current request
9. backend verifies:
   - OTP matches the Redis record
   - a pending device row exists for that same fingerprint
10. backend marks device as:
   - `trusted = true`
   - `pending = false`
11. backend may revoke the oldest trusted device if max trusted-device count has already been reached
12. backend issues access token and refresh token bound to that fingerprint

Important implementation detail:

- the OTP is not just tied to the user
- it is tied to the specific user plus fingerprint combination
- so verification must come from the same derived request environment expected by the backend

### Unlock OTP flow

Account unlock uses a similar pattern with a different scope:

1. locked user requests unlock OTP
2. backend generates a 6-digit OTP
3. backend stores the hashed OTP in Redis under unlock scope
4. backend emails the OTP
5. user submits OTP to `/auth/unlock/verify`
6. backend verifies the OTP and clears:
   - `failed_login_attempts`
   - `locked_until`
   - `unlock_requests`

## 10.8 Rate limiting

Redis-based rate limiting exists for important abuse-sensitive endpoints.

Examples in code:

- student registration
- login
- forgot password
- admin application submission

Rate limit keys can be based on:

- IP
- user
- both

## 10.9 Role-based access control

Backend uses `require_role(...)` to restrict:

- admin actions
- sysadmin actions
- protected management routes

Frontend also enforces route-level protection with `RoleGuard`, but backend remains the real enforcement layer.

## 10.10 Logout and device revocation

Logout revokes:

- the provided refresh token
- the current device record

Users can also revoke other devices manually.

Revocation also kills associated refresh tokens.

## 10.11 Soft-delete account safety

Account deletion is implemented as soft delete:

- user becomes inactive
- `deleted_at` is set
- refresh tokens are revoked

Deletion is blocked while the user has an active/created/disconnected exam session.

---

## 11. Identity Verification and Profile Image Policy

## 11.1 Registration identity controls

Student registration requires:

- valid image type
- exactly one detectable face
- acceptable face size
- generated face embedding
- privacy consent
- active-account email uniqueness

If the image is invalid, the backend returns clear error categories such as:

- no face
- multiple faces
- unclear image

## 11.2 Environment identity re-check

During pre-exam environment verification:

- client captures a live image
- backend validates one face
- backend creates a new embedding
- backend compares it against the student profile embedding

This helps confirm the exam taker matches the registered profile.

## 11.3 Profile image change policy

The student profile selfie update has explicit policy controls:

- only `STUDENT` users can update selfie
- update is blocked during an active exam
- update is allowed only once every 30 days
- only `image/jpeg`, `image/png`, and `image/jpg` are accepted
- uploaded image must contain a valid single face
- new face embedding must match the existing identity
- a mismatch returns a hard failure instead of silently replacing identity data

Current implementation detail:

- cooldown is enforced through `last_profile_image_update`
- comparison uses embedding similarity and distance checks
- updated selfie is saved to local storage under `storage/profiles/users`
- new image also replaces stored face embedding
- an audit log is written

Practical meaning:

The profile image is treated as an identity artifact, not a casual avatar.

---

## 12. Exam Security Controls

The exam system adds another layer of security on top of normal login security.

## 12.1 Exam guard

`exam_guard` protects active exam endpoints by checking:

- valid authenticated user
- trusted non-revoked device
- an active session exists
- session belongs to that same device
- session has not passed its personal deadline

This is applied to critical endpoints like:

- `/exam/submit`
- `/exam/heartbeat`
- `/exam/end`

## 12.2 Device binding during exam

When a session starts:

- backend binds `device_fingerprint` to the session

During protected exam operations:

- backend rejects requests from another device

## 12.3 Cross-device session lock before start

During the system lock stage:

- backend blocks start if the same exam is active on another device
- backend revokes all other refresh tokens for the user
- backend revokes all other device records for the user
- the lock is account-wide in practice for that user session, not only a cosmetic client-side warning

This is one of the strongest anti-multi-device controls in the project.

## 12.4 Fullscreen enforcement

Client side:

- system page checks fullscreen support
- active page watches fullscreen exit
- fullscreen loss produces warning UI and contributes to exam integrity enforcement

## 12.5 Heartbeat and disconnect handling

Client sends heartbeat regularly.

Backend uses heartbeat to:

- keep the session alive
- detect when student has left the active exam page

Scheduler rules currently implemented:

- active session without heartbeat for more than 90 seconds -> `DISCONNECTED`
- disconnected for more than 5 minutes -> `TERMINATED` with disconnect reason

## 12.6 Personal deadline enforcement

Backend does not rely only on exam end window during active session protection.

Instead it computes a personal deadline from:

- session start time
- exam duration
- any admin-granted extra time

This matters for reconnects and time extensions.

## 12.7 Appeal restrictions

Appeals are blocked in several cases:

- while session is active
- after exam is ended/submitted
- when an appeal is already pending
- after denial
- after second-chance exhaustion
- for termination recovery, no approval means no re-entry
- if the latest resume request is already `APPROVED`, a second termination path leads to `AGAIN`
- late-join review flow also depends on an approved resume request before start is allowed

The code enforces a practical one-appeal-per-termination model.

---

## 13. Exam States and Resume States

Two different concepts exist in the system.

## 13.1 Session status values

Backend exam session statuses:

- `CREATED`
- `ACTIVE`
- `DISCONNECTED`
- `ENDED`
- `TERMINATED`

Meaning:

- `CREATED`
  - session record exists but student is not actively taking exam yet
  - also used as the re-entry state after approved resume in current implementation

- `ACTIVE`
  - student is currently in the running exam

- `DISCONNECTED`
  - session was active but heartbeat was lost

- `ENDED`
  - exam is submitted or otherwise fully closed

- `TERMINATED`
  - exam attempt was force-closed before normal completion

## 13.2 Resume/appeal states

These are derived from the latest `ResumeRequest`:

- `CAN_APPLY`
- `PENDING`
- `APPROVED`
- `DENIED`
- `NOT_APPLIED`
- `AGAIN`

Meaning:

- `CAN_APPLY`
  - terminated and student has not appealed yet

- `PENDING`
  - appeal filed, waiting review

- `APPROVED`
  - approved appeal state in request history

- `DENIED`
  - appeal closed, no re-entry

- `NOT_APPLIED`
  - student dismissed the appeal chance

- `AGAIN`
  - student had an approved recovery once, got terminated again, and cannot appeal again

Important implementation note:

The project stores exam lifecycle in `ExamSession.status` and appeal lifecycle in `ResumeRequest.status`. They are related but not the same thing.

---

## 14. Detailed Student Exam Flow

This section combines the intended behavior from `temp.txt` with current server/client code.

## 14.1 Pre-exam flow

The pre-exam pipeline is:

1. Exam info
2. Device check
3. Environment and identity check
4. System lock down
5. Exam start

Current client route order:

1. `/student/exam/[id]/info`
2. `/student/exam/[id]/device`
3. `/student/exam/[id]/environment`
4. `/student/exam/[id]/system`
5. `/student/exam/[id]/active`

## 14.2 Normal case

Current implemented behavior:

1. session is effectively not yet active
2. student completes pre-exam flow
3. backend starts session
4. student takes exam
5. student submits
6. backend marks session `ENDED`
7. client goes to completion page

## 14.3 Auto-submit on timer expiry

Current behavior:

1. active page keeps a timer based on server timestamps
2. when timer reaches zero, client auto-submits
3. backend ends exam
4. session becomes `ENDED`
5. user goes to completion page

## 14.4 Disconnect and reconnect case

Current implemented behavior:

1. session is `ACTIVE`
2. heartbeats stop
3. scheduler marks session `DISCONNECTED`
4. if student returns before 5-minute disconnect termination:
   - student re-enters pre-exam flow
   - system page runs lock/system checks again
   - backend `/exam/start/{examId}` treats this as reconnect
   - session returns to `ACTIVE`
   - timer continues using authoritative session time
   - time may be compensated through admin-approved extension if used

5. if student does not return within 5 minutes:
   - scheduler marks session `TERMINATED`
   - reason becomes disconnect termination
   - student can use terminated flow if still within permitted rules
   - by current code, disconnected termination is written as `terminated_by = SYSTEM_DISCONNECT`

## 14.5 Late join case

Current behavior depends on exam policy:

- `DENY`
  - no late join

- `REVIEW`
  - student must submit appeal
  - admin must approve appeal
  - only then can student re-enter

- `ALLOW`
  - late entry can proceed within configured limits

The backend also respects:

- hard join deadline
- optional max late minutes extension window
- if `allow_late_extension` is enabled with `max_late_minutes`, the system still blocks entry after that extra cutoff passes

## 14.6 Termination case

Termination can occur through:

- admin manual termination
- system disconnect timeout
- engine-backed violation escalation

Once terminated:

- student is sent to terminated UX
- student may appeal if resume state allows it
- pending appeal blocks duplicate requests
- denied appeal closes path
- approved appeal allows controlled re-entry
- second termination after approved recovery leads to `AGAIN`

## 14.7 Ended case

Once `ENDED`:

- the exam is treated as submitted/completed
- no new appeal is allowed
- student sees completion/history behavior instead of resume flow

---

## 15. Backend Exam Route Responsibilities

Important student exam routes include:

- `GET /exam/upcoming`
- `GET /exam/history`
- `GET /exam/{exam_id}/status`
- `GET /exam/{exam_id}/session-active`
- `GET /exam/{exam_id}/session-summary`
- `POST /exam/{exam_id}/lock-session`
- `POST /exam/{exam_id}/verify-face`
- `POST /exam/{exam_id}/appeal`
- `POST /exam/{exam_id}/dismiss-appeal`
- `POST /exam/start/{exam_id}`
- `POST /exam/submit`
- `POST /exam/heartbeat`
- `POST /exam/end`
- `GET /exam/{exam_id}/engine-status`
- `POST /exam/{exam_id}/proctor-connect`
- `POST /exam/{exam_id}/proctor-ice`
- `POST /exam/{exam_id}/proctor-violation`
- `GET /exam/{exam_id}/proctor-events`

Admin exam routes include:

- exam create/list/detail/update
- resume request list/review
- individual and bulk time extension
- manual termination
- live frame
- live stream
- alert history
- debug mode

Sysadmin routes include:

- engine settings read/update
- engine containers
- engine metrics
- engine reports
- engine sessions
- global active sessions
- global live frame/live stream

---

## 16. Engine Integration in the Main System

This section covers only integration, not engine internals.

## 16.1 Why the engine is separated

The engine is treated as an external service so that:

- the main backend remains focused on business rules and system-of-record data
- proctoring workloads stay isolated
- engine containers can be scaled and monitored separately

## 16.2 Backend-owned engine metadata

The server maintains:

- active engine base URLs from config
- seeded engine container records
- per-session `proctor_pc_id`
- per-session `proctor_engine_url`
- global engine settings row

## 16.3 Student-side engine integration flow

From the main application point of view, this is the integration sequence:

1. system page calls `/exam/{examId}/engine-status`
2. backend checks engine container reachability and capacity
3. student starts exam through backend
4. active page creates `RTCPeerConnection`
5. active page posts offer to `/exam/{examId}/proctor-connect`
6. backend picks an engine container
7. backend merges:
   - exam-level detection toggles
   - sysadmin global engine settings
8. backend proxies the offer to the engine
9. backend stores returned engine session ID on `ExamSession`
10. client sends ICE candidates through `/exam/{examId}/proctor-ice`
11. client listens to `/exam/{examId}/proctor-events`
12. client reports tab switches with `/exam/{examId}/proctor-violation`

Small but important detail:

- `/proctor-connect` is allowed only after the session is already `ACTIVE`
- if the backend cannot find an engine container or the engine settings row, exam connection is blocked
- backend, not client, decides which engine URL is used

## 16.4 Admin-side engine integration flow

Admin monitoring uses backend proxy endpoints:

- `/admin/exams/{exam_id}/sessions/{session_id}/live-frame`
- `/admin/exams/{exam_id}/sessions/{session_id}/live-stream`
- `/admin/exams/{exam_id}/sessions/{session_id}/alert-history`
- `/admin/exams/{exam_id}/sessions/{session_id}/debug-mode`

This means the admin UI does not talk directly to engine endpoints.

## 16.5 Sysadmin-side engine integration flow

Sysadmin pages use backend aggregation/proxy endpoints for:

- engine container inventory
- engine metrics
- engine system reports
- active engine session lists
- live session streaming without exam scoping

## 16.6 Important design boundary

Students do not directly call the engine's signaling HTTP endpoints.

The backend is the signaling and policy gateway for:

- engine selection
- config injection
- persistence of engine session references
- translation of engine events into main-system state changes

## 16.7 End-of-exam integration

On exam end:

- backend tries to pull final session log from the engine
- backend updates stored `risk_score`
- backend stores engine-side report identifier if available

This is best-effort and should not block submission.

---

## 17. Appeals, Recovery, and Administrative Control

## 17.1 Appeal creation

Student can submit appeal through backend in allowed cases.

The system creates `ResumeRequest` rows and uses them as the review artifact.

## 17.2 Appeal dismissal

Student can explicitly dismiss the appeal option.

This creates a `NOT_APPLIED` state so the system remembers the student intentionally closed the recovery path.

## 17.3 Appeal review

Admin can:

- approve
- deny
- leave review note
- add time extension on approval

On approval:

- terminated session is moved back to `CREATED`
- student can restart pre-exam flow and rejoin

On denial:

- session is moved to `ENDED`
- no further re-entry path remains

## 17.4 Time extension

Admin can:

- extend one session
- extend all active sessions in an exam

Extensions are pushed to the active page via SSE and incorporated into timer calculation.

## 17.5 Manual termination

Admin can terminate an active or disconnected session.

This writes termination metadata and notifies the student through SSE.

## 17.6 Admin unsubmit

There is also an admin override that can:

- revert an ended session back into a resumable path
- create an approved resume request
- allow the student to rejoin natively

---

## 18. Time and Timezone Handling

The project has already had date/time issues addressed in multiple places.

Current patterns include:

- parsing server timestamps as UTC
- formatting in local browser timezone on client
- preserving personal deadlines on server
- allowing time extension beyond normal exam end window

Important practical rule:

The active exam timer is server-anchored, not just browser-local.

---

## 19. Current Policies Explicitly Enforced in Code

These are implementation-backed rules present in the project today.

### Account and device

- passwords are hashed with Argon2
- students use trusted-device login flow
- new student devices require OTP
- refresh tokens are device-bound
- excessive failed logins trigger lockout
- unlock uses OTP
- users can revoke devices
- logout revokes refresh token and current device

### Identity

- student registration requires a valid selfie
- exam environment check verifies face against stored embedding
- profile selfie updates are restricted
- profile selfie update requires same-person verification

### Profile image policy

- student only
- not during active exam
- once every 30 days

### Exam integrity

- exam actions require active trusted-device-bound session
- other devices are revoked before system lock/start
- fullscreen is expected during active exam
- heartbeat loss causes disconnect state
- prolonged disconnect causes termination
- late join can require review
- terminated sessions cannot freely re-enter
- ended sessions cannot be appealed

### Monitoring integration

- engine availability is checked before exam start
- engine config is controlled by admin and sysadmin settings through backend
- engine events can update backend risk score
- engine-triggered termination is reflected into backend session state

---

## 20. Known Current-State Notes

This document reflects the codebase as it exists now, including some rough edges.

Important observations:

- the root landing page is still the default Next.js starter page and not yet the final product landing page
- several README files are still placeholders
- some admin/sysadmin navigation targets appear ahead of fully finished pages
- role naming in product language sometimes says "teacher" while backend role enum uses `ADMIN`
- `session_context.md` indicates recent engine integration work is still not fully end-to-end tested

So this project already has substantial implementation, but parts of the UX and some newer integrations are still in active refinement.

---

## 21. Summary

The `client` and `server` together already implement a large portion of a secure online exam platform:

- identity-backed student registration
- trusted-device authentication
- account security and recovery
- role-specific dashboards and controls
- full pre-exam pipeline
- live exam session management
- disconnect handling
- appeal and recovery logic
- admin monitoring and intervention
- sysadmin platform control
- backend-controlled integration with a separate proctoring engine

If this document is used as the main reference going forward, it should be updated whenever any of these areas changes:

- session state rules
- appeal rules
- device trust flow
- profile image policy
- engine integration endpoints
- role permissions
