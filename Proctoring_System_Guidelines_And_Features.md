# **AI-Based Intelligent Online Exam Proctoring System**

## **1\. Purpose of This Document**

This document defines the complete system vision, functional scope, architecture principles, features, workflows, and page-level specifications of the AI-Based Online Exam Proctoring System. It serves as the single source of truth for developers, AI models, designers, and stakeholders.

---

## **2\. Product Vision**

### **2.1 Core Mission**

To provide a fair, secure, explainable, and scalable online exam proctoring platform that minimizes false positives and protects student integrity.

### **2.2 Key Values**

* Fairness  
* Transparency  
* Security  
* Reliability  
* Explainability  
* Auditability  
* Scalability

---

## **3\. System Architecture Overview**

### **3.1 High-Level Architecture**

Client (React/Nextjs) → API Gateway (FastAPI) → Core Services → Database & Storage

### **3.2 Components**

* Frontend: React/Nextjs (JavaScript)  
* Backend: FastAPI (Python)  
* AI Services: OpenCV, MediaPipe, YOLO, FaceNet/ArcFace  
* Database: PostgreSQL  
* Storage: Local (Dev) / S3-Compatible (Prod)  
* Auth: JWT \+ RBAC  
* ORM: SQLAlchemy  
* Migrations: Alembic

---

## **4\. User Roles**

### **4.1 Student**

* Takes exams  
* Receives warnings  
* Views own reports

### **4.2 Exam Admin**

* Creates and manages exams  
* Monitors students  
* Reviews reports  
* Approves reconnect/late requests

### **4.3 System Admin**

* Manages exam admins  
* Views audit logs  
* Controls platform-wide settings

---

## **5\. Exam Types & Timing System**

### **5.1 Exam Modes**

#### **Flexible Window**

* Start anytime within window  
* Fixed duration  
* Late join approval possible

#### **Fixed Window**

* Hard start and end  
* Auto-submit at end  
* No extension by default

### **5.2 Timing Controls**

* Start Window  
* End Window  
* Duration  
* Hard Join Deadline  
* Late Join Policy  
* Grace Period

---

## **6\. Monitoring Modules**

### **6.1 Webcam Module**

* Face detection  
* Multiple face detection  
* Head pose  
* Gaze tracking  
* Phone detection

### **6.2 Audio Module**

* Voice activity detection  
* Background speech detection

### **6.3 Browser Module**

* Tab switch detection  
* Fullscreen monitoring  
* Visibility changes

### **6.4 Identity Module**

* Registration selfie  
* Face embedding generation  
* Random verification  
* Backend comparison

### **6.5 Network Module**

* Heartbeat system  
* Disconnect tracking  
* Offline buffer

### **6.6 Dual Device Detection**

* Session fingerprinting  
* Active session enforcement

---

## **7\. Violation Verification Pipeline**

### **7.1 Two-Level Detection**

1. Client-side detection  
2. Server-side verification

### **7.2 Pipeline Flow**

1. Client triggers violation  
2. Evidence captured  
3. Evidence uploaded  
4. Backend AI re-verifies  
5. Confidence scoring  
6. Final verdict  
7. Risk update

### **7.3 Verdict Types**

* CONFIRMED  
* REVIEW  
* REJECTED

---

## **8\. Risk Scoring & Adaptive Termination**

### **8.1 Risk Weights (Example)**

* Tab Switch: \+10  
* Fullscreen Exit: \+10  
* Multiple Face: \+30  
* Face Mismatch: \+40  
* Phone: \+50  
* Audio: \+15

### **8.2 Severity Levels**

* Low  
* Medium  
* High

### **8.3 Adaptive Termination Logic**

Termination is based on:

* Total risk score  
* Recent violation density  
* Presence of high-severity violations

### **8.4 Risk Categories**

* 0–30: Low  
* 30–70: Medium  
* 70+: High

---

## **9\. Security Architecture**

### **9.1 Evidence Security**

* SHA256 hashing  
* Secure storage  
* Access control

### **9.2 Report Security**

* Digitally signed PDFs  
* Immutable logs

### **9.3 Data Protection**

* Encrypted tokens  
* Secure uploads  
* Role-based access

---

## **10\. Reliability & Recovery**

### **10.1 Heartbeat**

* 10s interval  
* Disconnect detection

### **10.2 Offline Buffer**

* IndexedDB/LocalStorage  
* Deferred sync

### **10.3 Resume System**

* Reconnect flow  
* Admin approval

---

## **11\. Page-Level Specifications**

---

## **11.1 Public Pages**

### **Landing Page (/)**

Components:

* Product overview  
* Login button  
* Register button  
* Info section

### **Register (/register)**

Components:

* Email field  
* Name field  
* Password field  
* Selfie upload  
* Preview  
* Submit

### **Login (/login)**

Components:

* Email  
* Password  
* Login button  
* Error display

---

## **11.2 Student Pages**

### **Student Dashboard (/student/dashboard)**

Components:

* Exam list  
* Status badges  
* Join buttons  
* Reports links

### **Exam Waiting Room (/exam/:token/wait)**

Components:

* Permission checker  
* System checklist  
* Instructions  
* Start button

### **Exam Page (/exam/:token/live)**

Components:

* Timer  
* Warning panel  
* Status indicator  
* Background proctor engine

### **Exam End Page (/exam/:token/end)**

Components:

* Completion message  
* Status  
* Logout

### **Report Page (/student/reports/:id)**

Components:

* Timeline  
* Evidence viewer  
* Risk summary

### **Reconnect Page (/exam/:token/reconnect)**

Components:

* Reason display  
* Request button  
* Status indicator

---

## **11.3 Exam Admin Pages**

### **Admin Login (/admin/login)**

Components:

* Credentials  
* Login

### **Admin Dashboard (/admin/dashboard)**

Components:

* Exam stats  
* Alerts  
* Navigation

### **Create Exam (/admin/exams/create)**

Components:

* Basic info form  
* Monitoring toggles  
* Timing settings  
* Warning config  
* Submit

### **Exam List (/admin/exams)**

Components:

* Table view  
* Filters  
* Status tags

### **Exam Detail (/admin/exams/:id)**

Components:

* Config view  
* Invite links  
* Student list  
* Controls

### **Live Monitor (/admin/exams/:id/live)**

Components:

* Student grid  
* Status indicators  
* Risk meters  
* Actions

### **Session Review (/admin/session/:id)**

Components:

* Timeline  
* Evidence gallery  
* Risk breakdown  
* Decision buttons

### **Requests (/admin/requests)**

Components:

* Pending list  
* Approve/Deny buttons

---

## **11.4 System Admin Pages**

### **System Dashboard (/sys/dashboard)**

Components:

* Metrics  
* Usage charts  
* Logs

### **Manage Admins (/sys/admins)**

Components:

* Admin list  
* Create/Disable

### **Audit Logs (/sys/logs)**

Components:

* Filterable log table  
* Export tools

---

## **12\. Data Model Overview**

Entities:

* User  
* Role  
* Exam  
* ExamSession  
* Violation  
* Evidence  
* RiskScore  
* AuditLog  
* ResumeRequest

---

## **13\. Development Workflow**

* Branch-based Git workflow  
* Conventional commits  
* Code reviews  
* CI checks  
* Migration-driven schema

---

## **14\. Quality Standards**

* Minimal false positives  
* Explainable decisions  
* Defensive programming  
* Extensive logging  
* Test coverage

---

## **15\. Non-Functional Requirements**

* High availability  
* Horizontal scalability  
* Secure storage  
* Low latency warnings  
* GDPR-style data control

---

## **16\. Success Criteria**

* Stable multi-exam operation  
* \<5% false positives  
* Complete audit trail  
* Positive admin feedback  
* Defensible reports

---

## **17\. Development Environment & Cross-Platform Standards**

### **17.1 Multi-OS Development Policy**

The system is designed to be developed and tested on multiple operating systems, primarily:

* Windows  
* Ubuntu (Linux)

Each development machine maintains its own local runtime data. No database files or evidence files are shared between machines.

Only source code, schema migrations, and configuration templates are shared via Git.

---

### **17.2 Docker-First Workflow**

All core services must be started using Docker Compose.

Standard development command:

docker compose up

This command must start:

* Backend (FastAPI)  
* PostgreSQL  
* Supporting services  
* Evidence storage mounts

Developers must avoid running backend or database services manually outside Docker.

---

### **17.3 Database Management Strategy**

* Each machine runs its own PostgreSQL instance inside Docker.  
* Docker volumes are local-only and never shared.  
* Database state differs per machine.  
* Only schema consistency is required.

Schema synchronization is maintained using Alembic migrations:

Workflow:

1. Modify models  
2. Generate migration  
3. Commit migration  
4. Pull on other machine  
5. Run migration

This ensures identical schemas across environments.

---

### **17.4 Evidence Storage Strategy**

Evidence files must never be stored inside the database.

Development storage path:

server/storage/evidence/

Recommended structure:

server/storage/evidence/

  └── session\_\<id\>/

      └── violation\_\<id\>.jpg

The backend stores only file paths or URLs in the database.

Example:

/storage/evidence/session123/violation\_001.jpg

In Docker, this directory must be mounted as a persistent volume so that files survive container restarts.

---

### **17.5 Git Configuration and Line Endings**

To avoid cross-platform line ending issues, the following Git settings must be used:

On Windows:

git config \--global core.autocrlf true

On Ubuntu/Linux:

git config \--global core.autocrlf input

This prevents CRLF/LF conflicts.

---

### **17.6 Node.js Version Consistency**

All developers must use the same Node.js version.

Recommended tools:

* nvm (Linux/macOS)  
* nvm-windows (Windows)

The active Node version must match the version specified in project documentation.

---

### **17.7 Dependency and Environment Consistency**

* Python dependencies are managed using pinned versions.  
* Node dependencies are locked via package-lock.json.  
* Environment variables are defined using .env templates.  
* Secrets are never committed to Git.

---

### **17.8 Local Data Isolation Policy**

The following data must remain local to each machine:

* PostgreSQL volumes  
* Evidence files  
* Cached AI models  
* Temporary logs

This data is not synchronized between systems.

Only the following are shared:

* Source code  
* Migrations  
* Documentation  
* Configuration templates

---

### **17.9 Recommended Project Run Strategy**

All development and testing must use:

docker compose up

This ensures:

* Consistent runtime behavior  
* Identical service versions  
* Ready storage mounts  
* Predictable networking

This approach mirrors company-grade deployment practices.

---

### **17.10 Production Readiness Considerations**

* Local storage is replaced by S3-compatible storage in production.  
* Database backups are automated.  
* Evidence files are archived.  
* Logs are centralized.  
* Secrets are managed via secure vaults.

also logging is missing and what ever code you give should be industry standard proper logs and documentation should be done as per industry standards

also for github also i want to work on differen branches so create feature wise branches

Also during the Edit the image of candidate should be check before and after as there can be students who would change image before exam 

in Exams : we are also providing option the if duration ends obviously it should auto submit but incase the candidate joined late and the duration of exam wont be ended within the end\_window the candidate can request full time also direct it would notify the exam admin that theres a student who joined late allow him or not if alows candidate could appear through out the exam duration and if not auto submit at end time

**we will have to take care that during the exam the token dosent get expired** 

We have two logger on is log and another is system\_logger so kindly add appropriate logging and industry standard documentation to the code you generate

While designing frontend we have access token and refresh token in backend so design it accordingly

Below are the **additions and clarifications** that were missing or implicit before.

---

## **1️⃣ Soft Delete Policy for Users**

### **Newly Clarified**

Users must never be permanently deleted.

Instead:

`is_deleted BOOLEAN`  
`deleted_at TIMESTAMP`

### **Purpose**

* Preserve historical exam records

* Maintain auditability

* Support legal/compliance needs

---

## **2️⃣ UUID-Based Primary Keys (Security Upgrade)**

### **Newly Added**

All major tables will use UUID instead of integers.

### **Reason**

* Prevent ID enumeration

* Improve security

* Support distributed scaling

* Safer public URLs

---

## **3️⃣ User Identity Storage Enhancement**

### **Newly Added**

Users table must include:

* Profile image path

* Face embedding storage

### **Purpose**

* Backend-controlled identity verification

* Faster server-side face matching

---

## **4️⃣ Exam-Level Risk Threshold Configuration**

### **Newly Clarified**

Each exam stores:

* flag\_threshold

* terminate\_threshold

Configured by admin.

### **Purpose**

* Per-exam cheating tolerance

* Flexible risk management

---

## **5️⃣ Late Join Policy as First-Class Feature**

### **Newly Formalized**

Late join handling is not just logic, but configuration.

Includes:

* allow\_late\_extension

* max\_late\_minutes

* late\_join\_policy

### **Purpose**

* Transparent late-join governance

* Prevent ad-hoc decisions

---

## **6️⃣ Violation Definitions as Configurable Data**

### **Newly Formalized**

Violation definitions live in DB:

`violation_types`

Includes:

* Code

* Name

* Severity

* Score

* Message

### **Purpose**

* Admin-configurable scoring

* No hardcoding in code

---

## **7️⃣ Dual Confidence Storage (Client \+ Server)**

### **Newly Added**

Each violation stores:

* client\_confidence

* server\_confidence

### **Purpose**

* Reduce false positives

* Enable appeal review

* Improve explainability

---

## **8️⃣ Evidence Metadata Management**

### **Newly Clarified**

Evidence includes:

* file\_path

* file\_hash

* mime\_type

Purpose:

* Integrity verification

* Proper rendering

* Forensic analysis

---

## **9️⃣ Risk History Tracking (Risk Snapshots)**

### **Newly Added**

Risk changes are logged historically.

`risk_snapshots`

Purpose:

* Explain score evolution

* Provide timeline view

* Support admin audits

---

## **🔟 Termination Reasons as Structured Data**

### **Newly Added**

Termination is categorized.

`termination_reasons`

Lookup table.

Purpose:

* Standardized termination reporting

* Analytics

* Fairness audits

---

## **1️⃣1️⃣ Model Verification Records (AI Accountability)**

### **Newly Formalized**

Server-side AI checks are logged.

`model_verifications`

Includes:

* Model name

* Version

* Confidence

* Verdict

Purpose:

* Support appeals

* Prove AI validation

* Reduce legal risk

---

## **1️⃣2️⃣ Session Device Fingerprinting Policy**

### **Newly Clarified**

Sessions record:

* Browser fingerprint

* IP

* User-agent

Purpose:

* Dual-device detection

* Proxy prevention

* Session hijack detection

---

## **1️⃣3️⃣ Structured Logging Architecture**

### **Newly Defined**

Three-tier logging:

| Type | Storage |
| ----- | ----- |
| App Logs | File |
| Audit Logs | DB |
| System Logs | File \+ DB (critical) |

With rotation in dev/prod.

---

## **1️⃣4️⃣ Hybrid ENUM \+ Lookup Strategy**

### **Newly Locked**

System uses:

* ENUM → Stable system states

* LOOKUP → Business-configurable data

Purpose:

* Performance \+ flexibility balance

---

## **1️⃣5️⃣ Resume Request Reviewer Notes**

### **Newly Added**

Resume decisions include:

`review_note`

Purpose:

* Transparency

* Appeal support

* Accountability

---

## **1️⃣6️⃣ Separation of Violation Event, Proof, and Impact**

### **Newly Formalized**

Violation system is 4-layered:

1. Definitions (violation\_types)

2. Events (violations)

3. Proof (evidences)

4. Impact (risk\_snapshots)

Purpose:

* Clean architecture

* Avoid duplication

* Forensic clarity

---

## **1️⃣7️⃣ Evidence Immutability Enforcement**

### **Newly Emphasized**

Once stored:

* Evidence cannot be modified

* Only referenced

* Hash-verified

Purpose:

* Legal defensibility

---

## **1️⃣8️⃣ Production vs Development Logging Policy**

### **Newly Clarified**

Different verbosity by environment.

Dev:

* Console \+ File

Prod:

* File \+ Alerting

Audit always in DB.

