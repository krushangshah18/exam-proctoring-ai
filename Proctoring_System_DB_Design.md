# **Database Design Specification**

## **AI-Based Intelligent Online Exam Proctoring System**

---

## **1\. Purpose of This Document**

This document defines the complete database design for the AI-Based Intelligent Online Exam Proctoring System. It explains each table, every field, their purpose, and how they are used within the system.

This document serves as the authoritative reference for backend development, audits, debugging, reporting, and system maintenance.

---

## **2\. Design Principles**

### **2.1 Core Principles**

* No data loss: Critical data is never hard-deleted  
* Full traceability: All actions are auditable  
* Explainability: All decisions are reconstructable  
* Security-first: Sensitive data is protected  
* Scalability: Schema supports multi-exam and multi-user load  
* Integrity: Evidence and records are immutable

### **2.2 Key Policies**

* All major tables use UUID primary keys  
* Soft deletion is used instead of hard deletion  
* All records are timestamped  
* Foreign key constraints are enforced  
* Evidence files are stored externally

---

## **3\. Primary Entities Overview**

The system is built around the following core entities:

* Users  
* Exams  
* Exam Invites  
* Exam Sessions  
* Devices  
* Violations  
* Evidence  
* Risk History  
* Resume Requests  
* Audit Logs  
* System Logs  
* AI Verifications

---

## **4\. Users Table**

### **Table: users**

Stores all registered platform users.

| Field | Type | Description |
| ----- | ----- | ----- |
| id | UUID | Primary identifier |
| name | String | Name of user |
| email | VARCHAR | Login credential |
| password\_hash | TEXT | Encrypted password |
| role | ENUM | STUDENT / ADMIN / SYSADMIN |
| profile\_image\_path | TEXT | Path to selfie image |
| face\_embedding | BYTEA | Face vector data |
| is\_active | BOOLEAN | Account status |
| is\_deleted | BOOLEAN | Soft delete flag |
| created\_at | TIMESTAMP | Account creation time |
| last\_login | TIMESTAMP | Last login time |
| deleted\_at | TIMESTAMP | Soft delete time |

#### **Usage**

* Authentication  
* Authorization  
* Identity verification  
* Audit tracking

---

## **5\. Exams Table**

### **Table: exams**

Stores all exam definitions.

| Field | Type | Description |
| ----- | ----- | ----- |
| id | UUID | Primary key |
| title | VARCHAR | Exam name |
| created\_by | UUID | Admin creator |
| exam\_mode | ENUM | FLEXIBLE / FIXED |
| start\_window | TIMESTAMP | Start window |
| end\_window | TIMESTAMP | End window |
| duration\_minutes | INT | Exam duration |
| hard\_join\_deadline | TIMESTAMP | Join cutoff |
| flag\_threshold | INT | Flag risk score |
| terminate\_threshold | INT | Termination score |
| late\_join\_policy | ENUM | ALLOW / REVIEW / DENY |
| allow\_late\_extension | BOOLEAN | Extension permission |
| max\_late\_minutes | INT | Max late allowance |
| config | JSONB | Monitoring options |
| status | ENUM | DRAFT / LIVE / ENDED |
| created\_at | TIMESTAMP | Creation time |

#### **Usage**

* Exam scheduling  
* Monitoring configuration  
* Risk policy enforcement

---

## **6\. Exam Invites Table**

### **Table: exam\_invites**

Controls secure exam access.

| Field | Type | Description |
| ----- | ----- | ----- |
| id | UUID | Primary key |
| exam\_id | UUID | Related exam |
| student\_email | VARCHAR | Invitee |
| token | TEXT | Access token |
| expires\_at | TIMESTAMP | Expiry time |
| used | BOOLEAN | Reuse prevention |
| created\_at | TIMESTAMP | Creation time |

#### **Usage**

* Secure exam access  
* Prevent link sharing  
* Invitation validation

---

## **7\. Exam Sessions Table**

### **Table: exam\_sessions**

Represents a student’s participation in an exam.

| Field | Type | Description |
| ----- | ----- | ----- |
| id | UUID | Primary key |
| user\_id | UUID | Student |
| exam\_id | UUID | Exam |
| status | ENUM | CREATED / ACTIVE / ENDED / TERMINATED |
| start\_time | TIMESTAMP | Session start |
| end\_time | TIMESTAMP | Session end |
| risk\_score | INT | Current risk |
| last\_heartbeat | TIMESTAMP | Network tracking |
| terminated\_reason | TEXT | Termination explanation |
| terminated\_by | ENUM | SYSTEM / ADMIN |
| created\_at | TIMESTAMP | Creation time |

#### **Usage**

* Session lifecycle management  
* Risk monitoring  
* Disconnection handling

---

## **8\. Session Devices Table**

### **Table: session\_devices**

Tracks device and browser information.

| Field | Type | Description |
| ----- | ----- | ----- |
| id | UUID | Primary key |
| session\_id | UUID | Exam session |
| fingerprint | TEXT | Browser fingerprint |
| ip\_address | INET | Network address |
| user\_agent | TEXT | Browser info |
| created\_at | TIMESTAMP | Creation time |

#### **Usage**

* Dual device detection  
* Proxy prevention  
* Security auditing

---

## **9\. Violation Types Table**

### **Table: violation\_types**

Defines violation categories.

| Field | Type | Description |
| ----- | ----- | ----- |
| id | UUID | Primary key |
| code | VARCHAR | System identifier |
| name | VARCHAR | Display name |
| severity | ENUM | LOW / MEDIUM / HIGH |
| default\_score | INT | Risk points |
| default\_message | TEXT | Default alert |
| is\_active | BOOLEAN | Availability |
| created\_at | TIMESTAMP | Creation time |

#### **Usage**

* Centralized scoring  
* Configurable violation rules

---

## **10\. Violations Table**

### **Table: violations**

Stores individual suspicious events.

| Field | Type | Description |
| ----- | ----- | ----- |
| id | UUID | Primary key |
| session\_id | UUID | Related session |
| violation\_type\_id | UUID | Violation reference |
| client\_confidence | FLOAT | Client AI score |
| server\_confidence | FLOAT | Server AI score |
| final\_verdict | ENUM | CONFIRMED / REVIEW / REJECTED |
| occurred\_at | TIMESTAMP | Event time |
| created\_at | TIMESTAMP | Record time |

#### **Usage**

* Cheating detection  
* AI verification  
* Appeal handling

---

## **11\. Evidence Table**

### **Table: evidences**

Stores proof files for violations.

| Field | Type | Description |
| ----- | ----- | ----- |
| id | UUID | Primary key |
| violation\_id | UUID | Parent violation |
| file\_path | TEXT | Storage path |
| file\_hash | TEXT | Integrity hash |
| mime\_type | VARCHAR | File type |
| created\_at | TIMESTAMP | Creation time |

#### **Usage**

* Proof storage  
* Forensic review  
* Tamper detection

---

## **12\. Risk Snapshots Table**

### **Table: risk\_snapshots**

Maintains risk score history.

| Field | Type | Description |
| ----- | ----- | ----- |
| id | UUID | Primary key |
| session\_id | UUID | Related session |
| risk\_score | INT | Total score |
| trigger\_violation\_id | UUID | Cause violation |
| reason | TEXT | Explanation |
| created\_at | TIMESTAMP | Snapshot time |

#### **Usage**

* Score explanation  
* Timeline reconstruction  
* Admin review

---

## **13\. Resume Requests Table**

### **Table: resume\_requests**

Handles reconnection approvals.

| Field | Type | Description |
| ----- | ----- | ----- |
| id | UUID | Primary key |
| session\_id | UUID | Exam session |
| reason | TEXT | Student explanation |
| status | ENUM | PENDING / APPROVED / DENIED |
| reviewed\_by | UUID | Admin reviewer |
| review\_note | TEXT | Decision reasoning |
| created\_at | TIMESTAMP | Creation time |

#### **Usage**

* Fair resume handling  
* Transparency  
* Appeal support

---

## **14\. Termination Reasons Table**

### **Table: termination\_reasons**

Standardizes termination causes.

| Field | Type | Description |
| ----- | ----- | ----- |
| id | UUID | Primary key |
| code | VARCHAR | Identifier |
| description | TEXT | Reason detail |
| is\_active | BOOLEAN | Availability |
| created\_at | TIMESTAMP | Creation time |

#### **Usage**

* Structured termination reporting  
* Analytics  
* Policy enforcement

---

## **15\. Audit Logs Table**

### **Table: audit\_logs**

Stores critical user actions.

| Field | Type | Description |
| ----- | ----- | ----- |
| id | UUID | Primary key |
| actor\_id | UUID | Action performer |
| action | TEXT | Operation |
| target | TEXT | Affected entity |
| ip\_address | INET | Source IP |
| created\_at | TIMESTAMP | Event time |

#### **Usage**

* Compliance  
* Security investigations  
* Accountability

---

## **16\. Model Verifications Table**

### **Table: model\_verifications**

Stores backend AI validation results.

| Field | Type | Description |
| ----- | ----- | ----- |
| id | UUID | Primary key |
| violation\_id | UUID | Related violation |
| model\_name | VARCHAR | AI model |
| model\_version | VARCHAR | Version |
| confidence | FLOAT | Detection score |
| verdict | ENUM | PASS / FAIL |
| created\_at | TIMESTAMP | Creation time |

#### **Usage**

* False positive reduction  
* Appeal support  
* AI accountability

---

## **17\. Data Retention Policy**

* User accounts: Retained  
* Exam records: Permanent  
* Evidence files: Archived  
* Logs: Rotated and archived

---

## **18\. Change Management**

All schema changes must be implemented using Alembic migrations.

Direct database modification is prohibited.

All changes must be documented and reviewed.

---

## **19\. Success Metrics**

* **Zero orphaned records**  
* **Complete audit trails**  
* **Explainable violations**  
* **Stable performance**  
* **Secure data handling**

