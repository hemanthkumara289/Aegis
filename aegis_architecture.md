# Aegis — Adaptive Authentication & Approval Platform
## Architecture Blueprint · Planning Document · v2.1

> **Status:** Planning only — no files created. Awaiting explicit approval to begin implementation.

---

## Table of Contents

1. [What Changed from v2.0](#1-what-changed-from-v20)
2. [Project Structure](#2-project-structure)
3. [Package Responsibilities & Dependency Rules](#3-package-responsibilities--dependency-rules)
4. [Core Domain Model](#4-core-domain-model)
5. [Database Schema & Flyway Migrations](#5-database-schema--flyway-migrations)
6. [OTP Design — Low-Entropy Analysis & Keyed Verification](#6-otp-design--low-entropy-analysis--keyed-verification)
7. [Token Lifecycle — Access, Refresh, Family Tracking & Revocation](#7-token-lifecycle--access-refresh-family-tracking--revocation)
8. [Device Fingerprints as Risk Signals Only](#8-device-fingerprints-as-risk-signals-only)
9. [Approval Engine — Responsibilities, State Machine & Execution Gate](#9-approval-engine--responsibilities-state-machine--execution-gate)
10. [Audit Integrity — HMAC Chain: Guarantees & Honest Limitations](#10-audit-integrity--hmac-chain-guarantees--honest-limitations)
11. [REST API Contracts](#11-rest-api-contracts)
12. [Testing Strategy](#12-testing-strategy)
13. [Threat Model & Mitigations](#13-threat-model--mitigations)
14. [Phased Roadmap — Implementation Milestones](#14-phased-roadmap--implementation-milestones)
15. [End-to-End Demonstration](#15-end-to-end-demonstration)
16. [Remaining Design Decisions](#16-remaining-design-decisions)

---

## 1. What Changed from v2.0

| Area | v2.0 | v2.1 |
|------|------|------|
| **Refresh reuse handling** | Revoke ALL user sessions on any reuse | Token-family tracking: revoke the compromised family only |
| **Sequence gap wording** | Gaps "indicate potential deletion" | Gaps are a suspicious signal only; MVCC rollbacks also cause gaps |
| **HMAC chain table** | Overclaims detection of sequence gaps | Restated: chain detects modification/deletion of rows it has covered; gaps are a separate heuristic |
| **Simulated action model** | "Simulated action" in the same transaction with no further explanation | Explicitly modelled as a structured log record; transaction semantics stated; future real actions require outbox/saga |
| **Execution token delivery** | Alice submits `execution_token` to `/execute` — delivery mechanism undefined | Token is internal-only; Alice calls `/execute` as authenticated requester; server validates everything |
| **OTP challenge flow** | `/auth/otp/send` exists as a separate public endpoint AND login triggers OTP — contradictory | Unified: login triggers OTP; `challengeId = OtpRecord.id` returned; `/otp/send` removed |
| **OtpRecord binding** | No session or challenge binding | `login_session_token` nonce added to `OtpRecord`; links the OTP challenge to the specific login attempt |
| **Audit DB role** | Unresolved: two DataSource beans vs. trigger | Resolved: trigger approach chosen for Phase 1 |
| **Milestone count** | 6 coarse milestones | 9 smaller milestones, each ~2–5 hours for a solo developer |
| **Contradiction inventory** | Not documented | Section 1 lists all contradictions resolved |

### 1.1 All Contradictions Resolved

| # | Contradiction | Resolution |
|---|--------------|-----------|
| C1 | `/auth/otp/send` (separate endpoint) conflicts with login-triggered OTP | Removed `/auth/otp/send`. Login always triggers OTP. `challengeId` is the returned `OtpRecord.id`. |
| C2 | `challengeId` returned by login but no column in `OtpRecord` maps to it | `OtpRecord.id` is the `challengeId`. Verify endpoint accepts `{ challengeId, code }`. |
| C3 | OTP verification is not bound to a specific login attempt | `login_nonce` (random token, hashed) added to `OtpRecord`; included in HMAC binding; returned to client with `challengeId` |
| C4 | `execution_token` must be submitted by Alice but no delivery mechanism defined | Token is internal. Alice calls `POST .../execute` as the authenticated requester. No token is transmitted. |
| C5 | Step 12 of E2E demo shows Alice submitting `execution_token` | Updated: Alice calls `/execute`; no token in request body. |
| C6 | Sequence gaps stated as proof of row deletion | Restated as a suspicious signal; MVCC transaction rollbacks also cause gaps in `BIGSERIAL`. |
| C7 | Simulated action inside a DB transaction with no model for real future actions | Phase 1: structured in-transaction log record. Future phases: outbox pattern with idempotent external call. |
| C8 | Two-DataSource vs. trigger for audit isolation — left unresolved | Decided: single `aegis_app` role + PostgreSQL trigger that raises an exception on `UPDATE` or `DELETE` of `audit_log`. Simpler; catches accidental app-level writes. |
| C9 | Threat table says "Refresh token theft → all sessions revoked" | Updated to "compromised family revoked". |
| C10 | `UNIQUE(user_id, fingerprint_hash)` on DeviceRecord: if a user deletes and re-enrols the same device, the constraint must allow re-insertion | Constraint changed to unique on `(user_id, fingerprint_hash)` with soft-delete semantics: `deleted_at` column; active records only are unique via partial index. |

---

## 2. Project Structure

### 2.1 Single Spring Boot Module — Rationale (unchanged from v2.0)

One Spring Boot application with package-level boundaries enforced by ArchUnit. Maven multi-module extraction is a mechanical future step requiring no redesign.

### 2.2 Directory Layout

```
Aegis/
├── docker-compose.yml            # PostgreSQL 16 + MailHog
├── .env.example                  # All required env vars; safe defaults for local dev
├── README.md
│
├── aegis-backend/
│   ├── pom.xml
│   ├── mvnw / mvnw.cmd
│   └── src/
│       ├── main/
│       │   ├── java/com/aegis/
│       │   │   ├── AegisApplication.java
│       │   │   ├── common/
│       │   │   │   ├── exception/     # AegisException, ErrorCode enum, GlobalExceptionHandler
│       │   │   │   ├── api/           # ApiResponse<T>, PageResponse<T>, ErrorResponse
│       │   │   │   ├── validation/    # @StrongPassword, @SafeString validators
│       │   │   │   ├── crypto/        # SecureTokenGenerator, ConstantTimeComparison
│       │   │   │   └── clock/         # ClockProvider (injectable Clock)
│       │   │   ├── config/
│       │   │   │   ├── SecurityConfig.java
│       │   │   │   ├── JpaConfig.java
│       │   │   │   ├── MailConfig.java
│       │   │   │   └── RateLimitConfig.java
│       │   │   ├── identity/
│       │   │   │   ├── domain/        # User, Role, Permission, Organization
│       │   │   │   ├── repository/
│       │   │   │   ├── service/       # UserService, RoleService
│       │   │   │   ├── dto/
│       │   │   │   └── api/           # UserController, RoleController
│       │   │   ├── auth/
│       │   │   │   ├── domain/        # Session, OtpRecord, RecoveryCode
│       │   │   │   ├── repository/
│       │   │   │   ├── service/       # AuthService, OtpService, TokenService, RecoveryService
│       │   │   │   ├── filter/        # JwtAuthenticationFilter
│       │   │   │   ├── dto/
│       │   │   │   └── api/           # AuthController
│       │   │   ├── device/
│       │   │   │   ├── domain/        # DeviceRecord
│       │   │   │   ├── repository/
│       │   │   │   ├── service/       # DeviceService
│       │   │   │   ├── dto/
│       │   │   │   └── api/           # DeviceController
│       │   │   ├── risk/
│       │   │   │   ├── domain/        # RiskAssessment
│       │   │   │   ├── signal/        # IpSignal, DeviceSignal, VelocitySignal
│       │   │   │   ├── engine/        # RiskEngine
│       │   │   │   ├── service/       # RiskAssessmentService
│       │   │   │   └── dto/
│       │   │   ├── authz/
│       │   │   │   ├── service/       # AuthorizationService, PermissionEvaluator
│       │   │   │   └── dto/
│       │   │   ├── approval/
│       │   │   │   ├── domain/        # ApprovalRequest, ApprovalDecision, ApprovalPolicy
│       │   │   │   ├── statemachine/  # ApprovalStateMachine
│       │   │   │   ├── repository/
│       │   │   │   ├── service/       # ApprovalRequestService, ApprovalDecisionService,
│       │   │   │   │                  # ApprovalExecutionService, PolicyService
│       │   │   │   ├── scheduler/     # DeadlineExpirationJob
│       │   │   │   ├── dto/
│       │   │   │   └── api/           # ApprovalController
│       │   │   └── audit/
│       │   │       ├── domain/        # AuditLog
│       │   │       ├── repository/
│       │   │       ├── service/       # AuditService (write), AuditQueryService (read)
│       │   │       ├── integrity/     # HmacChainVerifier
│       │   │       ├── dto/
│       │   │       └── api/           # AuditController
│       │   └── resources/
│       │       ├── application.yml
│       │       ├── application-local.yml
│       │       └── db/migration/      # V1__... through V14__...
│       └── test/java/com/aegis/
│           ├── common/                # TestFixtures, IntegrationTestBase
│           ├── identity/
│           ├── auth/
│           ├── approval/
│           ├── audit/
│           └── security/              # Cross-cutting negative security tests
│
└── aegis-frontend/                   # React + TypeScript + Vite + Tailwind
    ├── vite.config.ts
    ├── tailwind.config.ts
    └── src/
        ├── main.tsx
        ├── App.tsx
        ├── api/                       # Axios client, typed hooks
        ├── auth/                      # AuthContext, ProtectedRoute
        ├── pages/
        └── types/
```

---

## 3. Package Responsibilities & Dependency Rules

| Package | Responsibility | May call | Must NOT call |
|---------|---------------|----------|---------------|
| `common` | Utilities, DTOs, exceptions, clock | — | Any feature package |
| `config` | Spring beans only | `common` | Feature packages directly |
| `identity` | User/role/org CRUD | `common` | `auth`, `approval`, `audit` |
| `auth` | Login, logout, OTP, JWT, refresh, recovery | `common`, `identity`, `device`, `audit` | `approval`, `authz`, `risk` |
| `device` | Device record lifecycle | `common`, `identity` | `auth`, `approval` |
| `risk` | Signal collection, scoring | `common`, `identity`, `device` | `auth`, `approval` |
| `authz` | Permission evaluation | `common`, `identity` | `approval`, `risk`, `auth` |
| `approval` | Policy, request, decision, execution | `common`, `identity`, `authz`, `risk`, `audit` | `auth` |
| `audit` | Write and read audit events | `common`, `identity` | `approval`, `auth`, `risk` |

**ArchUnit rules fail the build if violated.** Treat them as compilation checks, not optional warnings.

---

## 4. Core Domain Model

### 4.1 Identity

```
User
  id              UUID PK DEFAULT gen_random_uuid()
  email           TEXT UNIQUE NOT NULL
  display_name    TEXT NOT NULL
  password_hash   TEXT NOT NULL         -- BCrypt(cost=12)
  status          TEXT NOT NULL DEFAULT 'ACTIVE'
                  -- 'ACTIVE' | 'LOCKED' | 'SUSPENDED' | 'DELETED'
  failed_attempts INT NOT NULL DEFAULT 0
  locked_until    TIMESTAMPTZ           -- null = not locked
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
  version         BIGINT NOT NULL DEFAULT 0  -- JPA @Version

Organization
  id              UUID PK
  name            TEXT UNIQUE NOT NULL
  status          TEXT NOT NULL DEFAULT 'ACTIVE'
  created_at      TIMESTAMPTZ NOT NULL

Role
  id              UUID PK
  name            TEXT NOT NULL
  org_id          UUID FK → Organization (null = platform-global)
  UNIQUE(name, org_id)

Permission
  id              UUID PK
  code            TEXT UNIQUE NOT NULL   -- e.g. "approval:decide", "audit:read"
  description     TEXT

user_roles (user_id UUID, role_id UUID, granted_by UUID, granted_at TIMESTAMPTZ)
  PK(user_id, role_id)
role_permissions (role_id UUID, permission_id UUID)
  PK(role_id, permission_id)
```

### 4.2 Authentication

```
Session
  id                  UUID PK
  user_id             UUID FK → User NOT NULL
  family_id           UUID NOT NULL          -- token-family ID; see Section 7.2
  refresh_token_hash  TEXT UNIQUE NOT NULL   -- SHA-256(raw refresh token)
  ip_address          INET
  user_agent          TEXT
  issued_at           TIMESTAMPTZ NOT NULL
  expires_at          TIMESTAMPTZ NOT NULL   -- refresh token expiry (7 days)
  last_refreshed_at   TIMESTAMPTZ
  revoked_at          TIMESTAMPTZ            -- null = active
  revocation_reason   TEXT
    -- 'USER_LOGOUT' | 'ADMIN_REVOKE' | 'FAMILY_REUSE_DETECTED' | 'LOGOUT_ALL'
  -- Access tokens are NOT stored; validated by JWT signature + expiry alone.

OtpRecord
  id                  UUID PK               -- this IS the challengeId returned to the client
  user_id             UUID FK → User NOT NULL
  purpose             TEXT NOT NULL
    -- 'LOGIN_MFA' | 'PASSWORD_RESET' | 'STEP_UP' | 'DEVICE_VERIFY'
  login_nonce_hash    TEXT                  -- SHA-256(random nonce); null for non-login purposes
    -- Ties this OTP challenge to the specific login attempt. See Section 6.5.
  otp_hmac            TEXT NOT NULL
    -- HMAC-SHA256(AEGIS_OTP_HMAC_KEY, userId|purpose|code|issuedAtEpochMs)
  channel             TEXT NOT NULL DEFAULT 'EMAIL'
  issued_at           TIMESTAMPTZ NOT NULL
  expires_at          TIMESTAMPTZ NOT NULL   -- issued_at + 10 minutes
  attempt_count       INT NOT NULL DEFAULT 0
  max_attempts        INT NOT NULL DEFAULT 5
  used_at             TIMESTAMPTZ            -- null = not yet consumed

RecoveryCode
  id                  UUID PK
  user_id             UUID FK → User NOT NULL
  code_hash           TEXT NOT NULL          -- BCrypt(12) of 12-char alphanumeric code
  used_at             TIMESTAMPTZ
  created_at          TIMESTAMPTZ NOT NULL
  -- 10 codes generated at registration; each usable exactly once
```

### 4.3 Device

```
DeviceRecord
  id                  UUID PK
  user_id             UUID FK → User NOT NULL
  fingerprint_hash    TEXT NOT NULL          -- SHA-256 of client-submitted fingerprint string
  label               TEXT                   -- user-assigned label
  first_seen_at       TIMESTAMPTZ NOT NULL
  last_seen_at        TIMESTAMPTZ NOT NULL
  seen_count          INT NOT NULL DEFAULT 1
  user_notified       BOOLEAN NOT NULL DEFAULT FALSE
  deleted_at          TIMESTAMPTZ            -- soft-delete; allows re-enrolment after removal

UNIQUE INDEX uq_device_active (user_id, fingerprint_hash) WHERE deleted_at IS NULL
  -- Prevents duplicate active records; allows the same fingerprint to be re-added after deletion.
```

### 4.4 Risk Assessment

```
RiskAssessment
  id                  UUID PK
  user_id             UUID FK → User NOT NULL
  session_id          UUID                   -- may be null (pre-login assessment)
  context             TEXT NOT NULL
    -- 'LOGIN' | 'ACTION_REQUEST' | 'STEP_UP'
  ip_address          INET
  fingerprint_hash    TEXT                   -- client-supplied; not verified as genuine
  signals             JSONB NOT NULL         -- { "new_device": true, "unusual_hour": false, ... }
  score               INT NOT NULL           -- 0 = lowest risk, 100 = critical
  level               TEXT NOT NULL          -- 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  explanation         TEXT NOT NULL          -- human-readable; included in audit payload
  evaluated_at        TIMESTAMPTZ NOT NULL
```

### 4.5 Approval

```
ApprovalPolicy
  id                  UUID PK
  name                TEXT NOT NULL
  action_code         TEXT NOT NULL          -- e.g. "sim_wire_transfer"
  policy_type         TEXT NOT NULL          -- 'SINGLE_APPROVER' | 'QUORUM'
  quorum_required     INT                    -- null unless QUORUM
  eligible_roles      TEXT[]                 -- empty = any user with approval:decide
  deadline_minutes    INT NOT NULL DEFAULT 60
  sod_enforced        BOOLEAN NOT NULL DEFAULT TRUE
  max_risk_level      TEXT                   -- null = no ceiling; 'HIGH' = block if CRITICAL
  org_id              UUID FK → Organization NOT NULL
  active              BOOLEAN NOT NULL DEFAULT TRUE
  created_at          TIMESTAMPTZ NOT NULL
  version             BIGINT NOT NULL DEFAULT 0

ApprovalRequest
  id                  UUID PK
  policy_id           UUID FK → ApprovalPolicy NOT NULL
  policy_snapshot     JSONB NOT NULL         -- immutable copy of full policy at creation time
  requester_id        UUID FK → User NOT NULL
  action_code         TEXT NOT NULL          -- copied from policy at creation; immutable
  action_description  TEXT NOT NULL          -- human-readable; shown to approver
  action_payload      JSONB NOT NULL         -- specific action parameters
  action_payload_hash TEXT NOT NULL          -- SHA-256(canonical JSON of action_payload)
  idempotency_key     TEXT UNIQUE NOT NULL   -- caller-supplied; DB-level duplicate prevention
  status              TEXT NOT NULL DEFAULT 'PENDING'
    -- 'PENDING' | 'APPROVED' | 'REJECTED' | 'CANCELLED' | 'EXPIRED'
  risk_assessment_id  UUID FK → RiskAssessment
  deadline_at         TIMESTAMPTZ NOT NULL
  resolved_at         TIMESTAMPTZ
  executed_at         TIMESTAMPTZ            -- set when action is performed
  internal_exec_token TEXT UNIQUE            -- internal only; NEVER returned via API
    -- Generated on APPROVED; nulled atomically with executed_at on execution.
    -- Purpose: DB-level one-time idempotency guard.
  created_at          TIMESTAMPTZ NOT NULL
  version             BIGINT NOT NULL DEFAULT 0

ApprovalDecision
  id                  UUID PK
  request_id          UUID FK → ApprovalRequest NOT NULL
  approver_id         UUID FK → User NOT NULL
  decision            TEXT NOT NULL          -- 'APPROVED' | 'REJECTED'
  comment             TEXT
  decided_at          TIMESTAMPTZ NOT NULL
  UNIQUE(request_id, approver_id)            -- one vote per approver; DB enforced
```

**Field renamed:** `execution_token` → `internal_exec_token`. The `internal_` prefix is a constant reminder that this column is never serialized into any API response or DTO.

### 4.6 Audit

```
AuditLog
  id              UUID PK
  sequence_no     BIGSERIAL NOT NULL     -- used as a gap-detection heuristic; see Section 10
  event_type      TEXT NOT NULL          -- e.g. 'AUTH.LOGIN_SUCCESS', 'APPROVAL.DECIDED'
  severity        TEXT NOT NULL          -- 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL'
  actor_id        UUID                   -- null for scheduler/system events
  target_id       UUID
  target_type     TEXT
  org_id          UUID
  session_id      UUID
  ip_address      INET
  payload         JSONB NOT NULL         -- sanitized; NO passwords, OTP codes, or raw tokens
  prior_hash      TEXT NOT NULL          -- entry_hash of the previous row (or genesis sentinel)
  entry_hash      TEXT NOT NULL          -- HMAC-SHA256(key, prior_hash || fixed_fields)
  created_at      TIMESTAMPTZ NOT NULL
  -- Protected by trigger: UPDATE and DELETE on this table raise an exception.
```

---

## 5. Database Schema & Flyway Migrations

### 5.1 Migration Sequence

```
V1__create_organizations.sql
V2__create_users.sql
V3__create_roles_and_permissions.sql
V4__create_sessions.sql
V5__create_otp_records.sql
V6__create_recovery_codes.sql
V7__create_device_records.sql
V8__create_risk_assessments.sql
V9__create_approval_policies.sql
V10__create_approval_requests.sql
V11__create_approval_decisions.sql
V12__create_audit_log.sql
V13__create_audit_trigger.sql      ← new: trigger prevents UPDATE/DELETE on audit_log
V14__create_indexes.sql
V15__seed_default_roles_and_permissions.sql
```

### 5.2 Audit Protection Trigger (V13)

```sql
CREATE OR REPLACE FUNCTION audit_log_protect()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_log rows are immutable. Operation: %', TG_OP;
END;
$$;

CREATE TRIGGER trg_audit_log_immutable
  BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_protect();
```

**Why a trigger rather than a separate database role:**
- A separate `aegis_audit_writer` role requires two `DataSource` beans, two connection pools, and careful routing of every audit write to the correct source. This adds meaningful complexity for a solo developer.
- The trigger catches accidental application-layer writes (including those from the standard `aegis_app` connection), which covers the practical risk.
- A determined DBA with superuser access can bypass the trigger — this is an acknowledged limitation documented in Section 10.

### 5.3 Schema Constraints Summary

| Constraint | Purpose |
|-----------|---------|
| All PKs: `UUID DEFAULT gen_random_uuid()` | Non-enumerable IDs in URLs |
| All timestamps: `TIMESTAMPTZ` | UTC in DB always |
| `Session.family_id` | Token-family grouping for scoped reuse revocation |
| `OtpRecord.login_nonce_hash` | Ties challenge to the specific login attempt |
| `ApprovalRequest.idempotency_key UNIQUE` | Duplicate submission rejected at DB level |
| `ApprovalDecision UNIQUE(request_id, approver_id)` | Double-voting rejected at DB level |
| Partial index on `DeviceRecord(user_id, fingerprint_hash) WHERE deleted_at IS NULL` | Allows re-enrolment; prevents active duplicates |
| `AuditLog.internal_exec_token` column does not exist | The column is on `ApprovalRequest`, not `AuditLog` |
| Audit trigger | `UPDATE`/`DELETE` on `audit_log` raises an exception |
| `@Version` columns | JPA optimistic locking on `User`, `ApprovalRequest`, `ApprovalPolicy` |

### 5.4 Indexes (V14)

```sql
CREATE INDEX idx_sessions_user_id          ON sessions(user_id);
CREATE INDEX idx_sessions_family_id        ON sessions(family_id);
CREATE INDEX idx_sessions_token_hash       ON sessions(refresh_token_hash);
CREATE INDEX idx_otp_records_user_purpose  ON otp_records(user_id, purpose)
  WHERE used_at IS NULL;
CREATE INDEX idx_approval_requests_requester     ON approval_requests(requester_id);
CREATE INDEX idx_approval_requests_pending       ON approval_requests(status, deadline_at)
  WHERE status = 'PENDING';
CREATE INDEX idx_approval_decisions_request_id   ON approval_decisions(request_id);
CREATE INDEX idx_audit_log_actor                 ON audit_log(actor_id, created_at DESC);
CREATE INDEX idx_audit_log_event_type            ON audit_log(event_type, created_at DESC);
CREATE INDEX idx_audit_log_sequence              ON audit_log(sequence_no);
```

---

## 6. OTP Design — Low-Entropy Analysis & Keyed Verification

*(Unchanged from v2.0 except for the login flow clarification in Section 6.5)*

### 6.1 The Low-Entropy Problem

A 6-digit numeric OTP has exactly 1,000,000 possible values. Security depends on **all five controls together**:

1. Short TTL (10 minutes)
2. Attempt limit (5 attempts; lock thereafter)
3. Purpose binding (a LOGIN OTP cannot satisfy STEP_UP)
4. Single use (`used_at` set on first valid verification)
5. Endpoint rate limiting (Bucket4j; independent of attempt_count)

With 5 attempts in a 10-minute window: probability of a correct guess = 5/1,000,000 = 0.0005%. Acceptable for MFA where the attacker must also have the primary password.

### 6.2 Why Not BCrypt for OTPs

- An attacker can pre-compute all 1,000,000 BCrypt(cost=12) values offline in minutes. The database is not protected by bcrypt's slowness here — the endpoint is the attack surface.
- BCrypt's cost makes the verification endpoint itself a denial-of-service target.
- HMAC-SHA256 verification takes microseconds; security comes from key secrecy, not computation time.

### 6.3 HMAC-SHA256 Keyed Verification

```
stored_hmac = HMAC-SHA256(
    key = AEGIS_OTP_HMAC_KEY,          -- 256-bit, environment-only
    msg = userId | "|" | purpose | "|" | rawCode | "|" | issuedAtEpochMs
)
```

**Bindings in the message prevent:**
- `issuedAtEpochMs` → reuse of a differently-timed OTP with the same digits
- `purpose` → cross-purpose replay (LOGIN code used for STEP_UP)
- `userId` → cross-user replay even if the key leaks

### 6.4 OTP Lifecycle

```
Issue:
  1. Invalidate any existing unused OtpRecord for (user_id, purpose)
  2. Generate 6-digit code with SecureRandom
  3. Compute stored_hmac; generate login_nonce (for LOGIN_MFA purpose only)
  4. Persist OtpRecord (id = challengeId; expires_at = now + 10 min)
  5. Send code via email (MailHog in dev)
  6. If delivery fails → return 503 with Retry-After; do NOT persist OtpRecord

Verify:
  1. Look up OtpRecord WHERE id = challengeId AND user_id matches login_nonce
  2. If not found → 401
  3. If expires_at ≤ NOW() → mark used; return 410 Gone
  4. Atomically: attempt_count = attempt_count + 1 (prevents TOCTOU on attempt limit)
  5. If attempt_count > max_attempts → return 429
  6. Compute candidate HMAC; constant-time compare
  7. On match: SET used_at = NOW(); proceed
  8. On mismatch: return 401 with { remainingAttempts }
```

### 6.5 Login Challenge Binding (Resolves C1–C3)

**Problem in v2.0:** The login endpoint triggers OTP issuance but returned `challengeId` with no schema backing. Additionally, `/auth/otp/send` as a public endpoint allows an attacker to trigger OTPs independently of login.

**v2.1 resolution:**

- `/auth/otp/send` is **removed** from the public API.
- `POST /auth/login` verifies the password, then automatically issues an OTP. It returns:
  ```json
  { "mfaRequired": true, "challengeId": "<OtpRecord.id>", "loginNonce": "<random token>" }
  ```
- `loginNonce` is a short-lived random token (UUID, 5-minute expiry) returned to the client in the login response body. It is stored hashed as `OtpRecord.login_nonce_hash`.
- `POST /auth/otp/verify` accepts `{ challengeId, loginNonce, code }`. The server verifies:
  - `challengeId` exists and belongs to an active `OtpRecord`
  - `SHA-256(loginNonce)` matches `OtpRecord.login_nonce_hash`
  - HMAC of the code matches
- This binds the OTP challenge to the specific login attempt. An attacker who independently obtains a valid code for a different challenge cannot use it here.
- **For non-login OTP purposes** (STEP_UP, PASSWORD_RESET): `login_nonce_hash` is null; verification uses only `challengeId` + code + the authenticated session.

---

## 7. Token Lifecycle — Access, Refresh, Family Tracking & Revocation

### 7.1 Design Principles

- **Access tokens are short-lived stateless JWTs.** Validated by signature + expiry only. Never stored in the database.
- **Refresh tokens are long-lived, opaque, and database-backed.** Can be explicitly revoked.
- **Every refresh token rotation issues a new token and invalidates the previous one.** Reuse of a rotated token is a theft indicator.
- **Reuse revokes only the compromised token family, not all user sessions.** A user with an active session on a trusted device is not logged out because a different browser/device was compromised.

### 7.2 Token-Family Tracking

A **token family** represents one logical session (e.g., one browser, one device). Every `Session` row carries a `family_id` (UUID). When a refresh token is rotated:
- A new `Session` row is inserted with the **same `family_id`** and a new `refresh_token_hash`.
- The old `Session` row is marked `revoked_at = NOW()`, `revocation_reason = 'ROTATED'`.

```
Session lifecycle for one family:

  family_id = F1

  Row 1: refresh_token_hash=H1, revoked_at=null          ← current
  -- client uses refresh token R1 →
  Row 1: revoked_at=now(), reason='ROTATED'               ← superseded
  Row 2: refresh_token_hash=H2, revoked_at=null           ← new current
  -- client uses refresh token R2 →
  Row 2: revoked_at=now(), reason='ROTATED'               ← superseded
  Row 3: refresh_token_hash=H3, revoked_at=null           ← new current
```

### 7.3 Reuse Detection and Scoped Revocation

```
On receiving a refresh token:
  1. Compute SHA-256(submitted_token) → hash
  2. Query Session WHERE refresh_token_hash = hash

  Case A: Found, revoked_at IS NULL (normal use)
    → Rotate: create new row in same family, revoke old row
    → Issue new access token and refresh token

  Case B: Found, revoked_at IS NOT NULL, reason = 'ROTATED'
    → This is a previously valid token being re-presented.
    → Token family F = session.family_id
    → Revoke ALL active sessions WHERE family_id = F
       (SET revoked_at = NOW(), reason = 'FAMILY_REUSE_DETECTED')
    → Write CRITICAL audit event: AUTH.REFRESH_FAMILY_REUSE_DETECTED
       { familyId: F, sessionId: session.id, reason: 'rotated_token_reused' }
    → Return 401

  Case C: Not found
    → The token is invalid, expired and cleaned up, or forged.
    → Return 401 (no session modification; no audit of user_id since we don't know it)

  Case D: Found, revoked_at IS NOT NULL, reason = 'USER_LOGOUT' or 'ADMIN_REVOKE'
    → Return 401 (already intentionally revoked)
```

**Why family-scoped and not all-sessions:**

| Scenario | All-sessions revocation | Family-scoped revocation |
|---------|------------------------|--------------------------|
| Attacker steals refresh token from laptop | Logs user out of phone, tablet, etc. | Only logs out the compromised device's session |
| Attacker steals token, uses it before victim | Both sessions invalidated; victim must re-auth | Compromised family revoked; victim's other sessions intact |
| Network retry delivers old token (client bug) | All sessions destroyed by a benign bug | Only the retrying session is affected |

**What family-scoped revocation does NOT prevent:** If the attacker steals the token *and rotates it before the legitimate client does*, the attacker now holds the current token. The legitimate client will present the old (rotated) token, triggering family revocation — which also revokes the attacker's session. This remains a contested state that only re-authentication resolves.

### 7.4 Token Specifications

| Property | Access Token | Refresh Token |
|----------|-------------|---------------|
| Format | Signed JWT (HS256, `AEGIS_JWT_SECRET`) | Opaque UUID (`SecureRandom`) |
| TTL | 15 minutes | 7 days |
| Server storage | None | SHA-256 hash in `sessions.refresh_token_hash` |
| Client storage | JavaScript memory (React context) | `HttpOnly; Secure; SameSite=Strict` cookie |
| Revocation | Not supported in Phase 1; 15-min expiry is the control | Immediate via `sessions.revoked_at` |
| Rotation | N/A | On every successful use |

### 7.5 JWT Claims

```json
{
  "sub": "user-uuid",
  "email": "alice@example.com",
  "orgId": "org-uuid",
  "roles": ["APPROVER"],
  "sessionId": "session-uuid",
  "familyId": "family-uuid",
  "iat": 1761385800,
  "exp": 1761386700
}
```

`familyId` is included so that the silent refresh client can detect if its family was revoked between two requests (future enhancement).

**NOT in JWT:** Permissions (evaluated fresh from DB on sensitive operations), risk level, device fingerprint.

### 7.6 Revocation Table

| Trigger | Scope | Reason stored |
|---------|-------|--------------|
| User logout | Current session only | `USER_LOGOUT` |
| Logout everywhere | All user sessions across all families | `LOGOUT_ALL` |
| Admin revoke | Specific session(s) | `ADMIN_REVOKE` |
| Token-family reuse detected | All sessions in the compromised family | `FAMILY_REUSE_DETECTED` |

### 7.7 Browser Storage Security

- **Access token: JavaScript memory only.** Lost on page refresh; silent refresh via cookie restores it. Never in `localStorage` or `sessionStorage` (XSS-accessible).
- **Refresh token: `HttpOnly; Secure; SameSite=Strict` cookie.** JavaScript cannot read it. `SameSite=Strict` prevents it being sent in cross-site navigations. `Secure` restricts to HTTPS in production (development uses `http://localhost` exception in browser).
- **CSRF:** The refresh endpoint uses a cookie, so a double-submit CSRF token is required. All other authenticated endpoints accept the JWT in `Authorization: Bearer <token>` header, which cannot be set by cross-origin requests.

---

## 8. Device Fingerprints as Risk Signals Only

*(Unchanged from v2.0 except soft-delete schema)*

A device fingerprint is self-reported, client-supplied data. It can be fabricated, copied, or changed by a browser update. It therefore cannot serve as proof of identity or grounds for automatic authorization.

**Device records inform only:**
- Risk score (new fingerprint seen for the first time → elevated signal)
- User notification ("we saw a new browser/device on your account")
- User-facing list of recognized devices in account settings

**Device records never:**
- Skip or reduce MFA requirements
- Reduce the required number of approvers
- Automatically authorize any sensitive action

Users may delete a device record (soft-delete via `deleted_at`). This causes the same fingerprint to be treated as new on next login, raising the risk signal again. It does **not** revoke sessions.

---

## 9. Approval Engine — Responsibilities, State Machine & Execution Gate

### 9.1 Separation of Responsibilities

```
Authentication   → proves who the caller is
Authorization    → proves what the caller is permitted to request
Approval         → obtains explicit, recorded consent from eligible approvers
Execution        → performs the sensitive action after all gates pass
Audit            → records every decision in tamper-evident form
```

These are strictly ordered. No gate may be skipped. An approved request does not execute automatically — the requester must explicitly invoke execution.

### 9.2 Approval State Machine

```
                         PENDING
                        (created)
                ┌──────────┼──────────┬──────────┐
          [approve]  [reject]   [cancel]    [expire-scheduler]
                ▼         ▼          ▼             ▼
           APPROVED  REJECTED   CANCELLED       EXPIRED

All four states are terminal. No further transitions are permitted from any terminal state.
```

### 9.3 Transition Guards

| Transition | Guards |
|-----------|--------|
| PENDING → APPROVED | `approval:decide` permission; eligible per policy roles; SOD (approver ≠ requester if enforced); has not previously voted; `deadline_at > NOW()` |
| PENDING → REJECTED | Same eligibility guards as APPROVED |
| PENDING → CANCELLED | Actor is the original requester OR has `approval:admin`; status is still PENDING |
| PENDING → EXPIRED | Scheduler only; no user interaction; `deadline_at < NOW()` |

### 9.4 Concurrency Controls

All concurrency controls are layered; no single control is the sole protection:

1. **`SELECT ... FOR UPDATE` on `ApprovalRequest`** — acquired at the start of every decision and execution transaction. Serializes concurrent operations on the same request row.
2. **JPA `@Version` optimistic locking** — catches any path that bypasses `SELECT FOR UPDATE`.
3. **`UNIQUE(request_id, approver_id)` on `ApprovalDecision`** — a DB-level final backstop if two concurrent decisions from the same approver both pass guard checks.
4. **State guard inside `@Transactional`** — `ApprovalStateMachine.assertCanTransition()` always called after the lock is acquired; throws on terminal status.
5. **`idempotency_key UNIQUE` on `ApprovalRequest`** — duplicate submission rejected at DB level before any business logic runs.

### 9.5 Execution Credentials — Issuance, Validation & Replay Prevention

#### Design choice: internal-only execution token (resolves C4, C5)

The v2.0 design required Alice to present an `execution_token` to the execute endpoint. This created two problems:
1. **Delivery gap:** no mechanism defined for how Alice receives the token.
2. **Confidentiality risk:** returning the token in `GET /approvals/requests/{id}` would expose it to anyone who can read the resource.

**v2.1 resolution:** The token is **internal-only**. It lives in `ApprovalRequest.internal_exec_token`, is never included in any DTO or API response, and is never transmitted to any client.

**Execution is authorized by:**
- The caller being the original `requester_id` (JWT `sub` claim matches)
- The request status being `APPROVED`
- `executed_at` being null
- The re-computed payload hash matching `action_payload_hash`
- `internal_exec_token` being non-null (proves this is an APPROVED request with token intact)

This is equivalent to a sealed envelope that only the server can see — the server issues it to itself and checks it internally.

#### Execution gate sequence

```
POST /api/v1/approvals/requests/{id}/execute
  (no request body required; Authorization: Bearer <access-token>)

1. Authenticate caller via JWT
2. Load ApprovalRequest WHERE id = {id} FOR UPDATE
3. Verify caller.userId == request.requester_id          → else 403
4. Verify request.status == 'APPROVED'                   → else 409 (wrong state)
5. Verify request.executed_at IS NULL                    → else 409 (already executed)
6. Verify request.internal_exec_token IS NOT NULL        → else 409 (internal integrity fault)
7. Re-compute SHA-256(canonical(request.action_payload))
   Compare to request.action_payload_hash               → mismatch: CRITICAL audit; 409
8. Execute the simulated action (see Section 9.6)
9. UPDATE ApprovalRequest SET
     executed_at         = NOW(),
     internal_exec_token = NULL
   WHERE id = {id} AND internal_exec_token IS NOT NULL   -- atomic guard
   If 0 rows updated → already executed by concurrent call → rollback → 409
10. Write audit event: APPROVAL.ACTION_EXECUTED
    { requestId, actionCode, actionDescription, actorId, payloadHash }
    -- internal_exec_token is NOT included in the audit payload
```

### 9.6 Simulated Action — Execution Model & Failure Recovery

#### What the simulated action is

For Phase 1, the "sensitive action" is a **structured log record** appended to the audit log inside the same database transaction as the execution gate. The action does not call any external service, does not modify any external state, and does not have side effects outside the database.

**Phase 1 simulated action record (written to `AuditLog`):**
```json
{
  "event_type": "ACTION.SIMULATED_EXECUTION",
  "severity": "INFO",
  "payload": {
    "action_code": "sim_wire_transfer",
    "action_description": "Simulated wire transfer of $5000 to Charlie",
    "action_payload_hash": "<sha256>",
    "simulated": true,
    "note": "No external system was contacted. This is a demonstration execution."
  }
}
```

#### Transaction semantics for Phase 1

```
┌─────────────────────────────────────────────────────────────────────┐
│  @Transactional                                                     │
│  1. SELECT ApprovalRequest FOR UPDATE                               │
│  2. All guard checks (steps 3–7 above)                              │
│  3. INSERT INTO audit_log (ACTION.SIMULATED_EXECUTION)              │
│  4. UPDATE ApprovalRequest SET executed_at=NOW(), token=NULL         │
│  5. INSERT INTO audit_log (APPROVAL.ACTION_EXECUTED)                │
│                                                                     │
│  If any step throws → entire transaction rolls back.                │
│  executed_at remains NULL → execution can be safely retried.        │
│  The simulated action is rolled back with the transaction.          │
└─────────────────────────────────────────────────────────────────────┘
```

**This only works because the simulated action is a database write.** If the action were an external HTTP call, rolling back the database transaction would not undo the external call.

#### Future real action integration (Phase 5+)

When real external integrations are added:

1. The execution service writes an **outbox record** inside the same database transaction as the `executed_at` update. The outbox record contains everything needed to invoke the external action.
2. A separate background process reads committed outbox records and performs the external call.
3. On success: outbox record is marked complete.
4. On failure: outbox record is retried with exponential back-off.
5. The external action must be **idempotent** (accept and ignore duplicate calls with the same idempotency key).

**The database transaction guarantees** that either both `executed_at` is set **and** the outbox record exists, or neither does. It cannot guarantee the external call succeeds, which is why the idempotent outbox pattern is necessary.

### 9.7 Transaction Boundaries

| Operation | Transaction content | On failure |
|-----------|-------------------|-----------|
| Create ApprovalRequest | Validate policy + insert request + insert audit | Rolls back; idempotency_key still available; safe to retry |
| Record ApprovalDecision | SELECT FOR UPDATE + guard checks + insert decision + maybe update status + insert audit | Rolls back; concurrent winner holds; loser retries or gets 409 |
| Execute action | SELECT FOR UPDATE + all guards + insert simulated-action audit + UPDATE executed_at/token + insert executed audit | Rolls back entirely; executed_at stays null; token stays intact; safe to retry |
| Expire requests | Batch UPDATE WHERE status='PENDING' AND deadline_at < NOW() + insert audit per row | Partial success is fine; next scheduler run processes remainder |

---

## 10. Audit Integrity — HMAC Chain: Guarantees & Honest Limitations

### 10.1 What the HMAC Chain Guarantees

| Claim | Accurate? | Notes |
|-------|----------|-------|
| Detecting modification of a stored row | ✓ | The entry_hash covers the row's fixed fields; any field change breaks the chain |
| Detecting deletion of a row that the chain covers | ✓ | The deleted row's hash is referenced by the next row's prior_hash; the chain breaks |
| Detecting out-of-order insertion | ✓ | An inserted row's prior_hash would not match any legitimate predecessor |
| Preventing deletion by a superuser DBA | ✗ | The trigger can be bypassed; the HMAC key can be used to rebuild the chain |
| Proving the log is complete (no omissions at write time) | ✗ | A bug could fail to write an event; the chain cannot detect what was never written |
| Proving event timestamps are accurate | ✗ | Timestamps are DB server time; a compromised server can set any timestamp |

**Summary:** The HMAC chain is a **tamper-detection** mechanism, not a tamper-prevention or completeness-proof mechanism. Its value is in incident response: after an incident, a chain verification can confirm or deny that the audit log was subsequently modified.

### 10.2 Sequence Number Gaps — Suspicious Signal, Not Proof

`AuditLog.sequence_no` is a `BIGSERIAL`. PostgreSQL allocates sequence values before the transaction commits. **A rolled-back transaction produces a gap in the sequence even though no row was ever deleted.** This is normal MVCC behaviour.

**What a gap means:**
- A transaction that began inserting an audit row was rolled back (benign)
- OR a row was deleted (suspicious — should be impossible given the trigger, but the trigger can be bypassed by a superuser)

**Policy:**
- Gaps are reported by the chain-verification endpoint as `SEQUENCE_GAP_DETECTED` warnings, **not** as proof of tampering.
- A gap alone is insufficient grounds to conclude the log was tampered with.
- A gap **combined with** a chain break at a nearby `sequence_no` is strong evidence of deletion.

### 10.3 HMAC Formula

```
fixed_fields  = sequence_no || "|" || event_type || "|" || actor_id || "|"
             || target_id   || "|" || created_at  || "|" || SHA-256(payload_json)
entry_hash   = HMAC-SHA256(AEGIS_AUDIT_HMAC_KEY, prior_hash || "|" || fixed_fields)
```

The genesis row uses `prior_hash = "AEGIS_CHAIN_GENESIS"` (a fixed sentinel string, not a secret).

### 10.4 Key Protection

```
AEGIS_AUDIT_HMAC_KEY:
  - 256-bit random value, base64-encoded
  - Set in environment only; never in application.yml or source control
  - Different from AEGIS_JWT_SECRET and AEGIS_OTP_HMAC_KEY
  - Key rotation: record the last sequence_no, start a new chain segment
    with prior_hash = "AEGIS_CHAIN_RESET:<last_seq>:<rotation_timestamp>"
```

### 10.5 Mandatory Audit Consistency Tests

These tests must pass before any milestone is complete. They are not optional future work.

- [ ] Every security-sensitive state transition produces exactly one audit event of the correct type.
- [ ] OTP failure audit payload does NOT contain the submitted code.
- [ ] Session-creation audit payload does NOT contain the raw refresh token.
- [ ] APPROVED decision audit payload does NOT contain `internal_exec_token`.
- [ ] Execution audit payload does NOT contain `internal_exec_token` (it is null at the time of the audit write, but the test explicitly verifies the field is absent from the JSONB).
- [ ] After N audit events, re-computing HMAC chain from genesis matches every `entry_hash` in the DB.
- [ ] Modifying any `fixed_field` of a stored audit row causes `verify-chain` to report it as invalid.
- [ ] Deleting a row produces a sequence gap; `verify-chain` reports `SEQUENCE_GAP_DETECTED` at the correct position.
- [ ] A rolled-back transaction that attempted to insert an audit row does NOT produce a persistent audit record (i.e., a gap from a rollback does not show a partial audit row).

---

## 11. REST API Contracts

### 11.1 URL Structure

```
Public endpoints (no authentication required):
  POST /api/v1/auth/register
  POST /api/v1/auth/login                ← returns challengeId + loginNonce on success
  POST /api/v1/auth/otp/verify           ← accepts challengeId + loginNonce + code
  POST /api/v1/auth/refresh              ← uses HttpOnly cookie; CSRF token required
  POST /api/v1/auth/password-reset/request
  POST /api/v1/auth/password-reset/confirm

Authenticated (valid JWT in Authorization: Bearer header):
  POST   /api/v1/auth/logout
  DELETE /api/v1/auth/sessions           ← logout everywhere
  GET    /api/v1/auth/sessions           ← list active sessions

  GET    /api/v1/users/me
  PATCH  /api/v1/users/me

  GET    /api/v1/devices/me
  DELETE /api/v1/devices/me/{id}         ← soft-delete device record

  POST   /api/v1/approvals/requests
  GET    /api/v1/approvals/requests
  GET    /api/v1/approvals/requests/{id}
  POST   /api/v1/approvals/requests/{id}/decide
  POST   /api/v1/approvals/requests/{id}/cancel
  POST   /api/v1/approvals/requests/{id}/execute   ← no token body; caller is authenticated requester

Admin only:
  GET    /api/v1/users
  POST   /api/v1/roles/assign
  POST   /api/v1/approvals/policies
  GET    /api/v1/approvals/policies
  PATCH  /api/v1/approvals/policies/{id}

Auditor role required (audit:read permission):
  GET    /api/v1/audit
  GET    /api/v1/audit/{id}
  GET    /api/v1/audit/verify-chain
```

**Removed from v2.0:** `POST /api/v1/auth/otp/send` (see Section 6.5, Contradiction C1).

### 11.2 Key Request/Response Contracts

**POST /auth/login**
```json
Request:  { "email": "alice@example.com", "password": "..." }
Response: { "mfaRequired": true, "challengeId": "<OtpRecord.id>", "loginNonce": "<random-token>" }
  -- loginNonce is short-lived (5 min); stored hashed in OtpRecord.login_nonce_hash
  -- NOT a session token; only valid for OTP verification
```

**POST /auth/otp/verify**
```json
Request:  { "challengeId": "<OtpRecord.id>", "loginNonce": "<random-token>", "code": "123456" }
Response: { "accessToken": "<JWT>", "expiresIn": 900 }
  Set-Cookie: refreshToken=<opaque-uuid>; HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth/refresh
```

**POST /approvals/requests**
```json
Request (header): Idempotency-Key: <caller-uuid>
Request (body):
{
  "policyId": "<UUID>",
  "actionDescription": "Transfer $5,000 to Charlie (account ending 4321)",
  "actionPayload": { "amount": 5000, "currency": "USD", "recipientAccount": "...4321" }
}
Response (201 or 200 for duplicate idempotency_key):
{
  "id": "<UUID>",
  "status": "PENDING",
  "actionCode": "sim_wire_transfer",
  "actionDescription": "Transfer $5,000 to Charlie (account ending 4321)",
  "actionPayload": { "amount": 5000, ... },
  "actionPayloadHash": "<sha256>",
  "deadlineAt": "...",
  "createdAt": "..."
  -- internal_exec_token: NOT present in any API response
}
```

**GET /approvals/requests/{id}**
```json
Response:
{
  "id": "...", "status": "APPROVED",
  "actionCode": "sim_wire_transfer",
  "actionDescription": "...",
  "actionPayload": { ... },
  "actionPayloadHash": "...",
  "decisions": [ { "approverId": "...", "decision": "APPROVED", "decidedAt": "..." } ],
  "executedAt": null
  -- internal_exec_token: NOT present
}
```

**POST /approvals/requests/{id}/execute**
```json
Request:  (empty body; authentication via JWT)
Response (200):
{
  "id": "...",
  "status": "APPROVED",
  "executedAt": "2026-10-24T17:35:00Z",
  "result": {
    "simulated": true,
    "message": "Simulated: Transfer $5,000 to Charlie (account ending 4321) executed."
  }
}
```

### 11.3 Standard Response Envelope

```json
{
  "success": true,
  "data": { ... },
  "error": null,
  "meta": { "requestId": "<UUID>", "timestamp": "ISO-8601" }
}
```

Error:
```json
{
  "success": false,
  "data": null,
  "error": { "code": "APPROVAL_ALREADY_EXECUTED", "message": "..." },
  "meta": { "requestId": "...", "timestamp": "..." }
}
```

### 11.4 HTTP Status Codes

| Situation | Code |
|-----------|------|
| Created | 201 + Location header |
| Success with body | 200 |
| Success, no body | 204 |
| Validation failure | 400 |
| Unauthenticated | 401 |
| Authenticated, forbidden | 403 |
| Not found | 404 |
| Duplicate, invalid state transition, replay | 409 |
| OTP expired (specifically) | 410 |
| Rate limited | 429 |
| Server error | 500 |
| Idempotent duplicate (same resource returned) | 200 |

### 11.5 Idempotency

- `POST /api/v1/approvals/requests` requires `Idempotency-Key` header (UUID).
- If a request with that key exists: return it with `200` and a `X-Idempotent-Replay: true` header.
- If it does not exist: create and return with `201`.

---

## 12. Testing Strategy

### 12.1 Test Categories

| Category | Tool | Scope |
|---------|------|-------|
| Unit | JUnit 5 + Mockito | Service logic, state machine, HMAC verification |
| Integration | Spring Boot Test + Testcontainers (PostgreSQL) | Full HTTP→service→DB; Flyway runs; constraint enforcement |
| Security negative | MockMvc | All cases in Section 12.2 |
| Audit consistency | Spring Boot Test | One event per transition; no secrets in payload; chain integrity |
| Architecture | ArchUnit | Package dependency rules; fail the build if violated |
| Frontend component | Vitest + RTL | Form rendering, validation, error states |
| Frontend API | MSW (Mock Service Worker) | Request shape, error handling, refresh flow |

**Coverage target:** ≥ 80% line coverage on all `service` and `statemachine` classes.

### 12.2 Mandatory Security Negative Tests

**Authentication:**
- [ ] Wrong password → 401; response body identical to "user not found" (no enumeration)
- [ ] Correct password, wrong OTP code → 401 with `remainingAttempts`
- [ ] OTP attempt limit exhausted → 429; further attempts still rejected after limit
- [ ] Expired OTP → 410 (not 401)
- [ ] Consumed OTP reused → 401
- [ ] OTP submitted with wrong `challengeId` → 401
- [ ] OTP submitted with wrong `loginNonce` → 401 (challenge binding failure)
- [ ] OTP submitted for LOGIN used against STEP_UP endpoint → 401 (purpose mismatch)
- [ ] Expired access token → 401
- [ ] Tampered JWT (any claim modified) → 401
- [ ] Missing `Authorization` header on protected endpoint → 401
- [ ] Revoked refresh token (logged out) → 401
- [ ] Rotated refresh token reused → revokes family; returns 401; other user sessions remain active

**Authorization:**
- [ ] User A accessing User B's resources → 403
- [ ] User without `approval:decide` calling decide → 403
- [ ] User with `approval:decide` but ineligible role per policy → 403
- [ ] Non-admin calling admin endpoint → 403

**Approval:**
- [ ] Requester self-approving (SOD policy) → 409
- [ ] Same approver voting twice → 409 (DB constraint fires)
- [ ] Decision on APPROVED request → 409
- [ ] Decision on EXPIRED request → 409
- [ ] Non-requester calling `/execute` → 403
- [ ] Execute on REJECTED request → 409
- [ ] Execute on already-executed request → 409
- [ ] Execute with corrupted payload (hash mismatch) → 409 + CRITICAL audit event
- [ ] Duplicate `idempotency_key` → 200 returning existing request (no new row created)

**Audit:**
- [ ] OTP failure audit payload has no `code` field
- [ ] Session creation audit payload has no `refreshToken` field
- [ ] Execution audit payload has no `internal_exec_token` field
- [ ] `internal_exec_token` is absent from all DTO serializations (verify with Jackson `@JsonIgnore` or exclusion test)

### 12.3 Test Infrastructure

- **Testcontainers:** Real PostgreSQL per test suite; all Flyway migrations run including the audit trigger (V13). No H2.
- **`ClockProvider`:** `Clock` bean; tests use `Clock.fixed(...)` to test OTP expiry, token expiry, and deadline enforcement precisely without `Thread.sleep`.
- **Shared `IntegrationTestBase`:** Provides `RestTemplate`/`MockMvc` setup, Testcontainers `@Container`, and `@DynamicPropertySource` for JDBC URL injection.
- **OTP tests:** Tests compute the expected HMAC from the test key, construct the OTP HMAC, and call the verify endpoint with the correct code. No real email is sent.
- **Audit trigger test:** Tests attempt a JDBC `UPDATE audit_log SET ...` directly and verify it throws a `PSQLException`.

---

## 13. Threat Model & Mitigations

| Threat | Mitigation | Phase |
|--------|-----------|-------|
| Credential stuffing / brute force | Per-user + per-IP rate limit (Bucket4j); `locked_until` after N failures | 1 |
| OTP brute force | 5-attempt limit + endpoint rate limit + 10-min TTL | 1 |
| OTP replay | Single-use `used_at`; purpose + userId + issuedAt in HMAC | 1 |
| OTP challenge hijacking | `login_nonce_hash` binds challenge to specific login attempt | 1 |
| JWT theft | 15-min TTL; Secure+HttpOnly refresh cookie; no DB lookup per request | 1 |
| Refresh token theft — family compromise | Reuse → entire family revoked; other families intact; CRITICAL audit | 1 |
| Approval bypass | Policy snapshot mandatory at creation; no bypass path | 1 |
| Self-approval (SOD) | SOD check inside `@Transactional` after `SELECT FOR UPDATE` | 1 |
| Double-voting | `UNIQUE(request_id, approver_id)` DB constraint | 1 |
| Execution replay | `internal_exec_token` nulled + `executed_at` set in same `UPDATE`; second execution finds no token | 1 |
| Payload substitution | `action_payload_hash` re-verified at execution; mismatch = CRITICAL audit + reject | 1 |
| Execution by wrong party | Caller's `userId` must equal `requester_id`; checked after `SELECT FOR UPDATE` | 1 |
| Approval race condition | `SELECT FOR UPDATE` + `@Version` + DB UNIQUE constraint | 1 |
| Audit tampering | Trigger prevents UPDATE/DELETE; HMAC chain detects post-hoc changes | 1 |
| Secrets in logs | OTPs, tokens, passwords never in audit payload; tested explicitly | 1 |
| Session fixation | New `family_id` + new session on every fresh login | 1 |
| Device fingerprint spoofing | Risk signal only; never authorization proof | 1 |
| CSRF on refresh endpoint | Double-submit CSRF token required | 1 |
| Mass assignment | DTOs explicitly mapped; entities never bound directly to request bodies | 1 |
| SQL injection | Spring Data JPA parameterized queries throughout | 1 |
| Privilege escalation | Permissions evaluated fresh from DB per sensitive operation | 1 |

---

## 14. Phased Roadmap — Implementation Milestones

Each milestone is independently testable: `./mvnw test` passes at the end of every milestone. Estimated effort is for a solo developer using an AI-assisted IDE.

---

### Milestone 1.1 — Project Scaffold (~2 hours)

**What:** A compiling, runnable Spring Boot application. No business logic. No database.

**Deliverables:**
- `aegis-backend/pom.xml` with Spring Boot parent, dependencies declared (Web, JPA, Flyway, Security, Mail, Testcontainers, JUnit 5, Bucket4j, jjwt, ArchUnit, Springdoc OpenAPI)
- `AegisApplication.java` with `@SpringBootApplication`
- `application.yml` (no secrets; placeholders only)
- `application-local.yml` (references env vars via `${...}` syntax)
- `.env.example` documenting all required variables
- `GET /actuator/health` → `{"status":"UP"}`
- `GlobalExceptionHandler` returning the standard error envelope
- `ClockProvider` bean
- `SecureTokenGenerator` utility (wraps `SecureRandom`)
- `ConstantTimeComparison` utility

**Acceptance Criteria:**
- [ ] `./mvnw compile` exits 0
- [ ] `./mvnw spring-boot:run -Dspring.profiles.active=local` starts without errors
- [ ] `GET /actuator/health` returns `{"status":"UP"}` with PostgreSQL not yet required
- [ ] `./mvnw test` passes (1 test: application context loads)
- [ ] No hardcoded secrets in any file; `.env.example` lists all variables

---

### Milestone 1.2 — Docker Compose & Flyway Migrations (~3 hours)

**What:** PostgreSQL running in Docker; all tables created; audit trigger installed.

**Deliverables:**
- `docker-compose.yml` (PostgreSQL 16 + MailHog)
- `V1__create_organizations.sql` through `V15__seed_default_roles_and_permissions.sql`
- `DataSource` configured from environment variables
- `IntegrationTestBase` with Testcontainers `@Container` and `@DynamicPropertySource`

**Acceptance Criteria:**
- [ ] `docker-compose up -d` starts both services
- [ ] `./mvnw spring-boot:run -Dspring.profiles.active=local` connects to PostgreSQL; all 15 migrations apply; application starts
- [ ] `./mvnw test` passes including: all 15 migrations succeed on a fresh DB; all expected tables exist; all indexes created; seed roles/permissions present
- [ ] Audit trigger test: direct `UPDATE audit_log` via JDBC throws `PSQLException`
- [ ] `GET /actuator/health` returns `{"status":"UP","components":{"db":{"status":"UP"}}}`

---

### Milestone 1.3 — User Registration & Role Assignment (~3 hours)

**What:** Users can be created and assigned roles. No authentication yet.

**Deliverables:**
- `User`, `Organization`, `Role`, `Permission` JPA entities
- `UserRepository`, `RoleRepository`
- `UserService.register(RegisterRequest)`
- `POST /api/v1/auth/register` (public)
- `POST /api/v1/roles/assign` (placeholder: no auth check yet; will be secured in 1.6)
- `GET /api/v1/users/me` (placeholder: returns hardcoded test user until auth is added)
- ArchUnit test class enforcing package boundaries

**Acceptance Criteria:**
- [ ] `POST /auth/register` with valid body → 201; user row in DB with BCrypt-hashed password
- [ ] `POST /auth/register` with duplicate email → 409
- [ ] `POST /auth/register` with weak password → 400 with field-level validation error
- [ ] `POST /roles/assign` (admin role exists in seed data) → 200; `user_roles` row created
- [ ] Unit: `UserService` duplicate email, password hashing, display name trimming
- [ ] Integration: full register → duplicate rejected at DB level
- [ ] ArchUnit: all package boundary rules pass; build fails if violated

---

### Milestone 1.4 — Login, OTP, and JWT Issuance (~4 hours)

**What:** Password verification, OTP generation, HMAC verification, session creation, JWT issuance.

**Deliverables:**
- `Session`, `OtpRecord` JPA entities
- `OtpService`: generate, HMAC-store, verify
- `TokenService`: sign JWT, generate refresh token, create Session row
- `AuthService.login(email, password)` → `LoginChallenge`
- `AuthService.verifyOtp(challengeId, loginNonce, code)` → `TokenPair`
- `POST /api/v1/auth/login` (public)
- `POST /api/v1/auth/otp/verify` (public)
- `JwtAuthenticationFilter` wired into `SecurityConfig`

**Acceptance Criteria:**
- [ ] `POST /auth/login` correct credentials → 200 `{mfaRequired:true, challengeId, loginNonce}`; OTP sent to MailHog; `OtpRecord` persisted
- [ ] `POST /auth/otp/verify` correct code + nonce → 200 `{accessToken}`; `refreshToken` cookie set; Session persisted
- [ ] `GET /api/v1/users/me` with valid JWT → 200 (real user now, not hardcoded)
- [ ] `GET /api/v1/users/me` with no JWT → 401
- [ ] `GET /api/v1/users/me` with tampered JWT → 401
- [ ] `GET /api/v1/users/me` with expired JWT → 401 (use `Clock.fixed`)
- [ ] Wrong password → 401 (identical response to unknown email)
- [ ] Wrong OTP code → 401 with `remainingAttempts`
- [ ] Correct OTP replayed → 401
- [ ] Wrong `challengeId` → 401
- [ ] Wrong `loginNonce` → 401
- [ ] OTP expired (`Clock.fixed` past `expires_at`) → 410
- [ ] OTP attempt limit reached → 429

---

### Milestone 1.5 — Token Refresh, Revocation & Session Management (~3 hours)

**What:** Refresh token rotation with family tracking; logout; session list.

**Deliverables:**
- `POST /api/v1/auth/refresh` (public; reads cookie; CSRF protection)
- `POST /api/v1/auth/logout`
- `DELETE /api/v1/auth/sessions` (logout everywhere)
- `GET /api/v1/auth/sessions`

**Acceptance Criteria:**
- [ ] `POST /auth/refresh` with valid cookie → 200 new `{accessToken}`; new `refreshToken` cookie set; old Session row `revoked_at` set; new Session row with same `family_id`
- [ ] `POST /auth/refresh` with rotated (old) token → old family all revoked; returns 401; user's other active sessions (different `family_id`) are NOT revoked
- [ ] `POST /auth/refresh` with unknown token → 401 (no session change)
- [ ] `POST /auth/refresh` with revoked token → 401
- [ ] `POST /auth/logout` → current session revoked; subsequent refresh with that cookie → 401
- [ ] `DELETE /auth/sessions` → all sessions revoked; refresh from any device → 401
- [ ] `GET /auth/sessions` → lists only non-revoked sessions with ip_address, user_agent, issued_at
- [ ] Audit events written: session_created, refresh_rotated, family_reuse_detected, session_revoked, logout_all

---

### Milestone 1.6 — Authorization & Admin Endpoint Security (~2 hours)

**What:** Permission-checked endpoints. Admin role enforced. Role assignment secured.

**Deliverables:**
- `AuthorizationService.requirePermission(userId, permissionCode)`
- `PermissionEvaluator` (loads roles → permissions from DB)
- Secure `POST /api/v1/roles/assign` (requires admin role)
- Secure `GET /api/v1/users` (requires admin role)
- `@PreAuthorize`-equivalent checks on admin endpoints

**Acceptance Criteria:**
- [ ] `POST /roles/assign` without JWT → 401
- [ ] `POST /roles/assign` with JWT but non-admin role → 403
- [ ] `POST /roles/assign` with admin JWT → 200
- [ ] `GET /api/v1/users` without admin → 403
- [ ] User A calling `GET /api/v1/users/me` while authenticated as User B → returns User A's data (scoped by JWT `sub`); direct manipulation of URL params is ignored

---

### Milestone 1.7 — Approval Policies, Requests & Decisions (~5 hours)

**What:** The core approval lifecycle: policy creation, request submission with idempotency, decision with state machine.

**Deliverables:**
- `ApprovalPolicy`, `ApprovalRequest`, `ApprovalDecision` JPA entities
- `ApprovalStateMachine` (all transitions and guards as unit-testable pure logic)
- `PolicyService`, `ApprovalRequestService`, `ApprovalDecisionService`
- `DeadlineExpirationJob` (`@Scheduled` every 60 seconds)
- `POST /api/v1/approvals/policies`
- `POST /api/v1/approvals/requests`
- `GET /api/v1/approvals/requests`
- `GET /api/v1/approvals/requests/{id}`
- `POST /api/v1/approvals/requests/{id}/decide`
- `POST /api/v1/approvals/requests/{id}/cancel`

**Acceptance Criteria:**
- [ ] Admin `POST /policies` → 201; policy stored
- [ ] `POST /requests` with idempotency key → 201; policy_snapshot and action_payload_hash stored
- [ ] Same idempotency key → 200; same resource returned; `X-Idempotent-Replay: true` header
- [ ] `GET /requests` returns PENDING requests visible to requester and eligible approvers
- [ ] Eligible approver `POST /decide` APPROVED → 200; request status = APPROVED; `internal_exec_token` set in DB (never in response)
- [ ] Eligible approver `POST /decide` REJECTED → 200; request status = REJECTED
- [ ] SOD violation (requester = approver) → 409
- [ ] Double vote → 409
- [ ] Decision on APPROVED request → 409
- [ ] Decision on EXPIRED request → 409
- [ ] Cancel by requester → 200; status = CANCELLED
- [ ] Cancel by non-requester → 403
- [ ] Scheduler: PENDING request past deadline → status = EXPIRED; audit event written
- [ ] Unit: `ApprovalStateMachine` — every valid transition succeeds; every invalid transition throws
- [ ] Audit events written for: request_created, decided, cancelled, expired

---

### Milestone 1.8 — Execution Gate (~3 hours)

**What:** Authenticated requester executes an approved request exactly once. Simulated action. Replay prevention.

**Deliverables:**
- `ApprovalExecutionService`
- `POST /api/v1/approvals/requests/{id}/execute`

**Acceptance Criteria:**
- [ ] Authenticated requester calls `/execute` on APPROVED request → 200; `executed_at` set; `internal_exec_token` nulled; audit event `APPROVAL.ACTION_EXECUTED` written; response includes `result.simulated=true`
- [ ] Second call to `/execute` → 409 (already executed)
- [ ] Non-requester calls `/execute` → 403
- [ ] `/execute` on REJECTED request → 409
- [ ] `/execute` on PENDING request → 409
- [ ] Payload hash mismatch (simulated via direct DB manipulation in test) → 409 + CRITICAL audit event
- [ ] `internal_exec_token` does NOT appear in any API response (verified by inspecting JSON serialization)
- [ ] Integration test: full Alice→Bob flow; Alice executes; second execute rejected

---

### Milestone 1.9 — Audit Query & Chain Verification (~3 hours)

**What:** Searchable audit log, HMAC chain verification endpoint, React audit log page.

**Deliverables:**
- `AuditQueryService` (pagination, filter by eventType/actorId/targetId/dateRange)
- `HmacChainVerifier`
- `GET /api/v1/audit`
- `GET /api/v1/audit/{id}`
- `GET /api/v1/audit/verify-chain`
- React: `AuditLogPage` with filters and paginated table (Milestone 1.9 is the first time the React frontend is introduced)

**Acceptance Criteria:**
- [ ] `GET /audit` without `audit:read` → 403
- [ ] `GET /audit` with `audit:read` → paginated list; filterable by `eventType`, `actorId`, date range
- [ ] `GET /audit/verify-chain` → `{valid: true, verifiedRows: N}` on a clean log
- [ ] Modify one audit row directly in DB → `verify-chain` returns `{valid: false, firstInvalidSequenceNo: K}`
- [ ] Delete one audit row → `verify-chain` reports `SEQUENCE_GAP_DETECTED` and notes it may be a rollback gap
- [ ] All mandatory audit consistency tests pass (Section 10.5)
- [ ] All mandatory security negative audit tests pass (Section 12.2)
- [ ] React audit page: renders event list, filters by type, handles empty state

---

### Phase 2 — Adaptive Auth & Risk Engine

*After all Phase 1 milestones pass.*

- Risk signal collectors: IP reputation, new-vs-seen device, unusual hour, velocity
- `RiskEngine`: signal aggregation → `RiskLevel` + explanation
- Risk level attached to sessions at login; to approval requests at creation
- `max_risk_level` policy ceiling: block if risk exceeds limit
- Step-up OTP: HIGH risk action → OTP re-verification required even with active session
- Device notification: email when new fingerprint seen
- React UI: risk level badge on approval detail; step-up OTP challenge flow

### Phase 3 — Quorum Approvals & Delegation

- `QUORUM` policy type: N-of-M approvals
- Eligible roles enforcement at decision time
- `pg_advisory_xact_lock(request_id hash)` for atomic quorum counting on single DB node
- Delegation: approver delegates to another eligible user for a specific request
- Escalation: auto-escalate to admin at 80% of deadline
- React UI: quorum progress indicator (e.g., "2 of 3 approved")

### Phase 4 — Account Recovery & Security Hardening

- Password reset via email link (time-limited, single-use signed token)
- Recovery codes: 10 BCrypt-hashed codes issued at registration
- Recovery code does NOT bypass approval requirements
- Session anomaly detection: flag IP/user-agent change since session issuance
- React UI: recovery code display/download; password reset flow

### Phase 5 — Multi-Application & API Key Access

- Application registration; API key issuance with scopes
- API key auth filter (parallel to JWT filter)
- Per-application approval policies
- Rate limiting per API key
- Outbox pattern for real external action integration
- React UI: application management; API key lifecycle

### Phase 6 — Analytics & Production Readiness

- Aggregated metrics from real DB data: login volume, risk distribution, approval throughput
- HMAC key rotation procedure; multi-segment verification
- WCAG 2.1 AA accessibility review
- OpenAPI spec review; README with architecture diagram and demo walkthrough
- React UI: analytics dashboard with real charts

---

## 15. End-to-End Demonstration

> **"Alice requests a simulated wire transfer. Bob approves it. It executes exactly once."**

**Actors:**
- Alice: `USER` role + `approval:request` permission
- Bob: `APPROVER` role + `approval:decide` permission
- Policy: `SINGLE_APPROVER`, `sod_enforced=true`, `action_code=sim_wire_transfer`, deadline 60 min

| # | Action | Expected Result |
|---|--------|----------------|
| 1 | Alice `POST /auth/register` | 201; user created |
| 2 | Bob `POST /auth/register` | 201; user created |
| 3 | Admin assigns Bob the APPROVER role | 200 |
| 4 | Alice `POST /auth/login` | `{mfaRequired:true, challengeId, loginNonce}`; OTP in MailHog |
| 5 | Alice `POST /auth/otp/verify` with correct code + nonce | 200; JWT + refresh cookie |
| 6 | Alice `POST /approvals/requests` with `Idempotency-Key: demo-001`, payload `{amount:5000, recipient:"Charlie"}` | 201; `status=PENDING`; `policy_snapshot` + `action_payload_hash` stored |
| 7 | Alice repeats the same request with `Idempotency-Key: demo-001` | 200; same resource; `X-Idempotent-Replay: true` |
| 8 | Alice `POST /approvals/requests/{id}/decide` APPROVED | 409; SOD violation |
| 9 | Bob `POST /auth/login` + `POST /auth/otp/verify` | JWT |
| 10 | Bob `GET /approvals/requests?status=PENDING` | sees Alice's request with description and payload |
| 11 | Bob `POST /approvals/requests/{id}/decide` APPROVED | 200; `status=APPROVED`; `internal_exec_token` set in DB (not in response) |
| 12 | Bob `POST /approvals/requests/{id}/decide` again | 409; already voted |
| 13 | Alice `POST /approvals/requests/{id}/execute` (no token body) | 200; `executed_at` set; `result.simulated=true`; audit event written |
| 14 | Alice retries `/execute` | 409; already executed |
| 15 | `GET /audit?eventType=APPROVAL.*` | Full trail: request_created, decided, action_executed |
| 16 | `GET /audit/verify-chain` | `{valid:true, verifiedRows:N}` |

**Coverage:** registration, OTP MFA with challenge binding, JWT, family-tracked refresh rotation, approval submission with idempotency and payload hash, SOD check, state machine, internal execution gate, replay prevention, simulated action, audit trail, HMAC chain verification.

---

## 16. Remaining Design Decisions

All decisions from v2.0 have been resolved or deferred with explicit justification. The following remain open:

| # | Decision | Options | Recommended | Must decide before |
|---|---------|---------|-------------|-------------------|
| D1 | **Step-up OTP scope** | Per-session (covers all actions for N minutes) vs. per-action (OTP required each time) | Per-session for UX; per-action for maximum security | Milestone 2.1 (Phase 2) |
| D2 | **OTP delivery failure** | Return 503 immediately vs. retry once before surfacing error | Single retry with 200ms timeout, then 503 | Milestone 1.4 |
| D3 | **Quorum atomicity mechanism** | `pg_advisory_xact_lock` vs. explicit serialization table | Advisory lock (simpler; single-node only) | Milestone 3.1 (Phase 3) |
| D4 | **Access token revocation (forced logout)** | No revocation in Phase 1 (15-min TTL controls exposure) vs. in-memory blacklist | No revocation in Phase 1; add in Phase 4 | Milestone 4.1 (Phase 4) |
| D5 | **HMAC key rotation** | Manual procedure vs. automated with version tagging | Manual procedure with documented runbook | Phase 6 |
| D6 | **Multi-tenancy** | Single org (Phase 1) vs. org-scoped from the start | Single org for Phase 1; `org_id` filter from Phase 2 | Milestone 2.1 (Phase 2) |
| D7 | **SameSite=Strict in development** | `Strict` (correct) may fail with Vite proxy | Use `Lax` in `local` profile with explicit CSRF token; `Strict` in production | Milestone 1.5 |

---

*Document version: 2.1 — Planning only. No files created. Awaiting explicit approval to begin Milestone 1.1 implementation.*
