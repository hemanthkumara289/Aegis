# Aegis — Adaptive Authentication & Approval Platform

Aegis is an enterprise-grade Adaptive Authentication and Risk-Aware Approval platform inspired by the Tally Code Brewers hackathon challenge.

---

## Prerequisites

- **Java Development Kit**: Eclipse Temurin OpenJDK 21 (or compatible Java 21 LTS)
- **Build Tool**: Apache Maven 3.9+ (or included Maven Wrapper `./mvnw` / `.\mvnw.cmd`)
- **Shell**: Windows PowerShell 5.1+ / PowerShell 7+

---

## Project Structure

```text
Aegis/
├── aegis_architecture.md         # Architecture Blueprint v2.1
├── README.md                     # Project overview and PowerShell commands
├── .env.example                  # Environment configuration template
│
└── aegis-backend/                # Spring Boot 3.3 Backend (Java 21)
    ├── pom.xml                   # Maven dependencies and build definition
    ├── mvnw / mvnw.cmd           # Maven Wrapper scripts
    ├── .mvn/wrapper/             # Maven Wrapper configuration
    └── src/
        ├── main/
        │   ├── java/com/aegis/
        │   │   ├── AegisApplication.java
        │   │   ├── common/
        │   │   │   ├── api/          # ApiResponse, ApiMeta
        │   │   │   ├── clock/        # ClockProvider, SystemClockProvider
        │   │   │   ├── crypto/       # SecureTokenGenerator, ConstantTimeComparison
        │   │   │   └── exception/    # AegisException, ErrorCode, GlobalExceptionHandler
        │   │   └── config/
        │   │       ├── ClockConfig.java
        │   │       └── SecurityConfig.java
        │   └── resources/
        │       ├── application.yml
        │       └── application-local.yml
        └── test/
            └── java/com/aegis/
                ├── AegisApplicationTests.java
                ├── actuator/
                │   └── HealthCheckIntegrationTest.java
                └── common/
                    ├── clock/
                    │   └── ClockProviderTest.java
                    └── crypto/
                        ├── ConstantTimeComparisonTest.java
                        └── SecureTokenGeneratorTest.java
```

---

## Windows PowerShell Commands

All commands below should be executed from within the `aegis-backend` directory or using the relative paths shown.

### 1. Navigate to the Backend Directory
```powershell
Set-Location -Path "d:\Project\Aegis\aegis-backend"
```

### 2. Clean and Compile
```powershell
.\mvnw.cmd clean compile
```

### 3. Run Automated Tests
```powershell
.\mvnw.cmd test
```

### 4. Run the Application Locally (Standalone / No PostgreSQL needed in Milestone 1.1)
```powershell
.\mvnw.cmd spring-boot:run "-Dspring-boot.run.profiles=local"
```

### 5. Verify Health Endpoint (in a separate PowerShell terminal)
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/actuator/health" -Method Get | ConvertTo-Json
```
Expected output:
```json
{
  "status": "UP"
}
```

---

## Milestone Status

- [x] **Milestone 1.1 — Project Scaffold**: Compiling, runnable Spring Boot application with Java 21, Actuator health check, global exception handling, injectable clock provider, constant-time comparison, secure token generator, and test suite. Starts locally without PostgreSQL.
- [ ] **Milestone 1.2 — Docker Compose & Flyway Migrations**: PostgreSQL 16 + MailHog, 15 migrations, audit trigger.
- [ ] **Milestone 1.3 — User Registration & Role Assignment**
- [ ] **Milestone 1.4 — Login, OTP, and JWT Issuance**
- [ ] **Milestone 1.5 — Session Management & Refresh Token Reuse Detection**
- [ ] **Milestone 1.6 — RBAC, Permissions, and Admin Endpoints**
- [ ] **Milestone 1.7 — Approval State Machine & Execution Gate**
- [ ] **Milestone 1.8 — Audit HMAC Chain & Verification**
- [ ] **Milestone 1.9 — Frontend Scaffold & End-to-End Demonstration**
