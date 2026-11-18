# QuantumShield Project Report

## 1. Executive Summary

QuantumShield is a Flask-based multi-factor authentication system designed to combine conventional security controls with a layer of post-quantum cryptographic verification and physical NFC-based authentication. The project is intended for high-sensitivity environments such as banking, healthcare, defense, and critical infrastructure, where authentication must resist both classic brute-force attacks and future quantum-era threats.

The platform is implemented as a modular application with a web backend, SQLite persistence, Python cryptographic routines, and a modern, responsive web interface with browser Web NFC capabilities. It demonstrates a three-stage authentication model:

1. Password validation using bcrypt
2. Smart-card validation using a Wang-Wang fuzzy verifier over a physical or virtual NFC credential
3. Ring-LWE challenge-response verification for a post-quantum session key

In addition to core authentication, the system includes defensive mechanisms such as smart-card attack detection (SCAD), honey-token tripwires, audit logging, and session revocation policies.

The implementation and architecture are centered around the following source files:

- [app.py](app.py)
- [config.py](config.py)
- [database.py](database.py)
- [routes/auth_routes.py](routes/auth_routes.py)
- [routes/admin_routes.py](routes/admin_routes.py)
- [routes/test_routes.py](routes/test_routes.py)
- [crypto/password.py](crypto/password.py)
- [crypto/fuzzy_verifier.py](crypto/fuzzy_verifier.py)
- [crypto/ring_lwe.py](crypto/ring_lwe.py)
- [security/scad.py](security/scad.py)
- [security/session_manager.py](security/session_manager.py)
- [security/audit_logger.py](security/audit_logger.py)
- [security/honey_tokens.py](security/honey_tokens.py)

---

## 2. Project Purpose and Objectives

The main goals of QuantumShield are:

- Provide a realistic 3-factor authentication workflow that combines password, smart card, and lattice-based cryptography
- Demonstrate practical defense-in-depth using modern and experimental security mechanisms
- Integrate a mobile/web NFC flow compatible with physical NTAG215 cards
- Log and detect suspicious authentication patterns in real time
- Show how layered security can reduce risk from offline attacks, credential stuffing, skimming, cloning, and replay attempts

This project is both a functional prototype and an educational security architecture demonstrating concepts from classical identity systems, fuzzy extractors, and lattice-based cryptography.

---

## 3. Business and Security Context

QuantumShield is positioned as a concept system for environments where security posture must remain resilient even if an attacker gains access to future quantum computing capabilities. The project intentionally blends:

- classical password hashing for user access
- physical hardware possession checks
- lattice-based verification as a post-quantum proof mechanism
- runtime event monitoring to catch attack behavior

This design makes the system appropriate as a research-oriented or demonstration platform, especially where the goal is to show how layered authentication can be rebuilt around modern assumptions.

---

## 4. System Architecture

The application follows a modular Flask architecture.

### 4.1 Core App Entry
The main application bootstrap is defined in [app.py](app.py). It:

- creates the Flask app instance
- loads configuration from [config.py](config.py)
- initializes the SQLite database using [database.py](database.py)
- registers authentication, admin, and test blueprints
- exposes page routes for the dashboard, mobile endpoint, QR pairing, admin console, and test suite
- generates self-signed TLS certificates when needed for mobile NFC compatibility

### 4.2 Application Layers

The system is conceptually split into several layers:

1. Presentation Layer
   - Web pages and authentication templates under [templates](templates)
   - Static styling and scripts under [static](static)
   - QR code generation and health endpoints in [app.py](app.py)

2. Routing and API Layer
   - [routes/auth_routes.py](routes/auth_routes.py) handles registration and authentication stages
   - [routes/admin_routes.py](routes/admin_routes.py) exposes telemetry and SOC functions
   - [routes/test_routes.py](routes/test_routes.py) runs scenario-based validation against the security model

3. Security and Cryptography Layer
   - Password hashing in [crypto/password.py](crypto/password.py)
   - Smart-card verification in [crypto/fuzzy_verifier.py](crypto/fuzzy_verifier.py)
   - Ring-LWE implementation in [crypto/ring_lwe.py](crypto/ring_lwe.py)
   - Attack detection in [security/scad.py](security/scad.py)
   - Session management in [security/session_manager.py](security/session_manager.py)

4. Data and Audit Layer
   - SQLite storage defined in [database.py](database.py)
   - Audit event generation in [security/audit_logger.py](security/audit_logger.py)
   - Honey-token storage and trigger handling in [security/honey_tokens.py](security/honey_tokens.py)

---

## 5. Authentication Model

The system implements a strict, staged authentication flow that prevents bypass between steps.

### Stage 1: Password Validation
The first gate verifies the username and password using bcrypt hashing. The logic is in [routes/auth_routes.py](routes/auth_routes.py).

Features:

- strong password validation checks
- bcrypt password hashing
- failed-attempt tracking
- lock state handling for accounts
- verification of honey-token decoy usernames

### Stage 2: Smart Card Validation
The second gate verifies a smart-card secret by using a fuzzy verifier. The implementation is in [crypto/fuzzy_verifier.py](crypto/fuzzy_verifier.py) and is invoked by the smart-card endpoint in [routes/auth_routes.py](routes/auth_routes.py).

This stage uses a Wang-Wang-style helper-data design:

- a random card secret is created
- a codeword is generated
- helper data is computed as $W = C \oplus S$
- a commitment is stored as HMAC-SHA256(salt, C)

The verifier tolerates minor noise by testing candidate codewords within a Hamming distance threshold, with a default tolerance of 2 bits.

### Stage 3: Ring-LWE Challenge-Response
The third gate verifies a lattice-based challenge-response using a Ring-LWE construction centered on the ring:

$$R_q = \mathbb{Z}_q[x] / (x^{256} + 1)$$

with:

- $n = 256$
- $q = 3329$
- small centered binomial noise

The implementation in [crypto/ring_lwe.py](crypto/ring_lwe.py) performs:

- key generation
- challenge issuance
- response computation
- verification by checking the bound on residual lattice error
- derivation of a session key using a hash-based method

The server checks whether:

$$\|v - v'\|_{\infty} \le 550$$

This bound is used as a gate for accepting the challenge-response.

---

## 6. Defensive Security Features

### 6.1 SCAD Engine
The smart-card attack detection engine is implemented in [security/scad.py](security/scad.py).

It tracks:

- rapid-fire bursts from individual IPs
- repeated failures on a smart card
- card-user mismatch conditions
- lock-out thresholds after repeated failures

The default configuration in [config.py](config.py) includes:

- maximum failed attempts = 3
- rapid-fire window = 10 seconds
- rapid-fire threshold = 4 attempts
- lock duration = 900 seconds

### 6.2 Honey Tokens
A honey-token mechanism is implemented in [security/honey_tokens.py](security/honey_tokens.py). It traps decoy usernames and card IDs such as:

- admin_root
- CARD-HONEY-7777

If such values are submitted, the system marks the activity as a critical security event and increments the token trigger count. This is used to detect bots, credential stuffing, and honeypot testing.

### 6.3 Audit Logging
The audit framework in [security/audit_logger.py](security/audit_logger.py) stores event metadata in SQLite under the audit_logs table, including:

- user id
- event type
- description
- IP address
- outcome
- severity
- metadata
- timestamp

This creates a searchable tamper-evident trail for security operations.

### 6.4 Session Management
The session manager in [security/session_manager.py](security/session_manager.py) handles:

- Stage 1 token creation and verification
- Stage 2 token creation and verification
- creation of a quantum/session-backed JWT
- expiration handling
- logout/revocation support

The app ensures that stage access is not bypassable by requiring valid prior-stage tokens.

---

## 7. Core Modules and Their Roles

### [app.py](app.py)
Responsible for app creation, route registration, QR code generation, health checks, and TLS-enabled startup.

### [config.py](config.py)
Contains global configuration values for security thresholds, TTLs, and PQ parameters.

### [database.py](database.py)
Defines the SQLite schema and seeds decoy records. Tables include:

- users
- smart_cards
- ringlwe_keys
- sessions
- audit_logs
- honey_tokens
- scad_events

### [crypto/password.py](crypto/password.py)
Implements password hashing and validation logic using bcrypt plus enterprise-strength complexity rules.

### [crypto/fuzzy_verifier.py](crypto/fuzzy_verifier.py)
Creates and verifies card secrets using helper data and HMAC-based codeword validation with tolerance to bit noise.

### [crypto/ring_lwe.py](crypto/ring_lwe.py)
Handles Ring-LWE key generation, challenge creation, response computation, and mathematical validation of the challenge-response flow.

### [routes/auth_routes.py](routes/auth_routes.py)
Contains the authentication engine for all three steps and the supporting user-card data retrieval route.

### [routes/admin_routes.py](routes/admin_routes.py)
Exposes SOC-style telemetry for metrics, audit logs, SCAD incidents, honey-token state, card list, and card unlock actions.

### [routes/test_routes.py](routes/test_routes.py)
Runs a battery of security scenarios used to validate the system under attack conditions.

### [tests](tests)
Contains automated tests verifying multiple security conditions and authentication flows.

---

## 8. Database Design

The project uses SQLite with relational tables that represent users, credentials, sessions, and security events.

### Users Table
Stores:

- username
- password hash
- failed login count
- lock state
- lock time

### Smart Cards Table
Stores:

- user ownership
- card UID
- fuzzy verifier data
- helper data
- card status (active/locked)

### Ring-LWE Keys Table
Stores:

- user association
- public lattice parameters

### Sessions Table
Stores:

- session token
- session key fingerprint
- expiration time
- status

### Audit Logs Table
Stores event history for incident tracking and later review.

### Honey Tokens Table
Stores the decoy values and their trigger counts.

### SCAD Events Table
Tracks rapid-fire attempts, card locking, user-card mismatch, and intrusion events.

---

## 9. NFC and Web Integration

The project supports real physical NTAG215 tags and provides a streamlined contactless authentication workflow leveraging the W3C Web NFC standard (`NDEFReader`).

The relevant functionality includes:

- QR code generation for pairing mobile browsers with the server over local network TLS
- Web NFC API integration for contactless smart card reading and writing
- Visual and interactive smart-card simulation with configurable sensor noise
- Secure self-signed TLS generation required by modern mobile browsers for Web NFC access

By implementing the W3C Web NFC standard directly, the application delivers cross-device NFC capabilities in modern mobile browsers without requiring native packaging or platform-specific builds.

---

## 10. Security Testing and Validation

The project contains automated tests under [tests](tests):

- [tests/test_auth_flow.py](tests/test_auth_flow.py)
- [tests/test_crypto.py](tests/test_crypto.py)
- [tests/test_nfc_ntag215.py](tests/test_nfc_ntag215.py)
- [tests/test_scad.py](tests/test_scad.py)
- [tests/test_security_battery.py](tests/test_security_battery.py)

The project describes nine mandatory security scenarios, including:

1. incorrect password rejection
2. fuzzy verifier rejection beyond tolerance
3. SCAD lock after repeated card failures
4. invalid Ring-LWE response rejection
5. authentication bypass prevention
6. session expiry and revocation
7. audit log completeness
8. sensitive data leak checks
9. honey-token tripwire detection

The test harness in [routes/test_routes.py](routes/test_routes.py) and the automated test suite (`python -m pytest`) execute this battery with all 26 automated tests passing (100% pass rate).

---

## 11. Runtime and Deployment Notes

The application is designed to run through Flask and can be started via:

```bash
python -m pip install -r requirements.txt
python app.py
```

It exposes endpoints such as:

- home page (2FA Authentication Portal)
- mobile authentication page
- QR pairing page (Web NFC)
- admin dashboard (SOC telemetry)
- security test suite
- health endpoint

The system features an automated certificate generator for local TLS (`cert.pem` / `key.pem`), which is required by mobile browsers to unlock hardware NFC sensor capabilities via the W3C Web NFC API.

---

## 12. Strengths of the Project

- Clear three-layer security model
- Strong modular design with separation between routes, crypto, security, and database layers
- Good practical demonstration of both classical and post-quantum authentication ideas
- Defensive telemetry via SCAD and honey-token detection
- Structured audit trail for security operations
- Strong educational usefulness for cryptographic and authentication design discussions

---

## 13. Limitations and Risks

Although the system is compelling as a prototype, it also has important limitations.

### 13.1 Real-World Cryptography
The Ring-LWE implementation is intentionally simplified and is not a production-grade lattice system. It is better viewed as a research demonstration of cryptographic logic and bounded-error verification than as an implementation aligned with Kyber or NIST-approved post-quantum standards.

### 13.2 Security Hardening
The project relies on default secrets and local certificate generation when not configured. In production, secrets should be managed via environment variables and secure secret stores, not hardcoded values.

### 13.3 NFC Realism
The NFC implementation is designed for a browser-based mobile web flow and realistically simulates physical card interactions, but a real-world deployment would require more rigorous hardware verification, secure provisioning, and production-safe binding between the card and the backend.

### 13.4 Session and Storage Design
The use of SQLite is suitable for demonstration and small deployments, but not for a scalable or highly regulated production environment. A production system would likely require stronger database controls, encryption-at-rest, and central identity management.

---

## 14. Overall Assessment

QuantumShield is a strong demonstration project that blends practical web security, physical token logic, and lattice-based cryptographic reasoning in one coherent application. It is particularly useful for understanding how layered identity checks can be structured and presented in a modern application.

The strongest parts of the project are its defense-in-depth architecture, clear route structure, and integrated testing approach. The weakest parts are the simplification of post-quantum algorithms and the fact that some operational assumptions would need stronger engineering before deployment in a high-assurance environment.

In summary, this project is best described as a high-value security research prototype and teaching application for advanced authentication systems.

---

## 15. File Map

- [app.py](app.py) — application bootstrap and routes
- [config.py](config.py) — configuration and security thresholds
- [database.py](database.py) — SQLite schema and seeded honey tokens
- [crypto/password.py](crypto/password.py) — bcrypt password handling
- [crypto/fuzzy_verifier.py](crypto/fuzzy_verifier.py) — smart-card fuzzy verifier logic
- [crypto/ring_lwe.py](crypto/ring_lwe.py) — lattice-based challenge-response engine
- [security/scad.py](security/scad.py) — smart-card attack detection
- [security/honey_tokens.py](security/honey_tokens.py) — decoy traps and intrusion detection
- [security/audit_logger.py](security/audit_logger.py) — event logging
- [security/session_manager.py](security/session_manager.py) — JWT stage gating and session lifecycle
- [routes/auth_routes.py](routes/auth_routes.py) — 3-stage authentication endpoints
- [routes/admin_routes.py](routes/admin_routes.py) — admin telemetry endpoints
- [routes/test_routes.py](routes/test_routes.py) — automated security harness
- [tests](tests) — automated verification suite

---



## 16. Conclusion

QuantumShield demonstrates a sophisticated, layered authentication design that brings together password security, physical possession verification, and a lattice-based challenge-response model. It showcases how multi-stage verification and monitoring can significantly improve posture against attack patterns that typically defeat simpler systems.

The project is highly valuable from both an engineering and educational perspective, and it provides a practical blueprint for exploring advanced authentication in a modern web application.
