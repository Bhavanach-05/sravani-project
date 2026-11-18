# QuantumShield: Quantum-Resistant Two-Factor Authentication Scheme
## Software & Hardware Implementation with Real Physical NTAG215 NFC & Ring-LWE

---

## 1. Project Overview

**QuantumShield** is a quantum-resistant multi-factor authentication (2FA) system designed for ultra-sensitive mobile and enterprise environments (banking, healthcare, critical infrastructure, defense). It unifies classical security with cutting-edge post-quantum lattice cryptography and physical hardware tokens:

1. **Factor 1 — Password Verification:** Salted `bcrypt` hashing with brute-force throttling and entropy validation.
2. **Factor 2 — Physical Smart Card Authentication:** Validated by a **Wang-Wang fuzzy verifier**, compatible with real physical **NTAG215 NFC cards** (and simulated cards), tolerating minor transmission noise while thwarting offline dictionary attacks on stolen verifiers.
3. **Factor 3 — Post-Quantum Security Layer:** **Ring-LWE challenge-response** over the polynomial ring $R_q = \mathbb{Z}_{3329}[x] / (x^{256} + 1)$, establishing a quantum-resistant session key impervious to Shor's algorithm.

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Mobile Client (Smartphone)                │
│ 1. Password Entry                                           │
│ 2. Physical NTAG215 Card Tap (Web NFC API / NDEFReader)     │
│ 3. Client Ring-LWE Response: v(x) = u*s + e2 mod q          │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTPS (TLS)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    Flask Security Backend                   │
│                                                             │
│ - Factor 1: Bcrypt password validator                       │
│ - Factor 2: Wang-Wang fuzzy verifier (W = C ⊕ S, V = HMAC)  │
│ - Factor 3: Ring-LWE challenge generator & norm verifier    │
│ - Defensive Layer:                                          │
│   • Smart Card Attack Detection (SCAD) engine               │
│   • Decoy Honey Token tripwire detector                     │
│   • Quantum-bound session manager (PyJWT)                   │
│   • Tamper-evident security audit logger                    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                       SQLite Database                       │
│  users | smart_cards | ringlwe_keys | sessions              │
│  audit_logs | honey_tokens | scad_events                    │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Mathematical Foundations

### 3.1 Wang-Wang Fuzzy Verifier Algorithm
- **Enrollment:** 
  - Card secret $S \in \{0, 1\}^{128}$ (16 bytes).
  - High-entropy random codeword $C \leftarrow \{0, 1\}^{128}$.
  - Helper data $W = C \oplus S$.
  - Commitment $V = \text{HMAC-SHA256}(salt, C)$.
- **Verification:**
  - Submitted noisy reading $S' = S \oplus e$.
  - Candidate codeword $C' = W \oplus S' = C \oplus e$.
  - Evaluates distance within Hamming ball $B_\tau(C')$ for tolerance $\tau = 2$ bits.
  - If $\text{HMAC}(salt, \tilde{C}) == V$, authenticates successfully.
  - Resists offline dictionary attacks: neither $S$ nor $C$ is stored in plaintext.

### 3.2 Ring-LWE Challenge-Response (Post-Quantum Layer)
- Polynomial ring $R_q = \mathbb{Z}_q[x] / (x^n + 1)$, with $n = 256$, $q = 3329$ (FIPS 203 / Kyber standard).
- Noise sampling: Centered Binomial Distribution $\text{CBD}_\eta$ ($\eta = 2$).
- **Public Key:** $b = a \cdot s + e \pmod q$ (where $s, e \leftarrow \text{CBD}_\eta$).
- **Challenge:** Server issues random challenge polynomial $u = a \cdot r + e_1 \pmod q$.
- **Response:** Client computes $v = u \cdot s + e_2 \pmod q$.
- **Verification:** Server computes expected projection $v' = b \cdot r \pmod q$ and checks:
  $$\Vert v - v' \Vert_\infty = \Vert e_1 \cdot s + e_2 - e \cdot r \Vert_\infty \le 550$$
- **Session Key Derivation:** $K_{session} = \text{HKDF-SHA256}(v \parallel \text{nonce}_{server} \parallel \text{nonce}_{client})$.

---

## 4. Hardware Integration: Real NTAG215 NFC

QuantumShield supports physical **NXP NTAG215 NFC tags**:
- **Interface:** W3C Web NFC API (`NDEFReader`).
- **UID Reading:** Captures the unique 7-byte factory hardware UID (`04:XX:XX:XX:XX:XX:XX`).
- **Card Programming:** Writes cryptographic payload (`QS:<card_secret>`) to blank NTAG215 tags.
- **Haptic Feedback:** Vibrates mobile phone antenna upon contactless tag detection.

---

## 5. Defensive Security Layer

1. **Smart Card Attack Detection (SCAD):**
   - Tracks failed card submissions in sliding 10s windows.
   - Detects rapid-fire burst attacks.
   - Automatically locks smart cards upon 3 consecutive failures.
   - Detects card-user identity mismatch (cloning/skimming attempts).
2. **Honey Tokens:**
   - Seeded decoy accounts (`admin_root`) and decoy card UIDs (`CARD-HONEY-7777`).
   - Immediately trips critical alarms, quarantines session, and updates hit telemetry.
3. **Security Operations Center (SOC) Dashboard:**
   - Threat score calculation (0 - 100), real-time audit trail, one-click smart card unlocking.

---

## 6. How to Run the System

### Installation
```bash
python -m pip install -r requirements.txt
```

### Start the Server (with TLS for Mobile NFC)
```bash
python app.py
```

### Endpoints Available:
- **Desktop 2FA Simulator:** `https://127.0.0.1:5000/`
- **Mobile Device View:** `https://<your-lan-ip>:5000/mobile`
- **Mobile Pairing QR Code:** `https://127.0.0.1:5000/connect`
- **SOC Admin Dashboard:** `https://127.0.0.1:5000/admin`
- **Security Test Battery:** `https://127.0.0.1:5000/test-suite`

---

## 7. Automated Testing Battery (All 9 Attack Scenarios)

Run the full pytest suite:
```bash
python -m pytest tests/ -v
```

All 9 mandatory security scenarios pass with 100% verification:
1. `test_scenario_1_incorrect_password`: Correctly rejects and logs invalid passwords.
2. `test_scenario_2_invalid_smart_card_fuzzy`: Wang-Wang fuzzy verifier rejects noise exceeding $\tau > 2$.
3. `test_scenario_3_scad_repeated_failures_lock`: SCAD locks card after 3 consecutive failures.
4. `test_scenario_4_invalid_ring_lwe_response`: Rejects forged lattice polynomials ($\Vert \cdot \Vert_\infty > 550$).
5. `test_scenario_5_authentication_bypass_prevention`: Blocks attempts to skip Stage 1 or Stage 2.
6. `test_scenario_6_session_expiry_and_revocation`: Revoked and expired session tokens denied.
7. `test_scenario_7_audit_log_completeness`: Confirms tamper-evident records for all events.
8. `test_scenario_8_sensitive_data_leakage_audit`: Scans DB & logs; zero plaintext secrets leaked.
9. `test_scenario_9_honey_token_tripwire`: Submitting decoy trips immediate CRITICAL alarm.
