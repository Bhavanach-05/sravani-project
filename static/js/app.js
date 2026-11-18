/**
 * QuantumShield 2FA Application Controller
 * Coordinates the 3-Factor Security Flow and Live Cryptography Inspector
 */

class QuantumShieldApp {
  constructor() {
    this.currentStep = 1;
    this.stage1Token = null;
    this.stage2Token = null;
    this.sessionInfo = null;
    this.currentUser = null;
    this.cardData = null;
    this.sessionTimer = null;
  }

  init() {
    this.bindEvents();
  }

  bindEvents() {
    // Step 1: Password Form
    const pwdForm = document.getElementById("passwordAuthForm");
    if (pwdForm) {
      pwdForm.addEventListener("submit", (e) => {
        e.preventDefault();
        this.submitStep1Password();
      });
    }

    // Step 2: Smart Card Tap
    const tapBtn = document.getElementById("tapCardBtn");
    if (tapBtn) {
      tapBtn.addEventListener("click", () => {
        this.submitStep2SmartCard();
      });
    }

    // Noise Slider
    const slider = document.getElementById("noiseSlider");
    if (slider) {
      slider.addEventListener("input", (e) => {
        window.nfcSimulator.setNoise(e.target.value);
      });
    }

    // Step 3: Ring-LWE Action
    const rlweBtn = document.getElementById("executeRLWEBtn");
    if (rlweBtn) {
      rlweBtn.addEventListener("click", () => {
        this.executeStep3RingLWE();
      });
    }

    // Logout
    const logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) {
      logoutBtn.addEventListener("click", () => {
        this.logout();
      });
    }

    // Quick Fill Buttons
    const quickAlice = document.getElementById("quickFillAlice");
    if (quickAlice) {
      quickAlice.addEventListener("click", () => this.selectDemoUser("alice"));
    }

    const quickHoney = document.getElementById("quickFillHoney");
    if (quickHoney) {
      quickHoney.addEventListener("click", () => this.fillHoneyToken());
    }

    // Register Form
    const regForm = document.getElementById("registerForm");
    if (regForm) {
      regForm.addEventListener("submit", (e) => {
        e.preventDefault();
        this.submitRegistration();
      });
    }
  }

  logTelemetry(msg, type = "info") {
    const logBox = document.getElementById("cryptoLogBox");
    if (!logBox) return;
    const timeStr = new Date().toLocaleTimeString();
    const entry = document.createElement("div");
    entry.style.marginBottom = "4px";
    
    let color = "var(--text-secondary)";
    if (type === "success") color = "var(--accent-emerald)";
    if (type === "warning") color = "var(--accent-amber)";
    if (type === "danger") color = "var(--accent-rose)";
    if (type === "quantum") color = "var(--accent-cyan)";

    entry.innerHTML = `<span style="color:var(--text-muted)">[${timeStr}]</span> <span style="color:${color}">${msg}</span>`;
    logBox.prepend(entry);
  }

  setStep(stepNum) {
    this.currentStep = stepNum;
    
    // Update Stepper Nodes
    for (let i = 1; i <= 3; i++) {
      const node = document.getElementById(`stepNode${i}`);
      if (!node) continue;
      node.classList.remove("active", "completed");
      if (i < stepNum) node.classList.add("completed");
      if (i === stepNum) node.classList.add("active");
    }

    // Toggle Panels
    const panels = ["step1Panel", "step2Panel", "step3Panel", "sessionPanel"];
    panels.forEach((pId, idx) => {
      const el = document.getElementById(pId);
      if (el) el.style.display = (idx + 1 === stepNum) ? "block" : "none";
    });
  }

  async selectDemoUser(username) {
    const userInp = document.getElementById("usernameInput");
    const pwdInp = document.getElementById("passwordInput");
    if (userInp) userInp.value = username;
    if (pwdInp) pwdInp.value = "QuantumPassword2026!";

    this.currentUser = username;
    try {
      const res = await fetch(`/api/auth/user-card-info?username=${username}`);
      const data = await res.json();
      if (data.success && data.card_info) {
        this.currentUser = username;
      }
    } catch (e) {
      console.warn("Could not fetch user card info:", e);
    }
  }

  fillHoneyToken() {
    const userInp = document.getElementById("usernameInput");
    const pwdInp = document.getElementById("passwordInput");
    if (userInp) userInp.value = "admin_root"; // Seeded decoy
    if (pwdInp) pwdInp.value = "HackedPassword999!";
    this.logTelemetry("HONEY TOKEN LOADED: 'admin_root'. Attempting login will trip defense alarms!", "warning");
  }

  async submitStep1Password() {
    const username = document.getElementById("usernameInput").value.trim();
    const password = document.getElementById("passwordInput").value;
    const alertBox = document.getElementById("step1Alert");
    alertBox.style.display = "none";

    this.logTelemetry(`[Factor 1] Submitting password for user: '${username}'...`);

    try {
      const res = await fetch("/api/auth/step1-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });

      const data = await res.json();
      if (!data.success) {
        alertBox.textContent = data.message;
        alertBox.style.display = "block";
        alertBox.className = "status-badge status-danger";
        this.logTelemetry(`[Factor 1] Password rejected: ${data.message}`, "danger");
        return;
      }

      this.stage1Token = data.stage1_token;
      this.currentUser = username;
      this.logTelemetry(`[Factor 1] Bcrypt verified. Stage 1 token issued.`, "success");

      // Update Inspector
      const insp1 = document.getElementById("inspFactor1Status");
      if (insp1) insp1.innerHTML = `<span style="color:var(--accent-emerald)">VERIFIED</span> (Bcrypt Salted Hash Check Passed)`;

      // Advance to Step 2
      this.setStep(2);
    } catch (err) {
      this.logTelemetry(`Network error in Step 1: ${err.message}`, "danger");
    }
  }

  async submitStep2SmartCard() {
    const alertBox = document.getElementById("step2Alert");
    alertBox.style.display = "none";

    const reading = window.nfcSimulator.getSimulatedCardReading();
    this.logTelemetry(`[Factor 2] Tapping smart card ${reading.card_uid} with ${window.nfcSimulator.noiseBits} noise bits...`);

    window.nfcSimulator.triggerTapAnimation(async () => {
      try {
        const res = await fetch("/api/auth/step2-smartcard", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            stage1_token: this.stage1Token,
            card_uid: reading.card_uid,
            submitted_secret: reading.submitted_secret
          })
        });

        const data = await res.json();
        if (!data.success) {
          alertBox.textContent = data.message;
          alertBox.style.display = "block";
          alertBox.className = "status-badge status-danger";

          if (data.scad_alert && data.scad_alert.locked) {
            this.logTelemetry(`[SCAD ALERT] Smart Card LOCKED by attack detection engine!`, "danger");
            if (this.cardData) {
              this.cardData.status = "locked";
              window.nfcSimulator.updateCardDisplay();
            }
          } else {
            this.logTelemetry(`[Factor 2] Smart card rejected: ${data.message}`, "danger");
          }
          return;
        }

        this.stage2Token = data.stage2_token;
        this.logTelemetry(`[Factor 2] Wang-Wang Fuzzy Verifier accepted! Error noise: ${data.error_distance} bit(s) (tolerance: ${data.tolerance})`, "success");

        // Update Inspector
        const insp2 = document.getElementById("inspFactor2Status");
        if (insp2) insp2.innerHTML = `<span style="color:var(--accent-emerald)">VERIFIED</span> (Wang-Wang Fuzzy Verifier: ${data.error_distance} bit noise corrected)`;

        // Advance to Step 3
        this.setStep(3);
        this.prepareStep3RingLWE();

      } catch (err) {
        this.logTelemetry(`Network error in Step 2: ${err.message}`, "danger");
      }
    });
  }

  async prepareStep3RingLWE() {
    this.logTelemetry(`[Factor 3] Requesting randomized Ring-LWE lattice challenge from server...`, "quantum");
    try {
      const res = await fetch("/api/auth/step3-challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ stage2_token: this.stage2Token })
      });
      const data = await res.json();
      if (!data.success) {
        this.logTelemetry(`Failed to get Ring-LWE challenge: ${data.message}`, "danger");
        return;
      }

      this.currentChallenge = data.challenge;
      this.logTelemetry(`[Factor 3] Ring-LWE challenge polynomial u(x) in R_q received (Nonce: ${data.challenge.nonce.substr(0, 8)}...)`, "quantum");

      // Render server challenge spectrum
      window.ringLWEClient.renderSpectrum("serverChallengeSpectrum", data.challenge.u);

      const chalStatus = document.getElementById("rlweChallengeStatus");
      if (chalStatus) {
        chalStatus.textContent = `Challenge polynomial u(x) ready (dim=256, q=3329). Nonce: ${data.challenge.nonce.substr(0, 10)}...`;
      }
    } catch (e) {
      this.logTelemetry(`Error preparing Ring-LWE: ${e.message}`, "danger");
    }
  }

  async executeStep3RingLWE() {
    if (!this.currentChallenge) {
      this.logTelemetry("No active Ring-LWE challenge found", "danger");
      return;
    }

    const alertBox = document.getElementById("step3Alert");
    alertBox.style.display = "none";

    this.logTelemetry(`[Factor 3] Client computing lattice response v(x) = u*s + e2 mod q...`, "quantum");

    const secretS = (this.cardData && this.cardData.ring_lwe_secret_s)
      ? this.cardData.ring_lwe_secret_s
      : new Array(256).fill(0).map(() => Math.floor(Math.random() * 3) - 1);

    const clientResponse = window.ringLWEClient.computeResponse(secretS, this.currentChallenge.u);
    window.ringLWEClient.renderSpectrum("clientResponseSpectrum", clientResponse.v);

    try {
      const res = await fetch("/api/auth/step3-verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          stage2_token: this.stage2Token,
          nonce: this.currentChallenge.nonce,
          response: clientResponse
        })
      });

      const data = await res.json();
      if (!data.success) {
        alertBox.textContent = data.message;
        alertBox.style.display = "block";
        this.logTelemetry(`[Factor 3] Lattice verification failed: ${data.message}`, "danger");
        return;
      }

      this.sessionInfo = data.session;
      this.logTelemetry(`[Factor 3] Lattice projection verified! Max error norm: ${data.max_error_norm.toFixed(1)} <= 550. Quantum Session Key derived!`, "success");

      // Update Inspector
      const insp3 = document.getElementById("inspFactor3Status");
      if (insp3) insp3.innerHTML = `<span style="color:var(--accent-cyan)">SECURED</span> (Ring-LWE Lattice Norm: ${data.max_error_norm.toFixed(1)})`;

      const inspKey = document.getElementById("inspSessionKey");
      if (inspKey) inspKey.textContent = data.session.derived_session_key;

      // Show Authenticated Dashboard
      this.showAuthenticatedSession(data.session);

    } catch (e) {
      this.logTelemetry(`Network error in Step 3: ${e.message}`, "danger");
    }
  }

  showAuthenticatedSession(session) {
    this.setStep(4);
    const userEl = document.getElementById("sessionUsername");
    const idEl = document.getElementById("sessionUserId");
    const fpEl = document.getElementById("sessionKeyFp");

    if (userEl) userEl.textContent = this.currentUser;
    if (idEl) idEl.textContent = session.session_id;
    if (fpEl) fpEl.textContent = session.pq_key_fingerprint;

    // Start 60-minute countdown simulation
    let secondsLeft = 3600;
    const timerEl = document.getElementById("sessionTimerDisplay");
    if (this.sessionTimer) clearInterval(this.sessionTimer);
    
    this.sessionTimer = setInterval(() => {
      secondsLeft--;
      if (secondsLeft <= 0) {
        clearInterval(this.sessionTimer);
        this.logout();
        return;
      }
      const mins = Math.floor(secondsLeft / 60);
      const secs = secondsLeft % 60;
      if (timerEl) timerEl.textContent = `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }, 1000);
  }

  async logout() {
    if (this.sessionTimer) clearInterval(this.sessionTimer);
    if (this.sessionInfo) {
      await fetch("/api/auth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_token: this.sessionInfo.session_token })
      });
    }
    this.stage1Token = null;
    this.stage2Token = null;
    this.sessionInfo = null;
    this.logTelemetry("Session terminated. Logged out.", "info");
    this.setStep(1);
  }

  async submitRegistration() {
    const username = document.getElementById("regUsername").value.trim();
    const password = document.getElementById("regPassword").value;
    const alertBox = document.getElementById("regAlert");
    alertBox.style.display = "none";

    try {
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (!data.success) {
        alertBox.textContent = data.message;
        alertBox.style.display = "block";
        alertBox.className = "status-badge status-danger";
        return;
      }

      this.logTelemetry(`Account '${username}' registered successfully. Real NFC provisioning must be completed on a physical device.`, "success");
      this.currentUser = username;

      // Close modal
      const modal = document.getElementById("registerModal");
      if (modal) modal.style.display = "none";
    } catch (e) {
      alertBox.textContent = e.message;
      alertBox.style.display = "block";
    }
  }
}

document.addEventListener("DOMContentLoaded", () => {
  window.app = new QuantumShieldApp();
  window.app.init();
});
