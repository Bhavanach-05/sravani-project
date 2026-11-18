/**
 * QuantumShield Mobile Application Controller
 * Handles native touch events, Web NFC hardware scanning for NTAG215, and 2FA flow
 */

class MobileAppController {
  constructor() {
    this.currentStep = 1;
    this.stage1Token = null;
    this.stage2Token = null;
    this.currentUser = null;
    this.scannedCard = null;
    this.cardCredentials = this.loadCardCredentials();
    this.isScanningNfc = false;
  }

  init() {
    this.checkNfcStatus();
    this.bindEvents();
    this.registerServiceWorker();
  }

  loadCardCredentials() {
    try {
      const stored = sessionStorage.getItem("quantumshield_enrollment");
      return stored ? JSON.parse(stored) : null;
    } catch (error) {
      return null;
    }
  }

  registerServiceWorker() {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('/static/sw.js')
        .then(() => console.log('QuantumShield PWA Service Worker Registered'))
        .catch(err => console.warn('SW registration:', err));
    }
  }

  checkNfcStatus() {
    const status = window.webNFCManager.getNfcStatus();
    const banner = document.getElementById("mobileNfcBanner");
    const bannerText = document.getElementById("mobileNfcStatusText");

    if (banner && bannerText) {
      if (status.supported) {
        banner.style.background = "rgba(16, 185, 129, 0.12)";
        banner.style.borderColor = "var(--accent-emerald)";
        banner.style.color = "var(--accent-emerald)";
        bannerText.textContent = "NFC Antenna Active • Ready for physical NTAG215 tap";
      } else {
        banner.style.background = "rgba(245, 158, 11, 0.12)";
        banner.style.borderColor = "var(--accent-amber)";
        banner.style.color = "var(--accent-amber)";
        bannerText.textContent = status.message;
      }
    }
  }

  bindEvents() {
    // Tab switching (Login vs Register)
    const tabLogin = document.getElementById("tabBtnLogin");
    const tabRegister = document.getElementById("tabBtnRegister");
    if (tabLogin && tabRegister) {
      tabLogin.addEventListener("click", () => this.switchAuthTab("login"));
      tabRegister.addEventListener("click", () => this.switchAuthTab("register"));
    }

    // Step 1: Password
    const form = document.getElementById("mobilePasswordForm");
    if (form) {
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        this.submitStep1();
      });
    }

    // Registration Form
    const regForm = document.getElementById("mobileRegisterForm");
    if (regForm) {
      regForm.addEventListener("submit", (e) => {
        e.preventDefault();
        this.submitRegistration();
      });
    }

    // Post-Registration Actions
    const btnWriteNew = document.getElementById("btnWriteNewCard");
    if (btnWriteNew) {
      btnWriteNew.addEventListener("click", () => {
        this.provisionRegisteredCard();
      });
    }

    const btnGoLogin = document.getElementById("btnGoToLogin");
    if (btnGoLogin) {
      btnGoLogin.addEventListener("click", () => {
        this.switchAuthTab("login");
      });
    }

    // Quick Fill Alice
    const quickBtn = document.getElementById("mobileQuickAlice");
    if (quickBtn) {
      quickBtn.addEventListener("click", () => {
        document.getElementById("mUsername").value = "alice";
        document.getElementById("mPassword").value = "QuantumPassword2026!";
      });
    }

    // Step 2: Scan Real NTAG215
    const scanBtn = document.getElementById("btnScanNfc");
    if (scanBtn) {
      scanBtn.addEventListener("click", () => {
        this.startPhysicalNfcScan();
      });
    }

    // Write / Provision Blank NTAG215 Card
    const writeBtn = document.getElementById("btnWriteNfc");
    if (writeBtn) {
      writeBtn.addEventListener("click", () => {
        this.provisionNtag215();
      });
    }

    // Step 3: Ring-LWE
    const rlweBtn = document.getElementById("btnMobileRlwe");
    if (rlweBtn) {
      rlweBtn.addEventListener("click", () => {
        this.executeRingLWE();
      });
    }

    // Logout
    const logoutBtn = document.getElementById("btnMobileLogout");
    if (logoutBtn) {
      logoutBtn.addEventListener("click", () => {
        location.reload();
      });
    }
  }

  setStep(step) {
    this.currentStep = step;
    for (let i = 1; i <= 3; i++) {
      const node = document.getElementById(`mStepNode${i}`);
      if (!node) continue;
      node.classList.remove("active", "completed");
      if (i < step) node.classList.add("completed");
      if (i === step) node.classList.add("active");
    }

    const panels = ["mStep1Panel", "mStep2Panel", "mStep3Panel", "mSessionPanel"];
    panels.forEach((id, idx) => {
      const el = document.getElementById(id);
      if (el) el.style.display = (idx + 1 === step) ? "block" : "none";
    });
  }

  switchAuthTab(tab) {
    const tabLogin = document.getElementById("tabBtnLogin");
    const tabRegister = document.getElementById("tabBtnRegister");
    const subLogin = document.getElementById("subPanelLogin");
    const subRegister = document.getElementById("subPanelRegister");

    if (tab === "login") {
      if (tabLogin) {
        tabLogin.style.background = "var(--bg-card-hover, #1a2542)";
        tabLogin.style.color = "var(--accent-cyan)";
      }
      if (tabRegister) {
        tabRegister.style.background = "none";
        tabRegister.style.color = "var(--text-muted)";
      }
      if (subLogin) subLogin.style.display = "block";
      if (subRegister) subRegister.style.display = "none";
    } else {
      if (tabRegister) {
        tabRegister.style.background = "var(--bg-card-hover, #1a2542)";
        tabRegister.style.color = "var(--accent-cyan)";
      }
      if (tabLogin) {
        tabLogin.style.background = "none";
        tabLogin.style.color = "var(--text-muted)";
      }
      if (subLogin) subLogin.style.display = "none";
      if (subRegister) subRegister.style.display = "block";
    }
  }

  async submitRegistration() {
    const username = document.getElementById("mRegUsername").value.trim();
    const password = document.getElementById("mRegPassword").value;
    const alertBox = document.getElementById("mRegAlert");
    const successBox = document.getElementById("mRegSuccessBox");
    const cardUidEl = document.getElementById("mRegCardUid");

    if (alertBox) alertBox.style.display = "none";
    if (successBox) successBox.style.display = "none";

    try {
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (!data.success) {
        if (alertBox) {
          alertBox.textContent = data.message || "Registration failed";
          alertBox.style.display = "block";
        }
        return;
      }

      this.cardCredentials = data.enrollment || {
        card_uid: data.card_uid,
        card_secret: null,
        ring_lwe_secret_s: null
      };
      sessionStorage.setItem("quantumshield_enrollment", JSON.stringify(this.cardCredentials));
      this.currentUser = username;

      const loginU = document.getElementById("mUsername");
      const loginP = document.getElementById("mPassword");
      if (loginU) loginU.value = username;
      if (loginP) loginP.value = password;

      this.switchAuthTab("register");

      if (cardUidEl) cardUidEl.textContent = data.card_uid;
      if (successBox) successBox.style.display = "block";
    } catch (err) {
      if (alertBox) {
        alertBox.textContent = `Connection error: ${err.message}. Check Server URL in settings.`;
        alertBox.style.display = "block";
      }
    }
  }

  async provisionRegisteredCard() {
    if (!this.cardCredentials || !this.cardCredentials.card_secret) {
      throw new Error("No physical card enrollment credentials are available.");
    }
    const alertBox = document.getElementById("mRegAlert");

    try {
      await window.webNFCManager.writeToTag(this.cardCredentials.card_secret, this.currentUser);
      alert(`Card programmed successfully for user ${this.currentUser}! You can now proceed to login.`);
      this.switchAuthTab("login");
    } catch (err) {
      if (alertBox) {
        alertBox.textContent = `NFC Write Error: ${err.message}. Ensure NFC is active and card is held steady against the back of your phone.`;
        alertBox.style.display = "block";
      }
      alert(`NFC Write Error: ${err.message}. Ensure NFC is active and card is held steady against the back of your phone.`);
    }
  }

  async submitStep1() {
    const username = document.getElementById("mUsername").value.trim();
    const password = document.getElementById("mPassword").value;
    const alertBox = document.getElementById("mStep1Alert");
    alertBox.style.display = "none";

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
        return;
      }

      this.stage1Token = data.stage1_token;
      this.currentUser = username;

      // Fetch user's registered card details to match against physical NTAG215
      await this.fetchUserCardInfo(username);

      this.setStep(2);
    } catch (err) {
      alertBox.textContent = err.message;
      alertBox.style.display = "block";
    }
  }

  async fetchUserCardInfo(username) {
    try {
      const res = await fetch(`/api/auth/user-card-info?username=${username}`);
      const data = await res.json();
      if (data.success && data.card_info) {
        if (!this.cardCredentials) {
          this.cardCredentials = {
            card_uid: data.card_info.card_uid,
            card_secret: null,
            ring_lwe_secret_s: null
          };
        } else {
          this.cardCredentials.card_uid = data.card_info.card_uid;
        }
        const infoEl = document.getElementById("mRegisteredCardUid");
        if (infoEl) infoEl.textContent = data.card_info.card_uid;
      }
    } catch (e) {
      console.warn("Card info fetch:", e);
    }
  }

  async startPhysicalNfcScan() {
    const statusBox = document.getElementById("mNfcScanPrompt");
    const scanBtn = document.getElementById("btnScanNfc");
    const radar = document.getElementById("nfcRadarGraphic");

    if (statusBox) statusBox.style.display = "block";
    if (radar) radar.style.display = "flex";
    if (scanBtn) scanBtn.disabled = true;

    window.webNFCManager.startScan(
      async (cardData) => {
        // Tag scanned successfully!
        this.scannedCard = cardData;
        
        // Show scanned tag badge
        const badge = document.getElementById("mScannedTagBadge");
        const uidText = document.getElementById("mScannedUidText");
        if (badge) badge.style.display = "flex";
        if (uidText) uidText.textContent = `NTAG215 UID: ${cardData.serialNumber}`;

        if (statusBox) statusBox.innerHTML = `<span style="color:var(--accent-emerald)">✓ NTAG215 Card Detected! Validating...</span>`;

        // Authenticate with server using scanned card UID & secret
        await this.verifyScannedCard(cardData);
      },
      (err) => {
        if (statusBox) {
          statusBox.style.display = "block";
          statusBox.innerHTML = `<span style="color:var(--accent-rose)">NFC Error: ${err.message}</span>`;
        }
        if (scanBtn) scanBtn.disabled = false;
        if (radar) radar.style.display = "none";
      }
    );
  }

  async verifyScannedCard(cardData) {
    const alertBox = document.getElementById("mStep2Alert");
    alertBox.style.display = "none";

    const submittedSecret = cardData && cardData.cardSecret;
    const submittedUid = cardData && cardData.serialNumber ? cardData.serialNumber : null;

    if (!submittedSecret || !submittedUid) {
      alertBox.textContent = "No valid NTAG215 secret was found on the tag. Program a blank NTAG215 card first, then tap it again.";
      alertBox.style.display = "block";
      return;
    }

    try {
      const res = await fetch("/api/auth/step2-smartcard", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          stage1_token: this.stage1Token,
          card_uid: submittedUid,
          submitted_secret: submittedSecret
        })
      });

      const data = await res.json();
      if (!data.success) {
        alertBox.textContent = data.message;
        alertBox.style.display = "block";
        return;
      }

      this.stage2Token = data.stage2_token;
      window.webNFCManager.stopScan();

      // Proceed to Step 3
      this.setStep(3);
      this.prepareStep3();
    } catch (e) {
      alertBox.textContent = e.message;
      alertBox.style.display = "block";
    }
  }

  async provisionNtag215() {
    const statusBox = document.getElementById("mNfcScanPrompt");
    if (!this.cardCredentials || !this.cardCredentials.card_secret) {
      alert("Please login with Step 1 first to load your credentials");
      return;
    }

    if (statusBox) {
      statusBox.style.display = "block";
      statusBox.innerHTML = `<span style="color:var(--accent-cyan)">Hold a blank NTAG215 card to the back of phone to write credentials...</span>`;
    }

    try {
      await window.webNFCManager.writeToTag(this.cardCredentials.card_secret, this.currentUser);
      if (statusBox) {
        statusBox.innerHTML = `<span style="color:var(--accent-emerald)">✓ NTAG215 card programmed successfully! You can now tap to login.</span>`;
      }
    } catch (err) {
      if (statusBox) {
        statusBox.innerHTML = `<span style="color:var(--accent-rose)">Write Failed: ${err.message}</span>`;
      }
    }
  }

  async prepareStep3() {
    try {
      const res = await fetch("/api/auth/step3-challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ stage2_token: this.stage2Token })
      });
      const data = await res.json();
      if (data.success) {
        this.currentChallenge = data.challenge;
        window.ringLWEClient.renderSpectrum("mServerChallengeSpectrum", data.challenge.u);
      }
    } catch (e) {
      console.warn("Challenge prep:", e);
    }
  }

  async executeRingLWE() {
    const alertBox = document.getElementById("mStep3Alert");
    alertBox.style.display = "none";

    const secretS = this.cardCredentials && this.cardCredentials.ring_lwe_secret_s;
    if (!secretS) {
      alertBox.textContent = "Physical enrollment credentials are unavailable. Register again and program the card first.";
      alertBox.style.display = "block";
      return;
    }

    const clientResp = window.ringLWEClient.computeResponse(secretS, this.currentChallenge.u);
    window.ringLWEClient.renderSpectrum("mClientResponseSpectrum", clientResp.v);

    try {
      const res = await fetch("/api/auth/step3-verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          stage2_token: this.stage2Token,
          nonce: this.currentChallenge.nonce,
          response: clientResp
        })
      });

      const data = await res.json();
      if (!data.success) {
        alertBox.textContent = data.message;
        alertBox.style.display = "block";
        return;
      }

      this.showSession(data.session);
    } catch (e) {
      alertBox.textContent = e.message;
      alertBox.style.display = "block";
    }
  }

  showSession(session) {
    this.setStep(4);
    const uEl = document.getElementById("mSessionUser");
    const kEl = document.getElementById("mSessionKeyHash");
    if (uEl) uEl.textContent = this.currentUser;
    if (kEl) kEl.textContent = session.pq_key_fingerprint;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  window.mobileApp = new MobileAppController();
  window.mobileApp.init();
});
