/**
 * QuantumShield Smart Card & NFC Simulator
 * Simulates contactless smart card reading with adjustable sensor noise
 */

class NFCSimulator {
  constructor() {
    this.currentCard = null;
    this.noiseBits = 0; // 0, 1, 2, 3, 4
  }

  setCard(cardData) {
    this.currentCard = cardData;
    this.updateCardDisplay();
  }

  setNoise(bits) {
    this.noiseBits = parseInt(bits, 10);
    const label = document.getElementById("noiseDisplayLabel");
    if (label) {
      if (this.noiseBits === 0) {
        label.textContent = "0 bits (Exact Reading)";
        label.style.color = "var(--accent-emerald)";
      } else if (this.noiseBits <= 2) {
        label.textContent = `${this.noiseBits} bits (Within Fuzzy Tolerance)`;
        label.style.color = "var(--accent-cyan)";
      } else {
        label.textContent = `${this.noiseBits} bits (Exceeds Tolerance - Reject)`;
        label.style.color = "var(--accent-rose)";
      }
    }
  }

  updateCardDisplay() {
    if (!this.currentCard) return;
    const uidEl = document.getElementById("displayCardUid");
    const holderEl = document.getElementById("displayCardHolder");
    const statusEl = document.getElementById("displayCardStatus");

    if (uidEl) uidEl.textContent = this.currentCard.card_uid || "NFC-CARD-0000";
    if (holderEl) holderEl.textContent = this.currentCard.username ? this.currentCard.username.toUpperCase() : "AUTHENTICATED HOLDER";
    
    if (statusEl) {
      const isLocked = this.currentCard.status === "locked";
      statusEl.textContent = isLocked ? "LOCKED" : "ACTIVE";
      statusEl.className = `card-status-pill ${isLocked ? "card-status-locked" : "card-status-active"}`;
    }
  }

  getSimulatedCardReading() {
    if (!this.currentCard || !this.currentCard.card_secret) {
      return { card_uid: "UNKNOWN", submitted_secret: "" };
    }

    const rawHex = this.currentCard.card_secret;
    if (this.noiseBits === 0) {
      return {
        card_uid: this.currentCard.card_uid,
        submitted_secret: rawHex
      };
    }

    // Corrupt bits according to slider
    const bytes = [];
    for (let i = 0; i < rawHex.length; i += 2) {
      bytes.push(parseInt(rawHex.substr(i, 2), 16));
    }

    // Flip specified number of bits
    for (let b = 0; b < this.noiseBits; b++) {
      const byteIdx = b % bytes.length;
      const bitMask = 1 << (b % 8);
      bytes[byteIdx] ^= bitMask;
    }

    const corruptedHex = bytes.map(x => x.toString(16).padStart(2, "0")).join("");
    return {
      card_uid: this.currentCard.card_uid,
      submitted_secret: corruptedHex
    };
  }

  triggerTapAnimation(callback) {
    const cardEl = document.getElementById("smartCardGraphic");
    if (!cardEl) {
      if (callback) callback();
      return;
    }

    // Add ripple effect
    const ripple = document.createElement("div");
    ripple.className = "nfc-ripple-ring";
    ripple.style.width = "200px";
    ripple.style.height = "200px";
    ripple.style.left = "50%";
    ripple.style.top = "50%";
    ripple.style.marginLeft = "-100px";
    ripple.style.marginTop = "-100px";
    cardEl.appendChild(ripple);

    cardEl.style.transform = "scale(0.96)";
    setTimeout(() => {
      cardEl.style.transform = "scale(1.0)";
      setTimeout(() => {
        ripple.remove();
        if (callback) callback();
      }, 400);
    }, 200);
  }
}

window.nfcSimulator = new NFCSimulator();
