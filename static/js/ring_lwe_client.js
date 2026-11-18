/**
 * QuantumShield Client-Side Ring-LWE Lattice Arithmetic & Spectrum Visualizer
 */

class RingLWEClient {
  constructor(n = 256, q = 3329, eta = 2) {
    this.n = n;
    this.q = q;
    this.eta = eta;
  }

  sampleCBD() {
    const res = new Array(this.n);
    for (let i = 0; i < this.n; i++) {
      let a = 0, b = 0;
      for (let k = 0; k < this.eta; k++) {
        if (Math.random() < 0.5) a++;
        if (Math.random() < 0.5) b++;
      }
      res[i] = ((a - b) % this.q + this.q) % this.q;
    }
    return res;
  }

  polyMulNegacyclic(p1, p2) {
    const res = new Array(this.n).fill(0);
    for (let i = 0; i < this.n; i++) {
      for (let j = 0; j < this.n; j++) {
        const deg = (i + j) % this.n;
        const sign = Math.floor((i + j) / this.n) % 2 === 1 ? -1 : 1;
        res[deg] = (res[deg] + sign * (p1[i] * p2[j])) % this.q;
      }
    }
    for (let i = 0; i < this.n; i++) {
      res[i] = (res[i] % this.q + this.q) % this.q;
    }
    return res;
  }

  computeResponse(secretS, challengeU) {
    const e2 = this.sampleCBD();
    const prod = this.polyMulNegacyclic(challengeU, secretS);
    const v = new Array(this.n);
    for (let i = 0; i < this.n; i++) {
      v[i] = (prod[i] + e2[i]) % this.q;
    }
    const clientNonce = Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    return {
      v: v,
      client_nonce: clientNonce
    };
  }

  renderSpectrum(containerId, polyCoeffs) {
    const container = document.getElementById(containerId);
    if (!container || !polyCoeffs) return;

    container.innerHTML = "";
    // Sample 64 representative coefficients for display
    const step = Math.floor(polyCoeffs.length / 64) || 1;
    for (let i = 0; i < polyCoeffs.length; i += step) {
      const val = polyCoeffs[i];
      const bar = document.createElement("div");
      bar.className = "spectrum-bar";
      const heightPercent = Math.min(100, Math.max(8, (val / this.q) * 100));
      bar.style.height = `${heightPercent}%`;
      bar.title = `coeff[${i}] = ${val}`;
      container.appendChild(bar);
    }
  }
}

window.ringLWEClient = new RingLWEClient();
