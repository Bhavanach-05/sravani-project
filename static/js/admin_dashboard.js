/**
 * QuantumShield SOC Admin Dashboard Controller
 * Real-time telemetry monitoring, audit log streamer, and SCAD management
 */

class AdminDashboard {
  constructor() {
    this.pollInterval = null;
  }

  init() {
    this.fetchMetrics();
    this.fetchAuditLogs();
    this.fetchSCADEvents();
    this.fetchHoneyTokens();
    this.fetchSmartCards();
    this.bindEvents();

    // Auto-poll telemetry every 3.5 seconds
    this.pollInterval = setInterval(() => {
      this.fetchMetrics();
      this.fetchAuditLogs();
      this.fetchSCADEvents();
      this.fetchHoneyTokens();
      this.fetchSmartCards();
    }, 3500);
  }

  bindEvents() {
    const filterSev = document.getElementById("logSeverityFilter");
    if (filterSev) {
      filterSev.addEventListener("change", () => this.fetchAuditLogs());
    }

    const resetBtn = document.getElementById("clearLogsBtn");
    if (resetBtn) {
      resetBtn.addEventListener("click", () => this.clearLogs());
    }
  }

  async fetchMetrics() {
    try {
      const res = await fetch("/api/admin/metrics");
      const data = await res.json();
      if (!data.success) return;

      const m = data.metrics;
      const scoreEl = document.getElementById("threatScoreNum");
      const levelEl = document.getElementById("threatLevelBadge");
      const honeyEl = document.getElementById("metricHoneyCount");
      const scadEl = document.getElementById("metricSCADCount");
      const lockedEl = document.getElementById("metricLockedCards");
      const sessionsEl = document.getElementById("metricActiveSessions");

      if (scoreEl) scoreEl.textContent = m.threat_score;
      if (levelEl) {
        levelEl.textContent = m.threat_level;
        levelEl.className = `threat-level-badge threat-${m.threat_level.toLowerCase()}`;
        if (m.threat_level === "CRITICAL") {
          levelEl.style.background = "rgba(244, 63, 94, 0.35)";
          levelEl.style.color = "#ff0044";
          levelEl.style.border = "1px solid #ff0044";
        } else if (m.threat_level === "HIGH") {
          levelEl.style.background = "rgba(244, 63, 94, 0.2)";
          levelEl.style.color = "var(--accent-rose)";
          levelEl.style.border = "1px solid var(--accent-rose)";
        } else if (m.threat_level === "ELEVATED") {
          levelEl.style.background = "rgba(245, 158, 11, 0.2)";
          levelEl.style.color = "var(--accent-amber)";
          levelEl.style.border = "1px solid var(--accent-amber)";
        } else {
          levelEl.style.background = "rgba(16, 185, 129, 0.2)";
          levelEl.style.color = "var(--accent-emerald)";
          levelEl.style.border = "1px solid var(--accent-emerald)";
        }
      }

      if (honeyEl) honeyEl.textContent = m.honey_token_triggers;
      if (scadEl) scadEl.textContent = m.scad_events_count;
      if (lockedEl) lockedEl.textContent = m.locked_cards_count;
      if (sessionsEl) sessionsEl.textContent = m.active_sessions;

    } catch (e) {
      console.warn("Failed fetching SOC metrics:", e);
    }
  }

  async fetchAuditLogs() {
    const sevFilter = document.getElementById("logSeverityFilter")?.value || "";
    let url = "/api/admin/audit-logs?limit=40";
    if (sevFilter) url += `&severity=${sevFilter}`;

    try {
      const res = await fetch(url);
      const data = await res.json();
      if (!data.success) return;

      const tbody = document.getElementById("auditLogsTbody");
      if (!tbody) return;

      tbody.innerHTML = "";
      data.logs.forEach(log => {
        const tr = document.createElement("tr");
        const time = new Date(log.timestamp).toLocaleTimeString();
        tr.innerHTML = `
          <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted)">${time}</td>
          <td><span class="tag-severity severity-${log.severity}">${log.severity}</span></td>
          <td style="font-family:var(--font-mono); font-weight:600; color:var(--text-cyan)">${log.event_type}</td>
          <td>${log.description}</td>
          <td style="font-family:var(--font-mono); font-size:0.75rem">${log.ip_address}</td>
          <td><span style="font-weight:700; color:${log.outcome === 'SUCCESS' ? 'var(--accent-emerald)' : 'var(--accent-rose)'}">${log.outcome}</span></td>
        `;
        tbody.appendChild(tr);
      });
    } catch (e) {
      console.warn("Failed fetching audit logs:", e);
    }
  }

  async fetchSCADEvents() {
    try {
      const res = await fetch("/api/admin/scad-events");
      const data = await res.json();
      if (!data.success) return;

      const tbody = document.getElementById("scadEventsTbody");
      if (!tbody) return;

      tbody.innerHTML = "";
      if (data.events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:1.5rem">No active intrusion anomalies detected. System secure.</td></tr>`;
        return;
      }

      data.events.forEach(evt => {
        const tr = document.createElement("tr");
        const time = new Date(evt.timestamp).toLocaleTimeString();
        tr.innerHTML = `
          <td style="font-family:var(--font-mono); font-size:0.75rem">${time}</td>
          <td><span class="tag-severity severity-${evt.severity}">${evt.severity}</span></td>
          <td>${evt.event_description}</td>
          <td style="font-family:var(--font-mono)">${evt.card_uid || 'N/A'}</td>
          <td style="font-family:var(--font-mono); font-size:0.75rem">${evt.ip_address}</td>
        `;
        tbody.appendChild(tr);
      });
    } catch (e) {
      console.warn("Failed fetching SCAD events:", e);
    }
  }

  async fetchHoneyTokens() {
    try {
      const res = await fetch("/api/admin/honey-tokens");
      const data = await res.json();
      if (!data.success) return;

      const tbody = document.getElementById("honeyTokensTbody");
      if (!tbody) return;

      tbody.innerHTML = "";
      data.tokens.forEach(tok => {
        const tr = document.createElement("tr");
        const isTripped = tok.triggered_count > 0;
        tr.innerHTML = `
          <td style="font-family:var(--font-mono); font-weight:600; color:var(--accent-amber)">${tok.token_type}</td>
          <td style="font-family:var(--font-mono); color:#ffffff">${tok.decoy_value}</td>
          <td>${tok.decoy_metadata || ''}</td>
          <td><span style="font-weight:700; color:${isTripped ? 'var(--accent-rose)' : 'var(--accent-emerald)'}">${tok.triggered_count} hits</span></td>
          <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted)">${tok.last_triggered_at ? new Date(tok.last_triggered_at).toLocaleTimeString() : 'Never'}</td>
        `;
        tbody.appendChild(tr);
      });
    } catch (e) {
      console.warn("Failed fetching honey tokens:", e);
    }
  }

  async fetchSmartCards() {
    try {
      const res = await fetch("/api/admin/smart-cards");
      const data = await res.json();
      if (!data.success) return;

      const tbody = document.getElementById("smartCardsTbody");
      if (!tbody) return;

      tbody.innerHTML = "";
      data.cards.forEach(card => {
        const tr = document.createElement("tr");
        const isLocked = card.status === "locked";
        tr.innerHTML = `
          <td style="font-family:var(--font-mono)">#${card.card_id}</td>
          <td><strong>${card.username}</strong></td>
          <td style="font-family:var(--font-mono); color:var(--accent-cyan)">${card.card_uid}</td>
          <td><span class="card-status-pill ${isLocked ? 'card-status-locked' : 'card-status-active'}">${card.status}</span></td>
          <td>
            ${isLocked 
              ? `<button class="btn btn-secondary" style="padding:0.3rem 0.75rem; font-size:0.75rem; width:auto" onclick="window.adminDashboard.unlockCard(${card.card_id})">Unlock Card</button>` 
              : `<span style="color:var(--text-muted); font-size:0.75rem">Operational</span>`}
          </td>
        `;
        tbody.appendChild(tr);
      });
    } catch (e) {
      console.warn("Failed fetching smart cards:", e);
    }
  }

  async unlockCard(cardId) {
    try {
      const res = await fetch("/api/admin/unlock-card", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ card_id: cardId })
      });
      const data = await res.json();
      if (data.success) {
        this.fetchSmartCards();
        this.fetchMetrics();
        this.fetchAuditLogs();
      } else {
        alert("Unlock failed: " + data.message);
      }
    } catch (e) {
      alert("Network error: " + e.message);
    }
  }

  async clearLogs() {
    if (!confirm("Are you sure you want to clear audit logs & reset threat telemetry?")) return;
    try {
      await fetch("/api/admin/clear-logs", { method: "POST" });
      this.fetchMetrics();
      this.fetchAuditLogs();
      this.fetchSCADEvents();
      this.fetchHoneyTokens();
    } catch (e) {
      alert("Clear failed: " + e.message);
    }
  }
}

document.addEventListener("DOMContentLoaded", () => {
  window.adminDashboard = new AdminDashboard();
  window.adminDashboard.init();
});
