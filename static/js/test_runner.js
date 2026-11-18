/**
 * QuantumShield Security Scenario Test Battery Runner
 * Executes all 9 security validation scenarios with real-time UI reporting
 */

class TestRunner {
  constructor() {
    this.isRunning = false;
  }

  init() {
    const runAllBtn = document.getElementById("runAllTestsBtn");
    if (runAllBtn) {
      runAllBtn.addEventListener("click", () => this.runAll());
    }

    // Bind individual test buttons
    for (let i = 1; i <= 9; i++) {
      const btn = document.getElementById(`runTestBtn${i}`);
      if (btn) {
        btn.addEventListener("click", () => this.runSingleScenario(i));
      }
    }
  }

  async runAll() {
    if (this.isRunning) return;
    this.isRunning = true;

    const btn = document.getElementById("runAllTestsBtn");
    btn.disabled = true;
    btn.innerHTML = `<span class="status-dot anim-pulse"></span> Executing 9 Security Scenarios...`;

    // Clear statuses
    for (let i = 1; i <= 9; i++) {
      const badge = document.getElementById(`badgeScenario${i}`);
      if (badge) {
        badge.textContent = "RUNNING...";
        badge.className = "status-badge status-warning";
      }
    }

    try {
      const res = await fetch("/api/test/run-all", { method: "POST" });
      const data = await res.json();

      if (data.results) {
        data.results.forEach(r => {
          this.updateScenarioDisplay(r);
        });
      }

      const summaryCard = document.getElementById("testSummaryCard");
      if (summaryCard) {
        summaryCard.style.display = "block";
        const scoreEl = document.getElementById("testScoreDisplay");
        if (scoreEl) {
          scoreEl.textContent = `${data.passed_count} / ${data.total_count} PASSED`;
          scoreEl.style.color = data.all_passed ? "var(--accent-emerald)" : "var(--accent-rose)";
        }
      }
    } catch (e) {
      alert("Error executing test battery: " + e.message);
    } finally {
      this.isRunning = false;
      btn.disabled = false;
      btn.innerHTML = `Run Complete Security Test Battery (9 Scenarios)`;
    }
  }

  async runSingleScenario(scenarioId) {
    const badge = document.getElementById(`badgeScenario${scenarioId}`);
    if (badge) {
      badge.textContent = "RUNNING...";
      badge.className = "status-badge status-warning";
    }

    try {
      const res = await fetch(`/api/test/run-scenario/${scenarioId}`, { method: "POST" });
      const data = await res.json();
      this.updateScenarioDisplay(data);
    } catch (e) {
      if (badge) {
        badge.textContent = "ERROR";
        badge.className = "status-badge status-danger";
      }
    }
  }

  updateScenarioDisplay(scenario) {
    const badge = document.getElementById(`badgeScenario${scenario.id}`);
    const details = document.getElementById(`detailsScenario${scenario.id}`);

    if (badge) {
      badge.textContent = scenario.status;
      badge.className = `status-badge ${scenario.status === 'PASS' ? 'status-active' : 'status-danger'}`;
      if (scenario.status === 'PASS') {
        badge.style.background = 'rgba(16, 185, 129, 0.2)';
        badge.style.color = 'var(--accent-emerald)';
        badge.style.borderColor = 'var(--accent-emerald)';
      } else {
        badge.style.background = 'rgba(244, 63, 94, 0.2)';
        badge.style.color = 'var(--accent-rose)';
        badge.style.borderColor = 'var(--accent-rose)';
      }
    }

    if (details) {
      details.textContent = scenario.details;
      details.style.display = "block";
    }
  }
}

document.addEventListener("DOMContentLoaded", () => {
  window.testRunner = new TestRunner();
  window.testRunner.init();
});
