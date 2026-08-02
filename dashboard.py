"""Live results dashboard for Agent Trap Lab.

Serves a single-page HTML dashboard that auto-refreshes and shows:
  - Coverage matrix (baseline vs defended)
  - Per-category defense rates
  - Individual trap results with expandable details
  - Real-time run status

Usage:
  python dashboard.py                    # Serve dashboard on port 8090
  python dashboard.py --port 9000       # Custom port
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from flask import Flask, jsonify, render_template_string

app = Flask(__name__)
RESULTS_DIR = Path("results")

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Agent Trap Lab — Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {
    --bg: #0a0e17; --bg2: #111827; --bg3: #1a2332;
    --fg: #e2e8f0; --fg2: #94a3b8; --fg3: #64748b;
    --green: #22c55e; --red: #ef4444; --yellow: #eab308;
    --cyan: #06b6d4; --blue: #3b82f6; --purple: #a855f7;
    --border: #1e293b;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
    background: var(--bg); color: var(--fg);
    padding: 20px; line-height: 1.5;
  }
  h1 { font-size: 1.4rem; color: var(--cyan); margin-bottom: 4px; }
  .subtitle { color: var(--fg3); font-size: 0.8rem; margin-bottom: 20px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card {
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px;
  }
  .card h3 { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--fg3); margin-bottom: 8px; }
  .stat { font-size: 2rem; font-weight: bold; }
  .stat.green { color: var(--green); }
  .stat.red { color: var(--red); }
  .stat.yellow { color: var(--yellow); }
  .stat.cyan { color: var(--cyan); }
  .stat-label { font-size: 0.7rem; color: var(--fg3); }

  table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  th { text-align: left; padding: 8px 12px; color: var(--fg3); border-bottom: 2px solid var(--border);
       font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; }
  td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
  tr:hover { background: var(--bg3); }

  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 0.7rem; font-weight: bold; text-transform: uppercase;
  }
  .badge-defended { background: #052e16; color: var(--green); border: 1px solid #166534; }
  .badge-gap { background: #450a0a; color: var(--red); border: 1px solid #991b1b; }
  .badge-clean { background: var(--bg3); color: var(--fg3); border: 1px solid var(--border); }
  .badge-fp { background: #422006; color: var(--yellow); border: 1px solid #854d0e; }
  .badge-blocked { background: #083344; color: var(--cyan); border: 1px solid #155e75; }
  .badge-compromised { background: #450a0a; color: var(--red); border: 1px solid #991b1b; }
  .badge-pass { background: #052e16; color: var(--green); border: 1px solid #166534; }

  .cat-bar { display: flex; gap: 4px; align-items: center; margin: 4px 0; }
  .cat-fill { height: 18px; border-radius: 3px; min-width: 4px; transition: width 0.3s; }
  .cat-fill.green { background: var(--green); }
  .cat-fill.red { background: var(--red); }
  .cat-fill.yellow { background: var(--yellow); }
  .cat-label { font-size: 0.7rem; color: var(--fg2); min-width: 140px; }
  .cat-pct { font-size: 0.7rem; color: var(--fg3); min-width: 40px; text-align: right; }

  .status-bar {
    background: var(--bg2); border: 1px solid var(--border); border-radius: 8px;
    padding: 12px 16px; margin-bottom: 20px; display: flex; align-items: center; gap: 12px;
  }
  .pulse {
    width: 8px; height: 8px; border-radius: 50%; background: var(--green);
    animation: pulse 2s infinite;
  }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
  .status-text { font-size: 0.8rem; color: var(--fg2); }
  .no-data { color: var(--fg3); text-align: center; padding: 60px; font-size: 0.9rem; }
  .refresh-note { font-size: 0.65rem; color: var(--fg3); }
</style>
</head>
<body>

<h1>AGENT TRAP LAB</h1>
<p class="subtitle">StegOFF Defense Coverage Dashboard <span class="refresh-note">(auto-refreshes every 5s)</span></p>

<div id="status-bar" class="status-bar">
  <div class="pulse"></div>
  <span class="status-text">Loading...</span>
</div>

<div id="metrics" class="grid"></div>
<div id="categories" class="card" style="margin-bottom: 24px;"></div>
<div id="matrix" class="card"></div>

<script>
async function load() {
  try {
    const resp = await fetch('/api/latest');
    const data = await resp.json();

    if (!data.coverage) {
      document.getElementById('status-bar').innerHTML =
        '<div class="pulse" style="background:var(--yellow)"></div>' +
        '<span class="status-text">No coverage data yet. Run: python lab.py run --compare</span>';
      document.getElementById('matrix').innerHTML = '<div class="no-data">Waiting for comparison run...</div>';
      return;
    }

    const c = data.coverage;
    const s = c.summary;

    // Status
    document.getElementById('status-bar').innerHTML =
      '<div class="pulse" style="background:var(--green)"></div>' +
      '<span class="status-text">Latest coverage: ' + (data.coverage_file || 'loaded') + '</span>';

    // Metrics cards
    document.getElementById('metrics').innerHTML = `
      <div class="card">
        <h3>Total Traps</h3>
        <div class="stat cyan">${s.total_traps}</div>
        <div class="stat-label">${s.baseline_compromised} compromised baseline</div>
      </div>
      <div class="card">
        <h3>StegOFF Blocked</h3>
        <div class="stat green">${s.stegoff_blocked}</div>
        <div class="stat-label">${(s.block_rate * 100).toFixed(0)}% block rate</div>
      </div>
      <div class="card">
        <h3>True Defense Rate</h3>
        <div class="stat ${s.true_defense_rate >= 0.8 ? 'green' : s.true_defense_rate >= 0.5 ? 'yellow' : 'red'}">${(s.true_defense_rate * 100).toFixed(0)}%</div>
        <div class="stat-label">${s.defended} of ${s.baseline_compromised} compromised blocked</div>
      </div>
      <div class="card">
        <h3>Coverage Gaps</h3>
        <div class="stat ${s.coverage_gaps === 0 ? 'green' : 'red'}">${s.coverage_gaps}</div>
        <div class="stat-label">${s.false_positives} false positives</div>
      </div>
    `;

    // Category bars
    const cats = c.per_category;
    let catHtml = '<h3 style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.1em;color:var(--fg3);margin-bottom:12px;">Defense by Category</h3>';
    for (const [cat, info] of Object.entries(cats)) {
      const rate = info.baseline_compromised > 0 ? info.defended / info.baseline_compromised : 1;
      const pct = (rate * 100).toFixed(0);
      const barColor = rate >= 0.8 ? 'green' : rate >= 0.5 ? 'yellow' : 'red';
      catHtml += `<div class="cat-bar">
        <span class="cat-label">${cat}</span>
        <div class="cat-fill ${barColor}" style="width: ${Math.max(pct, 4)}%;"></div>
        <span class="cat-pct">${pct}%</span>
        <span class="stat-label" style="margin-left:8px">${info.defended}/${info.baseline_compromised} defended, ${info.gaps} gaps</span>
      </div>`;
    }
    document.getElementById('categories').innerHTML = catHtml;

    // Trap matrix table
    let tableHtml = '<h3 style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.1em;color:var(--fg3);margin-bottom:12px;">Trap Coverage Matrix</h3>';
    tableHtml += '<table><thead><tr><th>Trap ID</th><th>Category</th><th>Baseline</th><th>StegOFF</th><th>Defended</th><th>Verdict</th></tr></thead><tbody>';
    for (const t of c.traps) {
      const blBadge = t.baseline_compromised
        ? '<span class="badge badge-compromised">compromised</span>'
        : '<span class="badge badge-pass">clean</span>';
      const blockBadge = t.stegoff_blocked
        ? '<span class="badge badge-blocked">blocked</span>'
        : '<span class="badge badge-clean">passed</span>';
      const defBadge = t.defended_compromised
        ? '<span class="badge badge-compromised">compromised</span>'
        : '<span class="badge badge-pass">clean</span>';
      const verdictClass = {
        'DEFENDED': 'badge-defended', 'GAP': 'badge-gap',
        'FALSE_POS': 'badge-fp', 'CLEAN': 'badge-clean',
      }[t.verdict] || 'badge-clean';
      tableHtml += `<tr>
        <td style="color:var(--cyan)">${t.trap_id}</td>
        <td>${t.category}</td>
        <td>${blBadge}</td>
        <td>${blockBadge}</td>
        <td>${defBadge}</td>
        <td><span class="badge ${verdictClass}">${t.verdict}</span></td>
      </tr>`;
    }
    tableHtml += '</tbody></table>';
    document.getElementById('matrix').innerHTML = tableHtml;

  } catch(e) {
    document.getElementById('status-bar').innerHTML =
      '<div class="pulse" style="background:var(--red)"></div>' +
      '<span class="status-text">Error loading data: ' + e.message + '</span>';
  }
}

load();
setInterval(load, 5000);
</script>
</body>
</html>"""


@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/latest")
def api_latest():
    """Return the latest coverage and analysis data."""
    if not RESULTS_DIR.exists():
        return jsonify({"coverage": None, "message": "No results directory"})

    # Find latest coverage file
    coverage_files = sorted(RESULTS_DIR.glob("coverage_*.json"), reverse=True)
    coverage_data = None
    coverage_file = None
    if coverage_files:
        coverage_file = coverage_files[0].name
        with open(coverage_files[0]) as f:
            coverage_data = json.load(f)

    return jsonify({
        "coverage": coverage_data,
        "coverage_file": coverage_file,
    })


if __name__ == "__main__":
    import click

    @click.command()
    @click.option("--port", default=8090, help="Dashboard port")
    @click.option("--host", default="0.0.0.0", help="Dashboard host")
    def main(port: int, host: str):
        print(f"Dashboard: http://localhost:{port}")
        app.run(host=host, port=port, debug=False)

    main()
