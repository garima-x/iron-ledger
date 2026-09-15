# IronLedger — Frontend

Blockchain-anchored digital forensics & threat intelligence dashboard for Industrial
Control System (ICS) incident response. This is the frontend layer of the framework:
a plain HTML/CSS/JS dashboard (no build step) that's a thin client of the real
FastAPI backend in `/ironledger-backend` — every block, hash, anomaly, and score
shown here is a live API response, not something computed in the browser.

## Why it looks the way it does

Most ICS/SOC tooling defaults to a dark terminal aesthetic — the implicit argument
being "this is serious, so it should look like a hacker screen." IronLedger's whole
thesis is the opposite: the ledger's mathematics is what proves tampering, not a
flashing red UI. So the design leans toward something closer to a claims or legal
record system — calm, cream/stone/navy, serif headers — the idea being that the
system should read as *evidentiary*, not alarmist. Alert color (a muted brick red)
is reserved for real state changes only, never decoration.

### Design tokens (`styles.css`, top of file)

| Token | Hex | Role |
|---|---|---|
| `--bg` | `#F6F2F0` | page background |
| `--card` | `#FFFDFC` | card surfaces |
| `--navy` / `--navy-deep` | `#3F5066` / `#2B3648` | primary UI, sidebar, headings |
| `--blush` | `#E9D9D8` | sidebar text tint, hover accents |
| `--stone` | `#DCD8D2` | dividers, inactive fills |
| `--critical` | `#9C4A3C` | breach / tamper / high-severity only |
| `--warning` | `#B98B4E` | medium severity |
| `--safe` | `#6E8271` | verified / nominal state |

Typography: a serif (`Iowan Old Style`/`Palatino`/`Georgia` stack) for headings —
deliberately chosen to read like a court document rather than a SaaS product — a
system sans for UI text, and monospace *only* where it's functionally necessary
(hashes, block IDs), not as a general "technical" decoration.

## File structure

```
index.html   sidebar nav + topbar act-stepper + connection banner + five view sections
styles.css   design tokens and all component styling
app.js       API client, state derived from backend responses, and all rendering logic
```

No bundler, no npm dependencies, no CDN calls at runtime. Requires the backend
(`/ironledger-backend`) running and reachable — see "Running the connected
pair" below. Serve this folder with `python3 -m http.server` rather than
opening `index.html` directly, to avoid `file://`-origin fetch quirks.

## The five views

1. **Dashboard** — live plant telemetry (pressure/temp/vibration), the ML
   anomaly score, a monitoring chart, recent ledger entries, SIS/valve state,
   and active alerts.
2. **Ledger Explorer** — every anchored block: source, command, entity,
   `prevHash`/`hash`, and a status badge. Clicking a row opens the block detail
   panel, which shows the exact preimage string
   `H(source, command, entity, params, prevHash)` and, for a tampered block,
   the off-chain claimed record next to the recomputed hash that no longer
   matches the on-chain anchor.
3. **Anomaly Detection** — the physics-envelope threshold table (hard limits
   on pressure/temp/vibration/SIS-valve consistency) alongside an Isolation
   Forest–style anomaly gauge, mirroring the dual-layer detection approach
   described in the project brief.
4. **Forensic Timeline** — a backward-walk reconstruction from the incident
   trigger back to the root-cause entry, flagging the tampered node and the
   root node distinctly, plus a threat-attribution panel and a "Generate
   Court-Ready Report" button (uses `window.print()` — no PDF library needed).
5. **ATT&CK Matrix** — the six MITRE ATT&CK for ICS techniques referenced in
   the project brief (T0855, T0836, T0831, T0879, T0815, T0888), highlighted
   as they're triggered by the simulation.

## How the four-act demo works

A stepper in the topbar drives one shared narrative — each click calls
`POST /simulate/act/{n}` on the backend, then the frontend re-fetches
everything (`/ledger/blocks`, `/anomalies`, `/mitre/techniques`,
`/ledger/verify`) and re-renders from the response:

1. **Baseline** — ~12 nominal telemetry blocks, hashed and chained.
2. **Attack Injection** — SIS interlock disabled, vent valve forced shut,
   pressure/temperature pushed past the hard thresholds, ML score spikes,
   an alarm gets suppressed. Each step maps to a MITRE technique.
3. **Log Tampering** — the valve-closure block's *off-chain* record is
   rewritten to look like a benign heartbeat. Its hash is recomputed from
   the claimed off-chain data and — because the content changed — no longer
   matches the hash that was anchored on-chain. This mismatch *is* the tamper
   detection; it isn't a hardcoded flag, and it's computed server-side.
4. **Reconstruct** — the backend walks the chain from the incident trigger
   back to the root-cause block, then scores threat actors (Xenotime,
   Sandworm, Equation Group, Volt Typhoon) by weighted overlap with the
   MITRE techniques observed — normalized against the strongest match, so
   the result is a genuine relative confidence ranking rather than every
   actor hitting 100%.

The backend's simulation state persists server-side (`GET /simulate/state`),
so reloading the page or opening a second tab picks up wherever the demo
currently is, rather than resetting silently.

## Known simplifications (by design)

- The backend's `_sim` act tracker is a single module-level state — fine for
  a one-narrative coursework demo, not safe for concurrent multi-user use
  (see `/ironledger-backend/README.md`).
- The ML "Isolation Forest" is trained on synthetic baseline telemetry
  generated at backend startup, not real historian data.
- MITRE technique → threat-actor weighting (`ACTOR_PROFILES` in the
  backend's `threat_intel.py`) is a simplified scoring model for
  demonstration; a real attribution engine would want to justify those
  weights from actual incident reporting (e.g. Dragos/MITRE ICS ATT&CK group
  profiles) rather than hand-picked numbers.
- Without Sepolia configured in the backend's `.env`, blocks are hashed and
  chained exactly the same way but not actually anchored on-chain — the
  chain-status area and each block's detail panel show which mode you're in.

## Next: backend integration

**This is done** — see `/ironledger-backend`. The frontend is now a thin
client of the real FastAPI backend: every ledger block, hash, anomaly, MITRE
hit, and attribution score you see is a live API response, not a local
simulation. The four-act stepper just tells the backend which act to run
next (`POST /simulate/act/{n}`); everything else is fetch + render.

### Running the connected pair

```bash
# Terminal 1 — backend
cd ironledger-backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # leave blank for local mode, or fill in Sepolia details
uvicorn app.main:app --reload --port 8000

# Terminal 2 — frontend
cd ironledger
python3 -m http.server 5500
# open http://localhost:5500
```

The sidebar shows an "API base" field (defaults to `http://localhost:8000`)
and a live connection status — if the backend isn't reachable, a banner
explains why and offers a retry, and the act-stepper/report buttons are
disabled rather than silently failing. Chain integrity, the ledger table,
anomalies, the MITRE matrix, forensic reconstruction, and the "Generate
Court-Ready Report" button (now a real PDF from the backend, not
`window.print()`) all read from the live API on every act.

If you open `index.html` directly via `file://` instead of a local server,
most browsers still allow the cross-origin fetch to `localhost:8000` since
the backend's CORS is permissive — but serving it (as above) avoids
occasional `file://`-origin quirks and is what I tested against.
