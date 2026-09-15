# IronLedger

**Blockchain-Anchored Digital Forensics and Threat Intelligence Framework for
Industrial Control System Incident Response.**

IronLedger anchors ICS command and sensor-state hashes onto a tamper-evident
ledger (Ethereum Sepolia, via a hash-chained smart contract). When a
dual-layer detection engine (hard physics envelopes + an Isolation Forest
anomaly model) flags anomalous behavior, IronLedger walks the ledger
backward to reconstruct the authentic timeline, exposes any off-chain log
tampering by recomputing and comparing hashes, and correlates the observed
technique signatures against the MITRE ATT&CK for ICS matrix to generate a
threat-attribution hypothesis.

## Project structure

```
frontend/    dashboard UI — plain HTML/CSS/JS, no build step (see frontend/README.md)
backend/     FastAPI service — ledger, anomaly detection, forensics, Sepolia
             anchoring, PDF reports (see backend/README.md)
```

## Quickstart

```bash
# Terminal 1 — backend
cd backend
python3 -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env      # leave blank for local mode, see backend/README.md for Sepolia setup
uvicorn app.main:app --reload --port 8000

# Terminal 2 — frontend
cd frontend
python3 -m http.server 5500
# open http://localhost:5500
```

Click through the four-act stepper (Baseline → Attack Injection → Log
Tampering → Reconstruct) to run the full demo: hash-chained ledger entries,
physics/ML anomaly detection, tamper-evidence via hash mismatch, backward-walk
forensic reconstruction, MITRE ATT&CK correlation, and threat attribution.

## Architecture

1. **ICS simulation** (`backend/app/routers/simulate_router.py`) — a
   four-act narrative (SIS-defeat style attack, in the spirit of
   Triton/HatMan) standing in for a live plant feed.
2. **Blockchain evidence layer** (`backend/contracts/IronLedger.sol`,
   `backend/app/blockchain.py`) — Solidity 0.8.20 contract for Sepolia;
   deterministic SHA-256 commitments `H(source, command, entity, params,
   prevHash)`; tamper detection by recomputing and comparing hashes.
3. **Dual-layer anomaly detection** (`backend/app/anomaly.py`) — hard
   physics thresholds (pressure/temperature/vibration/SIS-valve
   consistency) plus a scikit-learn `IsolationForest`.
4. **Forensic reconstruction & MITRE ATT&CK** (`backend/app/forensics.py`,
   `backend/app/threat_intel.py`) — backward-walk from an incident trigger
   to root cause; technique correlation (T0855, T0836, T0831, T0879, T0815,
   T0888); threat-actor attribution scoring (Xenotime, Sandworm, Equation
   Group, Volt Typhoon).
5. **Report generation** (`backend/app/reports.py`) — court-ready PDF via
   reportlab.
6. **Dashboard** (`frontend/`) — five views (Dashboard, Ledger Explorer,
   Anomaly Detection, Forensic Timeline, ATT&CK Matrix) as a thin client of
   the API above.

See `frontend/README.md` and `backend/README.md` for full details, design
rationale, and known simplifications.

## Security note

`.env` is git-ignored — never commit real Sepolia RPC URLs or private keys.
`backend/.env.example` documents the required variables; copy it to `.env`
and fill in your own.
