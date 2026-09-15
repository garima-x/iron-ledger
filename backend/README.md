# IronLedger — Backend (FastAPI)

Real ledger storage, hashing, physics/ML anomaly detection, forensic
reconstruction, MITRE ATT&CK scoring, and PDF report generation — with
optional real anchoring to Ethereum Sepolia via `web3.py`.

## Quick start (no Sepolia setup required)

```bash
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env       # leave SEPOLIA_RPC_URL/PRIVATE_KEY/CONTRACT_ADDRESS blank
uvicorn app.main:app --reload --port 8000
```

Open **http://localhost:8000/docs** for interactive API docs, or drive it
straight from the terminal:

```bash
curl -X POST http://localhost:8000/simulate/reset
curl -X POST http://localhost:8000/simulate/act/1
curl -X POST http://localhost:8000/simulate/act/2
curl -X POST http://localhost:8000/simulate/act/3
curl -X POST http://localhost:8000/simulate/act/4
curl http://localhost:8000/ledger/blocks
curl http://localhost:8000/mitre/techniques
curl http://localhost:8000/forensics/attribution
curl http://localhost:8000/reports/1.pdf -o report.pdf   # start_block_id = any block id
```

Without Sepolia configured, the app runs in **local mode**: every block is
still hashed and chained exactly the same way, tamper detection still works,
and `GET /` will report `"chain": {"configured": false, ...}` so you always
know which mode you're in.

## Wiring up real Sepolia anchoring

1. **Get an RPC endpoint.** Free tier from [Infura](https://infura.io) or
   [Alchemy](https://alchemy.com) — create a project, pick "Sepolia," copy
   the HTTPS URL into `SEPOLIA_RPC_URL`.
2. **Get a throwaway wallet + test ETH.** Create a fresh wallet (MetaMask is
   fine) — do **not** use a real wallet with real funds. Fund it from a
   faucet, e.g. [Sepolia Faucet (Google Cloud)](https://cloud.google.com/application/web3/faucet/ethereum/sepolia)
   or [sepoliafaucet.com](https://sepoliafaucet.com). Export its private key
   into `PRIVATE_KEY` (with or without the `0x` prefix — web3.py accepts
   both).
3. **Deploy `contracts/IronLedger.sol`.** Easiest path: paste it into
   [Remix IDE](https://remix.ethereum.org), compile with Solidity `0.8.20`,
   deploy via "Injected Provider" (MetaMask, connected to Sepolia, using the
   same funded wallet). Copy the deployed address into `CONTRACT_ADDRESS`.
   `contracts/IronLedgerABI.json` already matches this contract — you don't
   need to re-export the ABI from Remix.
4. Restart the server. `GET /` should now show `"configured": true,
   "connected": true`. Every `POST /ledger/blocks` (including via
   `/simulate/act/{n}`) will submit a real Sepolia transaction; the response
   includes `tx_hash` and `onchain_index`, and you can look the transaction
   up on [sepolia.etherscan.io](https://sepolia.etherscan.io).

If the RPC call or transaction fails for any reason (no test ETH, wrong
network, bad key), the block is still stored locally with
`anchor_error` explaining why — the forensic logic never breaks just
because the chain call did.

## API surface

| Endpoint | Purpose |
|---|---|
| `POST /ledger/blocks` | Hash + (optionally) anchor a new block |
| `GET /ledger/blocks` / `/{id}` | List / inspect blocks |
| `POST /ledger/blocks/{id}/tamper` | Simulate an off-chain historian rewrite |
| `GET /ledger/verify` | Recompute every block's hash and flag mismatches |
| `POST /telemetry/evaluate` | Physics-envelope + Isolation Forest scoring |
| `GET /anomalies` | Stored anomaly log |
| `POST /forensics/reconstruct` | Backward-walk from a block to root cause |
| `GET /forensics/attribution` | Threat-actor scoring from observed techniques |
| `GET /mitre/techniques` | ATT&CK for ICS matrix + hit status |
| `GET /reports/{block_id}.pdf` | Court-ready PDF report |
| `POST /simulate/act/{1-4}` | Run the four-act demo narrative server-side |
| `POST /simulate/reset` | Wipe the ledger/anomaly tables for a fresh run |

## Notes / known simplifications

- `_sim` in `simulate_router.py` is a single module-level dict — fine for a
  one-narrative coursework demo, not safe for concurrent multi-user use.
- The Isolation Forest is trained on synthetic baseline telemetry generated
  at startup (`anomaly.py: _baseline_sample`), not on real historian data —
  swap that for a real training set if you want to demonstrate proper model
  validation in the write-up.
- `ACTOR_PROFILES` in `threat_intel.py` are illustrative weights, not derived
  from actual incident-attribution literature — worth a caveat in your
  report if a grader asks where the numbers came from.
- CORS defaults to `*` for ease of local development; tighten
  `CORS_ORIGINS` in `.env` if you deploy this anywhere public.
