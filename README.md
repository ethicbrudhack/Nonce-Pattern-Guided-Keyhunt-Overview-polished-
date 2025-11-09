# 🧪 Pattern-Guided Keyhunt — Prototype (Safe / Corrected)

This repository contains a **corrected, safer prototype** for a pattern-guided key search that demonstrates how simple observational heuristics (from ECDSA `(r,s)` samples) might be used to bias a candidate private-key enumeration.  
**This is an educational research prototype only** — do not use it on keys you do not own or have explicit permission to analyze.

---

## ⚙️ What this project is

A small Python prototype that:

- Generates candidate private keys correctly in the secp256k1 private key space `[1, n-1]`.
- Derives **real Bitcoin addresses** (P2PKH and Bech32 P2WPKH) from each candidate.
- Maintains a bounded sliding window of observed `(r,s)` signature samples.
- Detects *integer* near-dependencies between recent `r` and `s` values using absolute difference thresholds (no floating point).
- When a pattern is detected, biases the next candidate toward a heuristically computed value (simple mean of last two `r` mapped into the key space).
- Logs progress and writes found keys to `found_key.txt` (if any).
- Includes a safe `max_iterations` cap to avoid runaway execution.

This is a prototype to explore research ideas — **not** a production key recovery tool.

---

## 🔧 Files

- `pattern_keyhunt.py` — the main fixed/prototype script (contains the implementation shown in this repo).
- `found_key.txt` — output file written if a matching private key is found.

---

## 🧩 How it works (high level)

1. **Candidate generation**  
   `generate_private_key(k_guess)` maps an integer `k_guess` into the valid private key range `[1, n-1]` (where `n` is secp256k1 group order).

2. **Address derivation**  
   For each candidate key we compute:
   - Legacy P2PKH (`1...`) using `private_key_to_p2pkh_address(priv)`.
   - Native SegWit P2WPKH (`bc1...`) using `private_key_to_bech32(priv)`.

3. **Observation cache**  
   The script keeps the last `WINDOW_SIZE` `(r,s)` samples in `deque`s (bounded memory).

4. **Integer-safe heuristic detection**  
   `integer_near_dependency_detected()` checks absolute integer differences between recent `r` and `s` values and triggers if any pair is within configurable thresholds.

5. **Biasing**  
   If a pattern is found, the next `k_guess` is biased toward a value computed from recent `r` (simple average → mapped into `[1,n-1]`). Otherwise the enumeration proceeds sequentially.

6. **Stop conditions**  
   The loop stops if:
   - A generated address equals the `TARGET_ADDRESS`, or
   - `max_iterations` is reached.

---

## ⚙️ Configurable parameters (top of script)

- `TRANSACTIONS` — example list of observed `(r,s)` samples (integers). Replace with your dataset.
- `TARGET_ADDRESS` — the Bitcoin address you want to match (string).
- `WINDOW_SIZE` — number of recent `(r,s)` to keep for heuristics (default 64).
- `R_DIFF_THRESHOLD`, `S_DIFF_THRESHOLD` — absolute integer thresholds controlling "closeness" detection.
- `MAX_ITERATIONS` — safety cap for the main loop.
- `use_bech32_check` — pass `True` to compare bech32 addresses instead of P2PKH.

---

## ✅ Example usage

Run the script (safe demo):

```bash
python3 pattern_keyhunt.py
Typical console output (progress logging):

2025-11-09 12:00:00 - INFO - Starting pattern-guided keyhunt prototype (safe mode).
2025-11-09 12:00:03 - INFO - iter=1000 k_guess=1000 p2pkh=1Ab... bech32=bc1q...
2025-11-09 12:05:10 - INFO - Detected pattern -> biasing next k_guess to ~0x1a2b...
2025-11-09 12:15:00 - INFO - FOUND matching private key after 12345 iter(s): priv=0xdeadbeef...


If a match is found, found_key.txt will contain the private key and derived addresses.

🛠 Important correctness & implementation notes

Private keys are generated in the correct range [1, n-1] (where n is secp256k1 order) — previous prototypes incorrectly used the curve prime p.

Addresses are real: P2PKH uses Base58Check; Bech32 addresses are built from HASH160(pubkey).

Heuristics are integer-based (absolute difference), avoiding floating-point precision loss on cryptographic integers.

Memory is bounded via deque(maxlen=WINDOW_SIZE).

This prototype uses a very simple bias (avg of last two r) — this is illustrative, not optimal.

❗ Limitations & warnings

This is not a reliable method to recover private keys from arbitrary on-chain data. It is a research/proof-of-concept demonstration only.

The heuristic is simplistic and unlikely to find keys in real networks unless there is a real predictable nonce generation bug and you have sufficient ground truth.

Performance: key enumeration is computationally expensive; this script is single-process and not optimized for brute force.

Security & ethics: never attempt to recover or use keys you are not explicitly authorized to analyze. Unauthorized key recovery is illegal and unethical.

🧾 Dependencies

Install required packages:

pip install ecdsa base58 bech32


(Everything else uses the Python standard library.)

📜 License & Author

MIT License
© 2025 — Author: [ethicbrudhack]

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
