#!/usr/bin/env python3
"""
Fixed, safer prototype: pattern-guided key search using observed (r,s) samples.

Notes:
- This is an educational / research prototype. Do NOT use on keys you do not own.
- The script now:
  * generates candidate private keys in the correct range [1, n-1]
  * derives real Bitcoin P2PKH and Bech32 addresses for verification
  * uses integer-safe heuristics (absolute difference thresholds) to detect
    simple linear/near-linear relationships between r and s samples
  * keeps bounded sliding windows (deque) to avoid unbounded memory growth
  * provides a max_iterations limit to avoid infinite loops
"""

import hashlib
import logging
from collections import deque
import base58
import bech32
import ecdsa

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Example observed signature dataset (r,s) pairs (hex constants converted to int)
TRANSACTIONS = [
    {"r": 0x27c90531406bbf08bd6325b06fe0ac32e61a66f3d8b2762a7bf2ac6c13e76ddc, "s": 0x096ddba45472fe9cca48753e7ca89b70ef358badbd458e08ef77fc79a85d7ae8},
    {"r": 0x29e2eee3a7066084e2ab775cad377c2a46d69d25aad5061327a44c6032d22ff6, "s": 0x2c361e12822e52c27b16fdce05214cb10173b2dab3098acc3724e89b9bb413e6},
    {"r": 0xab9467e44699c0ab5ee2da6389e1646725a03bd66433eb99e531e45d76476ee0, "s": 0x59098b9fe30776049508f91eea10e4a9972eec2c1afe79674379578447b7aa46},
    {"r": 0xba4cbf9de2d8f8cec6ace7fd8fde68b6bb247a3494618f0684a07542557d8dd1, "s": 0x6a8dd246334494bbb852c19e885af8b951e90983438cd6eef7daf01ba2a21453},
    {"r": 0xa674f3ced3e25621cde299d20a700ccab080eb8352db313c5e039473ae48df83, "s": 0x57d8156cb1f7d1b390a13bc008bb3f2478d5552d00cc75215f21bbef866bec55},
    {"r": 0x0de23453b8a730469c59071ed5cf28e4ea1a55d73ceb476aa1b268ddb4d9470a, "s": 0x5d5968a944894476b24e0e37a391fa9fa2b7a07457d91e00bec2a118bd51edd6},
    {"r": 0x0ea5de69f993b8d45df047375c024ee1de15d0e74ce724d620d9cb8af0a33b6b, "s": 0x09489be3c7507a53d0e9d2a2fc218bea2fe3515e57d6abf67c97ba1541a21bbf},
    {"r": 0xe628e3fd2726267d636274b3de47e04d84093faae46483739eefec0022b7eb57, "s": 0x3b14eb0958eafe03d5b74c62646145439111d4a4b59a684ad9f7eead5e3a7054},
    {"r": 0xf6c4e452854173e522b7d30d0072eb162101367e23f00956ad9c63c00baef6d5, "s": 0x246bdd9b1f92067713b9566d7a6bafa2ba43d4f5f07ec3f0bef8e6de78d39cd8},
    {"r": 0xab9467e44699c0ab5ee2da6389e1646725a03bd66433eb99e531e45d76476ee0, "s": 0x59098b9fe30776049508f91eea10e4a9972eec2c1afe79674379578447b7aa46},
]

# Target address to find (example). Make sure you use the proper format matching the address type you generate.
TARGET_ADDRESS = "1612PT2zpMCMRwJsaR9YYs8YPgtYCPKrYe"  # Example P2PKH-like (starts with '1')

# secp256k1 group order (n)
from ecdsa.ecdsa import generator_secp256k1
n = generator_secp256k1.order()

# Sliding window sizes and thresholds
WINDOW_SIZE = 64          # keep recent samples only
R_DIFF_THRESHOLD = 1 << 16   # absolute difference threshold for r (tunable)
S_DIFF_THRESHOLD = 1 << 16   # absolute difference threshold for s (tunable)
MAX_ITERATIONS = 200000     # safety cap for loop iterations

# Use deques for bounded memory
r_deque = deque(maxlen=WINDOW_SIZE)
s_deque = deque(maxlen=WINDOW_SIZE)
cache_rs = deque(maxlen=WINDOW_SIZE)

# === Helpers ===

def generate_private_key(k_guess: int) -> int:
    """
    Produce a candidate private key in the valid range [1, n-1].
    Simple deterministic mapping for prototyping: map k_guess into the group order.
    """
    return (k_guess % (n - 1)) + 1

def private_key_to_p2pkh_address(priv: int) -> str:
    """
    Derive a P2PKH (legacy) Bitcoin address from private key.
    """
    sk = ecdsa.SigningKey.from_secret_exponent(priv, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pub = b'\x04' + vk.to_string()  # uncompressed
    h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
    payload = b'\x00' + h160  # mainnet P2PKH
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

def private_key_to_bech32(priv: int) -> str:
    """
    Derive a native segwit (P2WPKH) bech32 address from private key.
    """
    sk = ecdsa.SigningKey.from_secret_exponent(priv, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pub = b'\x04' + vk.to_string()
    h160 = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
    # bech32.encode expects witness program converted into 5-bit -- library handles that
    return bech32.encode("bc", 0, list(h160))

def integer_near_dependency_detected(r_vals, s_vals, r_thresh=R_DIFF_THRESHOLD, s_thresh=S_DIFF_THRESHOLD) -> bool:
    """
    Detect simple near-equality / linear-like behaviour using integer absolute differences.
    Returns True if any pair of recent (r,s) are 'close' by thresholds.
    """
    L = len(r_vals)
    if L < 2:
        return False
    for i in range(L):
        ri = r_vals[i]
        si = s_vals[i]
        for j in range(i+1, L):
            rj = r_vals[j]
            sj = s_vals[j]
            if abs(ri - rj) <= r_thresh and abs(si - sj) <= s_thresh:
                logging.debug(f"Near-equal pair found: i={i}, j={j}, |Δr|={abs(ri-rj)}, |Δs|={abs(si-sj)}")
                return True
    return False

# === Main loop ===

def attack_loop(target_address: str,
                max_iterations: int = MAX_ITERATIONS,
                use_bech32_check: bool = False):
    """
    Main prototype loop:
     - generate private keys from k_guess
     - compute addresses (P2PKH and optionally Bech32)
     - compare to target
     - collect recent r,s and try integer-based heuristic to bias next guess
    """
    logging.info("Starting pattern-guided keyhunt prototype (safe mode).")
    k_guess = 1
    iterations = 0

    while iterations < max_iterations:
        iterations += 1
        priv = generate_private_key(k_guess)
        p2pkh = private_key_to_p2pkh_address(priv)
        bech = private_key_to_bech32(priv)

        # Check address match (choose which format to compare)
        if p2pkh == target_address or (use_bech32_check and bech == target_address):
            logging.info(f"FOUND matching private key after {iterations} iter(s): priv={hex(priv)}")
            with open("found_key.txt", "w") as f:
                f.write(f"private_key: {hex(priv)}\n")
                f.write(f"p2pkh: {p2pkh}\n")
                f.write(f"bech32: {bech}\n")
            return True

        # Log occasional progress
        if iterations % 1000 == 0:
            logging.info(f"iter={iterations} k_guess={k_guess} p2pkh={p2pkh} bech32={bech}")

        # Update observed sample caches (simulate adding latest TRANSACTIONS samples)
        for tx in TRANSACTIONS:
            r_deque.append(tx["r"])
            s_deque.append(tx["s"])
            cache_rs.append((tx["r"], tx["s"]))

        # If we detect a near-integer dependency in recent r,s, bias next guesses
        if integer_near_dependency_detected(list(r_deque), list(s_deque)):
            # simple bias: set next guess to average of last two r's modulo n
            try:
                avg_r = (r_deque[-1] + r_deque[-2]) // 2
                # map avg_r into keyspace [1, n-1]
                biased_guess = (avg_r % (n - 1)) + 1
                logging.info(f"Detected pattern -> biasing next k_guess to ~{biased_guess}")
                k_guess = biased_guess
            except Exception as e:
                logging.warning(f"Biasing failed: {e}; fallback to sequential increment.")
                k_guess += 1
        else:
            k_guess += 1

    logging.info("Reached max_iterations without finding a match.")
    return False

if __name__ == "__main__":
    # Run with safety caps; set use_bech32_check True if target is bech32
    attack_loop(TARGET_ADDRESS, max_iterations=50000, use_bech32_check=False)
