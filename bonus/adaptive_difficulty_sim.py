"""
Run: python adaptive_difficulty_sim.py
"""

import random
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lab3_blockchain'))
from blockchain import (
    Chain, Block, GENESIS_TIMESTAMP, DEFAULT_DIFFICULTY,
    TARGET_BLOCK_TIME as T, median_time_past,
)


def _add(chain, clock, hashrate=1.0, lie=False):
    difficulty = chain.compute_next_difficulty()
    expected   = T * (2 ** (difficulty - DEFAULT_DIFFICULTY)) / hashrate
    solvetime  = max(1, int(random.expovariate(1.0 / expected)))
    clock     += solvetime
    mtp_floor  = median_time_past(chain.tip, chain._by_hash) + 1
    timestamp  = max(clock + (100 * T if lie else 0), mtp_floor)
    prev_ts    = chain.tip.timestamp
    clamped    = max(1, min(timestamp - prev_ts, 6 * T))
    height     = chain.tip.height + 1
    block = Block(
        height    = height,
        prev_hash = chain.tip.hash,
        _txs_hash = b"\x00" * 32,
        timestamp = timestamp,
        difficulty = difficulty,
        nonce     = 0,
        hash      = height.to_bytes(32, "big"),
        tx_hashes = [],
    )
    chain._store(block)
    chain._tip = block
    return block, clock, clamped


def run_scenario(title, n_blocks, hashrate_fn, liar_fn=None, seed=0):
    random.seed(seed)
    liar_fn = liar_fn or (lambda i: False)
    chain   = Chain()
    clock   = GENESIS_TIMESTAMP + 1000

    print(f"\n=== {title} ===")
    print(f" block | difficulty | solvetime (clamped)")
    print("-" * 42)

    for i in range(1, n_blocks + 1):
        block, clock, clamped = _add(chain, clock, hashrate_fn(i), liar_fn(i))
        note = "  <- lie" if liar_fn(i) else ""
        print(f"  {i:>3}  |     {block.difficulty:>2}     |   {clamped:>5}s{note}")


if __name__ == "__main__":

    # Scenario 1: steady hashpower.
    # Warmup is 16 blocks; difficulty should stay at DEFAULT_DIFFICULTY throughout.
    run_scenario(
        "Scenario 1: steady hashpower",
        n_blocks    = 30,
        hashrate_fn = lambda i: 1.0,
    )

    # Scenario 2: 10x hashpower jump at block 20.
    # Difficulty should climb then settle near DEFAULT+3 (log2(10) ≈ 3.32 bits).
    run_scenario(
        "Scenario 2: 10x hashpower jump at block 20",
        n_blocks    = 70,
        hashrate_fn = lambda i: 10.0 if i >= 20 else 1.0,
    )

    # Scenario 3: 10x hashpower drop at block 20.
    # Difficulty should fall then settle near DEFAULT-3 (log2(10) ≈ 3.32 bits).
    run_scenario(
        "Scenario 3: 10x hashpower drop at block 20",
        n_blocks    = 70,
        hashrate_fn = lambda i: 0.1 if i >= 20 else 1.0,
    )

    # Scenario 4: one node lies about its timestamp every 3rd block.
    # Net-balance voting cancels liar contributions; difficulty should stay at DEFAULT_DIFFICULTY.
    run_scenario(
        "Scenario 4: one node lies every 3rd block",
        n_blocks    = 30,
        hashrate_fn = lambda i: 1.0,
        liar_fn     = lambda i: i % 3 == 0,
    )
