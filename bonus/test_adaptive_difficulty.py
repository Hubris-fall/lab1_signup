import random
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lab3_blockchain'))
from blockchain import (
    Chain, Block, GENESIS_TIMESTAMP, DEFAULT_DIFFICULTY,
    TARGET_BLOCK_TIME as T, VOTE_WINDOW, MTP_WINDOW, DEAD_BAND_FACTOR,
    median_time_past, mine_block,
)


def _add(chain, clock, hashrate=1.0, lie=False):
    difficulty = chain.compute_next_difficulty()
    expected   = T * (2 ** (difficulty - DEFAULT_DIFFICULTY)) / hashrate
    solvetime  = max(1, int(random.expovariate(1.0 / expected)))
    clock     += solvetime
    mtp_floor  = median_time_past(chain.tip, chain._by_hash) + 1
    timestamp  = max(clock + (100 * T if lie else 0), mtp_floor)
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
    return block, clock, solvetime


def _mtp_deltas(chain, tip):
    """Return the 5 MTP-deltas that compute_next_difficulty votes on."""
    blocks = [tip]
    cursor = tip
    for _ in range(VOTE_WINDOW):
        cursor = chain._by_hash.get(cursor.prev_hash)
        if cursor is None:
            return []
        blocks.append(cursor)
    blocks.reverse()
    mtps = [median_time_past(b, chain._by_hash) for b in blocks]
    return [max(1, min(mtps[i] - mtps[i-1], 6*T)) for i in range(1, len(mtps))]


def build(n, hashrate=1.0, liar_fn=None, seed=0, verbose=False):
    random.seed(seed)
    liar_fn = liar_fn or (lambda i: False)
    chain, clock = Chain(), GENESIS_TIMESTAMP + 1000
    if verbose:
        print(f"{'h':>4} {'diff':>4} {'solve':>6} {'mtp-deltas (5 votes)':>35} {'fast':>4} {'slow':>4}")
        print("-" * 65)
    for i in range(1, n + 1):
        block, clock, solvetime = _add(chain, clock, hashrate, liar_fn(i))
        if verbose:
            if block.height >= VOTE_WINDOW + MTP_WINDOW:
                deltas = _mtp_deltas(chain, chain._by_hash[chain.tip.prev_hash])
                fast = sum(1 for d in deltas if d < T / DEAD_BAND_FACTOR)
                slow = sum(1 for d in deltas if d > T * DEAD_BAND_FACTOR)
                delta_str = " ".join(f"{d:>5}" for d in deltas)
                print(f"{block.height:>4} {block.difficulty:>4} {solvetime:>6}s  [{delta_str}]  {fast:>4}  {slow:>4}")
            else:
                print(f"{block.height:>4} {block.difficulty:>4} {solvetime:>6}s  (warmup)")
    return chain


def test_steady_hashpower():
    chain = build(30)  # 30 > warmup of 16
    diffs = {chain._by_hash[h].difficulty for h in chain._by_hash}
    assert diffs == {DEFAULT_DIFFICULTY}, f"difficulty moved: {diffs}"
    print("PASS  steady: difficulty stayed at", DEFAULT_DIFFICULTY)


def test_difficulty_rises_after_jump():
    chain = build(70, hashrate=10.0, verbose=True)
    assert chain.tip.difficulty > DEFAULT_DIFFICULTY, \
        f"difficulty did not rise, still at {chain.tip.difficulty}"
    print(f"PASS  jump: difficulty rose to {chain.tip.difficulty}")


def test_liar_cannot_move_difficulty():
    # Every 3rd block lies. At most 4 of 11 MTP-window blocks are liars,
    # so the median is never a liar timestamp and MTP-deltas are unaffected.
    chain = build(30, liar_fn=lambda i: i % 3 == 0)
    diffs = {chain._by_hash[h].difficulty for h in chain._by_hash}
    assert diffs == {DEFAULT_DIFFICULTY}, f"liar moved difficulty: {diffs}"
    print("PASS  liar: difficulty stayed at", DEFAULT_DIFFICULTY)


def test_mtp_prevents_backdating():
    """Every block in the chain satisfies timestamp > its parent's MTP."""
    chain = build(30)
    cursor = chain.tip
    while cursor.height > 0:
        parent = chain._by_hash[cursor.prev_hash]
        parent_mtp = median_time_past(parent, chain._by_hash)
        assert cursor.timestamp > parent_mtp, (
            f"block {cursor.height}: timestamp {cursor.timestamp} <= parent MTP {parent_mtp}"
        )
        cursor = parent
    print(f"PASS  MTP: all {chain.tip.height} blocks satisfy timestamp > parent MTP")


def test_mine_block_accepted_by_chain():
    """mine_block produces a real PoW block that try_append accepts."""
    chain = Chain()
    block = mine_block(1, chain.tip.hash, [], chain)
    ok, reason = chain.try_append(block)
    assert ok, f"real mined block rejected: {reason}"
    print(f"PASS  real PoW: block at difficulty {block.difficulty} accepted by try_append")


def test_retarget_is_deterministic():
    chain_a = build(20, seed=0)
    chain_b = build(20, seed=0)
    da = chain_a.compute_next_difficulty()
    db = chain_b.compute_next_difficulty()
    assert da == db, f"not deterministic: {da} != {db}"
    print(f"PASS  deterministic: both computed difficulty {da}")


if __name__ == "__main__":
    test_steady_hashpower()
    test_difficulty_rises_after_jump()
    test_liar_cannot_move_difficulty()
    test_mtp_prevents_backdating()
    test_mine_block_accepted_by_chain()
    test_retarget_is_deterministic()
    print("\nAll tests passed.")
