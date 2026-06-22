import time
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from lab3_blockchain.blockchain import (
    DEFAULT_DIFFICULTY, Block,
    pack_header, block_hash, check_pow, txs_hash,
)

TARGET_BLOCK_TIME = 10  # target seconds per block
VOTE_WINDOW       = 5   # how many recent blocks vote
DEAD_BAND_FACTOR  = 2   # only vote if >2x slow or <0.5x fast
MTP_WINDOW        = 11  # blocks used for median-time-past


def median_time_past(chain, parent):
    timestamps = []
    cursor = parent
    for _ in range(min(MTP_WINDOW, parent.height + 1)):
        timestamps.append(cursor.timestamp)
        cursor = chain._by_hash.get(cursor.prev_hash)
        if cursor is None:
            break
    timestamps.sort()
    return timestamps[len(timestamps) // 2]


def compute_next_difficulty(chain, tip):
    if tip.height < VOTE_WINDOW + 1:
        return DEFAULT_DIFFICULTY

    T = TARGET_BLOCK_TIME

    blocks = [tip]
    cursor = tip
    for _ in range(VOTE_WINDOW):
        parent = chain._by_hash.get(cursor.prev_hash)
        if parent is None:
            return DEFAULT_DIFFICULTY
        blocks.append(parent)
        cursor = parent
    blocks.reverse()

    solvetimes = [
        max(1, min(blocks[i].timestamp - blocks[i - 1].timestamp, 6 * T))
        for i in range(1, len(blocks))
    ]

    slow = sum(1 for s in solvetimes if s > T * DEAD_BAND_FACTOR)
    fast = sum(1 for s in solvetimes if s < T / DEAD_BAND_FACTOR)

    if slow == VOTE_WINDOW:
        return max(1, tip.difficulty - 1)
    if fast == VOTE_WINDOW:
        return tip.difficulty + 1
    return tip.difficulty


def mine_next_block(chain, tx_hash_list=None, timestamp=None):
    if tx_hash_list is None:
        tx_hash_list = []

    tip        = chain.tip
    difficulty = compute_next_difficulty(chain, tip)
    mtp_floor  = median_time_past(chain, tip) + 1
    timestamp  = max(timestamp if timestamp is not None else int(time.time()), mtp_floor)

    body  = txs_hash(tx_hash_list)
    nonce = 0
    while True:
        hdr    = pack_header(tip.hash, body, timestamp, difficulty, nonce)
        digest = block_hash(hdr)
        if check_pow(digest, difficulty):
            return Block(
                height    = tip.height + 1,
                prev_hash = tip.hash,
                _txs_hash = body,
                timestamp = timestamp,
                difficulty = difficulty,
                nonce     = nonce,
                hash      = digest,
                tx_hashes = list(tx_hash_list),
            )
        nonce += 1