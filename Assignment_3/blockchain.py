from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# Shared constants

# 20-byte community ID derived from Lab 2 group ID "3f66c2c14924eab2"
BLOCKCHAIN_COMMUNITY_ID: bytes = b"Lab3_3f66c2c14924eab"
assert len(BLOCKCHAIN_COMMUNITY_ID) == 20

# Leading zero bits every mined block must satisfy
DEFAULT_DIFFICULTY: int = 12

# Timestamp derived from group ID: int("3f66c2c14924eab2", 16) % 10**9 = 425579698
GENESIS_TIMESTAMP: int = 425579698


# 1. Header packing

def pack_header(
    prev_hash: bytes,   # 32 bytes
    txs_hash: bytes,    # 32 bytes
    timestamp: int,     # uint64
    difficulty: int,    # uint32  ← 4 bytes, NOT 8
    nonce: int,         # uint64
) -> bytes:
    """
    Pack the five fields into the canonical 84-byte header blob.

    Layout:
      [32 bytes prev_hash]
      [32 bytes txs_hash]
      [ 8 bytes timestamp  — uint64 big-endian]
      [ 4 bytes difficulty — uint32 big-endian]  
      [ 8 bytes nonce      — uint64 big-endian]

    """
    assert len(prev_hash) == 32
    assert len(txs_hash)  == 32
    assert 0 <= timestamp  < 2**64
    assert 0 <= difficulty < 2**32
    assert 0 <= nonce      < 2**64

    return (
        prev_hash
        + txs_hash
        + struct.pack(">Q", timestamp)   # 8 bytes unsigned
        + struct.pack(">I", difficulty)  # 4 bytes unsigned
        + struct.pack(">Q", nonce)       # 8 bytes unsigned
    )


def block_hash(header_bytes: bytes) -> bytes:
    """SHA-256 of the 84-byte header. This IS the block's identity."""
    assert len(header_bytes) == 84, f"header must be 84 bytes, got {len(header_bytes)}"
    return hashlib.sha256(header_bytes).digest()


# 2. Proof-of-Work helpers

def count_leading_zero_bits(digest: bytes) -> int:
    """
    Count how many leading bits are zero in a hash.

    Example: 0x00 0x00 0x03 ...
      byte 0 = 0x00 → 8 zero bits
      byte 1 = 0x00 → 8 zero bits
      byte 2 = 0x03 = 0000 0011 → bit_length()=2 → 8-2=6 zero bits, stop
      total = 22
    """
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
        else:
            count += 8 - byte.bit_length()
            break
    return count


def check_pow(digest: bytes, difficulty: int) -> bool:
    """Return True if digest has at least `difficulty` leading zero bits."""
    return count_leading_zero_bits(digest) >= difficulty


# 3. Transaction hashing


def tx_hash(
    sender_key: bytes,
    data: bytes,
    timestamp: int,
    signature: bytes,
) -> bytes:
    """
    Hash one transaction.

    Formula: SHA256(sender_key || data || timestamp_8byte_be || signature)
    """
    ts_bytes = struct.pack(">q", timestamp)  # signed int64 big-endian
    return hashlib.sha256(sender_key + data + ts_bytes + signature).digest()


def txs_hash(tx_hash_list: List[bytes]) -> bytes:
    """
    Commit to a list of transactions.

    Formula: SHA256(tx_hash_1 || tx_hash_2 || ... || tx_hash_n)

    Empty block: SHA256(b"") — NOT 32 zero bytes.
    b"".join([]) == b"", so SHA256(b"") falls out naturally.
    """
    concatenated = b"".join(tx_hash_list)
    return hashlib.sha256(concatenated).digest()


# 4. Block dataclass

@dataclass
class Block:
    height:     int
    prev_hash:  bytes           # 32 bytes
    _txs_hash:  bytes           # 32 bytes
    timestamp:  int
    difficulty: int
    nonce:      int
    hash:       bytes           # 32 bytes — SHA256 of this block header
    tx_hashes:  List[bytes] = field(default_factory=list)

    @property
    def header_bytes(self) -> bytes:
        return pack_header(self.prev_hash, self._txs_hash,
                           self.timestamp, self.difficulty, self.nonce)

    def is_valid(self) -> tuple[bool, str]:
        """Self-check. Returns (True, "") or (False, reason)."""
        hdr = self.header_bytes
        if len(hdr) != 84:
            return False, f"header is {len(hdr)} bytes, expected 84"

        recomputed = block_hash(hdr)
        if recomputed != self.hash:
            return False, "block_hash mismatch"

        if not check_pow(self.hash, self.difficulty):
            return False, f"PoW not satisfied: need {self.difficulty} leading zero bits"

        expected_txs = txs_hash(self.tx_hashes)
        if expected_txs != self._txs_hash:
            return False, "txs_hash mismatch"

        return True, ""

    @classmethod
    def from_fields(
        cls,
        height: int,
        prev_hash: bytes,
        received_txs_hash: bytes,
        timestamp: int,
        difficulty: int,
        nonce: int,
        block_hash_bytes: bytes,
        tx_hashes_blob: bytes,
    ) -> "Block":
        """
        Reconstruct a Block from raw fields received over IPv8.
        """
        if len(tx_hashes_blob) % 32 != 0:
            raise ValueError(f"tx_hashes_blob length {len(tx_hashes_blob)} is not a multiple of 32")
        tx_hashes = [tx_hashes_blob[i:i+32] for i in range(0, len(tx_hashes_blob), 32)]
        return cls(
            height=height,
            prev_hash=prev_hash,
            _txs_hash=received_txs_hash,
            timestamp=timestamp,
            difficulty=difficulty,
            nonce=nonce,
            hash=block_hash_bytes,
            tx_hashes=tx_hashes,
        )

    def to_response_fields(self) -> dict:
        """
        Return the exact fields to send in a BlockResponse message.
        """
        return {
            "height":     self.height,
            "prev_hash":  self.prev_hash,
            "txs_hash":   self._txs_hash,
            "timestamp":  self.timestamp,
            "difficulty": self.difficulty,
            "nonce":      self.nonce,
            "block_hash": self.hash,
            "tx_hashes":  b"".join(self.tx_hashes),
        }

# 5. Mining


def mine_block(
    height: int,
    prev_hash: bytes,
    tx_hash_list: List[bytes],
    difficulty: int = DEFAULT_DIFFICULTY,
    start_nonce: int = 0,
) -> Block:
    """Search for a nonce that satisfies `difficulty` leading zero bits."""
    body_commitment = txs_hash(tx_hash_list)
    timestamp = int(time.time())
    nonce = start_nonce

    while True:
        hdr = pack_header(prev_hash, body_commitment, timestamp, difficulty, nonce)
        digest = block_hash(hdr)
        if check_pow(digest, difficulty):
            return Block(
                height=height,
                prev_hash=prev_hash,
                _txs_hash=body_commitment,
                timestamp=timestamp,
                difficulty=difficulty,
                nonce=nonce,
                hash=digest,
                tx_hashes=list(tx_hash_list),
            )
        nonce += 1
        if nonce >= 2**63:
            timestamp = int(time.time())
            nonce = 0


# 6. Genesis block

def _build_genesis() -> Block:
    body_commitment = txs_hash([])   # SHA256(b"")
    nonce = 0
    while True:
        hdr = pack_header(b"\x00" * 32, body_commitment,
                          GENESIS_TIMESTAMP, DEFAULT_DIFFICULTY, nonce)
        digest = block_hash(hdr)
        if check_pow(digest, DEFAULT_DIFFICULTY):
            return Block(
                height=0,
                prev_hash=b"\x00" * 32,
                _txs_hash=body_commitment,
                timestamp=GENESIS_TIMESTAMP,
                difficulty=DEFAULT_DIFFICULTY,
                nonce=nonce,
                hash=digest,
                tx_hashes=[],
            )
        nonce += 1


GENESIS: Block = _build_genesis()


# 7. Chain storage and validation

class Chain:
    """
    In-memory blockchain with fork support.

    Storage:
      _by_hash   : hash  → Block         (every block ever seen)
      _by_height : height → List[Block]  (ALL blocks at that height, not just one)

    Why a list per height:
      Two peers can mine valid blocks at the same height (a fork). Both are valid
      and both must be kept. Overwriting would lose one branch and corrupt the chain.

    The canonical chain is always found by walking backwards from _tip through
    prev_hash links — never by indexing _by_height directly.
    """

    def __init__(self) -> None:
        self._by_hash:   Dict[bytes, Block]     = {}
        self._by_height: Dict[int, List[Block]] = {}
        self._tip: Block = GENESIS
        self._store(GENESIS)

    @property
    def height(self) -> int:
        return self._tip.height

    @property
    def tip(self) -> Block:
        return self._tip

    def get_by_hash(self, h: bytes) -> Optional[Block]:
        return self._by_hash.get(h)

    def get_by_height(self, h: int) -> Optional[Block]:
        """Return the canonical block at height h (walks back from tip)."""
        return self._canonical_at(h)

    def try_append(self, block: Block) -> tuple[bool, str]:
        """Validate and store a block. Returns (True, "") on success."""
        if block.hash in self._by_hash:
            return True, "already known"

        ok, reason = block.is_valid()
        if not ok:
            return False, reason

        if block.height == 0:
            if block.hash != GENESIS.hash:
                return False, "genesis hash mismatch"
            return True, "genesis already stored"

        parent = self._by_hash.get(block.prev_hash)
        if parent is None:
            return False, "prev_hash unknown — need to fetch missing blocks first"

        if block.height != parent.height + 1:
            return False, f"height {block.height} does not follow parent {parent.height}"

        self._store(block)
        if block.height > self._tip.height:
            self._tip = block

        return True, ""

    def validate_full(self) -> tuple[bool, str]:
        """
        Walk the canonical chain backwards from tip to genesis.
        Correct even when forks exist — never uses _by_height.
        """
        block = self._tip
        while block.height > 0:
            ok, reason = block.is_valid()
            if not ok:
                return False, f"block {block.height} invalid: {reason}"

            parent = self._by_hash.get(block.prev_hash)
            if parent is None:
                return False, f"block {block.height}: parent not found"
            if parent.height != block.height - 1:
                return False, f"block {block.height}: parent height mismatch"
            block = parent

        if block.hash != GENESIS.hash:
            return False, "chain does not terminate at our genesis"
        return True, ""

    def replace_suffix(self, blocks: List[Block]) -> tuple[bool, str]:
        """Replace the local chain after the parent of blocks[0] with the fetched suffix."""
        if not blocks:
            return False, "empty replacement suffix"

        parent = self._by_hash.get(blocks[0].prev_hash)
        if parent is None:
            return False, "replacement suffix does not connect to local chain"

        prefix = []
        cursor = parent
        while True:
            prefix.append(cursor)
            if cursor.height == 0:
                break
            cursor = self._by_hash.get(cursor.prev_hash)
            if cursor is None:
                return False, "local prefix is incomplete"
        prefix.reverse()

        new_by_hash: Dict[bytes, Block] = {}
        new_by_height: Dict[int, List[Block]] = {}
        for block in prefix:
            new_by_hash[block.hash] = block
            new_by_height.setdefault(block.height, []).append(block)

        tip = parent
        for block in blocks:
            ok, reason = block.is_valid()
            if not ok:
                return False, f"block {block.height} invalid: {reason}"
            if block.prev_hash != tip.hash or block.height != tip.height + 1:
                return False, f"block {block.height}: suffix link mismatch"
            new_by_hash[block.hash] = block
            new_by_height.setdefault(block.height, []).append(block)
            tip = block

        self._by_hash = new_by_hash
        self._by_height = new_by_height
        self._tip = tip
        return self.validate_full()

    def _store(self, block: Block) -> None:
        self._by_hash[block.hash] = block
        self._by_height.setdefault(block.height, []).append(block)

    def _canonical_at(self, target_height: int) -> Optional[Block]:
        """Walk back from tip to find the canonical block at target_height."""
        if target_height > self._tip.height:
            return None
        block = self._tip
        while block.height > target_height:
            parent = self._by_hash.get(block.prev_hash)
            if parent is None:
                return None
            block = parent
        return block if block.height == target_height else None



if __name__ == "__main__":
    print("=== blockchain.py self-test ===\n")

    g = GENESIS
    print(f"Genesis nonce    : {g.nonce}")
    print(f"Genesis hash     : {g.hash.hex()}")
    print(f"Genesis txs_hash : {g._txs_hash.hex()}  (should be SHA256(b''))")
    assert g._txs_hash == hashlib.sha256(b"").digest(), "empty txs_hash wrong"
    ok, reason = g.is_valid()
    assert ok, f"Genesis invalid: {reason}"
    print("Genesis valid    : Yes\n")

    # header size
    hdr = pack_header(b"\x00"*32, b"\x00"*32, 1748000000, 12, 0)
    assert len(hdr) == 84, f"Header size wrong: {len(hdr)}"
    print(f"Header size ok     : {len(hdr)} bytes \n")

    # tx_hash
    sample_tx = tx_hash(b"key", b"data", 1748000000, b"sig")
    assert len(sample_tx) == 32
    print(f"Sample tx_hash   : {sample_tx.hex()}")
    print("tx_hash size    : 32 bytes ok\n")

    # txs_hash empty
    empty = txs_hash([])
    assert empty == hashlib.sha256(b"").digest(), "empty txs_hash wrong"
    print(f"txs_hash([])     : {empty.hex()}  ")
    print(f"SHA256(b'')      : {hashlib.sha256(b'').digest().hex()}\n")

    # mine block 1
    print("Mining block 1 ...")
    b1 = mine_block(1, g.hash, [], DEFAULT_DIFFICULTY)
    ok, reason = b1.is_valid()
    assert ok, f"Block 1 invalid: {reason}"
    print(f"Block 1 hash     : {b1.hash.hex()}")
    print(f"Block 1 nonce    : {b1.nonce}")
    print("Block 1 valid    : Yes\n")

    # chain
    chain = Chain()
    ok, msg = chain.try_append(b1)
    assert ok, f"Append failed: {msg}"
    assert chain.height == 1
    print(f"Chain height     : {chain.height} ok")
    ok, reason = chain.validate_full()
    assert ok, f"Full validation failed: {reason}"
    print("Full chain valid : Yes\n")

    # fork test
    print("Fork test ...")
    import time as _time; _time.sleep(1)
    b1_fork = mine_block(1, g.hash, [], DEFAULT_DIFFICULTY)
    assert b1_fork.hash != b1.hash
    fork_chain = Chain()
    fork_chain.try_append(b1)
    ok, msg = fork_chain.try_append(b1_fork)
    assert ok, f"Fork block rejected: {msg}"
    assert b1.hash in fork_chain._by_hash
    assert b1_fork.hash in fork_chain._by_hash
    assert len(fork_chain._by_height[1]) == 2
    print("Fork test        : Ok  (both blocks stored, no overwrite)\n")

    # tamper test
    print("Tamper test ...")
    bad = Block(
        height=1, prev_hash=g.hash, _txs_hash=txs_hash([]),
        timestamp=b1.timestamp, difficulty=DEFAULT_DIFFICULTY,
        nonce=b1.nonce + 1, hash=b1.hash, tx_hashes=[],
    )
    ok, reason = bad.is_valid()
    assert not ok, "tampered block should be rejected"
    print(f"Tamper rejected  : Yes  ({reason})\n")

    print("=== All tests passed ===")
    print(f"  BLOCKCHAIN_COMMUNITY_ID = {BLOCKCHAIN_COMMUNITY_ID!r}")
    print(f"  DEFAULT_DIFFICULTY      = {DEFAULT_DIFFICULTY}")
    print(f"  GENESIS_TIMESTAMP       = {GENESIS_TIMESTAMP}")
    print(f"  GENESIS nonce           = {GENESIS.nonce}")
    print(f"  GENESIS hash            = {GENESIS.hash.hex()}")