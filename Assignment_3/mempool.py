from __future__ import annotations
from dataclasses import dataclass
import logging
import threading

logger = logging.getLogger(__name__)

@dataclass
class Transaction:
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes

class Mempool:
    
    def __init__(self):
        self.lock = threading.Lock()
        self.pending : dict[bytes, Transaction] = {}
        self.known : dict[bytes, Transaction] = {}
    def add(self, tx_hash_bytes, tx_obj) -> bool:
        try:
            with self.lock:
                self.known[tx_hash_bytes] = tx_obj
                if tx_hash_bytes in self.pending:
                    logger.debug("tx %s already in mempool, skipping", tx_hash_bytes.hex()[:8])
                    return False
                self.pending[tx_hash_bytes] = tx_obj
                logger.info("tx %s added to mempool (size=%d)", tx_hash_bytes.hex()[:8], len(self.pending))
                return True
        except Exception as e:
            logger.error("add failed: %s", e)
            return False
    def drain(self) -> list:
        with self.lock:
            block_list = list(self.pending.items())
            logger.debug("drain: %d transactions", len(block_list))
            return block_list
    def remove_confirmed(self, hashes: list[bytes]):
        with self.lock:
            for h in hashes:
                if self.pending.pop(h, None) is not None:
                    logger.info("tx %s confirmed and removed (size=%d)", h.hex()[:8], len(self.pending))
    def readd_unconfirmed(self, hashes: list[bytes]):
        with self.lock:
            for h in hashes:
                tx_obj = self.known.get(h)
                if tx_obj is None or h in self.pending:
                    continue
                self.pending[h] = tx_obj
                logger.info("tx %s returned to mempool (size=%d)", h.hex()[:8], len(self.pending))
    def __len__(self):
        return len(self.pending)
