import asyncio, logging
from blockchain import mine_block, Block, Chain, DEFAULT_DIFFICULTY
from mempool import Mempool

logger = logging.getLogger(__name__)

class Miner:

    def __init__(self):
        self._task = None

    async def mine_one(self, chain: Chain, mempool: Mempool):
        """
        Run a single PoW mining attempt on top of the current chain tip.
        Pulls pending transactions from the mempool, runs mine_block() in a thread
        pool executor (non-blocking), then appends the result to the chain.
        Raises CancelledError if interrupted by a new tip — mining_loop handles restart.
        Returns the mined Block on success, None on failure.
        """
        # get tip of chain, height and pending transactions to mine

        tip_block = chain.tip
        block_height = tip_block.height
        pending_txs = mempool.drain() #gives a list of (hash, tx) tuples
        tx_hash_list = [h for h,_ in pending_txs]

        # mine in a event loop to make it non blocking
        loop = asyncio.get_running_loop()
        try:
            block = await loop.run_in_executor(None, mine_block, block_height + 1, tip_block.hash, tx_hash_list, DEFAULT_DIFFICULTY)
        except asyncio.CancelledError:
            logger.info("mining cancelled at height %d (new tip arrived)", block_height + 1)
            raise  # let mining_loop handle the restart

        try:
            result = chain.try_append(block)
        except Exception as e:
            logger.error("unexpected error appending block %d: %s", block_height + 1, e)
            return None

        # if appending succeeds, remove transactions from the pool
        if result[0]:
            logger.info("block %d appended, removing %d confirmed txs", block_height + 1, len(tx_hash_list))
            mempool.remove_confirmed(tx_hash_list)
            return block
        else:
            logger.warning("failed to append block %d: %s", block_height + 1, result[1])
            return None

    async def mining_loop(self, chain, mempool, community= None):
        """
        Outer mining loop. Continuously mines blocks by calling mine_one().
        On success, broadcasts the block to peers via broadcast_block().
        On CancelledError (new tip arrived), restarts immediately from the new tip.
        Should be started once with asyncio.ensure_future(miner.mining_loop(...)).
        """
        while True:
            try:
                self._task = asyncio.ensure_future(self.mine_one(chain, mempool))
                block = await self._task
                if block is not None:
                    self.broadcast_block(community, block)
            except asyncio.CancelledError:
                logger.info("restarting mining on new tip (height=%d)", chain.height)

    def restart_mining(self):
        """Cancel the current mine_one task so mining_loop restarts from the new chain tip."""
        if self._task and not self._task.done():
            self._task.cancel()

    def on_block_received(self, chain, block, peer, mempool, community):
        """
        Called by message handler when a BlockAnnounce arrives from a peer.
        Validates and appends the block to the chain. If the chain grew, restarts mining
        on the new tip. If prev_hash is unknown (orphan block), triggers catch-up to fetch
        the missing blocks from the peer.
        """
        try:
            prev_height = chain.height
            result = chain.try_append(block)
            if result[0]:
                if chain.height > prev_height:
                    mempool.remove_confirmed(block.tx_hashes)
                    logger.info(f"Chain grew to {chain.height}, restarting mining")
                    self.restart_mining()
            elif "prev_hash unknown" in result[1]:
                logger.info(f"Orphan block at height {block.height}, need catch-up")
                asyncio.ensure_future(self.catch_up(chain, peer, block.height, block, community, mempool))
            else:
                logger.warning(f"Failed to append block {block.height}")
                return None

        except Exception as e:
            logger.error(f"Unexpected error appending block {block.height}: {e}")
            return None

    def broadcast_block(self, community, block: Block):
        """Broadcast a newly mined block to all peers."""
        community.broadcast_block(block)
        logger.info(f"Broadcasting block {block.height} to peers")

    async def request_block(self, peer, height, community):
        """Send a RequestBlock message to a peer asking for the block at the given height. """
        logger.info(f"Requesting block at height {height} from peer")
        return await community.request_block(peer, height)

    def get_transacitons_from_previous_suffix(self, chain, suffix):
        old_confirmed = []
        parent = chain.get_by_hash(suffix[0].prev_hash)
        if parent is not None:
            for h in range(parent.height + 1, chain.height + 1):
                old_block = chain.get_by_height(h)
                if old_block is not None:
                    old_confirmed.extend(old_block.tx_hashes)
        return old_confirmed

    async def catch_up(self, chain, peer, target_height, block, community, mempool=None):
        """
        Fetch missing blocks from a peer to catch up to target_height.
        Requests each missing height one by one and waits for handler
        to apply the received block. Aborts if a height is not received within 1 second.
        """
        suffix = [block]
        for h in range(target_height, 0, -1):
            # send RequestBlock message to peer asking for height h
            logger.info(f"Requesting block at height {h} from peer")
            block = await self.request_block(peer, h, community)
            if block is None:
                logger.warning(f"Timed out waiting for block at height {h}, aborting catch-up")
                return
            if chain.get_by_hash(block.prev_hash) is not None:
                break
            suffix.append(block)
        else:
            logger.warning("Reached genesis during catch-up without connecting to local chain")
            return

        suffix.reverse()

        old_confirmed = self.get_transacitons_from_previous_suffix(chain, suffix)

        ok, reason = chain.replace_suffix(suffix)

        if ok:
            if mempool is not None:
                mempool.readd_unconfirmed(old_confirmed)
                confirmed = [tx_hash for suffix_block in suffix for tx_hash in suffix_block.tx_hashes]
                mempool.remove_confirmed(confirmed)
            logger.info(f"Replaced local suffix with peer suffix at height {chain.height}")
            self.restart_mining()
        else:
            logger.warning(f"Fetched suffix rejected: {reason}")

        logger.info(f"Catch-up done, chain at height {chain.height}")
