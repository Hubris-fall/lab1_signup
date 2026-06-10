from __future__ import annotations

import argparse
import asyncio
import logging
import struct
import time

from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8_service import IPv8

from blockchain import BLOCKCHAIN_COMMUNITY_ID, Block, Chain, tx_hash
from mempool import Mempool, Transaction
from miner import Miner


KEY_FILE = "key.pem"
GROUP_ID = "3f66c2c14924eab2"
REGISTRATION_COMMUNITY_ID = bytes.fromhex("4c616233426c6f636b636861696e323032365057")
SERVER_KEY = bytes.fromhex(
    "4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6"
)
MEMBER_KEYS_HEX = [
    "4c69624e61434c504b3ace00d54dc531c779ea9033c3ed9b81c5cf1dced8e16bb70efa91b195d119f07f7a48aea4e7285e9a8c4b3f14e8cf3ada17a5cd43c69e9479eccdc69c36655a42",
    "4c69624e61434c504b3a5f466412912c28b51bdb36dceadbf8d13513be72e463662a38832e46b9116a5175133644feb6a13ff83ff863ba434c50b68a2cd950a2ec85b9172a713e57e7f4",
    "4c69624e61434c504b3a2a607508759bbf8873496aae443013b136fdcd3e19f5a7ddb2b148df53b75e441cf7c024b1e84d9016e0a697dbe05dd307ab9e7ee1543464fdac2d7bb493ce88",
]

LOG = logging.getLogger("lab3")


class RegisterBlockchainPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenH"]
    names = ["group_id", "community_id"]


class RegisterResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]


TX_FORMAT = ["varlenH", "varlenH", "q", "varlenH"]
TX_NAMES = ["sender_key", "data", "timestamp", "signature"]
BLOCK_FORMAT = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]
BLOCK_NAMES = ["height", "prev_hash", "txs_hash", "timestamp", "difficulty", "nonce", "block_hash", "tx_hashes"]


class SubmitTransactionPayload(VariablePayload):
    msg_id = 1
    format_list = TX_FORMAT
    names = TX_NAMES


class SubmitTransactionResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenH", "varlenHutf8"]
    names = ["success", "tx_hash", "message"]


class GetChainHeightPayload(VariablePayload):
    msg_id = 3
    format_list = ["q"]
    names = ["request_id"]


class ChainHeightResponsePayload(VariablePayload):
    msg_id = 4
    format_list = ["q", "q", "varlenH"]
    names = ["request_id", "height", "tip_hash"]


class GetBlockPayload(VariablePayload):
    msg_id = 5
    format_list = ["q"]
    names = ["height"]


class BlockResponsePayload(VariablePayload):
    msg_id = 6
    format_list = BLOCK_FORMAT
    names = BLOCK_NAMES


class PeerTransactionPayload(VariablePayload):
    msg_id = 20
    format_list = TX_FORMAT
    names = TX_NAMES


class BlockAnnouncePayload(VariablePayload):
    msg_id = 21
    format_list = BLOCK_FORMAT
    names = BLOCK_NAMES


RegisterBlockchainPayload = vp_compile(RegisterBlockchainPayload)
RegisterResponsePayload = vp_compile(RegisterResponsePayload)
SubmitTransactionPayload = vp_compile(SubmitTransactionPayload)
SubmitTransactionResponsePayload = vp_compile(SubmitTransactionResponsePayload)
GetChainHeightPayload = vp_compile(GetChainHeightPayload)
ChainHeightResponsePayload = vp_compile(ChainHeightResponsePayload)
GetBlockPayload = vp_compile(GetBlockPayload)
BlockResponsePayload = vp_compile(BlockResponsePayload)
PeerTransactionPayload = vp_compile(PeerTransactionPayload)
BlockAnnouncePayload = vp_compile(BlockAnnouncePayload)


def verify_transaction(payload) -> tuple[bool, bytes, str, Transaction]:
    tx_obj = Transaction(payload.sender_key, payload.data, payload.timestamp, payload.signature)
    txh = tx_hash(payload.sender_key, payload.data, payload.timestamp, payload.signature)
    try:
        public_key = default_eccrypto.key_from_public_bin(payload.sender_key)
        signed = payload.sender_key + payload.data + struct.pack(">q", payload.timestamp)
    except Exception as exc:
        return False, txh, f"bad transaction key/timestamp: {exc}", tx_obj
    if not default_eccrypto.is_valid_signature(public_key, signed, payload.signature):
        return False, txh, "invalid transaction signature", tx_obj
    return True, txh, "accepted", tx_obj


def block_payload(payload_cls, block: Block):
    f = block.to_response_fields()
    return payload_cls(
        f["height"], f["prev_hash"], f["txs_hash"], f["timestamp"],
        f["difficulty"], f["nonce"], f["block_hash"], f["tx_hashes"],
    )


def block_from_payload(payload) -> Block:
    return Block.from_fields(
        payload.height, payload.prev_hash, payload.txs_hash, payload.timestamp,
        payload.difficulty, payload.nonce, payload.block_hash, payload.tx_hashes,
    )


class Lab3RegistrationCommunity(Community):
    community_id = REGISTRATION_COMMUNITY_ID

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.responses = asyncio.Queue()
        self.add_message_handler(RegisterResponsePayload, self.on_register_response)

    def server_peer(self):
        peer = self.network.get_verified_by_public_key_bin(SERVER_KEY)
        if peer:
            return peer
        return next((p for p in self.get_peers() if p.public_key.key_to_bin() == SERVER_KEY), None)

    def send_register(self, peer, group_id: str, community_id: bytes):
        self.ez_send(peer, RegisterBlockchainPayload(group_id, community_id))

    @lazy_wrapper(RegisterResponsePayload)
    def on_register_response(self, peer, payload):
        if peer.public_key.key_to_bin() != SERVER_KEY:
            LOG.warning("Ignoring RegisterResponse from non-server peer %s", peer.public_key.key_to_bin().hex())
            return
        self.responses.put_nowait(payload)


class Lab3BlockchainCommunity(Community):
    community_id = BLOCKCHAIN_COMMUNITY_ID

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.chain = Chain()
        self.mempool = Mempool()
        self.miner = Miner()
        self.member_keys = []
        self.block_waiters = {}
        self.request_id = 0
        self.add_message_handler(SubmitTransactionPayload, self.on_submit_transaction)
        self.add_message_handler(GetChainHeightPayload, self.on_get_chain_height)
        self.add_message_handler(GetBlockPayload, self.on_get_block)
        self.add_message_handler(BlockResponsePayload, self.on_block_response)
        self.add_message_handler(PeerTransactionPayload, self.on_peer_transaction)
        self.add_message_handler(BlockAnnouncePayload, self.on_block_announce)

    @property
    def local_key(self) -> bytes:
        return self.my_peer.public_key.key_to_bin()

    def configure(self, member_keys: list[bytes]):
        self.member_keys = member_keys
        if self.local_key not in self.member_keys:
            raise RuntimeError(f"My key is not in MEMBER_KEYS_HEX:\n  {self.local_key.hex()}")
        self.register_anonymous_task(
            "mining_loop",
            self.miner.mining_loop(self.chain, self.mempool, self),
            ignore=(Exception,),
        )

    def teammates(self, exclude=None):
        exclude_key = exclude.public_key.key_to_bin() if exclude else None
        return [
            p for p in self.get_peers()
            if p.public_key.key_to_bin() in self.member_keys
            and p.public_key.key_to_bin() not in (self.local_key, exclude_key)
        ]

    def send_submit_response(self, peer, success: bool, txh: bytes, message: str):
        self.ez_send(peer, SubmitTransactionResponsePayload(success, txh, message))

    def send_height_response(self, peer, request_id: int):
        self.ez_send(peer, ChainHeightResponsePayload(request_id, self.chain.height, self.chain.tip.hash))

    def send_block_response(self, peer, block: Block):
        self.ez_send(peer, block_payload(BlockResponsePayload, block))

    def send_get_block(self, peer, height: int):
        self.ez_send(peer, GetBlockPayload(height))

    async def request_block(self, peer, height: int, timeout: float = 3.0):
        key = (peer.public_key.key_to_bin(), height)
        future = asyncio.get_running_loop().create_future()
        self.block_waiters[key] = future
        try:
            self.send_get_block(peer, height)
            return await asyncio.wait_for(future, timeout)
        except asyncio.TimeoutError:
            return None
        finally:
            self.block_waiters.pop(key, None)

    def broadcast_block(self, block: Block, exclude=None):
        payload = block_payload(BlockAnnouncePayload, block)
        for peer in self.teammates(exclude):
            self.ez_send(peer, payload)

    def broadcast_transaction(self, tx_obj: Transaction, exclude=None):
        payload = PeerTransactionPayload(tx_obj.sender_key, tx_obj.data, tx_obj.timestamp, tx_obj.signature)
        for peer in self.teammates(exclude):
            self.ez_send(peer, payload)

    def accept_transaction(self, payload, gossip: bool, exclude=None) -> tuple[bool, bytes, str]:
        valid, txh, message, tx_obj = verify_transaction(payload)
        if not valid:
            return False, txh, message
        added = self.mempool.add(txh, tx_obj)
        if added and gossip:
            self.broadcast_transaction(tx_obj, exclude)
        return True, txh, "accepted" if added else "already known"

    @lazy_wrapper(SubmitTransactionPayload)
    def on_submit_transaction(self, peer, payload):
        success, txh, message = self.accept_transaction(payload, gossip=True, exclude=peer)
        self.send_submit_response(peer, success, txh, message)

    @lazy_wrapper(PeerTransactionPayload)
    def on_peer_transaction(self, peer, payload):
        self.accept_transaction(payload, gossip=True, exclude=peer)

    @lazy_wrapper(GetChainHeightPayload)
    def on_get_chain_height(self, peer, payload):
        self.send_height_response(peer, payload.request_id)

    @lazy_wrapper(GetBlockPayload)
    def on_get_block(self, peer, payload):
        block = self.chain.get_by_height(payload.height)
        if block is not None:
            self.send_block_response(peer, block)

    @lazy_wrapper(BlockResponsePayload)
    def on_block_response(self, peer, payload):
        try:
            block = block_from_payload(payload)
        except ValueError as exc:
            LOG.warning("Ignoring malformed block from %s: %s", peer.address, exc)
            return
        key = (peer.public_key.key_to_bin(), payload.height)
        future = self.block_waiters.get(key)
        if future is not None and not future.done():
            future.set_result(block)

    @lazy_wrapper(BlockAnnouncePayload)
    def on_block_announce(self, peer, payload):
        try:
            block = block_from_payload(payload)
        except ValueError as exc:
            LOG.warning("Ignoring malformed block from %s: %s", peer.address, exc)
            return
        self.apply_received_block(peer, block, rebroadcast=True)

    def apply_received_block(self, peer, block: Block, rebroadcast: bool):
        accepted = self.miner.on_block_received(self.chain, block, peer, self.mempool, self)
        if accepted and rebroadcast:
            self.broadcast_block(block, exclude=peer)


async def wait_for_server(community: Lab3RegistrationCommunity, timeout: float):
    start = time.perf_counter()
    next_bootstrap = 1.0
    while time.perf_counter() - start < timeout:
        peer = community.server_peer()
        if peer:
            LOG.info("Discovered Lab 3 server at %s", peer.address)
            return peer
        if time.perf_counter() >= next_bootstrap:
            community.bootstrap()
            next_bootstrap = time.perf_counter() + 3.0
            LOG.info("Waiting for Lab 3 server...")
        await asyncio.sleep(0.5)
    raise TimeoutError(f"Timed out after {timeout:.1f}s waiting for Lab 3 server")


async def register_blockchain(reg: Lab3RegistrationCommunity, group_id: str, community_id: bytes, timeout: float):
    server = await wait_for_server(reg, timeout)
    end = time.perf_counter() + timeout
    while time.perf_counter() < end:
        reg.send_register(server, group_id, community_id)
        try:
            response = await asyncio.wait_for(reg.responses.get(), timeout=3.0)
        except asyncio.TimeoutError:
            continue
        print(f"registration_success={response.success}")
        print(f"registration_message={response.message}")
        return response.success
    raise TimeoutError("Timed out waiting for RegisterResponse")


def parse_hex(value: str) -> bytes:
    try:
        return bytes.fromhex(value.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid hex: {value}") from exc


def parse_args():
    parser = argparse.ArgumentParser(description="Lab 3 IPv8 PoW blockchain node")
    parser.add_argument("--key-file", default=KEY_FILE)
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--group-id", default=GROUP_ID)
    parser.add_argument("--community-id", type=parse_hex, default=BLOCKCHAIN_COMMUNITY_ID)
    parser.add_argument("--member-key", action="append", type=parse_hex, default=None)
    parser.add_argument("--no-register", action="store_true")
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--log-level", default="INFO", choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"])
    return parser.parse_args()


def build_ipv8(args) -> IPv8:
    if len(args.community_id) != 20:
        raise ValueError("Blockchain community id must be exactly 20 bytes")
    Lab3BlockchainCommunity.community_id = args.community_id
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_address("0.0.0.0").set_port(args.port).set_log_level(args.log_level)
    builder.add_key("lab3", "curve25519", args.key_file)
    walkers = [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})]
    builder.add_overlay("Lab3RegistrationCommunity", "lab3", walkers, default_bootstrap_defs, {}, [])
    builder.add_overlay("Lab3BlockchainCommunity", "lab3", walkers, default_bootstrap_defs, {}, [])
    return IPv8(
        builder.finalize(),
        extra_communities={
            "Lab3RegistrationCommunity": Lab3RegistrationCommunity,
            "Lab3BlockchainCommunity": Lab3BlockchainCommunity,
        },
    )


async def async_main():
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    member_keys = args.member_key or [bytes.fromhex(k) for k in MEMBER_KEYS_HEX]
    ipv8 = build_ipv8(args)
    await ipv8.start()
    reg_community = next(o for o in ipv8.overlays if isinstance(o, Lab3RegistrationCommunity))
    chain_community = next(o for o in ipv8.overlays if isinstance(o, Lab3BlockchainCommunity))
    try:
        chain_community.configure(member_keys)
        print(f"local_public_key={chain_community.local_key.hex()}")
        print(f"blockchain_community_id={chain_community.community_id.hex()}")
        if not args.no_register:
            await register_blockchain(reg_community, args.group_id, chain_community.community_id, args.timeout)
        await asyncio.Event().wait()
    finally:
        await ipv8.stop()


if __name__ == "__main__":
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        LOG.info("Interrupted by user")
