import asyncio
from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8_service import IPv8

# ===================== CONFIGURE =====================
KEY_FILE = "../lab1_signup/my_key.pem"

# All 3 member public keys in canonical order (hex).
# This order is permanent — signatures must match it in every bundle.
MEMBER_KEYS_HEX = [
    "4c69624e61434c504b3ac8889c9ee8dd9918fe5edb935a0d9af8b5ffd3bc9cdfe9d46acd43ce23aef241016f0c1b5bc96018bb6b5ebc5f898fa54f7e8f34510fcbb6a4b366503a0bf82b",  # member 1 (round-1 submitter)
    "4c69624e61434c504b3a5f466412912c28b51bdb36dceadbf8d13513be72e463662a38832e46b9116a5175133644feb6a13ff83ff863ba434c50b68a2cd950a2ec85b9172a713e57e7f4",  # member 2 (round-2 submitter)
    "4c69624e61434c504b3a2a607508759bbf8873496aae443013b136fdcd3e19f5a7ddb2b148df53b75e441cf7c024b1e84d9016e0a697dbe05dd307ab9e7ee1543464fdac2d7bb493ce88",  # member 3 (round-3 submitter)
]
# =====================================================

SERVER_KEY_HEX = (
    "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d"
    "82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f68303"
    "1e60c96"
)
COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")


class RegisterPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "varlenH"]
    names = ["member1_key", "member2_key", "member3_key"]

class RegisterResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenHutf8", "varlenHutf8"]
    names = ["success", "group_id", "message"]

RegisterPayload         = vp_compile(RegisterPayload)
RegisterResponsePayload = vp_compile(RegisterResponsePayload)


class RegisterCommunity(Community):
    community_id = COMMUNITY_ID

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_message_handler(RegisterResponsePayload, self.on_response)
        self.server_peer = None
        self.sent = False

    def started(self, _ipv8):
        print(f"My public key: {self.my_peer.public_key.key_to_bin().hex()}")
        self.register_task("find_server", self._find_and_register, interval=1.0, delay=1.0)

    def _find_and_register(self):
        for peer in self.get_peers():
            if peer.public_key.key_to_bin().hex() == SERVER_KEY_HEX:
                self.server_peer = peer
                break

        if self.server_peer is None:
            print("Searching for server...")
            return

        if not self.sent:
            self.sent = True
            keys = [bytes.fromhex(k) for k in MEMBER_KEYS_HEX]
            self.ez_send(self.server_peer, RegisterPayload(*keys))
            print("Registration request sent...")

    @lazy_wrapper(RegisterResponsePayload)
    def on_response(self, peer, payload):
        if peer.public_key.key_to_bin().hex() != SERVER_KEY_HEX:
            return
        print(f"success={payload.success} | {payload.message}")
        if payload.success:
            print(f"\n>>> GROUP_ID = {payload.group_id!r}")
            print("Paste GROUP_ID into lab2.py, then run lab2.py on all 3 machines together.\n")
        asyncio.get_event_loop().stop()


async def main():
    builder = (
        ConfigBuilder()
        .clear_keys()
        .clear_overlays()
        .add_key("my peer", "curve25519", KEY_FILE)
        .add_overlay(
            "RegisterCommunity",
            "my peer",
            [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
            default_bootstrap_defs,
            {},
            [("started", [])],
        )
    )
    ipv8 = IPv8(builder.finalize(), extra_communities={"RegisterCommunity": RegisterCommunity})
    await ipv8.start()
    await asyncio.get_event_loop().create_future()


asyncio.run(main())
