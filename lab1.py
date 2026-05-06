import asyncio
import hashlib
import struct

from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8_service import IPv8

EMAIL = "shreyas@student.tudelft.nl"
GITHUB_URL = "https://github.com/Hubris-fall/lab1_signup.git"
NONCE = 234570333

SERVER_KEY_HEX = ("4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb"
                  "178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4"
                  "136c501ce5c09364e0ebb")
COMMUNITY_ID = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")
KEY_FILE = "my_key.pem"


def mine_pow(email: str, github_url: str, difficulty: int = 28) -> int:
    prefix = email.encode() + b"\n" + github_url.encode() + b"\n"
    for nonce in range(2**63):
        digest = hashlib.sha256(prefix + struct.pack(">q", nonce)).digest()
        if int.from_bytes(digest[:4], "big") >> (32 - difficulty) == 0:
            return nonce
    raise RuntimeError("No nonce found")


class SubmissionPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenHutf8", "q"]
    names = ["email", "github_url", "nonce"]


class ResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]


SubmissionPayload = vp_compile(SubmissionPayload)
ResponsePayload = vp_compile(ResponsePayload)


class Lab1Community(Community):
    community_id = COMMUNITY_ID

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_message_handler(ResponsePayload, self.on_response)
        self.submitted = False

    def started(self, _ipv8):
        self.register_task("find_server", self.find_and_submit, interval=2.0, delay=2.0)

    def find_and_submit(self):
        peers = self.get_peers()
        print(f"Known peers: {len(peers)}")
        for peer in peers:
            key_hex = peer.public_key.key_to_bin().hex()
            print(f"  peer key: {key_hex[:20]}...")
            if key_hex == SERVER_KEY_HEX:
                if not self.submitted:
                    self.submitted = True
                    print("Found server — sending submission...")
                    self.ez_send(peer, SubmissionPayload(EMAIL, GITHUB_URL, NONCE))
                return

    @lazy_wrapper(ResponsePayload)
    def on_response(self, peer, payload: ResponsePayload):
        if peer.public_key.key_to_bin().hex() != SERVER_KEY_HEX:
            return
        print(f"Server response: success={payload.success}, message={payload.message!r}")
        asyncio.get_event_loop().stop()


async def main():
    builder = (
        ConfigBuilder()
        .clear_keys()
        .clear_overlays()
        .add_key("my peer", "curve25519", KEY_FILE)
        .add_overlay(
            "Lab1Community",
            "my peer",
            [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
            default_bootstrap_defs,
            {},
            [("started", [])],
        )
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab1Community": Lab1Community})
    await ipv8.start()
    print(f"My public key: {ipv8.keys['my peer'].key.pub().key_to_bin().hex()}")
    print("Waiting for server peer...")
    await asyncio.get_event_loop().create_future()


asyncio.run(main())
