import asyncio
from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8_service import IPv8

# ===================== CONFIGURE THIS PER MEMBER =====================
MY_ROUND = 1    # Which round YOU submit: 1, 2, or 3
KEY_FILE  = "../lab1_signup/my_key.pem"
GROUP_ID  = "5b8a6718b3d6edf7"  # Paste the group_id printed by register.py here

# All 3 member public keys in the same canonical order used during registration.
# Index 0 = round-1 submitter, 1 = round-2 submitter, 2 = round-3 submitter.
MEMBER_KEYS_HEX = [
    "4c69624e61434c504b3ac8889c9ee8dd9918fe5edb935a0d9af8b5ffd3bc9cdfe9d46acd43ce23aef241016f0c1b5bc96018bb6b5ebc5f898fa54f7e8f34510fcbb6a4b366503a0bf82b",  # member 1 (round-1 submitter)
    "4c69624e61434c504b3a5f466412912c28b51bdb36dceadbf8d13513be72e463662a38832e46b9116a5175133644feb6a13ff83ff863ba434c50b68a2cd950a2ec85b9172a713e57e7f4",  # member 2 (round-2 submitter)
    "4c69624e61434c504b3a2a607508759bbf8873496aae443013b136fdcd3e19f5a7ddb2b148df53b75e441cf7c024b1e84d9016e0a697dbe05dd307ab9e7ee1543464fdac2d7bb493ce88",  # member 3 (round-3 submitter)
]
# =====================================================================

SERVER_KEY_HEX = (
    "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d"
    "82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f68303"
    "1e60c96"
)
COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")


class ChallengeRequestPayload(VariablePayload):
    msg_id = 3
    format_list = ["varlenHutf8"]
    names = ["group_id"]

class ChallengeResponsePayload(VariablePayload):
    msg_id = 4
    format_list = ["varlenH", "q", "d"]
    names = ["nonce", "round_number", "deadline"]

class SignatureBundlePayload(VariablePayload):
    msg_id = 5
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]
    names = ["group_id", "round_number", "sig1", "sig2", "sig3"]

class RoundResultPayload(VariablePayload):
    msg_id = 6
    format_list = ["?", "q", "q", "varlenHutf8"]
    names = ["success", "round_number", "rounds_completed", "message"]

class SigSharePayload(VariablePayload):
    msg_id = 10
    format_list = ["varlenHutf8", "q", "varlenH"]
    names = ["group_id", "round_number", "signature"]

ChallengeRequestPayload  = vp_compile(ChallengeRequestPayload)
ChallengeResponsePayload = vp_compile(ChallengeResponsePayload)
SignatureBundlePayload   = vp_compile(SignatureBundlePayload)
RoundResultPayload       = vp_compile(RoundResultPayload)
SigSharePayload          = vp_compile(SigSharePayload)


class Lab2Community(Community):
    community_id = COMMUNITY_ID

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_message_handler(ChallengeResponsePayload, self.on_challenge)
        self.add_message_handler(RoundResultPayload,       self.on_round_result)
        self.add_message_handler(SigSharePayload,          self.on_sig_share)

        self.server_peer = None
        self.done        = False
        self.sigs        = {}   # round_number -> {member_idx: sig_bytes}
        self.nonces      = {}   # round_number -> nonce bytes (submitter only)
        self.submitted   = set()

        self._my_hex = ""
        self._my_idx = -1

    def started(self, _ipv8):
        self._my_hex = self.my_peer.public_key.key_to_bin().hex()
        self._my_idx = MEMBER_KEYS_HEX.index(self._my_hex)
        print(f"My public key : {self._my_hex}")
        print(f"My round      : {MY_ROUND}")
        self.register_task("heartbeat", self._heartbeat, interval=0.5, delay=1.0)

    def _heartbeat(self):
        if self.done:
            return

        for peer in self.get_peers():
            if peer.public_key.key_to_bin().hex() == SERVER_KEY_HEX:
                self.server_peer = peer
                break

        if self.server_peer is None:
            print("Searching for server...")
            return

        self.ez_send(self.server_peer, ChallengeRequestPayload(GROUP_ID))

    @lazy_wrapper(ChallengeResponsePayload)
    def on_challenge(self, peer, payload):
        if peer.public_key.key_to_bin().hex() != SERVER_KEY_HEX:
            return

        rn, nonce = payload.round_number, payload.nonce
        my_sig = self.my_peer.key.signature(nonce)

        if MY_ROUND == rn:
            self.nonces.setdefault(rn, nonce)
            self.sigs.setdefault(rn, {})[self._my_idx] = my_sig
            self._try_submit(rn)
        else:
            submitter_peer = self._peer_by_key(MEMBER_KEYS_HEX[rn - 1])
            if submitter_peer:
                self.ez_send(submitter_peer, SigSharePayload(GROUP_ID, rn, my_sig))
            else:
                self.register_anonymous_task(
                    f"retry_sig_{rn}",
                    lambda r=rn, s=my_sig: self._retry_sig(r, s),
                    delay=0.3,
                )

    def _retry_sig(self, rn, my_sig):
        submitter_peer = self._peer_by_key(MEMBER_KEYS_HEX[rn - 1])
        if submitter_peer:
            self.ez_send(submitter_peer, SigSharePayload(GROUP_ID, rn, my_sig))

    @lazy_wrapper(SigSharePayload)
    def on_sig_share(self, peer, payload):
        sender_hex = peer.public_key.key_to_bin().hex()
        if sender_hex not in MEMBER_KEYS_HEX:
            return

        sender_idx = MEMBER_KEYS_HEX.index(sender_hex)
        rn = payload.round_number

        if rn != MY_ROUND or rn in self.submitted:
            return

        self.sigs.setdefault(rn, {})[sender_idx] = payload.signature
        print(f"[Round {rn}] Received sig from member {sender_idx + 1} ({len(self.sigs[rn])}/3)")
        self._try_submit(rn)

    def _try_submit(self, rn):
        if rn != MY_ROUND or rn in self.submitted:
            return
        nonce = self.nonces.get(rn)
        sigs  = self.sigs.get(rn, {})
        if nonce is None or len(sigs) < 3:
            print(f"[Round {rn}] Have {len(sigs)}/3 sigs — waiting")
            return

        self.submitted.add(rn)
        print(f"[Round {rn}] All 3 sigs — submitting bundle!")
        self.ez_send(
            self.server_peer,
            SignatureBundlePayload(GROUP_ID, rn, sigs[0], sigs[1], sigs[2]),
        )

    @lazy_wrapper(RoundResultPayload)
    def on_round_result(self, peer, payload):
        if peer.public_key.key_to_bin().hex() != SERVER_KEY_HEX:
            return

        print(f"[Round {payload.round_number}] success={payload.success} | {payload.message}")

        if payload.success and payload.rounds_completed >= 3:
            self.done = True
            print("All 3 rounds complete!")
            asyncio.get_event_loop().stop()
            return

        if "already completed" in payload.message:
            self.done = True
            asyncio.get_event_loop().stop()
            return

        if not payload.success and payload.round_number == MY_ROUND:
            msg = payload.message
            if "budget exceeded" in msg:
                print("Budget exceeded — re-run register.py and start over.")
                self.done = True
            elif "invalid signature" in msg or "wrong round" in msg:
                self.submitted.discard(payload.round_number)

    def _peer_by_key(self, key_hex):
        for peer in self.get_peers():
            if peer.public_key.key_to_bin().hex() == key_hex:
                return peer
        return None


async def main():
    builder = (
        ConfigBuilder()
        .clear_keys()
        .clear_overlays()
        .add_key("my peer", "curve25519", KEY_FILE)
        .add_overlay(
            "Lab2Community",
            "my peer",
            [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
            default_bootstrap_defs,
            {},
            [("started", [])],
        )
    )
    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab2Community": Lab2Community})
    await ipv8.start()
    print("IPv8 started — discovering peers...")
    await asyncio.get_event_loop().create_future()


asyncio.run(main())
