import asyncio
from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.keyvault.crypto import default_eccrypto
from ipv8_service import IPv8

# ===================== CONFIGURE THIS PER MEMBER =====================
MY_ROUND = 2    # Which round YOU submit: 1, 2, or 3
KEY_FILE  = "../my_key.pem"
GROUP_ID  = "5b8a6718b3d6edf7"  # Paste the group_id printed by register.py here

# All 3 member public keys in the same canonical order used during registration.
# Index 0 = round-1 submitter, 1 = round-2 submitter, 2 = round-3 submitter.
MEMBER_KEYS_HEX = [
    "4c69624e61434c504b3ace00d54dc531c779ea9033c3ed9b81c5cf1dced8e16bb70efa91b195d119f07f7a48aea4e7285e9a8c4b3f14e8cf3ada17a5cd43c69e9479eccdc69c36655a42",  # member 1 (round-1 submitter)
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

class NonceSharePayload(VariablePayload):
    msg_id = 11
    format_list = ["varlenHutf8", "q", "varlenH"]
    names = ["group_id", "round_number", "nonce"]

class RoundDonePayload(VariablePayload):
    msg_id = 12
    format_list = ["varlenHutf8", "q"]
    names = ["group_id", "rounds_completed"]

class ReadyPayload(VariablePayload):
    msg_id = 13
    format_list = ["varlenHutf8"]
    names = ["group_id"]

ChallengeRequestPayload  = vp_compile(ChallengeRequestPayload)
ChallengeResponsePayload = vp_compile(ChallengeResponsePayload)
SignatureBundlePayload   = vp_compile(SignatureBundlePayload)
RoundResultPayload       = vp_compile(RoundResultPayload)
SigSharePayload          = vp_compile(SigSharePayload)
NonceSharePayload        = vp_compile(NonceSharePayload)
RoundDonePayload         = vp_compile(RoundDonePayload)
ReadyPayload             = vp_compile(ReadyPayload)


class Lab2Community(Community):
    community_id = COMMUNITY_ID

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_message_handler(ChallengeResponsePayload, self.on_challenge)
        self.add_message_handler(RoundResultPayload,       self.on_round_result)
        self.add_message_handler(SigSharePayload,          self.on_sig_share)
        self.add_message_handler(NonceSharePayload,        self.on_nonce_share)
        self.add_message_handler(RoundDonePayload,         self.on_round_done)
        self.add_message_handler(ReadyPayload,             self.on_ready)

        self.server_peer = None
        self.done        = False
        self.done_event  = asyncio.Event()
        self.sigs        = {}   # round_number -> {member_idx: sig_bytes}
        self.nonces      = {}   # round_number -> nonce bytes (submitter only)
        self.pending            = set()  # sent to server, not yet confirmed
        self.submitted          = set()  # confirmed successful rounds
        self.challenge_requested = False  # guard against duplicate on_round_done triggers
        self.ready_members      = set()  # indices of teammates who confirmed bidirectional visibility
        self._ready_sent        = False

        self._my_hex = ""
        self._my_idx = -1

    def started(self, _ipv8):
        self._my_hex = self.my_peer.public_key.key_to_bin().hex()
        if self._my_hex not in MEMBER_KEYS_HEX:
            raise RuntimeError(f"My key not in MEMBER_KEYS_HEX:\n  {self._my_hex}")
        self._my_idx = MEMBER_KEYS_HEX.index(self._my_hex)
        # FIX 6: catch misconfigured MY_ROUND immediately
        if self._my_idx != MY_ROUND - 1:
            raise RuntimeError(
                f"MY_ROUND={MY_ROUND} wrong — key is at index {self._my_idx}, "
                f"set MY_ROUND={self._my_idx + 1}"
            )
        print(f"My public key : {self._my_hex}")
        print(f"My round      : {MY_ROUND}")
        self.register_task("heartbeat", self._heartbeat, interval=0.5, delay=1.0)

    def _heartbeat(self):
        if self.done:
            return

        peers_by_key = {p.public_key.key_to_bin().hex(): p for p in self.get_peers()}

        self.server_peer = peers_by_key.get(SERVER_KEY_HEX)
        if self.server_peer is None:
            print("Searching for server...")
            return

        missing = [k[-16:] + "..." for k in MEMBER_KEYS_HEX
                   if k != self._my_hex and k not in peers_by_key]
        if missing:
            print(f"Waiting for teammates: {missing}")
            return

        # All peers visible — announce ready on every tick until we hear back from all teammates.
        # This proves bidirectional connectivity before starting the protocol.
        if not self._ready_sent:
            self._ready_sent = True
            print("All peers visible — announcing ready.")
        for tm in self._teammates():
            self.ez_send(tm, ReadyPayload(GROUP_ID))

        not_ready = [i + 1 for i, k in enumerate(MEMBER_KEYS_HEX)
                     if k != self._my_hex and i not in self.ready_members]
        if not_ready:
            print(f"Waiting for ready from member(s): {not_ready}")
            return

        self.cancel_pending_task("heartbeat")
        print("All peers mutually visible — starting protocol.")
        if MY_ROUND == 1:
            self._request_challenge()

    @lazy_wrapper(ReadyPayload)
    def on_ready(self, peer, payload):
        sender_hex = peer.public_key.key_to_bin().hex()
        if sender_hex not in MEMBER_KEYS_HEX or payload.group_id != GROUP_ID:
            return
        sender_idx = MEMBER_KEYS_HEX.index(sender_hex)
        if sender_idx not in self.ready_members:
            self.ready_members.add(sender_idx)
            print(f"Member {sender_idx + 1} is ready ({len(self.ready_members)}/2 teammates ready)")

    def _request_challenge(self):
        if self.done or self.server_peer is None:
            return
        self.ez_send(self.server_peer, ChallengeRequestPayload(GROUP_ID))
        try:
            self.cancel_pending_task("challenge_retry")
        except Exception:
            pass
        self.register_task("challenge_retry", self._request_challenge, delay=1.0)

    @lazy_wrapper(ChallengeResponsePayload)
    def on_challenge(self, peer, payload):
        if peer.public_key.key_to_bin().hex() != SERVER_KEY_HEX:
            return
        rn, nonce = payload.round_number, payload.nonce
        if rn != MY_ROUND or rn in self.nonces:
            return

        self.cancel_pending_task("challenge_retry")
        self.nonces[rn] = nonce

        # FIX 2: use self.crypto.create_signature — safe for any key type
        my_sig = default_eccrypto.create_signature(self.my_peer.key, nonce)
        self.sigs.setdefault(rn, {})[self._my_idx] = my_sig

        # Broadcast nonce to teammates; retry twice to survive packet loss
        self._broadcast_nonce(rn, nonce)
        for delay in (0.2, 0.5):
            self.register_anonymous_task(
                f"rebroadcast_nonce_{rn}_{delay}",
                lambda r=rn, n=nonce: self._broadcast_nonce(r, n),
                delay=delay,
            )

        self._try_submit(rn)

    def _broadcast_nonce(self, rn, nonce):
        if rn in self.submitted or self.done:
            return
        for tm in self._teammates():
            self.ez_send(tm, NonceSharePayload(GROUP_ID, rn, nonce))
        print(f"[Round {rn}] Broadcast nonce to teammates")

    # FIX 3: non-submitters receive the nonce here instead of polling the server
    @lazy_wrapper(NonceSharePayload)
    def on_nonce_share(self, peer, payload):
        sender_hex = peer.public_key.key_to_bin().hex()
        if sender_hex not in MEMBER_KEYS_HEX:
            return
        rn, nonce = payload.round_number, payload.nonce
        if payload.group_id != GROUP_ID or rn < 1 or rn > 3:
            return
        # Validate the nonce came from the expected submitter for this round
        if sender_hex != MEMBER_KEYS_HEX[rn - 1]:
            print(f"[Round {rn}] Ignoring nonce from wrong submitter")
            return
        my_sig = default_eccrypto.create_signature(self.my_peer.key, nonce)
        submitter_peer = self._peer_by_key(MEMBER_KEYS_HEX[rn - 1])
        if submitter_peer:
            self.ez_send(submitter_peer, SigSharePayload(GROUP_ID, rn, my_sig))
            print(f"[Round {rn}] Sent my signature to submitter")

    @lazy_wrapper(SigSharePayload)
    def on_sig_share(self, peer, payload):
        sender_hex = peer.public_key.key_to_bin().hex()
        if sender_hex not in MEMBER_KEYS_HEX:
            return
        if payload.group_id != GROUP_ID:
            return

        sender_idx = MEMBER_KEYS_HEX.index(sender_hex)
        rn = payload.round_number

        if rn != MY_ROUND or rn in self.submitted or rn in self.pending:
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
        if rn in self.pending:
            return

        self.pending.add(rn)
        print(f"[Round {rn}] All 3 sigs — submitting bundle!")
        self._send_bundle(rn)
        # Retry a few times in case the bundle or server response is lost
        for delay in (0.2, 0.5, 1.0):
            self.register_anonymous_task(
                f"retry_bundle_{rn}_{delay}",
                lambda r=rn: self._send_bundle(r),
                delay=delay,
            )

    def _send_bundle(self, rn):
        if rn in self.submitted or self.done or self.server_peer is None:
            return
        sigs = self.sigs.get(rn, {})
        if len(sigs) < 3:
            return
        print(f"[Round {rn}] Sending bundle")
        self.ez_send(
            self.server_peer,
            SignatureBundlePayload(GROUP_ID, rn, sigs[0], sigs[1], sigs[2]),
        )

    @lazy_wrapper(RoundResultPayload)
    def on_round_result(self, peer, payload):
        if peer.public_key.key_to_bin().hex() != SERVER_KEY_HEX:
            return
        rn = payload.round_number
        print(f"[Round {rn}] success={payload.success} | {payload.message}")

        if payload.success:
            # FIX 4: confirm only after server says so
            self.pending.discard(rn)
            self.submitted.add(rn)

            # Notify all members (3 attempts each to survive packet loss)
            rc = payload.rounds_completed
            for key in MEMBER_KEYS_HEX:
                target = self._peer_by_key(key)
                if target and key != self._my_hex:
                    for delay in (0.0, 0.2, 0.5):
                        self.register_anonymous_task(
                            f"notify_{key[-8:]}_{delay}",
                            lambda p=target, r=rc: self.ez_send(p, RoundDonePayload(GROUP_ID, r)),
                            delay=delay,
                        )

            if rc >= 3:
                self.done = True
                print("All 3 rounds complete!")
                self.done_event.set()
        else:
            self.pending.discard(rn)
            msg = payload.message
            if "budget exceeded" in msg:
                print("Budget exceeded — re-run register.py and start over.")
                self.done = True
                self.done_event.set()
            else:
                # Transient failure — retry immediately if we still have all sigs
                self._try_submit(rn)

    # FIX 3: non-round-1 submitters start when the previous round completes
    @lazy_wrapper(RoundDonePayload)
    def on_round_done(self, peer, payload):
        sender_hex = peer.public_key.key_to_bin().hex()
        if sender_hex not in MEMBER_KEYS_HEX:
            return
        if payload.group_id != GROUP_ID:
            return
        rc = int(payload.rounds_completed)
        if rc < 1 or rc > 3:
            return
        # For rc==3 accept from any teammate (gossip); for intermediate rounds
        # only the submitter of that round is authoritative.
        if rc != 3 and sender_hex != MEMBER_KEYS_HEX[rc - 1]:
            print(f"Ignoring RoundDone from wrong member")
            return
        if rc == 3:
            # All rounds done — re-broadcast once so every member terminates
            if not self.done:
                self.done = True
                print("All 3 rounds complete!")
                for key in MEMBER_KEYS_HEX:
                    target = self._peer_by_key(key)
                    if target and key != self._my_hex:
                        self.ez_send(target, RoundDonePayload(GROUP_ID, 3))
                self.done_event.set()
            return
        if rc + 1 == MY_ROUND and not self.challenge_requested:
            self.challenge_requested = True
            print(f"Round {rc} done — requesting my challenge (round {MY_ROUND})")
            self._request_challenge()

    def _teammates(self):
        return [
            p for p in self.get_peers()
            if p.public_key.key_to_bin().hex() in MEMBER_KEYS_HEX
            and p.public_key.key_to_bin().hex() != self._my_hex
        ]

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
    community = next(o for o in ipv8.overlays if isinstance(o, Lab2Community))
    print("IPv8 started — discovering peers...")
    # FIX 5: await an Event set by the community instead of stopping the loop from a callback
    await community.done_event.wait()
    await ipv8.stop()


asyncio.run(main())
