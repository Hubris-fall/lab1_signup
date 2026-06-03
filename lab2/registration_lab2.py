from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
from dataclasses import dataclass
from pathlib import Path


from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.keyvault.crypto import default_eccrypto
from ipv8_service import IPv8
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8.peer import Peer



LAB2_COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")
LAB2_SERVER_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40"
    "cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
)

GROUP_SIZE = 3
LOG = logging.getLogger("lab2")


@dataclass(frozen=True)
class RegistrationResponse:
    success: bool
    group_id: str
    message: str
    
@dataclass
class RegisterPayload(DataClassPayload[1]):
    member1_key: bytes
    member2_key: bytes
    member3_key: bytes


@dataclass
class RegistrationResponsePayload(DataClassPayload[2]):
    success: bool
    group_id: str
    message: str


class Lab2Community(Community):
    community_id = LAB2_COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.member_keys: list[bytes] = []
        self.group_id: str | None = None
        self.registration_responses: asyncio.Queue[RegistrationResponse] = asyncio.Queue()

        self.add_message_handler(RegistrationResponsePayload, self.on_registration_response)

    @property
    def local_key(self) -> bytes:
        return self.my_peer.public_key.key_to_bin()

    def configure_group(self, member_keys: list[bytes], group_id: str | None = None) -> None:
        validate_member_keys(member_keys)
        self.member_keys = member_keys
        self.group_id = group_id
        if self.local_key not in member_keys:
            raise ValueError("This key file is not one of the three configured Lab 2 member keys.")

    def peer_by_key(self, public_key: bytes) -> Peer | None:
        peer = self.network.get_verified_by_public_key_bin(public_key)
        if peer is not None:
            return peer
        for discovered in self.get_peers():
            if discovered.public_key.key_to_bin() == public_key:
                return discovered
        return None
    
    def send_register(self, peer: Peer) -> None:    
        self.ez_send(peer, RegisterPayload(*self.member_keys))
        
    @lazy_wrapper(RegistrationResponsePayload)
    def on_registration_response(self, peer: Peer, payload: RegistrationResponsePayload) -> None:
        if peer.public_key.key_to_bin() != LAB2_SERVER_PUBLIC_KEY:
            LOG.warning("Ignoring registration response from non-server peer %s", peer.public_key.key_to_bin().hex())
            return
        self.registration_responses.put_nowait(RegistrationResponse(payload.success, payload.group_id, payload.message))


async def recv_registration_response(community: Lab2Community, timeout: float) -> RegistrationResponse:
    return await asyncio.wait_for(community.registration_responses.get(), timeout=timeout)

async def wait_for_peer(community: Lab2Community, public_key: bytes, label: str, timeout: float) -> Peer:
    start = time.perf_counter()
    next_bootstrap = 0.0

    while True:
        peer = community.peer_by_key(public_key)
        if peer is not None:
            LOG.info("Discovered %s at %s", label, peer.address)
            return peer

        elapsed = time.perf_counter() - start
        if elapsed >= timeout:
            raise TimeoutError(f"Timed out after {timeout:.1f}s waiting for {label}.")

        now = time.perf_counter()
        if now >= next_bootstrap:
            community.bootstrap()
            next_bootstrap = now + 3.0
            LOG.info("Waiting for %s... known peers in community: %d", label, len(community.get_peers()))

        await asyncio.sleep(0.5)

def validate_member_keys(member_keys: list[bytes]) -> None:
    if len(member_keys) != GROUP_SIZE:
        raise ValueError(f"Exactly {GROUP_SIZE} member keys are required.")
    if len(set(member_keys)) != GROUP_SIZE:
        raise ValueError("Member keys must be unique.")

def build_ipv8_instance(key_file: Path, port: int, log_level: str) -> IPv8:
    key_file.parent.mkdir(parents=True, exist_ok=True)

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_address("0.0.0.0")
    builder.set_port(port)
    builder.set_log_level(log_level)
    builder.add_key("lab2", "curve25519", str(key_file))
    builder.add_overlay(
        "Lab2Community",
        "lab2",
        [WalkerDefinition(Strategy.RandomWalk, 30, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [],
    )
    return IPv8(builder.finalize(), extra_communities={"Lab2Community": Lab2Community})

async def start_lab2(args: argparse.Namespace) -> tuple[IPv8, Lab2Community]:
    ipv8 = build_ipv8_instance(Path(args.key_file), args.port, args.log_level)
    await ipv8.start()
    community = ipv8.get_overlay(Lab2Community)
    if community is None:
        await ipv8.stop()
        raise RuntimeError("Lab2Community failed to start.")
    LOG.info("Local public key: %s", community.local_key.hex())
    return ipv8, community

def parse_public_key(value: str) -> bytes:
    try:
        public_key = bytes.fromhex(value.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid public key hex: {value}") from exc
    if len(public_key) != 74:
        raise argparse.ArgumentTypeError(f"Expected a 74-byte IPv8 public key, got {len(public_key)} bytes.")
    return public_key

async def register_group(args: argparse.Namespace) -> int:
    ipv8, community = await start_lab2(args)
    try:
        community.configure_group(args.member_key)
        server = await wait_for_peer(community, LAB2_SERVER_PUBLIC_KEY, "Lab 2 server", args.discovery_timeout)

        end = time.perf_counter() + args.response_timeout
        while True:
            community.send_register(server)
            try:
                response = await recv_registration_response(community, timeout=0.75)
            except asyncio.TimeoutError:
                if time.perf_counter() >= end:
                    raise TimeoutError("Timed out waiting for registration response.")
                continue
            print(f"registration_success={response.success}")
            print(f"group_id={response.group_id}")
            print(f"registration_message={response.message}")
            return 0 if response.success else 1
    finally:
        await ipv8.stop()

def add_common_network_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--key-file",
        default="key.pem",
        help="Path to the Lab 1 IPv8 private key file to reuse for Lab 2",
    )
    parser.add_argument("--port", type=int, default=8090, help="Preferred UDP port for IPv8")
    parser.add_argument(
        "--discovery-timeout",
        type=float,
        default=300.0,
        help="Seconds to wait for the server and teammates to appear",
    )
    parser.add_argument(
        "--response-timeout",
        type=float,
        default=30.0,
        help="Seconds to wait for server responses or teammate progress",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
        help="Python logging level",
    )


def add_member_key_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--member-key",
        action="append",
        type=parse_public_key,
        required=True,
        help="Canonical member public key as hex. Pass exactly three times, in registration/signature order.",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lab 2 coordinated IPv8 group signing client",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    register_parser = subparsers.add_parser("register", help="Register the three-member Lab 2 group")
    add_common_network_args(register_parser)
    add_member_key_arg(register_parser)

    return parser.parse_args()

def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

async def async_main(args: argparse.Namespace) -> int:
    return await register_group(args)



def main() -> int:
    args = parse_args()
    configure_logging(args.log_level)
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        LOG.error("Interrupted by user.")
        return 130
    except Exception as exc:
        LOG.error("%s", exc)
        LOG.error("Full exception details", exc_info=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())