"""Defensive LAN TCP protocol resource-limit regression tests.

Tests only loopback sockets. No external hosts, no agent execution.
"""
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import handoff_server as hs
import mesh_broker as mb
import pairing as pr


def handshake_denial(host: str, port: int) -> dict:
    with socket.create_connection((host, port), timeout=2.0) as s:
        # Declare >4 KiB without sending payload; server must reject before allocation.
        s.sendall(struct.pack(">I", 4097))
        return json.loads(hs._recv_frame(s, max_len=4096).decode())


def test_oversized_unauthenticated_broker_hello_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        ident = pr.load_or_create_identity(os.path.join(tmp, "id.key"))
        broker = mb.MeshBroker(
            identity=ident,
            peers=hs.PeerStore(os.path.join(tmp, "peers.json")),
            store=mb.MeshStore(os.path.join(tmp, "queue.db")),
            host="127.0.0.1",
            port=0,
        )
        broker.start(advertise=False)
        try:
            reply = handshake_denial(broker.host, broker.port)
            assert reply["ok"] is False and "frame too large" in reply["err"]
            # Broker must still accept a subsequent, well-framed (unpaired) hello.
            with socket.create_connection((broker.host, broker.port), timeout=2) as sock:
                stranger = pr.load_or_create_identity(os.path.join(tmp, "stranger.key"))
                hs._send_frame(sock, json.dumps({
                    "did": stranger.device_id, "pk": stranger.public_b64,
                }).encode())
                answer = json.loads(hs._recv_frame(sock, max_len=4096).decode())
                assert answer["ok"] is False and answer["err"] == "not paired"
        finally:
            broker.stop()


def test_oversized_unauthenticated_handoff_hello_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        ident = pr.load_or_create_identity(os.path.join(tmp, "id.key"))
        server = hs.HandoffServer(
            identity=ident,
            peers=hs.PeerStore(os.path.join(tmp, "peers.json")),
            export_fn=lambda sid: None,
            host="127.0.0.1",
        )
        server.start(advertise=False)
        try:
            reply = handshake_denial(server.host, server.port)
            assert reply["ok"] is False and "frame too large" in reply["err"]
        finally:
            server.stop()


def test_connection_slots_reject_when_full():
    with tempfile.TemporaryDirectory() as tmp:
        ident = pr.load_or_create_identity(os.path.join(tmp, "id.key"))
        broker = mb.MeshBroker(
            identity=ident,
            peers=hs.PeerStore(os.path.join(tmp, "peers.json")),
            store=mb.MeshStore(os.path.join(tmp, "queue.db")),
            host="127.0.0.1",
        )
        # Reserve the only slot before opening a listener. No worker should spawn.
        broker._connection_slots = threading.BoundedSemaphore(1)
        assert broker._connection_slots.acquire(blocking=False)
        broker.start(advertise=False)
        try:
            with socket.create_connection((broker.host, broker.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                assert sock.recv(1) == b"", "over-capacity client should be closed"
        finally:
            broker._connection_slots.release()
            broker.stop()


def test_handoff_connection_slots_reject_when_full():
    with tempfile.TemporaryDirectory() as tmp:
        ident = pr.load_or_create_identity(os.path.join(tmp, "id.key"))
        server = hs.HandoffServer(
            identity=ident,
            peers=hs.PeerStore(os.path.join(tmp, "peers.json")),
            export_fn=lambda sid: None,
            host="127.0.0.1",
        )
        server._connection_slots = threading.BoundedSemaphore(1)
        assert server._connection_slots.acquire(blocking=False)
        server.start(advertise=False)
        try:
            with socket.create_connection((server.host, server.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                assert sock.recv(1) == b""
        finally:
            server._connection_slots.release()
            server.stop()


def _pairing_broker(tmp, paired_phone=None):
    ident = pr.load_or_create_identity(os.path.join(tmp, "id.key"))
    peers = hs.PeerStore(os.path.join(tmp, "peers.json"))
    if paired_phone is not None:
        peers.add(paired_phone.device_id, bytes(paired_phone.public_key))
    broker = mb.MeshBroker(
        identity=ident,
        peers=peers,
        store=mb.MeshStore(os.path.join(tmp, "queue.db")),
        host="127.0.0.1",
        port=0,
    )
    broker.start(advertise=False)
    broker.open_pairing(300)
    return broker, ident


def _hello(sock, phone):
    hs._send_frame(sock, json.dumps({"did": phone.device_id, "pk": phone.public_b64}).encode())
    return json.loads(hs._recv_frame(sock, max_len=4096).decode())


def test_unpaired_request_over_16k_rejected_and_not_trusted():
    """Even with the pairing window open, a stranger may not send >16 KiB."""
    with tempfile.TemporaryDirectory() as tmp:
        broker, _ = _pairing_broker(tmp)
        stranger = pr.load_or_create_identity(os.path.join(tmp, "stranger.key"))
        try:
            with socket.create_connection((broker.host, broker.port), timeout=5) as sock:
                assert _hello(sock, stranger).get("ok") is True  # window open
                sock.sendall(struct.pack(">I", 16 * 1024 + 1))  # declare, never send
                reply = json.loads(hs._recv_frame(sock, max_len=4096).decode())
            assert reply["ok"] is False and "frame too large" in reply["err"]
            assert not broker.peers.is_paired(stranger.device_id, bytes(stranger.public_key))
        finally:
            broker.stop()


def test_unpaired_pair_request_within_limit_still_pairs():
    """The 16 KiB bound must not break the legitimate QR pairing op."""
    with tempfile.TemporaryDirectory() as tmp:
        broker, ident = _pairing_broker(tmp)
        phone = pr.load_or_create_identity(os.path.join(tmp, "phone.key"))
        try:
            with socket.create_connection((broker.host, broker.port), timeout=5) as sock:
                assert _hello(sock, phone).get("ok") is True
                hs._send_frame(sock, pr.box_encrypt(phone.private_key, bytes(ident.public_key),
                                                    json.dumps({"op": "pair"}).encode()))
                reply = json.loads(hs._recv_frame(sock).decode())
            assert reply["ok"] is True
            assert broker.peers.is_paired(phone.device_id, bytes(phone.public_key))
        finally:
            broker.stop()


def test_paired_phone_may_exceed_unpaired_limit():
    """Paired devices keep the large encrypted-request budget (here a 1 MiB task)."""
    with tempfile.TemporaryDirectory() as tmp:
        phone = pr.load_or_create_identity(os.path.join(tmp, "phone.key"))
        broker, ident = _pairing_broker(tmp, paired_phone=phone)
        try:
            prompt = "x" * (1024 * 1024)
            with socket.create_connection((broker.host, broker.port), timeout=10) as sock:
                assert _hello(sock, phone).get("ok") is True
                req = {"op": "push", "task": {"id": "big-1", "prompt": prompt}}
                hs._send_frame(sock, pr.box_encrypt(phone.private_key, bytes(ident.public_key),
                                                    json.dumps(req).encode()))
                reply = json.loads(hs._recv_frame(sock).decode())
            assert reply == {"ok": True, "id": "big-1"}
        finally:
            broker.stop()
