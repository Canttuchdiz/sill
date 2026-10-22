"""Fault-injected protocol checks and loopback integration; no OS settings changed."""
import contextlib
import errno
import importlib.util
import io
import json
import math
from pathlib import Path
import socket
import struct
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("probe", ROOT / "Scripts/locked_access_probe.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


class Peer:
    def __init__(self, data, fragment=1):
        self.data = data
        self.fragment = fragment
        self.sent = bytearray()
        self.read = 0

    def settimeout(self, value):
        if value <= 0:
            raise AssertionError("unbounded or invalid timeout")

    def recv(self, count):
        part, self.data = self.data[:min(count, self.fragment)], self.data[min(count, self.fragment):]
        self.read += len(part)
        return part

    def sendall(self, data):
        self.sent.extend(data)


class DiscoveryTests(unittest.TestCase):
    def discover(self, data, fragment=1):
        peer = Peer(data, fragment)
        result = P.discover(peer, time.monotonic() + 1)
        self.assertEqual(len(peer.sent), 12, "only a version greeting may leave the probe")
        return result, peer

    def test_apple_fragmented(self):
        result, peer = self.discover(b"RFB 003.889\n\x04\x1e\x21\x24\x23")
        self.assertTrue(result["apple_ard_offered"])
        self.assertFalse(result["no_authentication_offered"])
        self.assertEqual(result["security_types"], [30, 33, 36, 35])
        self.assertEqual(peer.sent, b"RFB 003.008\n")

    def test_standard_versions_and_coalesced_payload(self):
        for minor in (7, 8):
            with self.subTest(minor=minor):
                result, peer = self.discover(f"RFB 003.{minor:03d}\n".encode() + b"\x02\x01\x02", 1024)
                self.assertTrue(result["no_authentication_offered"])
                self.assertTrue(result["password_only_vnc_offered"])
                self.assertEqual(peer.sent, f"RFB 003.{minor:03d}\n".encode())

    def test_legacy_33_and_unknown_type_preserved(self):
        result, _ = self.discover(b"RFB 003.003\n" + struct.pack("!I", 999))
        self.assertEqual(result["security_types"], [999])
        self.assertFalse(result["apple_ard_offered"])

    def test_every_truncation(self):
        data = b"RFB 003.889\n\x04\x1e\x21\x24\x23"
        for length in range(len(data)):
            with self.subTest(length=length), self.assertRaisesRegex(P.ProbeError, "unexpected_eof"):
                self.discover(data[:length])

    def test_invalid_greetings_and_versions(self):
        for greeting, reason in [(b"HTTP/1.1 200", "invalid_greeting"),
                                 (b"RFB 003.00x\n", "invalid_greeting"),
                                 (b"RFB 004.008\n", "unsupported_version"),
                                 (b"RFB 003.009\n", "unsupported_version"),
                                 (b"RFB 003.008\x00", "invalid_greeting")]:
            peer = Peer(greeting)
            with self.subTest(greeting=greeting), self.assertRaisesRegex(P.ProbeError, reason):
                P.discover(peer, time.monotonic() + 1)
            self.assertFalse(peer.sent)

    def test_refusal_does_not_read_or_leak_server_reason(self):
        for minor, refusal in [(8, b"\x00"), (3, b"\x00\x00\x00\x00")]:
            peer = Peer(f"RFB 003.{minor:03d}\n".encode() + refusal + b"private arbitrary text")
            with self.assertRaisesRegex(P.ProbeError, "^server_refused$"):
                P.discover(peer, time.monotonic() + 1)
            self.assertEqual(peer.data, b"private arbitrary text")

    def test_invalid_types(self):
        for payload in (b"\x01\x00", b"\x02\x1e\x1e"):
            with self.assertRaisesRegex(P.ProbeError, "invalid_security_types"):
                self.discover(b"RFB 003.008\n" + payload)

    def test_maximum_type_list_is_bounded(self):
        result, _ = self.discover(b"RFB 003.008\n\xff" + bytes(range(1, 256)))
        self.assertEqual(len(result["security_types"]), 255)

    def test_deadline_covers_entire_operation(self):
        # A peer sending individual bytes must not reset the total deadline.
        peer = Peer(b"RFB 003.008\n\x01\x1e")
        with patch.object(P.time, "monotonic", side_effect=[0, 0.5, 1.1]):
            with self.assertRaises(TimeoutError):
                P.discover(peer, 1)
        self.assertEqual(peer.read, 2)

    def test_already_expired_deadline(self):
        peer = Peer(b"RFB 003.008\n")
        with self.assertRaises(TimeoutError):
            P.discover(peer, time.monotonic() - 1)
        self.assertEqual(peer.read, 0)


class ProbeTests(unittest.TestCase):
    def test_connect_is_fixed_and_refusal_is_distinct(self):
        with patch.object(P.socket, "socket") as factory:
            connection = factory.return_value.__enter__.return_value
            connection.connect.side_effect = ConnectionRefusedError(errno.ECONNREFUSED, "private network details")
            result = P.probe()
        connection.connect.assert_called_once_with(("127.0.0.1", 5900))
        self.assertEqual(result["status"], "not_listening")
        self.assertFalse(result["authentication_tested"])
        self.assertFalse(result["locked_access_verified"])
        self.assertNotIn("private", json.dumps(result))
        factory.return_value.__exit__.assert_called_once()

    def test_timeout_reset_and_network_errors(self):
        for error, expected in [(TimeoutError(), "timeout"), (ConnectionResetError(), "network_error")]:
            with patch.object(P.socket, "socket") as factory:
                factory.return_value.__enter__.return_value.connect.side_effect = error
                self.assertEqual(P.probe()["status"], expected)
            factory.return_value.__exit__.assert_called_once()

    def test_timeout_validation_before_network(self):
        for value in (0, -1, math.nan, math.inf, 31):
            with self.subTest(value=value), patch.object(P.socket, "socket") as factory:
                with self.assertRaises(ValueError):
                    P.probe(value)
                factory.assert_not_called()

    def test_success_is_discovery_only_and_connection_closes(self):
        peer = Peer(b"RFB 003.889\n\x01\x1e")
        with patch.object(P.socket, "socket") as factory:
            connection = factory.return_value.__enter__.return_value
            connection.recv.side_effect = peer.recv
            result = P.probe()
        self.assertEqual(result["status"], "discovered")
        self.assertFalse(result["authentication_tested"])
        self.assertFalse(result["locked_access_verified"])
        self.assertGreaterEqual(result["elapsed_ms"], 0)
        connection.sendall.assert_called_once_with(b"RFB 003.008\n")
        factory.return_value.__exit__.assert_called_once()

    def test_protocol_error_closes_connection(self):
        with patch.object(P.socket, "socket") as factory:
            connection = factory.return_value.__enter__.return_value
            connection.recv.return_value = b""
            self.assertEqual(P.probe()["status"], "unexpected_eof")
        connection.sendall.assert_not_called()
        factory.return_value.__exit__.assert_called_once()

    def test_real_stalled_peer_times_out(self):
        client, server = socket.socketpair()
        with client, server:
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                P.discover(client, started + 0.05)
            # Generous ceiling, intended to detect an absent socket timeout rather
            # than benchmark scheduling on loaded CI machines.
            self.assertLess(time.monotonic() - started, 2)

    def test_watch_is_sequential_and_stops(self):
        with patch.object(P, "probe", side_effect=[{"status": "discovered"}, {"status": "timeout"}]) as probe:
            with patch.object(P.time, "sleep") as sleep, contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(P.main(["--samples", "2"]), 1)
            self.assertEqual(probe.call_count, 2)
            sleep.assert_called_once_with(5)
            self.assertEqual(len(output.getvalue().splitlines()), 2)

    def test_invalid_cli_arguments_never_connect(self):
        for args in (["--samples", "0"], ["--samples", "121"], ["--interval", "0"],
                     ["--timeout", "nan"], ["--timeout", "inf"], ["--timeout", "31"],
                     ["--interval", "61"], ["--host", "example.org"]):
            with self.subTest(args=args), patch.object(P, "probe") as probe:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    P.main(args)
                self.assertEqual(error.exception.code, 2)
                probe.assert_not_called()

    def test_interrupt_stops_without_retry(self):
        with patch.object(P, "probe", side_effect=KeyboardInterrupt()) as probe:
            self.assertEqual(P.main(), 130)
            probe.assert_called_once()

    def test_real_loopback_fragmentation_and_reconnect(self):
        # Ephemeral fixture port; does not touch the real system service.
        errors, received = [], []
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(2)
            listener.settimeout(3)

            def server():
                try:
                    for _ in range(2):
                        connection, _ = listener.accept()
                        with connection:
                            connection.settimeout(2)
                            for byte in b"RFB 003.889\n":
                                connection.sendall(bytes([byte]))
                            received.append(P.read_exact(connection, 12, time.monotonic() + 2))
                            connection.sendall(b"\x01\x1e")
                            # Client must close instead of sending security selection.
                            received.append(connection.recv(1))
                except Exception as error:
                    errors.append(error)

            thread = threading.Thread(target=server, daemon=True)
            thread.start()
            try:
                for _ in range(2):
                    with socket.create_connection(listener.getsockname(), timeout=2) as client:
                        result = P.discover(client, time.monotonic() + 2)
                        self.assertEqual(result["security_types"], [30])
            finally:
                thread.join(3)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(received, [b"RFB 003.008\n", b"", b"RFB 003.008\n", b""])


if __name__ == "__main__":
    unittest.main(verbosity=2)
