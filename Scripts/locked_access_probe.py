#!/usr/bin/env python3
"""Inspect local Screen Sharing without authenticating or requesting screen data.

Run before/after manually locking the Mac, e.g.:
  python3 Scripts/locked_access_probe.py --samples 12 --interval 5

One JSON line per sample. A successful result proves protocol discovery only,
not successful login or locked-screen control. No credentials are accepted.
Only the fixed IPv4 loopback endpoint is reachable from the command line.
"""

import argparse
import datetime
import errno
import json
import math
import re
import socket
import struct
import time


class ProbeError(Exception):
    """A fixed diagnostic category; never includes server-supplied text."""


def remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError()
    return left


def read_exact(connection, size, deadline):
    chunks = bytearray()
    while len(chunks) < size:
        connection.settimeout(remaining(deadline))
        part = connection.recv(size - len(chunks))
        if not part:
            raise ProbeError("unexpected_eof")
        chunks.extend(part)
    return bytes(chunks)


def discover(connection, deadline):
    """RFB version/security discovery; never selects a security type.

    RFB 3.3 uses a 32-bit selected security type; 3.7/3.8 use a byte count and
    list. Apple's 3.889 greeting accepts the standard 3.8 client version.
    Reject unknown versions rather than guess their framing. Even if the server
    offers None (type 1), close before ClientInit/authentication can begin.
    """
    greeting = read_exact(connection, 12, deadline)
    if re.fullmatch(rb"RFB [0-9]{3}\.[0-9]{3}\n", greeting) is None:
        raise ProbeError("invalid_greeting")
    major, minor = int(greeting[4:7]), int(greeting[8:11])
    if major != 3 or minor not in (3, 7, 8, 889):
        raise ProbeError("unsupported_version")
    selected = 8 if minor == 889 else minor
    connection.settimeout(remaining(deadline))
    connection.sendall(f"RFB 003.{selected:03d}\n".encode("ascii"))
    if selected == 3:
        security = struct.unpack("!I", read_exact(connection, 4, deadline))[0]
        if security == 0:
            raise ProbeError("server_refused")
        types = [security]
    else:
        count = read_exact(connection, 1, deadline)[0]
        if count == 0:
            # Do not fetch or print the server's arbitrary failure reason.
            raise ProbeError("server_refused")
        types = list(read_exact(connection, count, deadline))
    if 0 in types or len(set(types)) != len(types):
        raise ProbeError("invalid_security_types")
    return {
        "server_version": f"{major}.{minor:03d}",
        "client_version": f"3.{selected:03d}",
        "security_types": types,
        "apple_ard_offered": 30 in types,
        "no_authentication_offered": 1 in types,
        "password_only_vnc_offered": 2 in types,
    }


def probe(timeout=3.0):
    if not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError("timeout must be finite and in (0, 30]")
    started = time.monotonic()
    deadline = started + timeout
    result = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "endpoint": "127.0.0.1:5900",
        "authentication_tested": False,
        "locked_access_verified": False,
    }
    try:
        # A numeric address avoids DNS delay outside our single operation deadline.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(remaining(deadline))
            connection.connect(("127.0.0.1", 5900))
            result.update(discover(connection, deadline))
        result["status"] = "discovered"
    except ProbeError as error:
        result["status"] = str(error)
    except TimeoutError:
        result["status"] = "timeout"
    except OSError as error:
        result["status"] = "not_listening" if error.errno == errno.ECONNREFUSED else "network_error"
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def finite_number(value):
    number = float(value)
    if not math.isfinite(number):
        raise argparse.ArgumentTypeError("must be finite")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--interval", type=finite_number, default=5)
    parser.add_argument("--timeout", type=finite_number, default=3)
    args = parser.parse_args(argv)
    if not 1 <= args.samples <= 120:
        parser.error("samples must be in [1, 120]")
    if not 1 <= args.interval <= 60:
        parser.error("interval must be in [1, 60] seconds")
    if not 0 < args.timeout <= 30:
        parser.error("timeout must be in (0, 30] seconds")
    try:
        failed = False
        for sample in range(args.samples):
            result = probe(args.timeout)
            print(json.dumps(result, sort_keys=True), flush=True)
            failed |= result["status"] != "discovered"
            if sample + 1 < args.samples:
                # Sequential, at most one connection alive. No rapid retry loop.
                time.sleep(args.interval)
        return 1 if failed else 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
