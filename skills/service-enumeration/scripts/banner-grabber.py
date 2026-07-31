#!/usr/bin/env python3
"""Banner Grabber - connect to a TCP port and capture whatever banner the
service sends (or send a minimal probe for services that don't banner
first, like HTTP).

Usage: banner-grabber.py --target IP --port PORT [--timeout SECONDS]
"""
import argparse
import socket
import sys

# Services that wait for the client to speak first rather than banner
# immediately - send a minimal probe to elicit a response
PROBE_PORTS = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
}


def grab(target: str, port: int, timeout: float) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((target, port))

        probe = PROBE_PORTS.get(port)
        if probe:
            sock.sendall(probe)

        try:
            data = sock.recv(4096)
        except socket.timeout:
            data = b""

        return data.decode("utf-8", errors="replace").strip()


def main():
    parser = argparse.ArgumentParser(description="Grab a service banner")
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    try:
        banner = grab(args.target, args.port, args.timeout)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"{args.target}:{args.port} - ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    if banner:
        print(f"{args.target}:{args.port} - {banner}")
    else:
        print(f"{args.target}:{args.port} - (connected, no banner received)")


if __name__ == "__main__":
    main()
