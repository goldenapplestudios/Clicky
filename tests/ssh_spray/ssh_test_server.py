#!/usr/bin/env python3
"""A real SSH server for testing tools/ssh-spray.py.

This is not a mock of the SSH client library - it is an actual SSH server
speaking the real SSH-2 protocol over a real socket: real KEX, real host key,
real password authentication. The sprayer under test talks to it exactly as it
would talk to OpenSSH, so a passing test means the tool genuinely works rather
than that a stub returned what the test wanted.

It can also reproduce the behavior that produced a false negative in the field:
OpenSSH's MaxStartups drops inbound connections under load, and a connection
dropped before the banner never reaches authentication. A sprayer that scores
those as "wrong password" reports a clean negative for credentials it never
tried. `--throttle-every N` drops every Nth connection pre-banner so that path
is exercised for real.

Usage:
  ssh_test_server.py --user U --password P [--port 0] [--throttle-every N]
                     [--throttle-first N]
Prints "READY <port>" on stdout once listening.
"""
import argparse
import socket
import sys
import threading

import paramiko


class _Server(paramiko.ServerInterface):
    def __init__(self, user, password):
        self.user, self.password = user, password

    def check_auth_password(self, username, password):
        if username == self.user and password == self.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED


def serve(args):
    host_key = paramiko.RSAKey.generate(2048)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", args.port))
    sock.listen(64)
    print(f"READY {sock.getsockname()[1]}", flush=True)

    count = {"n": 0}
    lock = threading.Lock()

    def handle(client):
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        try:
            transport.start_server(server=_Server(args.user, args.password))
            chan = transport.accept(5)
            if chan is not None:
                chan.close()
        except Exception:
            pass
        finally:
            try:
                transport.close()
            except Exception:
                pass

    while True:
        try:
            client, _ = sock.accept()
        except OSError:
            break
        with lock:
            count["n"] += 1
            n = count["n"]
        # Drop pre-banner, exactly like MaxStartups: the client sees
        # "Error reading SSH protocol banner" / connection reset, and no
        # authentication ever happens.
        throttled = (
            (args.throttle_first and n <= args.throttle_first)
            or (args.throttle_every and n % args.throttle_every == 0)
        )
        if throttled:
            try:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                  __import__("struct").pack("ii", 1, 0))
                client.close()
            except OSError:
                pass
            continue
        threading.Thread(target=handle, args=(client,), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--throttle-every", type=int, default=0)
    ap.add_argument("--throttle-first", type=int, default=0)
    args = ap.parse_args()
    try:
        serve(args)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
