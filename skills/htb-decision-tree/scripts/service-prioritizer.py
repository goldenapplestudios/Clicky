#!/usr/bin/env python3
"""Service Prioritizer - order discovered ports/services by Clicky's
self-calibrated htb-decision-tree priority data (see priority_data.py):
real measured success rates from this operator's own session history
where enough exist, honest heuristic ordering otherwise. Never a static
hardcoded table - see skills/htb-decision-tree/SKILL.md.

Usage:
  service-prioritizer.py --services "21,22,80,445" [--target {ip}] [--min-samples N]
  service-prioritizer.py --show-matrix [--min-samples N]
"""
import argparse
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import priority_data  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Prioritize discovered services against Clicky's calibrated priority data")
    parser.add_argument("--services", default=None, help="Comma-separated ports, e.g. '21,22,80,445'")
    parser.add_argument("--target", default=None)
    parser.add_argument("--min-samples", type=int, default=None, help="Override the min_sample_threshold for this run")
    parser.add_argument("--show-matrix", action="store_true", help="Print the full merged priority table (all known services), not just discovered ports")
    args = parser.parse_args()

    merged, threshold = priority_data.load_merged_services(min_samples=args.min_samples)

    if args.show_matrix:
        print(f"htb-decision-tree priority matrix (min_sample_threshold={threshold}):")
        ordered = sorted(merged.items(), key=lambda kv: kv[1]["value"], reverse=True)
        for svc, entry in ordered:
            ports = "/".join(str(p) for p in entry["ports"])
            print(f"  [{ports}] {priority_data.format_entry(svc, entry)} - {entry['notes']}")
        return

    if not args.services:
        parser.error("--services is required unless --show-matrix is given")

    ports = []
    for raw in args.services.split(","):
        raw = raw.strip()
        if raw.isdigit():
            ports.append(int(raw))

    port_to_service = priority_data.port_to_service_map(merged)

    matched = []
    unmatched = []
    seen_services = set()
    for port in ports:
        svc = port_to_service.get(port)
        if svc and svc not in seen_services:
            matched.append((svc, merged[svc]))
            seen_services.add(svc)
        elif not svc:
            unmatched.append(port)

    matched.sort(key=lambda kv: kv[1]["value"], reverse=True)

    target_str = f" on {args.target}" if args.target else ""
    print(f"Recommended attack sequence{target_str}:")
    for i, (svc, entry) in enumerate(matched, 1):
        print(f"  {i}. {priority_data.format_entry(svc, entry)} - {entry['notes']}")

    if unmatched:
        print()
        print(f"Ports not in the priority matrix (test manually): {', '.join(str(p) for p in unmatched)}")


if __name__ == "__main__":
    main()
