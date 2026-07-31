#!/usr/bin/env python3
"""Service Prioritizer - order discovered ports/services by the HTB
Priority Matrix from this skill's SKILL.md.

Usage: service-prioritizer.py --services "21,22,80,445" --target {ip}

Accepts a comma-separated list of ports (or service names) and returns
them in recommended testing order.
"""
import argparse

# Mirrors the "HTB Service Priority Matrix" table in SKILL.md - keep these
# two in sync if the table changes.
PRIORITY_MATRIX = [
    {"priority": 1, "service": "FTP", "ports": [21], "success_rate": 1.00, "notes": "Anonymous access, credential files"},
    {"priority": 2, "service": "SMB", "ports": [445, 139], "success_rate": 0.75, "notes": "Null sessions, user enumeration"},
    {"priority": 3, "service": "HTTP/HTTPS", "ports": [80, 443], "success_rate": 0.68, "notes": "Web vulnerabilities, default creds"},
    {"priority": 4, "service": "SSH", "ports": [22], "success_rate": 0.45, "notes": "Credential reuse, weak passwords"},
    {"priority": 5, "service": "MySQL", "ports": [3306], "success_rate": 0.41, "notes": "Default/blank root, UDF exploitation"},
    {"priority": 6, "service": "Redis", "ports": [6379], "success_rate": 0.95, "notes": "Unauthenticated access"},
    {"priority": 7, "service": "Docker", "ports": [2375, 2376], "success_rate": 0.90, "notes": "API exposure, container escape"},
    {"priority": 8, "service": "MongoDB", "ports": [27017], "success_rate": 0.85, "notes": "No authentication"},
    {"priority": 9, "service": "Elasticsearch", "ports": [9200], "success_rate": 0.82, "notes": "No authentication, data exposure"},
    {"priority": 10, "service": "RDP", "ports": [3389], "success_rate": 0.35, "notes": "BlueKeep, credential attacks"},
]

PORT_TO_ENTRY = {port: entry for entry in PRIORITY_MATRIX for port in entry["ports"]}


def main():
    parser = argparse.ArgumentParser(description="Prioritize discovered services against the HTB priority matrix")
    parser.add_argument("--services", required=True, help="Comma-separated ports, e.g. '21,22,80,445'")
    parser.add_argument("--target", default=None)
    args = parser.parse_args()

    ports = []
    for raw in args.services.split(","):
        raw = raw.strip()
        if raw.isdigit():
            ports.append(int(raw))

    matched = []
    unmatched = []
    seen_services = set()
    for port in ports:
        entry = PORT_TO_ENTRY.get(port)
        if entry and entry["service"] not in seen_services:
            matched.append(entry)
            seen_services.add(entry["service"])
        elif not entry:
            unmatched.append(port)

    matched.sort(key=lambda e: e["priority"])

    target_str = f" on {args.target}" if args.target else ""
    print(f"Recommended attack sequence{target_str}:")
    for i, entry in enumerate(matched, 1):
        print(f"  {i}. {entry['service']} (priority {entry['priority']}, {entry['success_rate']:.0%} success rate) - {entry['notes']}")

    if unmatched:
        print()
        print(f"Ports not in the priority matrix (test manually): {', '.join(str(p) for p in unmatched)}")


if __name__ == "__main__":
    main()
