#!/usr/bin/env python3
"""Service Correlator - suggest attack paths from combinations of
discovered services (per this skill's own "Service Correlation" examples:
Web + MySQL = SQL injection potential, SSH + FTP = credential reuse
opportunity, SMB + LDAP = Active Directory environment).

Usage: service-correlator.py --services "ftp,ssh,http,mysql"
"""
import argparse

# (required services, suggestion) - required services must ALL be present
# (order doesn't matter; matching is case-insensitive)
RULES = [
    ({"http", "mysql"}, "Web + MySQL: check the web app for SQL injection reaching this database"),
    ({"https", "mysql"}, "Web + MySQL: check the web app for SQL injection reaching this database"),
    ({"ssh", "ftp"}, "SSH + FTP: credential reuse opportunity - test any FTP creds against SSH and vice versa"),
    ({"smb", "ldap"}, "SMB + LDAP: likely Active Directory environment - prioritize AD enumeration (see active-directory skill)"),
    ({"smb", "kerberos"}, "SMB + Kerberos (88): likely Active Directory environment - prioritize AD enumeration"),
    ({"http", "redis"}, "Web + Redis: check for SSRF/RCE chains via exposed Redis (webshell write, or redis used as a cache with app-level trust)"),
    ({"http", "mongodb"}, "Web + MongoDB: check for NoSQL injection in the web app's query construction"),
    ({"ftp", "http"}, "FTP + HTTP: check whether the FTP root overlaps the web root (upload a webshell via FTP, execute via HTTP)"),
    ({"docker", "http"}, "Docker API + HTTP: check whether the web app is containerized and whether the Docker API (2375/2376) is reachable from it"),
    ({"kubernetes", "http"}, "Kubernetes API + HTTP: check whether the web app runs in-cluster with a mounted service account token"),
    ({"smtp", "http"}, "SMTP + HTTP: check the web app for email-header/SMTP injection in any contact-form or notification feature"),
    ({"mssql", "http"}, "MSSQL + HTTP: check the web app for SQL injection, and MSSQL for xp_cmdshell if credentials are found"),
]


def normalize(services: str):
    return {s.strip().lower() for s in services.split(",") if s.strip()}


def main():
    parser = argparse.ArgumentParser(description="Correlate services into attack path suggestions")
    parser.add_argument("--services", required=True, help="Comma-separated service names, e.g. 'ftp,ssh,http,mysql'")
    args = parser.parse_args()

    found = normalize(args.services)
    print(f"Services: {', '.join(sorted(found))}")
    print()

    matches = [suggestion for required, suggestion in RULES if required.issubset(found)]

    if matches:
        print("Correlated attack paths:")
        for m in matches:
            print(f"  - {m}")
    else:
        print("No known service combinations matched. This isn't exhaustive - use judgment for")
        print("combinations not in this list.")


if __name__ == "__main__":
    main()
