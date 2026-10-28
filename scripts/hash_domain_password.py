#!/usr/bin/env python3
"""Prints the DOMAIN_PASSWORDS entry for a domain's password.

    venv/bin/python scripts/hash_domain_password.py voorbeeld.nl

Asks for the password (twice, not echoed) and prints "voorbeeld.nl=<hash>",
to add to DOMAIN_PASSWORDS in .env (comma-separated for several domains).
"""
import getpass
import sys

from werkzeug.security import generate_password_hash


def main():
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <domain>")
    domain = sys.argv[1].strip().lower().rstrip(".")
    password = getpass.getpass(f"Password for {domain}: ")
    if not password:
        sys.exit("Empty password, nothing printed")
    if getpass.getpass("Again: ") != password:
        sys.exit("Passwords don't match")
    print(f"{domain}={generate_password_hash(password)}")


if __name__ == "__main__":
    main()
