"""Create/update a user in a credentials file; passwords are never stored in plaintext."""

import argparse
import getpass
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.security import ROLES, hash_password  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("name")
    parser.add_argument("--role", choices=sorted(ROLES), required=True)
    parser.add_argument("--token", action="store_true", help="Generate a collector bearer token")
    args = parser.parse_args()
    users = json.loads(args.file.read_text()) if args.file.exists() else []
    user = {"name": args.name, "role": args.role}
    if args.token:
        secret = secrets.token_urlsafe(32)
        user["token_hash"] = hashlib.sha256(secret.encode()).hexdigest()
    else:
        password = getpass.getpass("Password (at least 14 characters): ")
        if len(password) < 14 or password != getpass.getpass("Confirm password: "):
            parser.error("passwords must match and contain at least 14 characters")
        user["password_hash"] = hash_password(password)
    users = [u for u in users if u["name"] != args.name] + [user]
    args.file.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.file.with_suffix(args.file.suffix + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(users, stream, indent=2)
    os.replace(temporary, args.file)
    print(f"Saved {args.name} ({args.role}). Restart the service to load changes.")
    if args.token:
        print(f"Save this token now; it is shown only once: {secret}")


if __name__ == "__main__":
    main()
