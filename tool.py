import argparse
import getpass
import hashlib
import json
import os
import subprocess
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# =========================================================
# PORTABLE CONFIGURATION
# Modify these values directly in the source code before deployment
# =========================================================
WORKER_URL = "https://your-worker.your-subdomain.workers.dev"
REPO_OWNER = "your-github-username"
REPO_NAME = "your-repo-name"
# =========================================================


def get_auth_hash():
    password = getpass.getpass("Enter access password: ")
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def fetch_token(action, password_hash):
    payload = json.dumps({"action": action, "auth": password_hash}).encode("utf-8")
    req = Request(
        f"{WORKER_URL}/token",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            return data.get("token")
    except HTTPError as e:
        sys.exit(f"Authentication/Worker Error ({e.code}): {e.reason}")


def revoke_token(token):
    req = Request(
        "https://api.github.com/installation/token",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        method="DELETE",
    )
    try:
        with urlopen(req):
            pass
    except Exception:
        pass  # Silent failure on cleanup attempt


def main():
    parser = argparse.ArgumentParser(description="Portable Secure Git Proxy CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Clone / Pull Subcommand
    fetch_parser = subparsers.add_parser("fetch", help="Clone or Pull changes (Read-Only)")
    fetch_parser.add_argument("target_dir", help="Directory path to clone into or pull within")

    # Push Subcommand
    push_parser = subparsers.add_parser("push", help="Push local commits (Write)")
    push_parser.add_argument("target_dir", help="Directory path of the local repository")

    args = parser.parse_args()
    auth_hash = get_auth_hash()

    if args.command == "fetch":
        token = fetch_token("read", auth_hash)
        authed_url = f"https://x-access-token:{token}@github.com/{REPO_OWNER}/{REPO_NAME}.git"
        target = os.path.abspath(args.target_dir)

        try:
            if not os.path.exists(os.path.join(target, ".git")):
                subprocess.run(["git", "clone", authed_url, target], check=True)
            else:
                subprocess.run(["git", "-C", target, "pull", authed_url], check=True)
        finally:
            revoke_token(token)

        print("Fetch completed and session token revoked.")

    elif args.command == "push":
        token = fetch_token("write", auth_hash)
        authed_url = f"https://x-access-token:{token}@github.com/{REPO_OWNER}/{REPO_NAME}.git"
        clean_url = f"https://github.com/{REPO_OWNER}/{REPO_NAME}.git"
        target = os.path.abspath(args.target_dir)

        try:
            subprocess.run(["git", "-C", target, "remote", "set-url", "origin", authed_url], check=True)
            subprocess.run(["git", "-C", target, "push", "origin"], check=True)
        finally:
            subprocess.run(["git", "-C", target, "remote", "set-url", "origin", clean_url])
            revoke_token(token)

        print("Push completed and session token revoked.")


if __name__ == "__main__":
    main()
