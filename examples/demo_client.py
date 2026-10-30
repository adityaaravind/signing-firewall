#!/usr/bin/env python3
"""Demo client: makes REAL API calls to a running Signing Firewall server.

Start the server first in another terminal:
  python signing-firewall.py serve

Then run:
  python examples/demo_client.py

It tries a normal transfer, a single-approval large transfer,
a non-allowlisted transfer, and a velocity burst. The firewall
must block the last three in the ways printed below.
"""
import json
import urllib.request

BASE = "http://127.0.0.1:8765"


def api(path, body=None):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"},
        method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return {"http_error": e.code, **json.loads(e.read().decode())}


def propose(to, amount):
    return api("/api/transfers", {"from_account": "ops-001",
                                  "to_account": to, "amount": amount})


def approve(tid, who):
    return api(f"/api/transfers/{tid}/approve", {"approver": who})


def main():
    print("== 1. Normal small transfer (should approve with 1 approver) ==")
    r = propose("vendor-001", 5000)
    print(r)
    if "transfer" in r:
        print(approve(r["transfer"]["id"], "alice"))

    print("\n== 2. Large transfer, only 1 approval (must stay PENDING) ==")
    r = propose("vendor-001", 20000)
    print(r)
    if "transfer" in r:
        print(approve(r["transfer"]["id"], "alice"))

    print("\n== 3. Non-allowlisted destination (must be rejected) ==")
    print(propose("attacker-999", 100))

    print("\n== 4. Velocity burst (must freeze the system) ==")
    for i in range(6):
        r = propose("payroll-001", 9000)
        print("propose", i, r.get("transfer", {}).get("id"), r.get("error", ""))
        if "transfer" in r:
            print(" approve:", approve(r["transfer"]["id"], "alice"))

    print("\n== Final state ==")
    print(api("/api/state")["counts"] if "counts" in api("/api/state") else "state fetch failed")


if __name__ == "__main__":
    main()
