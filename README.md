# Signing Firewall

**One compromised laptop should not be able to drain your money.**

Signing Firewall is a small, real policy proxy that sits between the app that asks for a transfer and the system that actually signs or sends it. If a transfer breaks the rules, the firewall really says no — it does not just show a warning on a dashboard.

It was built after the October 2026 Binance hack, where attackers did not need to steal wallet keys. They got a signing system to approve transfers that looked valid, across many chains, in about 20 minutes. The lesson is simple: do not let one machine, one app, or one approval decide everything.

![Signing Firewall demo](docs/demo.gif)

*Demo GIF: captured from a real run of the terminal dashboard — a small transfer approved, a large transfer stuck on 1 of 2 approvals, a velocity burst freezing the system, and Watchtower freezing it again on an unauthorised delegation. Not a mockup.*

## What this is for

Use it when money, payroll, vendor payments, or crypto withdrawals go through an internal system, and you want a second, independent gate in front of them.

It is for small teams, solo builders, and ops / IT / security people who want:

- a transfer to need **two different people** when it is large,
- transfers to go **only to destinations you have allowlisted**,
- a **speed limit** that freezes everything when too much leaves too fast,
- large transfers to **wait** before they can be released, so a bad one can be cancelled,
- a **watcher** that freezes everything if a watched Ethereum wallet suddenly delegates control to an unknown contract.

It is not a wallet, not an exchange, and not a signer. It holds no private keys and signs nothing. That is deliberate: it is the gate, not the key.

## Quickstart: 3 steps

You need Python 3.9 or newer. No other packages. It works on Linux, macOS, and Windows.

### Step 1. Install

**Linux / macOS, one command:**

```bash
curl -fsSL https://raw.githubusercontent.com/adityaaravind/signing-firewall/main/install.sh | bash
```

**Windows, one command in PowerShell:**

```powershell
irm https://raw.githubusercontent.com/adityaaravind/signing-firewall/main/install.ps1 | iex
```

**Or, from this repo, with no install step:**

```bash
python signing-firewall.py serve
```

### Step 2. Start it

```bash
signing-firewall serve
```

You will see something like:

```text
Signing Firewall 0.1.0
Web app:  http://127.0.0.1:8765/
Terminal: python signing-firewall.py dashboard --url http://127.0.0.1:8765
```

Leave that terminal running. That is your firewall server.

### Step 3. Watch it, two ways

**Web app** — open http://127.0.0.1:8765/ in a browser. Propose a transfer, approve it, freeze or unfreeze the system, and add a wallet to Watchtower. The page refreshes every second.

**Terminal dashboard** — in a second terminal, while the server is running:

```bash
signing-firewall dashboard
```

For a single snapshot, for screenshots or scripts:

```bash
signing-firewall dashboard --once
signing-firewall dashboard --once --no-color
```

The terminal dashboard uses plain ASCII (`#` and `-` bars), so it renders in Windows cmd as well as Terminal and PowerShell.

## Try it in 2 minutes

With the server running, run the demo client. It makes real API calls to your server, including the ones the firewall must block:

```bash
python examples/demo_client.py
```

You should see, in order:

| What the demo tries | What should happen |
|---|---|
| Small transfer, $5,000 to `vendor-001` | Approved with 1 approver |
| Large transfer, $20,000, only 1 approval | Stays `PENDING` — it needs 2 different approvers |
| Transfer to `attacker-999` | Rejected — destination is not allowlisted |
| Six $9,000 transfers in a burst | The last one breaches velocity, the transfer is blocked, and the whole system freezes |

Then open the web app or terminal dashboard and you will see that frozen state, live. To try again, unfreeze it in the web app with a reason.

## How a transfer flows

1. Your app sends a transfer to the firewall, not directly to the signer:
   `POST /api/transfers` with `from_account`, `to_account`, and `amount`.
2. The firewall checks, in order: Is the system frozen? Is the destination allowlisted? Is the amount positive?
3. The transfer becomes `PENDING`. Small transfers need 1 approval. Large transfers need 2 different approvers.
4. Very large transfers also wait out a timelock. After approvals, use `POST /api/transfers/<id>/release` once the timelock has expired.
5. On approval, the firewall checks velocity again. If the approved total in the window would exceed the limit, it blocks that transfer and freezes the system.
6. Every decision — proposed, approved, blocked, frozen, un-frozen, Watchtower alert — is written to a hash-chained audit log in `signing-firewall-data/audit.log`. Changing an earlier entry breaks the chain.

## Watchtower: watching a real wallet

Watchtower checks a real Ethereum wallet using a public RPC and `eth_getCode`:

- An ordinary wallet has code `0x`.
- A wallet delegated under EIP-7702 has code starting `0xef0100`, followed by the contract it delegated to.
- If that contract is not in your `allowed_delegations`, Watchtower freezes the system and logs `WATCHTOWER_ALERT`.
- If the RPC itself fails, Watchtower reports an error. It does **not** freeze on a network error, so an outage alone cannot shut you down.

Check a wallet without starting the server:

```bash
python signing-firewall.py watchtower --address 0x28C6c06298d514Db089934071355E5743bf21d60
```

Add a wallet in the web app, or set `watched_addresses` and `rpc_url` in your config. The default RPC is a public endpoint (`https://ethereum.publicnode.com`). For production, use your own RPC.

If your own wallet legitimately delegates to a contract you trust, add that contract to `allowed_delegations`. Otherwise Watchtower will, correctly, treat it as unauthorised.

## Configuration

Copy `config.example.json` to `config.json`, edit it, and start with `--config config.json`.

| Setting | Default | What it means |
|---|---|---|
| `allowlist` | `vendor-001`, `payroll-001`, `ops-001` | Only these destinations can receive transfers |
| `dual_approval_threshold` | `10000` | At or above this, 2 different approvers are required |
| `timelock_threshold` | `100000` | At or above this, the transfer waits before release |
| `timelock_seconds` | `60` | How long it waits (use hours in production) |
| `velocity_limit` | `50000` | Maximum approved total in the window |
| `velocity_window_seconds` | `600` | The window for that limit, in seconds |
| `allowed_delegations` | `[]` | Contracts a watched wallet is allowed to delegate to |
| `rpc_url` | `https://ethereum.publicnode.com` | RPC used by Watchtower |
| `watch_interval_seconds` | `60` | How often the server re-checks watched wallets |

## API, in brief

| Endpoint | Use |
|---|---|
| `GET /api/state` | Live counts, velocity, pending transfers, Watchtower, audit tail |
| `POST /api/transfers` | Propose: `{from_account, to_account, amount}` |
| `POST /api/transfers/<id>/approve` | Approve: `{approver}` |
| `POST /api/transfers/<id>/release` | Release after the timelock expires |
| `POST /api/freeze` / `POST /api/unfreeze` | Freeze / unfreeze: `{reason}` |
| `POST /api/watchtower` | Watch a wallet: `{address}` |
| `POST /api/watchtower/check` | Check all watched wallets now |

## How to deploy it safely

1. **Run it separately.** This only helps if the firewall runs on separate credentials, ideally a separate machine, from the laptop or app that requests transfers. If an attacker owns both, they own the policy.
2. **Start with test accounts.** Test your allowlist, thresholds, timelock, and unfreeze procedure before you point it at anything real. Start on testnet for any crypto wallets.
3. **Make unfreezing a real procedure.** This version lets an admin unfreeze with a reason. In production, require two different admins and an out-of-band confirmation.
4. **Do not rely on this alone.** In production, pair it with an HSM or threshold signing, a cold wallet for large amounts, and a separate approval device. This tool is one gate, not the whole security system.

## Limits, honestly

- It cannot un-sign a transaction. Once a valid signature is broadcast on-chain, no tool can take it back. That is why the checks happen before signing, and why timelocks matter.
- It cannot stop an attacker who already controls the firewall machine and its credentials. Separation is part of the design, not an optional extra.
- Watchtower detects delegation, it does not revoke it for you. Revoking still needs a transaction signed by the wallet owner, or pausing deposits to that wallet.
- This is a defensive tool only. It contains no exploit code.

## Tests and project layout

```bash
python -m unittest tests.test_engine -v
```

- `signing-firewall.py` — the whole tool in one file: policy engine, web server, terminal dashboard, Watchtower. One file is why one-command install is real.
- `install.sh`, `install.ps1` — one-command installers.
- `config.example.json` — editable policy.
- `examples/demo_client.py` — real API test client.
- `tests/test_engine.py` — unit tests for policy, Watchtower parsing, and the audit chain.

## License

MIT. See LICENSE.
