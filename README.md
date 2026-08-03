# Offline EVM Transaction Signer

A standalone, **air-gap ready** Python script to sign unsigned EVM transactions.

> **This tool makes zero network calls.** It is safe to run on a machine with no internet connection.

---

## Directory Structure

```
offline_signer/
├── signer.py        ← the only script you need
├── requirements.txt ← eth-account + colorama (no web3)
└── README.md
```

## Setup (one-time, can be done online before air-gapping)

### Option A: USB wheelhouse (recommended for Tails / air-gapped systems)

On the online machine:

```bash
cd offline_signer
python3 -m venv venv
source venv/bin/activate
pip download --only-binary=:all: -r requirements.txt -d wheelhouse
```

Copy the entire folder to a USB stick, then on the offline machine:

```bash
cd offline_signer
python3 -m venv venv
source venv/bin/activate
pip install --no-index --find-links wheelhouse -r requirements.txt
```

This avoids any network access and keeps every dependency on the USB drive.

### Option B: install directly from the offline machine's package cache

```bash
cd offline_signer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Use this only if the offline machine already has access to the necessary package cache.

---

## Usage

### Sign a transaction

```bash
python signer.py /path/to/unsigned_tx.json
```

With a custom output path:
```bash
python signer.py unsigned_tx.json -o my_signed_tx.json
```

### Inspect a TX file without signing

```bash
python signer.py unsigned_tx.json --inspect-only
```

---

## Full Air-Gap Workflow

```
ONLINE MACHINE                        OFFLINE MACHINE (air-gapped)
──────────────────────                ─────────────────────────────
python main.py                        python signer.py unsigned_tx.json
  → Build unsigned TX                   → Review all TX fields carefully
  → Export unsigned_tx.json             → Enter private key (hidden)
         │                              → Address match verified
         │   USB / QR / SD             → Signed → signed_tx.json
         ├──────────────────►                  │
         │                                     │   USB / QR / SD
         │◄────────────────────────────────────┘
         │
  → main.py → option 8
  → Broadcast signed_tx.json
```

---

## Signed TX Output Format

```json
{
  "schema":        "evm-signed-tx/v1",
  "created_at":    "2025-01-01T00:00:00+00:00",
  "status":        "signed",
  "chain":         "Ethereum Mainnet",
  "chain_key":     "ethereum",
  "tx_type":       "ETH Transfer",
  "from":          "0xYourWallet...",
  "to":            "0xRecipient...",
  "tx_hash":       "0xExpectedHash...",
  "signed_raw_tx": "0xf86c...",
  "original_unsigned_tx": { ... }
}
```

The `signed_raw_tx` field is what the online machine broadcasts.

---

## Security Notes

### USB transport checklist

- Create a dedicated folder such as `wheelhouse/` and copy it to a fresh USB drive.
- Verify the SHA-256 hashes of the downloaded wheels before transferring them.
- Prefer a read-only USB filesystem or verify the files after copy.
- Keep the signed JSON and unsigned JSON on separate USB devices if possible.
- Never reuse the same USB stick for both dependency transfer and transaction data unless it is fully wiped and re-verified.

### Redundancy and weakness review

- The script now has a single, explicit dependency boundary: it only requires `eth-account` and no network-capable imports.
- Private-key handling was hardened by centralizing normalization and rejecting malformed input early.
- The code path now fails loudly if `eth-account` is missing instead of crashing later in a confusing way.
- The offline workflow is documented as a wheelhouse-based transfer, which is better suited to Tails and air-gapped laptops than ad-hoc `pip install`.

| Property | Detail |
|---|---|
| 🔌 No network calls | Zero imports that touch the network |
| 🔑 Hidden key input | `getpass` — key never echoed to terminal |
| 🧹 Memory scrub | Key bytes and hex string overwritten after signing |
| ✅ Address verification | Derived address must match TX `from` field before signing |
| 📋 Full audit trail | Original unsigned TX embedded in signed output |
| ⚠️ Screen security | Ensure no screen recording / keyloggers are active |
