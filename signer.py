#!/usr/bin/env python3
"""
signer.py — Offline EVM Transaction Signer
============================================
Designed to run on a completely AIR-GAPPED machine.

Workflow:
  1. Copy the unsigned_tx.json from the online machine (USB / QR / SD card)
  2. Run:  python signer.py unsigned_tx.json
  3. Review every TX field carefully before confirming
  4. Enter your private key when prompted (hidden input, never logged)
  5. The signed_tx.json is written to disk
  6. Copy signed_tx.json back to the online machine for broadcast

Security contract:
  • No network calls are made — ever.
  • Private key is read via getpass (not echoed to terminal).
  • Key bytes are overwritten in memory immediately after signing.
  • The signed output contains ONLY the raw signed hex — no key material.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import sys
from datetime import datetime, timezone
from decimal import Decimal
from getpass import getpass
from pathlib import Path
from typing import Any

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:  # pragma: no cover - exercised in minimal offline environments
    class _ColorFallback:
        BLACK = ""
        RED = ""
        GREEN = ""
        YELLOW = ""
        BLUE = ""
        CYAN = ""
        WHITE = ""
        DIM = ""
        BRIGHT = ""
        RESET_ALL = ""

    Fore = _ColorFallback()
    Style = _ColorFallback()

    def colorama_init(*_args: Any, **_kwargs: Any) -> None:
        return None

try:
    from eth_account import Account
    from eth_account.signers.local import LocalAccount
except ImportError:  # pragma: no cover - exercised when wheelhouse is not installed yet
    Account = None
    LocalAccount = Any

colorama_init(autoreset=True)

# ---------------------------------------------------------------------------
# Schema constants
# ---------------------------------------------------------------------------
UNSIGNED_SCHEMA = "evm-unsigned-tx/v1"
SIGNED_SCHEMA   = "evm-signed-tx/v1"

# ---------------------------------------------------------------------------
# Terminal helpers (self-contained — no dependency on online utils.py)
# ---------------------------------------------------------------------------

W = 64  # banner width


def _c(text: str, colour: str, bold: bool = False) -> str:
    b = Style.BRIGHT if bold else ""
    return f"{colour}{b}{text}{Style.RESET_ALL}"


def banner() -> None:
    print()
    print(_c("─" * W, Fore.CYAN, bold=True))
    print(_c("  OFFLINE EVM TRANSACTION SIGNER", Fore.CYAN, bold=True))
    print(_c("  Air-Gap Ready  ·  No Network Required", Fore.WHITE))
    print(_c("─" * W, Fore.CYAN, bold=True))
    print()


def header(text: str) -> None:
    print()
    print(_c(f"  ── {text} ", Fore.CYAN, bold=True))


def ok(text: str) -> None:
    print(_c("✔  ", Fore.GREEN, bold=True) + text)


def err(text: str) -> None:
    print(_c("✘  ", Fore.RED, bold=True) + text)


def warn(text: str) -> None:
    print(_c("⚠  ", Fore.YELLOW, bold=True) + text)


def info(text: str) -> None:
    print(_c("ℹ  ", Fore.BLUE) + text)


def field(label: str, value: str, indent: int = 4, alert: bool = False) -> None:
    colour = Fore.YELLOW if alert else Fore.CYAN
    pad = " " * indent
    print(f"{pad}{_c(f'{label:<26}', colour)}{value}")


def sep() -> None:
    print(_c("─" * W, Fore.WHITE + Style.DIM))


# ---------------------------------------------------------------------------
# Load & validate unsigned TX
# ---------------------------------------------------------------------------

def load_unsigned_tx(filepath: str) -> tuple[dict, dict]:
    """
    Load and validate an unsigned TX JSON file.

    Returns:
        (payload, tx_dict)  — the full JSON payload and the core tx fields.
    Raises:
        SystemExit on any validation failure.
    """
    path = Path(filepath).expanduser().resolve()
    if not path.exists():
        err(f"File not found: {path}")
        sys.exit(1)

    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except json.JSONDecodeError as exc:
        err(f"Invalid JSON: {exc}")
        sys.exit(1)

    schema = payload.get("schema", "")
    if not schema.startswith("evm-unsigned-tx"):
        warn(f"Unexpected schema '{schema}' — proceeding with caution.")

    status = payload.get("status", "unknown")
    if status == "signed":
        err("This file is already SIGNED. Nothing to do.")
        sys.exit(1)

    tx_raw = payload.get("tx", payload)
    return payload, tx_raw


def extract_core_tx(tx_raw: dict) -> dict:
    """
    Strip metadata blocks and return only the EVM-consensus fields
    that eth_account.sign_transaction() expects.
    """
    SKIP = {"_meta", "_hex"}
    INT_FIELDS = {
        "chainId", "nonce", "value", "gas",
        "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas",
    }
    tx: dict[str, Any] = {}
    for key, value in tx_raw.items():
        if key in SKIP:
            continue
        if key in INT_FIELDS:
            tx[key] = int(value)
        elif key == "data" and isinstance(value, str):
            tx[key] = bytes.fromhex(value[2:]) if value.startswith("0x") else bytes.fromhex(value)
        else:
            tx[key] = value
    return tx


# ---------------------------------------------------------------------------
# Display TX for human review
# ---------------------------------------------------------------------------

CHAIN_NAMES = {
    1:     "Ethereum Mainnet",
    56:    "BNB Smart Chain",
    137:   "Polygon Mainnet",
    42161: "Arbitrum One",
    10:    "Optimism Mainnet",
    8453:  "Base Mainnet",
    43114: "Avalanche C-Chain",
}


def wei_to_eth(wei: int) -> str:
    return f"{Decimal(wei) / Decimal(10**18):.10f}"


def wei_to_gwei(wei: int) -> str:
    return f"{Decimal(wei) / Decimal(10**9):.4f}"


def display_tx(payload: dict, tx_raw: dict) -> None:
    """Print every TX field for careful human review."""
    meta   = tx_raw.get("_meta", {})
    gas_r  = meta.get("gas_readable", {})
    tx     = extract_core_tx(tx_raw)

    chain_id   = tx.get("chainId", "?")
    chain_name = CHAIN_NAMES.get(chain_id, f"Unknown (chain_id={chain_id})")
    tx_type    = tx.get("type", 0)

    header("Transaction Details — Review Carefully")
    sep()

    # Source metadata
    field("File created",    payload.get("created_at", "unknown"))
    field("Schema",          payload.get("schema", "unknown"))
    field("Status",          payload.get("status", "unknown"))
    print()

    # Chain
    field("Chain",           f"{chain_name}  (ID: {chain_id})", alert=True)
    field("TX Type",         meta.get("tx_type", "unknown"), alert=True)
    field("From",            meta.get("from", tx_raw.get("from", "NOT SET")), alert=True)
    field("To",              tx.get("to", "NOT SET"), alert=True)
    print()

    # Value
    value_wei = tx.get("value", 0)
    field("Value (ETH)",     f"{wei_to_eth(value_wei)} ETH", alert=(value_wei > 0))
    field("Value (wei)",     str(value_wei))
    print()

    # Nonce & gas
    field("Nonce",           str(tx.get("nonce", "?")))
    field("Gas Limit",       str(tx.get("gas", "?")))

    if tx_type == 2:
        mfpg = tx.get("maxFeePerGas", 0)
        mpfpg = tx.get("maxPriorityFeePerGas", 0)
        field("maxFeePerGas",      f"{wei_to_gwei(mfpg)} Gwei  ({mfpg} wei)")
        field("maxPriorityFeePerGas", f"{wei_to_gwei(mpfpg)} Gwei  ({mpfpg} wei)")
    else:
        gp = tx.get("gasPrice", 0)
        field("gasPrice",    f"{wei_to_gwei(gp)} Gwei  ({gp} wei)")

    print()

    # Calldata
    data = tx_raw.get("data", "0x")
    data_str = data if isinstance(data, str) else ("0x" + data.hex() if isinstance(data, bytes) else str(data))
    preview = data_str[:90] + ("…" if len(data_str) > 90 else "")
    field("Data",            preview, alert=(len(data_str) > 2))
    field("Data length",     f"{(len(data_str) - 2) // 2} bytes")

    sep()

    # Warnings
    if value_wei > 0:
        warn(f"This TX sends {wei_to_eth(value_wei)} ETH — confirm the recipient address above!")
    if len(data_str) > 2:
        warn("This TX includes calldata — verify you trust the contract.")
    if meta.get("from", ""):
        info("Signing address derived from private key must match 'From' above.")
    print()


# ---------------------------------------------------------------------------
# Private key input & validation
# ---------------------------------------------------------------------------

def normalize_private_key(raw: str) -> bytes:
    """Normalize a private-key input string into 32 raw bytes."""
    if not raw:
        raise ValueError("Private key is empty.")

    stripped = raw[2:] if raw.startswith(("0x", "0X")) else raw
    if not re.fullmatch(r"[0-9a-fA-F]+", stripped):
        raise ValueError("Private key must contain only hexadecimal characters.")

    try:
        key_bytes = bytes.fromhex(stripped)
    except ValueError as exc:
        raise ValueError("Private key is not valid hex.") from exc

    if len(key_bytes) != 32:
        raise ValueError(f"Invalid private key — expected 32 bytes, got {len(key_bytes)}.")

    return key_bytes


def prompt_private_key() -> bytes:
    """
    Securely prompt for a private key. Returns the raw 32 bytes.
    The entered string is scrubbed from Python objects as soon as possible.
    """
    print(_c("  Enter your private key (input is hidden):", Fore.YELLOW, bold=True))
    print(_c("  Tip: prefix 0x is optional.", Fore.WHITE + Style.DIM))
    print()

    raw = getpass("  Private key: ")

    try:
        key_bytes = normalize_private_key(raw)
    except ValueError as exc:
        err(str(exc))
        _scrub_str(raw)
        sys.exit(1)

    _scrub_str(raw)
    return key_bytes


def _scrub_str(s: str) -> None:
    """
    Best-effort overwrite of a string's internal buffer.
    Python strings are immutable so this is not cryptographically guaranteed,
    but it limits how long key material lingers in memory.
    """
    try:
        # Access the internal char buffer via ctypes and zero it
        buf_size = len(s) * 2 + 1  # UCS-2 / UTF-16 approx
        offset = sys.getsizeof(s) - buf_size
        ctypes.memset(id(s) + offset, 0, buf_size)
    except Exception:
        pass  # Non-fatal — best effort only


# ---------------------------------------------------------------------------
# Derive address & confirm
# ---------------------------------------------------------------------------

def derive_address(key_bytes: bytes) -> Any:
    """Derive eth_account LocalAccount from raw key bytes."""
    if Account is None:
        raise RuntimeError("eth-account is not installed. Install dependencies from the USB wheelhouse first.")

    hex_key = "0x" + key_bytes.hex()
    account = Account.from_key(hex_key)
    return account


def confirm_signing_address(account: LocalAccount, expected_from: str) -> bool:
    """
    Show the derived address and ask the user to confirm it matches
    the 'from' address in the TX before signing.
    """
    header("Signing Address Verification")
    sep()
    field("Derived address", account.address, alert=True)
    field("TX 'from' field", expected_from or "(not set)", alert=True)
    sep()

    if expected_from and account.address.lower() != expected_from.lower():
        err("ADDRESS MISMATCH — the private key does not match the TX 'from' address!")
        err("Signing would produce an invalid signature. Aborting.")
        return False

    ok("Address verified — private key matches TX 'from' field.")
    print()
    raw = input(_c("  Confirm and SIGN this transaction? [yes/NO]: ", Fore.YELLOW, bold=True)).strip().lower()
    return raw in ("yes", "y")


# ---------------------------------------------------------------------------
# Sign transaction
# ---------------------------------------------------------------------------

def sign_transaction(tx_raw: dict, key_bytes: bytes) -> tuple[str, str]:
    """
    Sign the transaction and return (signed_raw_hex, tx_hash_hex).
    The key_bytes buffer is zeroed immediately after use.
    """
    if Account is None:
        raise RuntimeError("eth-account is not installed. Install dependencies from the USB wheelhouse first.")

    tx = extract_core_tx(tx_raw)
    hex_key = "0x" + key_bytes.hex()

    try:
        signed = Account.sign_transaction(tx, private_key=hex_key)
    finally:
        # Zero the hex key string (best effort)
        _scrub_str(hex_key)
        # Zero the key bytes
        for i in range(len(key_bytes)):
            key_bytes = key_bytes[:i] + b'\x00' + key_bytes[i+1:]

    raw_tx  = signed.raw_transaction.hex()
    tx_hash = signed.hash.hex()

    if not raw_tx.startswith("0x"):
        raw_tx = "0x" + raw_tx
    if not tx_hash.startswith("0x"):
        tx_hash = "0x" + tx_hash

    return raw_tx, tx_hash


# ---------------------------------------------------------------------------
# Export signed TX
# ---------------------------------------------------------------------------

def export_signed_tx(
    signed_raw_tx: str,
    tx_hash:       str,
    original_payload: dict,
    output_path:   str,
) -> Path:
    """
    Write the signed TX JSON file.

    The output format is compatible with export.py's import_signed_tx()
    on the online machine.
    """
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    meta = original_payload.get("tx", {}).get("_meta", {})

    signed_payload = {
        "schema":       SIGNED_SCHEMA,
        "created_at":   datetime.now(timezone.utc).isoformat(),
        "status":       "signed",
        "chain":        meta.get("chain", "unknown"),
        "chain_key":    meta.get("chain_key", "unknown"),
        "tx_type":      meta.get("tx_type", "unknown"),
        "from":         meta.get("from", "unknown"),
        "to":           original_payload.get("tx", {}).get("to", "unknown"),
        "tx_hash":      tx_hash,
        "signed_raw_tx": signed_raw_tx,
        # Keep original unsigned TX for audit trail
        "original_unsigned_tx": original_payload,
    }

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(signed_payload, fh, indent=2, default=str)

    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Offline EVM Transaction Signer — air-gap ready, no network required.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python signer.py unsigned_tx.json
  python signer.py unsigned_tx.json -o signed_tx.json
  python signer.py unsigned_tx.json --inspect-only
        """,
    )
    p.add_argument(
        "input",
        help="Path to the unsigned TX JSON file (from the online machine).",
    )
    p.add_argument(
        "-o", "--output",
        default=None,
        help="Output path for signed TX JSON. Default: signed_<input_filename>",
    )
    p.add_argument(
        "--inspect-only",
        action="store_true",
        help="Display TX details and exit without signing.",
    )
    return p.parse_args()


def main() -> None:
    args  = parse_args()
    banner()

    # ── Step 1: Load ──────────────────────────────────────────────────────
    info(f"Loading: {args.input}")
    payload, tx_raw = load_unsigned_tx(args.input)
    ok("File loaded and validated.")

    # ── Step 2: Display TX ────────────────────────────────────────────────
    display_tx(payload, tx_raw)

    if args.inspect_only:
        info("--inspect-only mode: exiting without signing.")
        sys.exit(0)

    # ── Step 3: Private key input ─────────────────────────────────────────
    header("Private Key Input")
    sep()
    warn("Your private key is NEVER written to disk or transmitted.")
    warn("Ensure no screen-recording or key-logging software is running.")
    print()
    key_bytes = prompt_private_key()

    # ── Step 4: Derive address & confirm ──────────────────────────────────
    account      = derive_address(key_bytes)
    expected_from = tx_raw.get("_meta", {}).get("from", tx_raw.get("from", ""))

    if not confirm_signing_address(account, expected_from):
        # Scrub key bytes on abort
        key_bytes = b'\x00' * len(key_bytes)
        err("Signing aborted by user.")
        sys.exit(1)

    # ── Step 5: Sign ──────────────────────────────────────────────────────
    header("Signing")
    sep()
    info("Signing transaction…")

    try:
        signed_raw, tx_hash = sign_transaction(tx_raw, bytearray(key_bytes))
    except Exception as exc:
        err(f"Signing failed: {exc}")
        sys.exit(1)

    ok("Transaction signed successfully.")
    print()
    field("TX Hash",        tx_hash)
    field("Signed TX size", f"{(len(signed_raw) - 2) // 2} bytes")

    # ── Step 6: Export ────────────────────────────────────────────────────
    input_path = Path(args.input)
    output_path = args.output or str(input_path.parent / f"signed_{input_path.name}")

    export_path = export_signed_tx(signed_raw, tx_hash, payload, output_path)
    print()
    sep()
    ok(f"Signed TX written to: {export_path}")
    info("Transfer this file to your ONLINE machine and broadcast with:")
    print(_c(f"    python main.py  → option 8 (Broadcast a signed TX)", Fore.WHITE))
    sep()
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        warn("Interrupted — no file was written.")
        sys.exit(0)
