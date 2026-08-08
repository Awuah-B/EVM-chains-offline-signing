#!/usr/bin/env python3
"""
signer.py — Multi-Chain Offline Transaction Signer (EVM + Dogecoin)
===================================================================
Designed to run on an amnesia air-gapped machine (Tails / ephemeral RAM OS).

Workflow:
  1. Copy unsigned_tx.json from online machine (USB / SD card)
  2. Run:  python signer.py unsigned_tx.json
  3. Pre-configured per-chain default private keys automatically sign transactions
  4. The signed_tx.json is written to disk
  5. Copy signed_tx.json back to online machine for broadcast
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from typing import Any

try:
    from eth_account import Account
except ImportError:
    Account = None

try:
    from eth_keys import keys as eth_keys
except ImportError:
    eth_keys = None

# ---------------------------------------------------------------------------
# Default Private Keys per Chain
# Pre-configure keys here or export environment variables for amnesia systems.
# ---------------------------------------------------------------------------
DEFAULT_PRIVATE_KEYS: dict[str, str] = {
    "ethereum":  os.environ.get("ETH_PRIVATE_KEY", ""),
    "bsc":       os.environ.get("BSC_PRIVATE_KEY", ""),
    "polygon":   os.environ.get("POLYGON_PRIVATE_KEY", ""),
    "arbitrum":  os.environ.get("ARBITRUM_PRIVATE_KEY", ""),
    "optimism":  os.environ.get("OPTIMISM_PRIVATE_KEY", ""),
    "base":      os.environ.get("BASE_PRIVATE_KEY", ""),
    "avalanche": os.environ.get("AVALANCHE_PRIVATE_KEY", ""),
    "dogecoin":  os.environ.get("DOGECOIN_PRIVATE_KEY", ""),
    "default":   os.environ.get("DEFAULT_PRIVATE_KEY", ""),
}

DEFAULT_KEY_CONFIG_PATH = Path.home() / ".offline_signer.json"


def load_key_config(path: Path | None = None) -> dict[str, str]:
    """Load an optional JSON key config file for manually editable private keys."""
    path = path or DEFAULT_KEY_CONFIG_PATH
    if not path.exists():
        return {}

    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to load key configuration from {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"Key configuration file {path} must contain a JSON object.")

    return {k: str(v) for k, v in data.items() if isinstance(k, str) and v is not None}

# ---------------------------------------------------------------------------
# Key Normalization & Resolution
# ---------------------------------------------------------------------------

def normalize_private_key(raw: str) -> bytes:
    """Normalize a private key hex string into 32 raw bytes."""
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


def resolve_private_key(chain_key: str, cli_key: str | None = None) -> bytes:
    """
    Resolve private key in priority order:
    1. Explicit CLI argument (`--key`)
    2. JSON config file (`~/.offline_signer.json`)
    3. Environment variable (`<CHAIN>_PRIVATE_KEY` / `PRIVATE_KEY`)
    4. `DEFAULT_PRIVATE_KEYS[chain_key]` entry
    5. `DEFAULT_PRIVATE_KEYS["default"]` fallback
    6. Interactive getpass prompt
    """
    if cli_key:
        return normalize_private_key(cli_key)

    config = load_key_config()
    env_var_name = f"{chain_key.upper()}_PRIVATE_KEY"
    key_str = (
        config.get(chain_key)
        or config.get("default")
        or os.environ.get(env_var_name)
        or os.environ.get("PRIVATE_KEY")
        or DEFAULT_PRIVATE_KEYS.get(chain_key, "")
        or DEFAULT_PRIVATE_KEYS.get("default", "")
    )

    if key_str:
        try:
            return normalize_private_key(key_str)
        except ValueError:
            pass

    print(f"No default private key set for '{chain_key}'.")
    raw = getpass("Enter private key (hidden input): ")
    return normalize_private_key(raw)


# ---------------------------------------------------------------------------
# EVM Transaction Signing
# ---------------------------------------------------------------------------

def extract_core_evm_tx(tx_raw: dict) -> dict:
    """Extract standard EVM consensus fields from transaction dict."""
    SKIP = {"_meta", "_hex", "chain_family", "chain_key"}
    INT_FIELDS = {
        "chainId", "nonce", "value", "gas", "gasLimit",
        "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas",
    }
    tx: dict[str, Any] = {}
    for key, value in tx_raw.items():
        if key in SKIP:
            continue
        if key in INT_FIELDS:
            tx[key] = int(value)
        elif key == "data":
            if isinstance(value, str):
                tx[key] = bytes.fromhex(value[2:]) if value.startswith("0x") else bytes.fromhex(value)
            elif isinstance(value, bytes):
                tx[key] = value
        else:
            tx[key] = value

    if "gasLimit" in tx and "gas" not in tx:
        tx["gas"] = tx.pop("gasLimit")

    # Remove 'type' field if it is 0/legacy, as eth_account expects type to be omitted for legacy transactions
    if tx.get("type") in (0, "0", "0x0", "0x", None):
        tx.pop("type", None)

    return tx


def sign_evm_tx(tx_raw: dict, key_bytes: bytes) -> tuple[str, str, str]:
    """Sign EVM transaction and return (signed_raw_hex, tx_hash, derived_address)."""
    if Account is None:
        raise RuntimeError("eth_account is required for EVM transaction signing.")
    tx = extract_core_evm_tx(tx_raw)
    hex_key = "0x" + key_bytes.hex()
    account = Account.from_key(hex_key)
    signed = Account.sign_transaction(tx, private_key=hex_key)
    raw_tx = signed.raw_transaction.hex()
    tx_hash = signed.hash.hex()
    if not raw_tx.startswith("0x"):
        raw_tx = "0x" + raw_tx
    if not tx_hash.startswith("0x"):
        tx_hash = "0x" + tx_hash
    return raw_tx, tx_hash, account.address


# ---------------------------------------------------------------------------
# Dogecoin UTXO Transaction Signing
# ---------------------------------------------------------------------------

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def b58encode(v: bytes) -> str:
    num = int.from_bytes(v, "big")
    res = ""
    while num > 0:
        num, mod = divmod(num, 58)
        res = B58_ALPHABET[mod] + res
    pad = len(v) - len(v.lstrip(b"\x00"))
    return B58_ALPHABET[0] * pad + res


def b58check_encode(v: bytes) -> str:
    digest = hashlib.sha256(hashlib.sha256(v).digest()).digest()[:4]
    return b58encode(v + digest)


def b58decode(s: str) -> bytes:
    num = 0
    for char in s:
        num = num * 58 + B58_ALPHABET.index(char)
    combined = num.to_bytes((num.bit_length() + 7) // 8 or 1, byteorder="big")
    pad = len(s) - len(s.lstrip(B58_ALPHABET[0]))
    return b"\x00" * pad + combined


def b58check_decode(s: str) -> bytes:
    raw = b58decode(s)
    data, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4] != checksum:
        raise ValueError("Invalid Base58Check checksum.")
    return data


def doge_address_from_key(key_bytes: bytes) -> tuple[str, bytes]:
    if eth_keys is None:
        raise RuntimeError("eth_keys is required for Dogecoin key operations.")
    pk = eth_keys.PrivateKey(key_bytes)
    pub_point = pk.public_key
    x = pub_point.to_bytes()[:32]
    y = int.from_bytes(pub_point.to_bytes()[32:], "big")
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    compressed_pubkey = prefix + x
    pubkey_hash = hashlib.new("ripemd160", hashlib.sha256(compressed_pubkey).digest()).digest()
    address = b58check_encode(b"\x1e" + pubkey_hash)
    return address, compressed_pubkey


def varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


def der_encode_sig(r: int, s: int) -> bytes:
    if s > SECP256K1_ORDER // 2:
        s = SECP256K1_ORDER - s
    rb = r.to_bytes((r.bit_length() + 7) // 8, "big")
    if rb[0] >= 0x80:
        rb = b"\x00" + rb
    sb = s.to_bytes((s.bit_length() + 7) // 8, "big")
    if sb[0] >= 0x80:
        sb = b"\x00" + sb
    body = b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb
    return b"\x30" + bytes([len(body)]) + body + b"\x01"


def sign_doge_tx(tx_raw: dict, key_bytes: bytes) -> tuple[str, str, str]:
    """Sign Dogecoin P2PKH UTXO transaction and return (signed_raw_hex, tx_hash, derived_address)."""
    sender_addr, compressed_pub = doge_address_from_key(key_bytes)
    inputs = tx_raw.get("inputs", [])
    outputs = tx_raw.get("outputs", [])
    if not inputs or not outputs:
        raise ValueError("Dogecoin transaction must specify inputs and outputs.")

    outs_bin = b""
    for out in outputs:
        val = int(out["value_satoshis"])
        dest_addr = out["address"]
        dest_hash = b58check_decode(dest_addr)[1:21]
        script_pub = b"\x76\xa9\x14" + dest_hash + b"\x88\xac"
        outs_bin += struct.pack("<Q", val) + varint(len(script_pub)) + script_pub

    script_sigs = []
    pk = eth_keys.PrivateKey(key_bytes)

    for i, _inp in enumerate(inputs):
        inp_hash = b58check_decode(sender_addr)[1:21]
        inp_script_pub = b"\x76\xa9\x14" + inp_hash + b"\x88\xac"

        preimage = struct.pack("<I", 1) + varint(len(inputs))
        for j, in_j in enumerate(inputs):
            txid_j = bytes.fromhex(in_j["txid"])[::-1]
            vout_j = int(in_j["vout"])
            preimage += txid_j + struct.pack("<I", vout_j)
            if j == i:
                preimage += varint(len(inp_script_pub)) + inp_script_pub
            else:
                preimage += b"\x00"
            preimage += struct.pack("<I", 0xffffffff)

        preimage += varint(len(outputs)) + outs_bin
        preimage += struct.pack("<I", 0)
        preimage += struct.pack("<I", 1)

        sighash = hashlib.sha256(hashlib.sha256(preimage).digest()).digest()
        sig = pk.sign_msg_hash(sighash)
        der_sig = der_encode_sig(sig.r, sig.s)
        script_sig = varint(len(der_sig)) + der_sig + varint(len(compressed_pub)) + compressed_pub
        script_sigs.append(script_sig)

    final_tx = struct.pack("<I", 1) + varint(len(inputs))
    for i, inp in enumerate(inputs):
        prev_txid = bytes.fromhex(inp["txid"])[::-1]
        prev_vout = int(inp["vout"])
        final_tx += prev_txid + struct.pack("<I", prev_vout)
        final_tx += varint(len(script_sigs[i])) + script_sigs[i]
        final_tx += struct.pack("<I", 0xffffffff)
    final_tx += varint(len(outputs)) + outs_bin
    final_tx += struct.pack("<I", 0)

    signed_raw_hex = final_tx.hex()
    tx_hash = hashlib.sha256(hashlib.sha256(final_tx).digest()).digest()[::-1].hex()
    return signed_raw_hex, tx_hash, sender_addr


# ---------------------------------------------------------------------------
# High-Level Transaction Signing & Export
# ---------------------------------------------------------------------------

def sign_payload(unsigned_payload: dict, key_bytes: bytes) -> tuple[str, str, str, str]:
    """
    Detect chain and sign payload.
    Returns (signed_raw_hex, tx_hash, derived_address, chain_key).
    """
    tx_raw = unsigned_payload.get("tx", unsigned_payload)
    meta = tx_raw.get("_meta", {})
    chain_family = meta.get("chain_family") or tx_raw.get("chain_family") or meta.get("family") or "evm"
    chain_key = meta.get("chain_key") or tx_raw.get("chain_key") or "ethereum"

    if chain_family == "dogecoin" or chain_key == "dogecoin":
        signed_raw, tx_hash, address = sign_doge_tx(tx_raw, key_bytes)
    else:
        signed_raw, tx_hash, address = sign_evm_tx(tx_raw, key_bytes)

    return signed_raw, tx_hash, address, chain_key


def export_signed_tx(
    signed_raw_tx: str,
    tx_hash: str,
    from_address: str,
    original_payload: dict,
    output_path: str | Path,
) -> Path:
    """Export signed transaction payload to JSON file."""
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    tx_block = original_payload.get("tx", original_payload)
    meta = tx_block.get("_meta", {})
    chain_key = meta.get("chain_key") or tx_block.get("chain_key") or "ethereum"
    chain_name = meta.get("chain") or chain_key.title()
    tx_type = meta.get("tx_type") or "transfer"
    to_address = meta.get("to") or tx_block.get("to") or "unknown"

    signed_payload = {
        "schema": "crypto-signed-tx/v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "signed",
        "chain": chain_name,
        "chain_key": chain_key,
        "tx_type": tx_type,
        "from": from_address,
        "to": to_address,
        "tx_hash": tx_hash,
        "signed_raw_tx": signed_raw_tx,
        "original_unsigned_tx": original_payload,
    }

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(signed_payload, fh, indent=2, default=str)

    return path


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Offline Transaction Signer (EVM + Dogecoin) — Air-Gap Ready.",
    )
    p.add_argument("input", help="Path to the unsigned TX JSON file.")
    p.add_argument("-o", "--output", help="Output path for signed TX JSON.")
    p.add_argument("-k", "--key", help="Private key (hex). Overrides default/env keys.")
    p.add_argument("-y", "--yes", action="store_true", help="Auto-confirm without prompting.")
    p.add_argument("--inspect-only", action="store_true", help="Display TX details and exit.")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        print(f"Error: File not found: {input_path}")
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)

    tx_raw = payload.get("tx", payload)
    meta = tx_raw.get("_meta", {})
    chain_key = meta.get("chain_key") or tx_raw.get("chain_key") or "ethereum"

    print("=" * 60)
    print(f"  OFFLINE SIGNER — Chain: {chain_key.upper()}")
    print("=" * 60)
    print(f"Input file : {input_path.name}")
    print(f"Target chain: {meta.get('chain', chain_key)}")
    print(f"From address: {meta.get('from', tx_raw.get('from', 'NOT SET'))}")
    print(f"To address  : {meta.get('to', tx_raw.get('to', 'NOT SET'))}")

    if args.inspect_only:
        print("\n[--inspect-only mode] Exiting without signing.")
        sys.exit(0)

    key_bytes = resolve_private_key(chain_key, args.key)
    signed_raw, tx_hash, derived_addr, resolved_chain = sign_payload(payload, key_bytes)

    expected_from = meta.get("from") or tx_raw.get("from")
    if expected_from and expected_from.lower() != derived_addr.lower():
        print(f"Warning: Derived signing address {derived_addr} does not match unsigned TX 'from': {expected_from}")

    if not args.yes:
        confirm = input(f"\nSign transaction with derived address {derived_addr}? [Y/n]: ").strip().lower()
        if confirm and confirm not in ("y", "yes"):
            print("Signing cancelled.")
            sys.exit(0)

    out_file = args.output or f"signed_{input_path.name}"
    export_path = export_signed_tx(signed_raw, tx_hash, derived_addr, payload, out_file)
    print("\n✔ Transaction signed successfully!")
    print(f"TX Hash    : {tx_hash}")
    print(f"Signed file: {export_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
