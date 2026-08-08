import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "signer.py"
SPEC = importlib.util.spec_from_file_location("signer", MODULE_PATH)
signer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(signer)


class PrivateKeyParsingTests(unittest.TestCase):
    def test_normalizes_0x_prefixed_key(self) -> None:
        key = signer.normalize_private_key("0x" + "11" * 32)
        self.assertEqual(key, bytes.fromhex("11" * 32))

    def test_rejects_non_hex_input(self) -> None:
        with self.assertRaises(ValueError):
            signer.normalize_private_key("not-hex")

    def test_rejects_wrong_length(self) -> None:
        with self.assertRaises(ValueError):
            signer.normalize_private_key("0" * 63)


class PrivateKeyResolutionTests(unittest.TestCase):
    def test_cli_key_precedence(self) -> None:
        cli_key = "0x" + "22" * 32
        resolved = signer.resolve_private_key("ethereum", cli_key=cli_key)
        self.assertEqual(resolved, bytes.fromhex("22" * 32))

    def test_default_dict_fallback(self) -> None:
        signer.DEFAULT_PRIVATE_KEYS["polygon"] = "0x" + "33" * 32
        resolved = signer.resolve_private_key("polygon")
        self.assertEqual(resolved, bytes.fromhex("33" * 32))


class SigningExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key_bytes = bytes.fromhex("11" * 32)

    def test_evm_signing(self) -> None:
        unsigned_payload = {
            "schema": "crypto-unsigned-tx/v1",
            "tx": {
                "chainId": 1,
                "nonce": 0,
                "value": 1000,
                "gas": 21000,
                "gasPrice": 20000000000,
                "to": "0x0000000000000000000000000000000000000001",
                "data": "0x",
                "type": 0,
                "_meta": {
                    "chain": "Ethereum Mainnet",
                    "chain_key": "ethereum",
                    "chain_family": "evm",
                    "from": "0x19E7E376E7C213B7E7e7e46cc70A5dd086DAffCA",
                },
            },
        }

        raw_hex, tx_hash, addr, chain = signer.sign_payload(unsigned_payload, self.key_bytes)
        self.assertTrue(raw_hex.startswith("0x"))
        self.assertTrue(tx_hash.startswith("0x"))
        self.assertEqual(chain, "ethereum")
        self.assertEqual(addr.lower(), "0x19E7E376E7C213B7E7e7e46cc70A5dd086DAffCA".lower())

    def test_dogecoin_signing(self) -> None:
        sender_addr, _ = signer.doge_address_from_key(self.key_bytes)
        unsigned_payload = {
            "schema": "crypto-unsigned-tx/v1",
            "tx": {
                "chain_family": "dogecoin",
                "chain_key": "dogecoin",
                "inputs": [
                    {
                        "txid": "11" * 32,
                        "vout": 0,
                        "value_satoshis": 100000000,
                    }
                ],
                "outputs": [
                    {
                        "address": sender_addr,
                        "value_satoshis": 90000000,
                    }
                ],
                "_meta": {
                    "chain": "Dogecoin Mainnet",
                    "chain_key": "dogecoin",
                    "chain_family": "dogecoin",
                    "from": sender_addr,
                },
            },
        }

        raw_hex, tx_hash, addr, chain = signer.sign_payload(unsigned_payload, self.key_bytes)
        self.assertTrue(len(raw_hex) > 50)
        self.assertEqual(chain, "dogecoin")
        self.assertEqual(addr, sender_addr)

    def test_export_signed_tx(self) -> None:
        unsigned_payload = {
            "schema": "crypto-unsigned-tx/v1",
            "tx": {
                "chainId": 1,
                "to": "0x0000000000000000000000000000000000000001",
                "_meta": {
                    "chain": "Ethereum Mainnet",
                    "chain_key": "ethereum",
                    "from": "0x19E7E376E7C213B7E7e7e46cc70A5dd086DAffCA",
                },
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "signed_tx.json"
            exported = signer.export_signed_tx(
                "0x123456",
                "0x789abc",
                "0x19E7E376E7C213B7E7e7e46cc70A5dd086DAffCA",
                unsigned_payload,
                out_file,
            )

            self.assertTrue(exported.exists())
            with open(exported, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            self.assertEqual(data["status"], "signed")
            self.assertEqual(data["chain_key"], "ethereum")
            self.assertEqual(data["signed_raw_tx"], "0x123456")
            self.assertEqual(data["tx_hash"], "0x789abc")


if __name__ == "__main__":
    unittest.main()
