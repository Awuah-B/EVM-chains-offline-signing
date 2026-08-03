import importlib.util
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


if __name__ == "__main__":
    unittest.main()
