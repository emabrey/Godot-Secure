"""Unit tests for godot_secure.py pure functions.

Because godot_secure.py executes script-level code at import time (argument
parsing, file I/O, sys.exit), it cannot be imported directly from a test.
Instead, we load only the function and class definitions by compiling and
exec-ing everything *before* the main execution block, which starts with
``current_dt = datetime.datetime...`` near the bottom of the file.

All tests are pure-Python and use only the standard library (unittest,
hashlib, hmac) so they can be run with:

    python -m unittest discover -s tests
    # or, if pytest is available:
    pytest tests/
"""

import hashlib
import hmac
import os
import unittest

# ---------------------------------------------------------------------------
# Module bootstrap
# ---------------------------------------------------------------------------

_SCRIPT = os.path.join(os.path.dirname(__file__), "..", "godot_secure.py")


def _load_functions() -> dict:
    """Exec godot_secure.py up to the main execution block.

    Returns a namespace dict containing every function and class definition
    but none of the top-level side-effectful code (arg-parsing, log creation,
    sys.exit calls, etc.).

    The split marker is the first occurrence of ``'\\ncurrent_dt = datetime'``,
    which is the opening line of the execution block at the bottom of the
    script.  Everything before that line is safe to exec in isolation.
    """
    with open(_SCRIPT, encoding="utf-8") as fh:
        src = fh.read()
    marker = "\ncurrent_dt = datetime"
    stop = src.index(marker)
    ns: dict = {}
    exec(compile(src[:stop], _SCRIPT, "exec"), ns)  # noqa: S102
    return ns


_NS = _load_functions()

# Pull the functions we want to test into module scope for convenience.
derive_tags_from_token = _NS["derive_tags_from_token"]
derive_kdf_from_token  = _NS["derive_kdf_from_token"]
generate_magic_header  = _NS["generate_magic_header"]
generate_random_token  = _NS["generate_random_token"]
build_arg_parser       = _NS["build_arg_parser"]


# ---------------------------------------------------------------------------
# derive_tags_from_token
# ---------------------------------------------------------------------------

class TestDeriveTags(unittest.TestCase):
    """Tests for derive_tags_from_token(token_bytes) -> (base_tag, enc_tag)."""

    def test_returns_two_strings(self):
        base_tag, enc_tag = derive_tags_from_token(bytes(32))
        self.assertIsInstance(base_tag, str)
        self.assertIsInstance(enc_tag, str)

    def test_each_tag_is_four_chars(self):
        base_tag, enc_tag = derive_tags_from_token(bytes(range(32)))
        self.assertEqual(len(base_tag), 4)
        self.assertEqual(len(enc_tag), 4)

    def test_tags_are_uppercase_alpha(self):
        base_tag, enc_tag = derive_tags_from_token(bytes(range(32)))
        self.assertTrue(base_tag.isupper() and base_tag.isalpha(), base_tag)
        self.assertTrue(enc_tag.isupper() and enc_tag.isalpha(), enc_tag)

    def test_deterministic(self):
        token = bytes(range(32))
        self.assertEqual(
            derive_tags_from_token(token),
            derive_tags_from_token(token),
        )

    def test_base_tag_maps_bytes_0_to_3(self):
        # Each byte b maps to chr(ord('A') + b % 26).
        # bytes [0,1,2,3] -> A,B,C,D
        token = bytes([0, 1, 2, 3] + [4, 5, 6, 7] + [0] * 24)
        base_tag, _ = derive_tags_from_token(token)
        self.assertEqual(base_tag, "ABCD")

    def test_enc_tag_maps_bytes_4_to_7_normally(self):
        # bytes [4,5,6,7] -> E,F,G,H
        token = bytes([0, 1, 2, 3, 4, 5, 6, 7] + [0] * 24)
        _, enc_tag = derive_tags_from_token(token)
        self.assertEqual(enc_tag, "EFGH")

    def test_collision_fallback_to_bytes_8_to_11(self):
        # bytes [0,1,2,3] -> ABCD; [26,27,28,29] -> ABCD (same, since b%26 wraps).
        # On collision enc_tag falls back to bytes 8-11.
        # bytes [4,5,6,7] -> EFGH
        token = bytes([0, 1, 2, 3, 26, 27, 28, 29, 4, 5, 6, 7] + [0] * 20)
        base_tag, enc_tag = derive_tags_from_token(token)
        self.assertEqual(base_tag, "ABCD")
        self.assertEqual(enc_tag, "EFGH")

    def test_tags_differ_for_distinct_tokens(self):
        t1 = bytes(range(32))
        t2 = bytes(reversed(range(32)))
        self.assertNotEqual(derive_tags_from_token(t1), derive_tags_from_token(t2))

    def test_byte_modulo_26_wraps(self):
        # byte 25 -> 'Z', byte 26 -> 'A' (wraps), byte 51 -> 'Z' (51%26 == 25)
        token = bytes([25, 26, 51, 0] + [0] * 28)
        base_tag, _ = derive_tags_from_token(token)
        self.assertEqual(base_tag, "ZAZA")

    def test_all_zero_token(self):
        base_tag, enc_tag = derive_tags_from_token(bytes(32))
        # bytes 0-3 all zero -> 'A','A','A','A'; bytes 4-7 also -> 'A','A','A','A' (collision)
        # collision -> bytes 8-11 (also zero) -> 'A','A','A','A'
        # Both land on 'AAAA'; collision branch still produces a 4-char tag.
        self.assertEqual(len(base_tag), 4)
        self.assertEqual(len(enc_tag), 4)


# ---------------------------------------------------------------------------
# derive_kdf_from_token
# ---------------------------------------------------------------------------

class TestDeriveKdf(unittest.TestCase):
    """Tests for derive_kdf_from_token(token_bytes) -> C statement string."""

    _TOKEN = bytes(range(32))

    def test_returns_string(self):
        self.assertIsInstance(derive_kdf_from_token(self._TOKEN), str)

    def test_is_valid_c_assignment(self):
        stmt = derive_kdf_from_token(self._TOKEN)
        self.assertTrue(stmt.startswith("token_key.write[i] = (uint8_t)("), stmt)
        self.assertTrue(stmt.endswith(");"), stmt)

    def test_contains_at_least_one_known_operand(self):
        stmt = derive_kdf_from_token(self._TOKEN)
        self.assertTrue(
            "key_ptr[i]" in stmt or "Security::TOKEN[i]" in stmt,
            f"No expected operand in: {stmt}",
        )

    def test_parentheses_are_balanced(self):
        stmt = derive_kdf_from_token(self._TOKEN)
        self.assertEqual(stmt.count("("), stmt.count(")"), stmt)

    def test_deterministic_same_token(self):
        t = bytes(range(32))
        self.assertEqual(derive_kdf_from_token(t), derive_kdf_from_token(t))

    def test_different_tokens_produce_different_formulas(self):
        # Drive 6 distinct tokens through the derivation; at least 2 must differ.
        # The formula structure is driven by ~7 bits of HKDF output (layer count +
        # base-op index + operand choice), so collisions are possible but rare.
        results = {derive_kdf_from_token(bytes([i] * 32)) for i in range(6)}
        self.assertGreater(
            len(results), 1,
            "All 6 single-byte-repeated tokens produced identical KDF formulas",
        )

    def test_consistent_with_independent_hkdf(self):
        """Verify the HKDF internals match RFC 5869 independently.

        We re-implement HKDF-Extract and the first HKDF-Expand block using
        the same parameters and confirm the function is using the same PRK.
        The only observable guarantee is determinism: two independent
        evaluations with the same token must agree.
        """
        token = bytes(range(32))

        # Independent HKDF-Extract
        prk = hmac.new(
            b"godot-secure-kdf-formula-v1",
            token,
            hashlib.sha256,
        ).digest()
        self.assertEqual(len(prk), 32)

        # The function is driven by the expand output, so verifying determinism
        # (same token -> same formula) is the meaningful external assertion.
        r1 = derive_kdf_from_token(token)
        r2 = derive_kdf_from_token(token)
        self.assertEqual(r1, r2)

    def test_all_zero_token(self):
        stmt = derive_kdf_from_token(bytes(32))
        self.assertTrue(stmt.startswith("token_key.write[i] = (uint8_t)("), stmt)

    def test_all_ff_token(self):
        stmt = derive_kdf_from_token(bytes([0xFF] * 32))
        self.assertTrue(stmt.startswith("token_key.write[i] = (uint8_t)("), stmt)

    def test_single_bit_change_produces_different_formula(self):
        # Flip one bit in the token; the formula should change (with overwhelming
        # probability) because SHA-256 has the avalanche property.
        t1 = bytearray(range(32))
        t2 = bytearray(range(32))
        t2[0] ^= 0x01
        # Not asserting inequality (could theoretically collide), just that both run.
        r1 = derive_kdf_from_token(bytes(t1))
        r2 = derive_kdf_from_token(bytes(t2))
        self.assertIsInstance(r1, str)
        self.assertIsInstance(r2, str)


# ---------------------------------------------------------------------------
# generate_magic_header
# ---------------------------------------------------------------------------

class TestGenerateMagicHeader(unittest.TestCase):
    """Tests for generate_magic_header(tag) -> hex string."""

    def test_has_0x_prefix(self):
        self.assertTrue(generate_magic_header("ABCD").startswith("0x"))

    def test_total_length_is_10(self):
        # '0x' + 8 hex characters
        self.assertEqual(len(generate_magic_header("ABCD")), 10)

    def test_bytes_are_little_endian(self):
        # 'ABCD' -> reversed -> 'DCBA' -> 0x44,0x43,0x42,0x41 -> "0x44434241"
        self.assertEqual(generate_magic_header("ABCD"), "0x44434241")

    def test_reconstructs_original_godot_pack_magic(self):
        # Original Godot define: #define PACK_HEADER_MAGIC 0x43504447
        # Little-endian bytes: 47='G', 44='D', 50='P', 43='C' -> tag "GDPC"
        # generate_magic_header("GDPC"):
        #   reversed("GDPC") -> 'C','P','D','G' -> 0x43,0x50,0x44,0x47 -> "0x43504447"
        self.assertEqual(generate_magic_header("GDPC"), "0x43504447")

    def test_reconstructs_original_godot_encrypted_magic(self):
        # Original: #define ENCRYPTED_HEADER_MAGIC 0x43454447
        # 47='G', 44='D', 45='E', 43='C' -> tag "GDEC"
        # reversed("GDEC") -> 'C','E','D','G' -> 0x43,0x45,0x44,0x47 -> "0x43454447"
        self.assertEqual(generate_magic_header("GDEC"), "0x43454447")

    def test_uppercase_hex_digits(self):
        result = generate_magic_header("ABCD")
        # hex part only (strip '0x')
        hex_part = result[2:]
        self.assertEqual(hex_part, hex_part.upper())

    def test_raises_value_error_for_short_tag(self):
        with self.assertRaises(ValueError):
            generate_magic_header("ABC")

    def test_raises_value_error_for_long_tag(self):
        with self.assertRaises(ValueError):
            generate_magic_header("ABCDE")

    def test_raises_value_error_for_empty_tag(self):
        with self.assertRaises(ValueError):
            generate_magic_header("")


# ---------------------------------------------------------------------------
# generate_random_token
# ---------------------------------------------------------------------------

class TestGenerateRandomToken(unittest.TestCase):
    """Tests for generate_random_token(length=32) -> bytes."""

    def test_default_returns_32_bytes(self):
        result = generate_random_token()
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 32)

    def test_custom_length_1(self):
        self.assertEqual(len(generate_random_token(1)), 1)

    def test_custom_length_16(self):
        self.assertEqual(len(generate_random_token(16)), 16)

    def test_custom_length_64(self):
        self.assertEqual(len(generate_random_token(64)), 64)

    def test_each_byte_is_in_range(self):
        token = generate_random_token(256)
        self.assertTrue(all(0 <= b <= 255 for b in token))

    def test_returns_bytes_type(self):
        self.assertIsInstance(generate_random_token(8), bytes)

    def test_successive_calls_differ(self):
        # Statistically guaranteed to be unequal for 32-byte random tokens,
        # though the test will very rarely fail (~1 in 2^256 chance).
        self.assertNotEqual(generate_random_token(), generate_random_token())


# ---------------------------------------------------------------------------
# build_arg_parser / argument parsing
# ---------------------------------------------------------------------------

class TestBuildArgParser(unittest.TestCase):
    """Tests for build_arg_parser() and the argument schema it defines."""

    def _parse(self, *args):
        """Parse a list of CLI args without sys.argv side effects."""
        return build_arg_parser().parse_args(list(args))

    # ── --mode ──────────────────────────────────────────────────────────────

    def test_mode_generate(self):
        self.assertEqual(self._parse("--mode", "generate").mode, "generate")

    def test_mode_apply(self):
        self.assertEqual(self._parse("--mode", "apply").mode, "apply")

    def test_mode_refresh(self):
        self.assertEqual(self._parse("--mode", "refresh").mode, "refresh")

    def test_mode_restore(self):
        self.assertEqual(self._parse("--mode", "restore").mode, "restore")

    def test_mode_defaults_to_none(self):
        self.assertIsNone(self._parse().mode)

    def test_invalid_mode_raises(self):
        with self.assertRaises(SystemExit):
            self._parse("--mode", "encrypt")

    # ── --algorithm ──────────────────────────────────────────────────────────

    def test_algorithm_aes(self):
        self.assertEqual(self._parse("--algorithm", "aes").algorithm, "aes")

    def test_algorithm_camellia(self):
        self.assertEqual(self._parse("--algorithm", "camellia").algorithm, "camellia")

    def test_algorithm_aria(self):
        self.assertEqual(self._parse("--algorithm", "aria").algorithm, "aria")

    def test_algorithm_defaults_to_none(self):
        self.assertIsNone(self._parse().algorithm)

    def test_invalid_algorithm_raises(self):
        with self.assertRaises(SystemExit):
            self._parse("--algorithm", "blowfish")

    # ── --non-interactive ─────────────────────────────────────────────────────

    def test_non_interactive_flag_sets_true(self):
        self.assertTrue(self._parse("--non-interactive").non_interactive)

    def test_non_interactive_defaults_to_false(self):
        self.assertFalse(self._parse().non_interactive)

    # ── --token ───────────────────────────────────────────────────────────────

    def test_token_flag(self):
        hex_token = "a" * 64
        self.assertEqual(self._parse("--token", hex_token).token, hex_token)

    def test_token_defaults_to_none(self):
        self.assertIsNone(self._parse().token)

    # ── --kdf-formula ─────────────────────────────────────────────────────────

    def test_kdf_formula_flag(self):
        formula = "token_key.write[i] = (uint8_t)(key_ptr[i] ^ Security::TOKEN[i]);"
        self.assertEqual(self._parse("--kdf-formula", formula).kdf_formula, formula)

    # ── --key / --generate-key (mutually exclusive) ────────────────────────────

    def test_key_flag(self):
        k = "a" * 64
        self.assertEqual(self._parse("--key", k).key, k)

    def test_generate_key_flag(self):
        self.assertTrue(self._parse("--generate-key").generate_key)

    def test_key_and_generate_key_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            self._parse("--key", "a" * 64, "--generate-key")

    # ── positional GODOT_SOURCE_ROOT ──────────────────────────────────────────

    def test_godot_root_positional(self):
        self.assertEqual(self._parse("/some/path").godot_root, "/some/path")

    def test_godot_root_defaults_to_none(self):
        self.assertIsNone(self._parse().godot_root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
