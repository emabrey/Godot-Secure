import os
import sys
import json
import binascii
import hashlib
import hmac
import secrets
import datetime
import argparse
from enum import Enum, auto

# ── UTF-8 stdout/stderr ────────────────────────────────────────────────────────
# Windows uses cp1252 by default, which cannot encode the Unicode symbols used
# in log output (ℹ, ✓, ✗, ⚠). Reconfigure both streams to UTF-8 at startup so
# output is consistent across all platforms.
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# ── CLI argument parsing ───────────────────────────────────────────────────────

def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="godot_secure.py",
        description="Patch Godot Engine source with cryptographically unique encryption.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes
-----
  apply    Patch a clean Godot source tree (default when no --mode given).
  refresh  Rotate the security token on an already-patched source tree.
  restore  Revert all patches and remove generated files.

Examples
--------
  # Interactive (default)
  python godot_secure.py /path/to/godot

  # Fully non-interactive CI run with AES-256 and a pre-existing key
  python godot_secure.py /path/to/godot \\
      --mode apply --algorithm aes --generate-key \\
      --non-interactive

  # Refresh token, supplying the key via env var
  python godot_secure.py /path/to/godot --mode refresh --non-interactive

  # Restore original source files
  python godot_secure.py /path/to/godot --mode restore --non-interactive
"""
    )

    p.add_argument(
        "godot_root",
        nargs="?",
        default=None,
        metavar="GODOT_SOURCE_ROOT",
        help="Path to the Godot source root (default: current directory).",
    )

    # ── Mode ──────────────────────────────────────────────────────────────────
    p.add_argument(
        "--mode",
        choices=["apply", "refresh", "restore", "generate"],
        default=None,
        help=(
            "Operation to perform. Replaces the interactive main menu. "
            "'generate' outputs a security-token for use in CI setup jobs "
            "without requiring a Godot source tree. "
            "The KDF formula, base-tag, and enc-tag are all derived "
            "deterministically from the token in the apply step. "
            "When GITHUB_OUTPUT is set the token is written there directly; "
            "otherwise it is printed as a key=value pair on stdout."
        ),
    )

    # ── Apply options ─────────────────────────────────────────────────────────
    apply_group = p.add_argument_group("Apply options (--mode apply)")
    apply_group.add_argument(
        "--algorithm",
        choices=["aes", "camellia", "aria"],
        default=None,
        help="Encryption algorithm. Default: aes.",
    )
    apply_group.add_argument(
        "--kdf-formula",
        metavar="FORMULA",
        default=None,
        help=(
            "Expert override: verbatim C statement for the per-byte key derivation "
            "inside the token XOR loop. "
            "When omitted the formula is derived deterministically from the security "
            "token via HKDF (RFC 5869) — no manual management required. "
            "Only supply this when reproducing an exact formula from a previous build "
            "that predates automatic HKDF derivation. "
            "Must be identical across every OS build in a distribution. "
            "Example: 'token_key.write[i] = (uint8_t)(key_ptr[i] ^ Security::TOKEN[i]);'"
        ),
    )

    # ── Key options (apply + refresh) ─────────────────────────────────────────
    key_group = p.add_argument_group("Encryption key options (apply / refresh)")
    key_mutex = key_group.add_mutually_exclusive_group()
    key_mutex.add_argument(
        "--key",
        metavar="HEX",
        default=None,
        help="64-character hex encryption key. Sets SCRIPT_AES256_ENCRYPTION_KEY.",
    )
    key_mutex.add_argument(
        "--generate-key",
        action="store_true",
        default=False,
        help="Generate a new 256-bit encryption key automatically.",
    )

    # ── Token option (apply + refresh) ────────────────────────────────────────
    p.add_argument(
        "--token",
        metavar="HEX",
        default=None,
        help="64-character hex security token (apply / refresh modes).",
    )

    # ── Behaviour flags ───────────────────────────────────────────────────────
    p.add_argument(
        "--non-interactive",
        action="store_true",
        default=False,
        help=(
            "Skip all confirmation prompts and 'Press Enter' pauses. "
            "All missing values fall back to their defaults. "
            "Required when running in a CI environment."
        ),
    )

    return p


# ── Generation helpers ─────────────────────────────────────────────────────────

def generate_random_token(length=32):
    return secrets.token_bytes(length)

def derive_tags_from_token(token_bytes):
    """Derive base-tag and enc-tag deterministically from the security token.

    Maps bytes 0-3 to base-tag and bytes 4-7 to enc-tag by reducing each byte
    modulo 26 and mapping to A-Z. In the astronomically unlikely case that both
    tags are identical, bytes 8-11 are used for enc-tag instead.
    """
    def _to_tag(b4):
        return ''.join(chr(ord('A') + (b % 26)) for b in b4)

    base_tag = _to_tag(token_bytes[0:4])
    enc_tag  = _to_tag(token_bytes[4:8])
    if enc_tag == base_tag:
        enc_tag = _to_tag(token_bytes[8:12])
    return base_tag, enc_tag

def derive_kdf_from_token(token_bytes: bytes) -> str:
    """Derive the KDF formula deterministically from the security token using HKDF.

    Implements HKDF (RFC 5869) with a domain-separation label so this derivation
    is cryptographically independent from the tag derivation (which uses raw token
    bytes directly).  The produced formula is one-way: knowing the compiled C
    expression does not help an attacker recover the 32-byte token (SHA-256
    preimage resistance).  Two builds using the same token always produce
    identical compiled KDF code, eliminating the need to pass kdf-formula as a
    separate CI parameter.

    HKDF-Extract:  PRK  = HMAC-SHA256(salt=b"godot-secure-kdf-formula-v1", IKM=token)
    HKDF-Expand:   OKM  = T(1) || T(2) || ...
                   T(i) = HMAC-SHA256(PRK, T(i-1) || info || counter)
                   info = b"kdf-formula"
    """
    # ── HKDF-Extract ──────────────────────────────────────────────────────────
    prk = hmac.new(
        b"godot-secure-kdf-formula-v1",
        token_bytes,
        hashlib.sha256,
    ).digest()

    # ── HKDF-Expand ───────────────────────────────────────────────────────────
    info    = b"kdf-formula"
    output  = b""
    block   = b""
    counter = 1
    while len(output) < 64:   # 64 bytes is more than enough to drive all choices
        block   = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1

    # ── Consume bytes from the stream to make all structural choices ──────────
    pos = 0

    def _next() -> int:
        nonlocal pos
        b = output[pos % len(output)]
        pos += 1
        return b

    def _choose(options: list):
        return options[_next() % len(options)]

    def _const() -> int:
        return (_next() % 255) + 1

    def _rotation() -> tuple:
        shift = (_next() % 7) + 1
        return shift, 8 - shift

    operands = ["key_ptr[i]", "Security::TOKEN[i]"]
    base_ops = [
        "({a} ^ {b})",
        "({a} + {b})",
        "({a} | {b})",
        "({a} & {b})",
        "(({a} << {shift}) | ({a} >> {rshift}))",
        "(({a} ^ {b}) + {const})",
        "(({a} + {b}) ^ {const})",
    ]
    chain_ops = [
        "({expr} ^ {value})",
        "({expr} + {value})",
        "({expr} | {value})",
        "(({expr} << {shift}) | ({expr} >> {rshift}))",
        "(({expr} ^ {value}) + {const})",
        "(({expr} + {value}) ^ {const})",
    ]

    layers = (_next() % 5) + 2
    a      = _choose(operands)
    b      = operands[1] if a == operands[0] else operands[0]
    shift, rshift = _rotation()
    expression = _choose(base_ops).format(
        a=a, b=b, shift=shift, rshift=rshift, const=_const()
    )

    for _ in range(layers - 1):
        shift, rshift = _rotation()
        value      = _choose(operands)
        expression = _choose(chain_ops).format(
            expr=expression, value=value, shift=shift, rshift=rshift, const=_const()
        )

    return f"token_key.write[i] = (uint8_t)({expression});"


def generate_magic_header(tag: str) -> str:
    if len(tag) != 4:
        raise ValueError("Tag must be exactly 4 characters.")
    return "0x" + ''.join(f"{ord(c):02X}" for c in reversed(tag))

# ── Logging ────────────────────────────────────────────────────────────────────

class LogColors:
    HEADER    = '\033[95m'
    OKBLUE    = '\033[94m'
    OKGREEN   = '\033[92m'
    WARNING   = '\033[93m'
    FAIL      = '\033[91m'
    ENDC      = '\033[0m'
    BOLD      = '\033[1m'
    UNDERLINE = '\033[4m'

logFileName = None  # set before first log_print call

def save_log(message):
    if logFileName and not str(message).find("\033[") > 0:
        with open(logFileName, "a", encoding="utf-8") as lf:
            lf.write(f"{message}\n")
    return message


class MsgType(Enum):
    SUCCESS   = auto()
    ERROR     = auto()
    INFO      = auto()
    OPERATION = auto()
    WARNING   = auto()

_MSG_CONFIG = {
    MsgType.SUCCESS:   (LogColors.OKGREEN,  "      ✓", "      [✓] ", ""),
    MsgType.ERROR:     (LogColors.FAIL,     "      ✗", "      [✗] ", "\n"),
    MsgType.INFO:      (LogColors.OKBLUE,   " ℹ ",     "\n[INFO] -   ", "\n"),
    MsgType.OPERATION: (LogColors.HEADER,   "   =>",   "   [=>] ",    ""),
    MsgType.WARNING:   (LogColors.WARNING,  " ⚠ ",     "\n[WARN] -   ", "\n"),
}

def log_print(msg_type: MsgType, message: str):
    color, symbol, log_prefix, leading = _MSG_CONFIG[msg_type]
    save_log(f"{log_prefix}{message}")
    print(f"{leading}{color}{symbol}{LogColors.ENDC} {message}")

def init_log(suffix):
    global logFileName
    logFileName = f"godot_secure_{suffix}_{current_dt}.log"
    with open(logFileName, "w", encoding="utf-8") as lf:
        lf.write(f"Created On - {current_dt}\nGodot-Secure log — SAVE IT.\n\n")

# ── Interactive / non-interactive input helper ─────────────────────────────────

def prompt(question: str, default: str = "", non_interactive: bool = False) -> str:
    """Return user input, or `default` when running non-interactively."""
    if non_interactive:
        save_log(f"{question} [non-interactive, using default: {default!r}]")
        return default
    return input(question).strip()

def pause_exit(non_interactive: bool = False):
    """Wait for Enter before exiting, unless running non-interactively."""
    if non_interactive:
        return
    try:
        input("\nPress Enter key to exit...")
    except EOFError:
        pass

# ── Encryption key resolution ──────────────────────────────────────────────────

def _apply_key(key, godot_root, source):
    """Set the env var, write godot.gdkey, and log the outcome."""
    os.environ["SCRIPT_AES256_ENCRYPTION_KEY"] = key
    key_file = os.path.join(godot_root, "godot.gdkey")
    try:
        with open(key_file, "w", encoding="utf-8") as kf:
            kf.write(key)
        log_print(MsgType.SUCCESS, f"Key written to: {key_file}")
        log_print(MsgType.WARNING,
            f"Store this key and {LogColors.BOLD}godot.gdkey{LogColors.ENDC}{LogColors.WARNING} in "
            "secure storage — they must never be committed to version control."
        )
        save_log(f"Encryption Key ({source}): {key}")
        save_log(f"Key written to: {key_file}")
    except Exception as e:
        log_print(MsgType.ERROR, f"Could not write godot.gdkey ({e}). Key is set for this session only.")
        save_log(f"Encryption Key ({source}): {key}")
        save_log(f"Could not write godot.gdkey: {e}")
    return key

def _abort_no_key(non_interactive: bool):
    save_log("No valid encryption key provided. Cannot proceed.")
    print(f"\n{LogColors.FAIL}Operation cannot proceed without a valid SCRIPT_AES256_ENCRYPTION_KEY.{LogColors.ENDC}")
    pause_exit(non_interactive)
    sys.exit(1)

def resolve_encryption_key(godot_root, args):
    """Return the value of SCRIPT_AES256_ENCRYPTION_KEY.

    Resolution order:
      1. --key CLI argument
      2. --generate-key CLI flag
      3. SCRIPT_AES256_ENCRYPTION_KEY environment variable (if valid)
      4. Interactive prompt (skipped / aborted when --non-interactive)
    """
    ni = args.non_interactive

    # 1. Explicit --key value
    if args.key:
        if len(args.key) == 64 and all(c in "0123456789abcdefABCDEF" for c in args.key):
            save_log("Encryption key provided via --key argument.")
            return _apply_key(args.key, godot_root, "cli --key")
        else:
            print(f"{LogColors.FAIL}Error: --key value is not a valid 64-character hex string.{LogColors.ENDC}")
            pause_exit(ni)
            sys.exit(1)

    # 2. --generate-key flag
    if args.generate_key:
        new_key = secrets.token_hex(32)
        save_log("Encryption key generated via --generate-key flag.")
        return _apply_key(new_key, godot_root, "cli --generate-key")

    # 3. Environment variable
    raw = os.environ.get("SCRIPT_AES256_ENCRYPTION_KEY", "")
    if len(raw) == 64 and all(c in "0123456789abcdefABCDEF" for c in raw):
        return raw

    if raw:
        log_print(MsgType.WARNING,
            "SCRIPT_AES256_ENCRYPTION_KEY is set but is not a valid 256-bit hex key "
            f"(expected 64 hex characters, got {len(raw)})."
        )
    else:
        log_print(MsgType.WARNING,
            "SCRIPT_AES256_ENCRYPTION_KEY has not been configured. "
            "Generate a 256-bit hex key (e.g. python -c \"import secrets; print(secrets.token_hex(32))\") "
            "and supply it via the SCRIPT_AES256_ENCRYPTION_KEY environment variable, "
            "or store it as a GitHub Actions secret and pass it with --key."
        )

    # 4. Interactive prompt
    if ni:
        print(f"\n{LogColors.FAIL}Error: no encryption key available.{LogColors.ENDC}")
        print(f"\n  To fix this, generate a 256-bit AES key and provide it one of these ways:\n")
        print(f"    Generate a key:")
        print(f"      python -c \"import secrets; print(secrets.token_hex(32))\"")
        print(f"\n    Then either:")
        print(f"      Set the environment variable : SCRIPT_AES256_ENCRYPTION_KEY=<your-64-char-hex-key>")
        print(f"      Pass it on the command line  : --key <your-64-char-hex-key>")
        print(f"\n    When using GitHub Actions, store the key as an encrypted repository secret")
        print(f"    named GODOT_ENCRYPTION_KEY and pass it to the workflow via:")
        print(f"      env:")
        print(f"        SCRIPT_AES256_ENCRYPTION_KEY: ${{{{ secrets.GODOT_ENCRYPTION_KEY }}}}")
        sys.exit(1)

    print(f"\n  How would you like to provide an encryption key?\n")
    print(f"    [1] Enter my own 64-character hex key")
    print(f"    [2] Generate a secure key automatically")
    print(f"    [3] Cancel")
    choice = input(f"\n  {LogColors.FAIL}Enter choice [1/2/3]:{LogColors.ENDC} ").strip()
    save_log(f"\n[INFO] - Encryption key resolution choice: {choice}")

    if choice == "1":
        while True:
            value = input("    Enter your 64-character hex key: ").strip()
            if len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value):
                save_log("User supplied a custom encryption key.")
                return _apply_key(value, godot_root, "user-supplied")
            log_print(MsgType.ERROR, "Invalid key — must be exactly 64 hexadecimal characters. Please try again.")
    elif choice == "2":
        new_key = secrets.token_hex(32)
        save_log("Script generated a new encryption key.")
        return _apply_key(new_key, godot_root, "generated")
    else:
        _abort_no_key(ni)

# ── State file ─────────────────────────────────────────────────────────────────

STATE_FILE_NAME = ".godot_secure"

def write_state_file(state_path, algorithm, godot_version, token):
    state = {
        "algorithm":     algorithm,
        "godot_version": godot_version,
        "token_hex":     token,
        "applied_at":    current_dt,
    }
    with open(state_path, "w", encoding="utf-8") as sf:
        json.dump(state, sf, indent=2)

def read_state_file(state_path):
    with open(state_path, encoding="utf-8") as sf:
        return json.load(sf)

# ── File lists for backup restoration ─────────────────────────────────────────

RESTORE_FILES = [
    "version.py",
    "editor/export/project_export.cpp",
    "core/io/file_access_pack.h",
    "core/io/file_access_encrypted.h",
    "core/io/file_access_encrypted.cpp",
    "core/crypto/crypto_core.h",   # Camellia and ARIA only — silently skipped when no backup
    "core/crypto/crypto_core.cpp",
]

CIPHER_EXTRA_FILES = {
    "core/crypto/crypto_core.h",
    "core/crypto/crypto_core.cpp",
}

CREATED_FILES = [
    "core/crypto/security_token.h",
]

# ── Restore ────────────────────────────────────────────────────────────────────

def restore_backups(root_dir, state_path):
    log_print(MsgType.INFO, "Restoring original Godot source files from backups...")
    all_ok = True

    for rel_path in RESTORE_FILES:
        file_path   = os.path.join(root_dir, rel_path)
        backup_path = file_path + ".backup"
        if not os.path.exists(backup_path):
            if rel_path not in CIPHER_EXTRA_FILES:
                log_print(MsgType.WARNING, f"Backup not found, skipping: {rel_path}")
                all_ok = False
            continue
        try:
            if os.path.exists(file_path):
                os.replace(backup_path, file_path)
                log_print(MsgType.SUCCESS, f"Restored: {rel_path}")
            else:
                os.rename(backup_path, file_path)
                log_print(MsgType.SUCCESS, f"Restored (from backup only): {rel_path}")
        except Exception as e:
            log_print(MsgType.ERROR, f"Failed to restore {rel_path}: {e}")
            all_ok = False

    for rel_path in CREATED_FILES:
        file_path = os.path.join(root_dir, rel_path)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                log_print(MsgType.SUCCESS, f"Removed generated file: {rel_path}")
            except Exception as e:
                log_print(MsgType.ERROR, f"Failed to remove {rel_path}: {e}")
                all_ok = False

    if os.path.exists(state_path):
        try:
            os.remove(state_path)
            log_print(MsgType.SUCCESS, f"Removed state file: {STATE_FILE_NAME}")
        except Exception as e:
            log_print(MsgType.ERROR, f"Failed to remove state file: {e}")

    return all_ok

# ── apply_modifications engine ─────────────────────────────────────────────────

def apply_modifications(root_dir, MODIFICATIONS, non_interactive=False):
    quiz_override       = False
    override_backup     = True
    not_modify_on_error = True
    track_backup_file   = set()
    backup_path_ref     = [None]

    step = 0
    for mod in MODIFICATIONS:
        file_path = os.path.join(root_dir, mod["file"])
        step += 1

        # ── create_file ops ──────────────────────────────────────────────────
        if any(op.get("type") == "create_file" for op in mod["operations"]):
            log_print(MsgType.INFO, f"Step {step} (Creating: {file_path}):")
            for op in mod["operations"]:
                if op["type"] != "create_file":
                    continue
                log_print(MsgType.OPERATION, f"Operation: {op['description']}")
                os.makedirs(os.path.dirname(file_path), exist_ok=True)

                if os.path.exists(file_path):
                    log_print(MsgType.WARNING, f"File already exists: {file_path}")
                    choice = prompt("   Do you want to overwrite it? (y/n): ", "y", non_interactive).lower()
                    if choice not in ('y', 'yes'):
                        log_print(MsgType.OPERATION, "Skipping file creation.")
                        continue
                    bk = file_path + ".backup"
                    try:
                        os.replace(file_path, bk)
                        backup_path_ref[0] = bk
                        log_print(MsgType.OPERATION, f"Backup created at: {bk}")
                    except Exception as e:
                        log_print(MsgType.ERROR, f"Failed to create backup: {e}")
                        log_print(MsgType.OPERATION, "Skipping file creation.")
                        continue

                try:
                    content = op["content"]
                    if isinstance(content, list):
                        content = "\n".join(content)
                    with open(file_path, "w") as f:
                        f.write(content)
                    log_print(MsgType.SUCCESS, f"File created: {file_path}")
                except Exception as e:
                    log_print(MsgType.ERROR, f"Failed to write file: {e}")
            continue

        # ── modification ops ─────────────────────────────────────────────────
        if not os.path.exists(file_path):
            log_print(MsgType.ERROR, f"File not found: {file_path}")
            continue

        local_backup = file_path + ".backup"
        if local_backup not in track_backup_file:
            track_backup_file.add(local_backup)
            create_backup = True
            if os.path.exists(local_backup):
                if not quiz_override:
                    quiz_override = True
                    log_print(MsgType.WARNING, "Backup of origin file already exists")
                    ans = prompt("   Do you want to overwrite it? (y/n): ", "y", non_interactive).lower()
                    override_backup = ans in ('y', 'yes')
                create_backup = override_backup
            if create_backup:
                try:
                    with open(file_path, 'r') as f0:
                        content = f0.read()
                    with open(local_backup, "w") as f1:
                        f1.write(content)
                    log_print(MsgType.SUCCESS, f"Backup created: {local_backup}")
                except Exception as e:
                    log_print(MsgType.ERROR, f"Failed to create backup: {e}")
                    if not_modify_on_error:
                        log_print(MsgType.OPERATION, "Skipping file modification.")
                        continue

        log_print(MsgType.INFO, f"Step {step} (Processing: {file_path}):")
        with open(file_path, "r") as f:
            lines = f.readlines()

        modified = False
        for op in mod["operations"]:
            op_type     = op["type"]
            description = op.get("description", "")
            log_print(MsgType.OPERATION, f"Operation: {description}. (Type: {op_type})")

            if op_type == "replace_line":
                find  = op["find"].strip()
                replace = op["replace"] + "\n"
                found = False
                for i in range(len(lines)):
                    if lines[i].strip() == find:
                        lines[i] = replace
                        log_print(MsgType.SUCCESS, f"Line replaced at line {i+1}")
                        found = modified = True
                        break
                if not found:
                    log_print(MsgType.ERROR, f"Target line not found: {find}")

            elif op_type == "replace_block":
                find_lines    = [ln.strip() for ln in op["find"]]
                replace_lines = [ln + "\n" for ln in op["replace"]]
                block_found   = False
                for i in range(len(lines) - len(find_lines) + 1):
                    if all(lines[i + j].strip() == find_lines[j] for j in range(len(find_lines))):
                        lines[i:i + len(find_lines)] = replace_lines
                        log_print(MsgType.SUCCESS, f"Block replaced starting at line {i+1}")
                        modified = block_found = True
                        break
                if not block_found:
                    log_print(MsgType.ERROR, "Target block not found")

            elif op_type == "insert_after":
                find          = op["find"].strip()
                replace_lines = (
                    [ln + "\n" for ln in op["replace"]]
                    if isinstance(op["replace"], list)
                    else [op["replace"] + "\n"]
                )
                found = False
                for i in range(len(lines)):
                    if lines[i].strip() == find:
                        already = all(
                            i + 1 + j < len(lines) and lines[i + 1 + j] == replace_lines[j]
                            for j in range(len(replace_lines))
                        )
                        if not already:
                            lines[i+1:i+1] = replace_lines
                            log_print(MsgType.SUCCESS, f"Inserted after line {i+1}")
                            modified = True
                        else:
                            log_print(MsgType.SUCCESS, "Content already present, skipping insertion")
                        found = True
                        break
                if not found:
                    log_print(MsgType.ERROR, f"Insertion point not found: {find}")

            elif op_type == "append":
                replace_lines   = [ln + "\n" for ln in op["replace"]]
                already_present = (
                    len(lines) >= len(replace_lines)
                    and all(lines[-len(replace_lines) + i] == replace_lines[i] for i in range(len(replace_lines)))
                )
                if not already_present:
                    lines.extend(replace_lines)
                    log_print(MsgType.SUCCESS, "Appended to end of file")
                    modified = True
                else:
                    log_print(MsgType.SUCCESS, "Content already present at end, skipping append")

        if modified:
            with open(file_path, "w") as f:
                f.writelines(lines)
            log_print(MsgType.SUCCESS, f"File updated: {file_path}")
        else:
            log_print(MsgType.WARNING, f"No changes made to file (Step {step})")

    return backup_path_ref[0]

# ── Token header writer ────────────────────────────────────────────────────────

def write_security_token_header(root_dir, token_hex, token_c_array):
    path = os.path.join(root_dir, "core", "crypto", "security_token.h")
    content = "\n".join([
        "#ifndef SECURITY_TOKEN_H",
        "#define SECURITY_TOKEN_H",
        "",
        "#include \"core/typedefs.h\"",
        "",
        "namespace Security {",
        f"    //Security Token: {token_hex}",
        f"    static const uint8_t TOKEN[32] = {{ {token_c_array} }};",
        "};",
        "",
        "#endif // SECURITY_TOKEN_H",
    ])
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path

# ── Shared token + KDF prompts ─────────────────────────────────────────────────

def resolve_token_and_kdf(default_token_hex, default_security_token, args):
    """Resolve security token and key derivation algorithm.

    CLI option --token takes precedence over the interactive prompt.
    --kdf-formula is an expert override; when absent the formula is derived from the token via HKDF.
    Returns (token_hex, security_token, token_c_array, key_derivation_algorithm).
    """
    ni        = args.non_interactive
    token_hex = default_token_hex
    sec_token = default_security_token

    # Token
    if args.token:
        token_hex = args.token.lower()
        sec_token = bytes.fromhex(token_hex)
        save_log(f"Security token provided via --token argument: {token_hex}")
    else:
        ans = prompt(
            f"\n\n ℹ  {LogColors.OKBLUE}Use Custom Token {LogColors.ENDC}{LogColors.FAIL}(y/n)?{LogColors.ENDC}: ",
            "n", ni
        ).lower()
        save_log(f"\n[INFO] - Use Custom Token (y/n)?: {ans}")
        if ans in ('y', 'yes'):
            token_hex = str(input("    Enter Custom Security Token: ")).lower()
            sec_token = bytes.fromhex(token_hex)
            save_log(f"    Enter Custom Security Token: {token_hex}")

    token_c_array = ', '.join([f'0x{b:02X}' for b in sec_token])

    # Key derivation
    # Priority: --kdf-formula (expert override) > HKDF derivation from token
    kdf_formula = getattr(args, 'kdf_formula', None)
    if kdf_formula:
        key_deriv = kdf_formula
        save_log(f"KDF formula provided via --kdf-formula (expert override):\n            {key_deriv}")
    else:
        key_deriv = derive_kdf_from_token(sec_token)
        save_log(f"KDF formula derived from security token via HKDF:\n            {key_deriv}")

    return token_hex, sec_token, token_c_array, key_deriv

# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

current_dt = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f")

args = build_arg_parser().parse_args()
ni   = args.non_interactive  # shorthand used throughout

# ── Generate mode: produce shared security parameters for CI setup jobs ────────
# Does not require a Godot source tree. Generates a security-token and writes
# it to GITHUB_OUTPUT (when running inside GitHub Actions) or prints it as a
# key=value pair on stdout.
#
# The KDF formula, base-tag, and enc-tag are all derived deterministically
# from the token by the apply step via HKDF and byte-mapping, so only a single
# security-token value needs to be generated, stored, and shared.
#
# Typical usage:
#   python godot_secure.py --mode generate --non-interactive
if args.mode == "generate":
    init_log("Generate")

    security_token    = generate_random_token()
    token_hex         = binascii.hexlify(security_token).decode('utf-8')
    base_tag, enc_tag = derive_tags_from_token(security_token)
    kdf               = derive_kdf_from_token(security_token)

    save_log(f"security-token: {token_hex}")
    save_log(f"base-tag (derived from token): {base_tag}")
    save_log(f"enc-tag  (derived from token): {enc_tag}")
    save_log(f"kdf-formula (derived from token via HKDF): {kdf}")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        log_print(MsgType.INFO, "security-token: ***")
        log_print(MsgType.INFO, f"base-tag (derived):        {base_tag}")
        log_print(MsgType.INFO, f"enc-tag  (derived):        {enc_tag}")
        log_print(MsgType.INFO, f"kdf-formula (derived):     {kdf}")
        with open(github_output, "a", encoding="utf-8") as fh:
            fh.write(f"security-token={token_hex}\n")
        log_print(MsgType.SUCCESS, "Security token written to GITHUB_OUTPUT.")
    else:
        # Local / non-CI use: print as key=value pair on stdout.
        print(f"security-token={token_hex}")
        log_print(MsgType.INFO,
            "GITHUB_OUTPUT is not set — security-token printed to stdout. "
            "Pass it to your build via --token. "
            "The KDF formula, base-tag, and enc-tag are derived from the token automatically.")

    pause_exit(ni)
    sys.exit(0)

# ── Resolve Godot source root ──────────────────────────────────────────────────
if args.godot_root:
    godot_root = args.godot_root
else:
    godot_root = os.getcwd()
    print("\nNo directory specified. Using current directory as Godot Source Root.")

# ── Validate Godot source ──────────────────────────────────────────────────────
core_dir        = os.path.join(godot_root, "core")
sconstruct_file = os.path.join(godot_root, "SConstruct")

if not (os.path.isdir(core_dir) and os.path.isfile(sconstruct_file)):
    print(f"{LogColors.FAIL}Error: No valid Godot Source Detected in the Specified Directory.{LogColors.ENDC}")
    pause_exit(ni)
    sys.exit(1)

# ── Detect Godot version ───────────────────────────────────────────────────────
godot_minor          = 0
detected_version_str = "unknown"
version_py_path      = os.path.join(godot_root, "version.py")

if os.path.isfile(version_py_path):
    version_vars = {}
    try:
        with open(version_py_path, encoding="utf-8") as vf:
            exec(vf.read(), version_vars)
        godot_minor          = int(version_vars.get("minor", 0))
        godot_major          = int(version_vars.get("major", 4))
        godot_patch          = int(version_vars.get("patch", 0))
        godot_status         = version_vars.get("status", "unknown")
        detected_version_str = f"{godot_major}.{godot_minor}.{godot_patch}-{godot_status}"
    except Exception as e:
        print(f"{LogColors.WARNING}Warning: Could not parse version.py ({e}). Assuming v4.5.x code paths.{LogColors.ENDC}")
else:
    print(f"{LogColors.WARNING}Warning: version.py not found. Assuming v4.5.x code paths.{LogColors.ENDC}")

compress_ptr = "compressed.ptr()" if godot_minor >= 6 else "compressed.ptrw()"

# ── Read state file (may not exist) ───────────────────────────────────────────
state_file_path = os.path.join(godot_root, STATE_FILE_NAME)
state = None
if os.path.isfile(state_file_path):
    try:
        state = read_state_file(state_file_path)
    except Exception as e:
        print(f"{LogColors.WARNING}Warning: Could not read state file ({e}).{LogColors.ENDC}")

already_applied = state is not None

# ── Main menu (or --mode bypass) ───────────────────────────────────────────────
print(f"\n{LogColors.HEADER}{'=' * 54}")
print(f"  Godot Secure")
print(f"{'=' * 54}{LogColors.ENDC}")
print(f"\n  Source root      : {godot_root}")
print(f"  Godot version    : {detected_version_str}")
if already_applied:
    print(f"  Status           : {LogColors.WARNING}Godot Secure already applied{LogColors.ENDC}")
    print(f"  Algorithm        : {state.get('algorithm', '?')}")
    print(f"  Last applied     : {state.get('applied_at', '?')}")
else:
    print(f"  Status           : {LogColors.OKGREEN}Clean Godot source{LogColors.ENDC}")

if args.mode:
    # Map CLI mode name to menu choice string
    # 'generate' exits early above and never reaches this point.
    menu_choice = {"apply": "1", "refresh": "2", "restore": "3"}[args.mode]
    print(f"\n  Mode selected via --mode: {args.mode}")
else:
    print(f"\n  What would you like to do?\n")
    opt1_note = f" {LogColors.WARNING}(already applied — will re-apply){LogColors.ENDC}" if already_applied else ""
    opt2_note = f" {LogColors.FAIL}(requires prior application){LogColors.ENDC}"         if not already_applied else ""
    opt3_note = f" {LogColors.FAIL}(requires prior application){LogColors.ENDC}"         if not already_applied else ""
    print(f"    [1] Apply Godot Secure to this source tree{opt1_note}")
    print(f"    [2] Refresh security token{opt2_note}")
    print(f"    [3] Restore original Godot source{opt3_note}")
    print()
    menu_choice = prompt(f"  {LogColors.FAIL}Enter choice [1/2/3]:{LogColors.ENDC} ", "", ni)

# ══════════════════════════════════════════════════════════════════════════════
# MODE 1 — Apply Godot Secure
# ══════════════════════════════════════════════════════════════════════════════
if menu_choice == "1":

    # Algorithm
    if args.algorithm:
        chosen_algo = args.algorithm
        save_log(f"Algorithm provided via --algorithm: {args.algorithm}")
    else:
        print(f"\n\n ℹ  {LogColors.OKBLUE}Choose Encryption Algorithm:{LogColors.ENDC}")
        print(f"     [1] AES-256  (default)")
        print(f"     [2] Camellia-256")
        print(f"     [3] ARIA-256")
        algo_choice = prompt(f"     {LogColors.FAIL}Enter choice [1/2/3]:{LogColors.ENDC} ", "1", ni)
        if algo_choice == "2":
            chosen_algo = "camellia"
        elif algo_choice == "3":
            chosen_algo = "aria"
        else:
            chosen_algo = "aes"

    _ALGO_META = {
        "aes":      ("AES-256",      "CryptoCore::AESContext"),
        "camellia": ("Camellia-256", "CryptoCore::CamelliaContext"),
        "aria":     ("ARIA-256",     "CryptoCore::AriaContext"),
    }
    algorithm_name, ctx_class = _ALGO_META[chosen_algo]
    export_title = f"Export With Godot Secure ({algorithm_name})"

    # Guard: if already applied with a different algorithm, refuse to continue.
    # Mixing algorithm patches on the same source tree corrupts crypto_core.h/cpp
    # and produces undefined behaviour at compile time.
    if already_applied:
        prev_algorithm = state.get("algorithm", "")
        if prev_algorithm and prev_algorithm != algorithm_name:
            print(f"\n{LogColors.FAIL}Error: Algorithm mismatch.{LogColors.ENDC}")
            print(f"  This source tree was previously patched with {LogColors.BOLD}{prev_algorithm}{LogColors.ENDC}.")
            print(f"  You selected {LogColors.BOLD}{algorithm_name}{LogColors.ENDC}.")
            print(f"\n  Applying a different algorithm on top of an existing patch would")
            print(f"  leave conflicting context classes in crypto_core.h/cpp and produce")
            print(f"  undefined behaviour when Godot is compiled.")
            print(f"\n  To switch algorithms:")
            print(f"    1. Run option [3] to restore the original Godot source.")
            print(f"    2. Re-run option [1] and choose {algorithm_name}.")
            save_log(f"[ERROR] Algorithm mismatch: state={prev_algorithm}, requested={algorithm_name}. Aborting.")
            pause_exit(ni)
            sys.exit(1)

    init_log({"aes": "AES", "camellia": "Camellia", "aria": "ARIA"}[chosen_algo])
    save_log(f"\nUsing Godot Source Root: {godot_root}")
    save_log(f"Detected Godot Version : {detected_version_str} (minor={godot_minor}, compress_ptr={compress_ptr})")
    save_log(f"Algorithm: {algorithm_name}")
    save_log(f"Mode: apply | non-interactive: {ni}")

    encKey = resolve_encryption_key(godot_root, args)

    # Resolve token first; derive magic header tags from it.
    security_token = generate_random_token()
    token_hex      = binascii.hexlify(security_token).decode('utf-8')

    token_hex, security_token, token_c_array, key_derivation_algorithm = \
        resolve_token_and_kdf(token_hex, security_token, args)

    baseTag, encTag = derive_tags_from_token(security_token)
    baseHeader      = generate_magic_header(baseTag)
    encHeader       = generate_magic_header(encTag)
    save_log(f"Pack header tag (derived from token): {baseTag}")
    save_log(f"Encrypted header tag (derived from token): {encTag}")

    # Build MODIFICATIONS
    MODIFICATIONS = [
        {
            "file": "version.py",
            "operations": [{"type": "replace_line", "description": "Modify Godot title to add Godot Secure",
                "find": "name = \"Godot Engine\"", "replace": "name = \"Godot Engine (With Godot Secure)\""}]
        },
        {
            "file": "editor/export/project_export.cpp",
            "operations": [{"type": "replace_line", "description": "Modify Godot export popup title",
                "find": "set_title(TTR(\"Export\"));", "replace": f"set_title(TTR(\"{export_title}\"));"}]
        },
        {
            "file": "core/crypto/security_token.h",
            "operations": [{"type": "create_file", "description": "Create security token header",
                "content": [
                    "#ifndef SECURITY_TOKEN_H", "#define SECURITY_TOKEN_H", "",
                    "#include \"core/typedefs.h\"", "", "namespace Security {",
                    f"    //Security Token: {token_hex}",
                    f"    static const uint8_t TOKEN[32] = {{ {token_c_array} }};",
                    "};", "", "#endif // SECURITY_TOKEN_H"
                ]}]
        },
        {
            "file": "core/io/file_access_pack.h",
            "operations": [{"type": "replace_line", "description": "Modify Packed File Header Magic",
                "find": "#define PACK_HEADER_MAGIC 0x43504447",
                "replace": f"#define PACK_HEADER_MAGIC {baseHeader}  // Generated Tag: \"{baseTag}\""}]
        },
        {
            "file": "core/io/file_access_encrypted.h",
            "operations": [{"type": "replace_line", "description": "Modify Encrypted File Header Magic",
                "find": "#define ENCRYPTED_HEADER_MAGIC 0x43454447",
                "replace": f"#define ENCRYPTED_HEADER_MAGIC {encHeader}  // Generated Tag: \"{encTag}\""}]
        },
        {
            "file": "core/io/file_access_encrypted.cpp",
            "operations": [
                {"type": "insert_after", "description": "Include security token header",
                    "find": "#include \"file_access_encrypted.h\"",
                    "replace": "#include \"core/crypto/security_token.h\""},
                {"type": "replace_block", "description": "Add token obfuscation for decryption",
                    "find": ["{", "CryptoCore::AESContext ctx;", "",
                        "ctx.set_encode_key(key.ptrw(), 256); // Due to the nature of CFB, same key schedule is used for both encryption and decryption!",
                        "ctx.decrypt_cfb(ds, iv.ptrw(), data.ptrw(), data.ptrw());", "}"],
                    "replace": ["{", f"{ctx_class} ctx;", "",
                        "    // Apply security token to key", "    Vector<uint8_t> token_key;",
                        "    token_key.resize(32);", "    const uint8_t *key_ptr = key.ptr();",
                        "    for (int i = 0; i < 32; i++) {", f"        {key_derivation_algorithm}", "    }",
                        "", "    ctx.set_encode_key(token_key.ptrw(), 256); // Due to the nature of CFB, same key schedule is used for both encryption and decryption!",
                        "    ctx.decrypt_cfb(ds, iv.ptrw(), data.ptrw(), data.ptrw());", "}"]}
            ]
        },
        {
            "file": "core/io/file_access_encrypted.cpp",
            "operations": [{"type": "replace_block", "description": "Add token obfuscation for encryption",
                "find": ["CryptoCore::AESContext ctx;", "ctx.set_encode_key(key.ptrw(), 256);", "",
                    "if (use_magic) {", "    file->store_32(ENCRYPTED_HEADER_MAGIC);", "}",
                    "", "file->store_buffer(hash, 16);", "file->store_64(data.size());",
                    "file->store_buffer(iv.ptr(), 16);", "",
                    f"ctx.encrypt_cfb(len, iv.ptrw(), {compress_ptr}, {compress_ptr});"],
                "replace": [f"{ctx_class} ctx;", "",
                    "    // Apply security token to key", "    Vector<uint8_t> token_key;",
                    "    token_key.resize(32);", "    const uint8_t *key_ptr = key.ptr();",
                    "    for (int i = 0; i < 32; i++) {", f"        {key_derivation_algorithm}", "    }",
                    "", "    ctx.set_encode_key(token_key.ptrw(), 256);",
                    "", "if (use_magic) {", "file->store_32(ENCRYPTED_HEADER_MAGIC);", "}",
                    "", "file->store_buffer(hash, 16);", "file->store_64(data.size());",
                    "file->store_buffer(iv.ptr(), 16);", "",
                    f"ctx.encrypt_cfb(len, iv.ptrw(), {compress_ptr}, {compress_ptr});"]}]
        },
    ]

    if chosen_algo == "camellia":
        MODIFICATIONS += [
            {
                "file": "core/crypto/crypto_core.h",
                "operations": [{"type": "insert_after", "description": "Add CamelliaContext class declaration",
                    "find": "};",
                    "replace": [
                        "// Camellia-256 (via Mbed TLS)", "class CamelliaContext {", "private:",
                        "    void *ctx = nullptr;", "", "public:", "    CamelliaContext();", "    ~CamelliaContext();", "",
                        "    Error set_encode_key(const uint8_t *p_key, size_t p_bits);",
                        "    Error set_decode_key(const uint8_t *p_key, size_t p_bits);",
                        "    Error encrypt_ecb(const uint8_t p_src[16], uint8_t r_dst[16]);",
                        "    Error decrypt_ecb(const uint8_t p_src[16], uint8_t r_dst[16]);",
                        "    Error encrypt_cbc(size_t p_length, uint8_t r_iv[16], const uint8_t *p_src, uint8_t *r_dst);",
                        "    Error decrypt_cbc(size_t p_length, uint8_t r_iv[16], const uint8_t *p_src, uint8_t *r_dst);",
                        "    Error encrypt_cfb(size_t p_length, uint8_t p_iv[16], const uint8_t *p_src, uint8_t *r_dst);",
                        "    Error decrypt_cfb(size_t p_length, uint8_t p_iv[16], const uint8_t *p_src, uint8_t *r_dst);",
                        "};", ""
                    ]}]
            },
            {
                "file": "core/crypto/crypto_core.cpp",
                "operations": [
                    {"type": "insert_after", "description": "Add Camellia include",
                        "find": "#include <mbedtls/aes.h>", "replace": "#include <mbedtls/camellia.h>"},
                    {"type": "append", "description": "Add Camellia implementation",
                        "replace": [
                            "// ----------------------------------------------------------------",
                            "// Camellia-256 implementation", "",
                            "CryptoCore::CamelliaContext::CamelliaContext() {",
                            "    ctx = memalloc(sizeof(mbedtls_camellia_context));",
                            "    mbedtls_camellia_init((mbedtls_camellia_context *)ctx);", "}", "",
                            "CryptoCore::CamelliaContext::~CamelliaContext() {",
                            "    mbedtls_camellia_free((mbedtls_camellia_context *)ctx);",
                            "    memfree(ctx);", "}", "",
                            "Error CryptoCore::CamelliaContext::set_encode_key(const uint8_t *p_key, size_t p_bits) {",
                            "    int ret = mbedtls_camellia_setkey_enc((mbedtls_camellia_context *)ctx, p_key, p_bits);",
                            "    return ret ? FAILED : OK;", "}", "",
                            "Error CryptoCore::CamelliaContext::set_decode_key(const uint8_t *p_key, size_t p_bits) {",
                            "    int ret = mbedtls_camellia_setkey_dec((mbedtls_camellia_context *)ctx, p_key, p_bits);",
                            "    return ret ? FAILED : OK;", "}", "",
                            "Error CryptoCore::CamelliaContext::encrypt_ecb(const uint8_t p_src[16], uint8_t r_dst[16]) {",
                            "    int ret = mbedtls_camellia_crypt_ecb((mbedtls_camellia_context *)ctx, MBEDTLS_CAMELLIA_ENCRYPT, p_src, r_dst);",
                            "    return ret ? FAILED : OK;", "}", "",
                            "Error CryptoCore::CamelliaContext::decrypt_ecb(const uint8_t p_src[16], uint8_t r_dst[16]) {",
                            "    int ret = mbedtls_camellia_crypt_ecb((mbedtls_camellia_context *)ctx, MBEDTLS_CAMELLIA_DECRYPT, p_src, r_dst);",
                            "    return ret ? FAILED : OK;", "}", "",
                            "Error CryptoCore::CamelliaContext::encrypt_cbc(size_t p_length, uint8_t r_iv[16], const uint8_t *p_src, uint8_t *r_dst) {",
                            "    int ret = mbedtls_camellia_crypt_cbc((mbedtls_camellia_context *)ctx, MBEDTLS_CAMELLIA_ENCRYPT, p_length, r_iv, p_src, r_dst);",
                            "    return ret ? FAILED : OK;", "}", "",
                            "Error CryptoCore::CamelliaContext::decrypt_cbc(size_t p_length, uint8_t r_iv[16], const uint8_t *p_src, uint8_t *r_dst) {",
                            "    int ret = mbedtls_camellia_crypt_cbc((mbedtls_camellia_context *)ctx, MBEDTLS_CAMELLIA_DECRYPT, p_length, r_iv, p_src, r_dst);",
                            "    return ret ? FAILED : OK;", "}", "",
                            "Error CryptoCore::CamelliaContext::encrypt_cfb(size_t p_length, uint8_t p_iv[16], const uint8_t *p_src, uint8_t *r_dst) {",
                            "    size_t iv_off = 0;",
                            "    int ret = mbedtls_camellia_crypt_cfb128((mbedtls_camellia_context *)ctx, MBEDTLS_CAMELLIA_ENCRYPT, p_length, &iv_off, p_iv, p_src, r_dst);",
                            "    return ret ? FAILED : OK;", "}", "",
                            "Error CryptoCore::CamelliaContext::decrypt_cfb(size_t p_length, uint8_t p_iv[16], const uint8_t *p_src, uint8_t *r_dst) {",
                            "    size_t iv_off = 0;",
                            "    int ret = mbedtls_camellia_crypt_cfb128((mbedtls_camellia_context *)ctx, MBEDTLS_CAMELLIA_DECRYPT, p_length, &iv_off, p_iv, p_src, r_dst);",
                            "    return ret ? FAILED : OK;", "}"
                        ]}
                ]
            },
        ]

    elif chosen_algo == "aria":
        MODIFICATIONS += [
            {
                "file": "core/crypto/crypto_core.h",
                "operations": [{"type": "insert_after", "description": "Add AriaContext class declaration",
                    "find": "};",
                    "replace": [
                        "// ARIA-256 (via Mbed TLS)", "class AriaContext {", "private:",
                        "    void *ctx = nullptr;", "", "public:", "    AriaContext();", "    ~AriaContext();", "",
                        "    Error set_encode_key(const uint8_t *p_key, size_t p_bits);",
                        "    Error set_decode_key(const uint8_t *p_key, size_t p_bits);",
                        "    Error encrypt_ecb(const uint8_t p_src[16], uint8_t r_dst[16]);",
                        "    Error decrypt_ecb(const uint8_t p_src[16], uint8_t r_dst[16]);",
                        "    Error encrypt_cbc(size_t p_length, uint8_t r_iv[16], const uint8_t *p_src, uint8_t *r_dst);",
                        "    Error decrypt_cbc(size_t p_length, uint8_t r_iv[16], const uint8_t *p_src, uint8_t *r_dst);",
                        "    Error encrypt_cfb(size_t p_length, uint8_t p_iv[16], const uint8_t *p_src, uint8_t *r_dst);",
                        "    Error decrypt_cfb(size_t p_length, uint8_t p_iv[16], const uint8_t *p_src, uint8_t *r_dst);",
                        "};", ""
                    ]}]
            },
            {
                "file": "core/crypto/crypto_core.cpp",
                "operations": [
                    {"type": "insert_after", "description": "Add ARIA include",
                        "find": "#include <mbedtls/aes.h>", "replace": "#include <mbedtls/aria.h>"},
                    {"type": "append", "description": "Add ARIA implementation",
                        "replace": [
                            "// ----------------------------------------------------------------",
                            "// ARIA-256 implementation", "",
                            "CryptoCore::AriaContext::AriaContext() {",
                            "    ctx = memalloc(sizeof(mbedtls_aria_context));",
                            "    mbedtls_aria_init((mbedtls_aria_context *)ctx);", "}", "",
                            "CryptoCore::AriaContext::~AriaContext() {",
                            "    mbedtls_aria_free((mbedtls_aria_context *)ctx);",
                            "    memfree(ctx);", "}", "",
                            "Error CryptoCore::AriaContext::set_encode_key(const uint8_t *p_key, size_t p_bits) {",
                            "    int ret = mbedtls_aria_setkey_enc((mbedtls_aria_context *)ctx, p_key, p_bits);",
                            "    return ret ? FAILED : OK;", "}", "",
                            "Error CryptoCore::AriaContext::set_decode_key(const uint8_t *p_key, size_t p_bits) {",
                            "    int ret = mbedtls_aria_setkey_dec((mbedtls_aria_context *)ctx, p_key, p_bits);",
                            "    return ret ? FAILED : OK;", "}", "",
                            "Error CryptoCore::AriaContext::encrypt_ecb(const uint8_t p_src[16], uint8_t r_dst[16]) {",
                            "    int ret = mbedtls_aria_crypt_ecb((mbedtls_aria_context *)ctx, p_src, r_dst);",
                            "    return ret ? FAILED : OK;", "}", "",
                            "Error CryptoCore::AriaContext::decrypt_ecb(const uint8_t p_src[16], uint8_t r_dst[16]) {",
                            "    int ret = mbedtls_aria_crypt_ecb((mbedtls_aria_context *)ctx, p_src, r_dst);",
                            "    return ret ? FAILED : OK;", "}", "",
                            "Error CryptoCore::AriaContext::encrypt_cbc(size_t p_length, uint8_t r_iv[16], const uint8_t *p_src, uint8_t *r_dst) {",
                            "    int ret = mbedtls_aria_crypt_cbc((mbedtls_aria_context *)ctx, MBEDTLS_ARIA_ENCRYPT, p_length, r_iv, p_src, r_dst);",
                            "    return ret ? FAILED : OK;", "}", "",
                            "Error CryptoCore::AriaContext::decrypt_cbc(size_t p_length, uint8_t r_iv[16], const uint8_t *p_src, uint8_t *r_dst) {",
                            "    int ret = mbedtls_aria_crypt_cbc((mbedtls_aria_context *)ctx, MBEDTLS_ARIA_DECRYPT, p_length, r_iv, p_src, r_dst);",
                            "    return ret ? FAILED : OK;", "}", "",
                            "Error CryptoCore::AriaContext::encrypt_cfb(size_t p_length, uint8_t p_iv[16], const uint8_t *p_src, uint8_t *r_dst) {",
                            "    size_t iv_off = 0;",
                            "    int ret = mbedtls_aria_crypt_cfb128((mbedtls_aria_context *)ctx, MBEDTLS_ARIA_ENCRYPT, p_length, &iv_off, p_iv, p_src, r_dst);",
                            "    return ret ? FAILED : OK;", "}", "",
                            "Error CryptoCore::AriaContext::decrypt_cfb(size_t p_length, uint8_t p_iv[16], const uint8_t *p_src, uint8_t *r_dst) {",
                            "    size_t iv_off = 0;",
                            "    int ret = mbedtls_aria_crypt_cfb128((mbedtls_aria_context *)ctx, MBEDTLS_ARIA_DECRYPT, p_length, &iv_off, p_iv, p_src, r_dst);",
                            "    return ret ? FAILED : OK;", "}"
                        ]}
                ]
            },
        ]

    log = save_log(f"\n=== Applying Enhanced {algorithm_name} Encryption For Godot ===")
    print(f"\n\n{LogColors.HEADER}{log}{LogColors.ENDC}")
    log_print(MsgType.INFO, f"Generated PACK_HEADER_MAGIC      : {baseHeader}  // Tag: \"{baseTag}\"")
    log_print(MsgType.INFO, f"Generated ENCRYPTED_HEADER_MAGIC : {encHeader}  // Tag: \"{encTag}\"")
    log_print(MsgType.INFO, f"Security Token: {token_hex}")

    backup_path = apply_modifications(godot_root, MODIFICATIONS, ni)

    write_state_file(state_file_path, algorithm_name, detected_version_str, token_hex)
    log_print(MsgType.SUCCESS, f"State file written: {state_file_path}")
    save_log(f"State file written at {state_file_path}")

    print(f"\n{LogColors.HEADER}=== Operation Complete ==={LogColors.ENDC}")
    print(f"\n{LogColors.HEADER}{'─' * 54}{LogColors.ENDC}")
    print(f"{LogColors.BOLD}  SAVE THESE VALUES — YOU CANNOT RECOVER THEM LATER{LogColors.ENDC}")
    print(f"{LogColors.HEADER}{'─' * 54}{LogColors.ENDC}\n")
    print(f"{LogColors.BOLD}  Security Token:{LogColors.ENDC}  {token_hex}")
    print(f"{LogColors.BOLD}  Encryption Key:{LogColors.ENDC}  {encKey}")
    print(f"\n{LogColors.HEADER}{'─' * 54}{LogColors.ENDC}\n")
    log_print(MsgType.WARNING,
        "The Security Token is embedded in the compiled engine binary. "
        f"Enter the {LogColors.FAIL}Encryption Key{LogColors.WARNING} in Godot's export preset — "
        "not the Security Token."
    )
    log_print(MsgType.WARNING, "Store both values in secure storage — they are required to re-export or rebuild.")
    log_print(MsgType.SUCCESS, f"{LogColors.OKGREEN} Build is now Cryptographically Unique{LogColors.ENDC}")
    save_log(f"\nSecurity Token: {token_hex}\nEncryption Key: {encKey}")
    save_log("\n[WARN] - Use Encryption Key during export. Store both values securely.")
    if backup_path:
        save_log(f"\n[INFO] - Old Key Backup Created at: {backup_path}")
        log_print(MsgType.INFO, f"{LogColors.OKGREEN} Old Key Backup: {LogColors.ENDC}{LogColors.BOLD}{backup_path}{LogColors.ENDC}\n")

# ══════════════════════════════════════════════════════════════════════════════
# MODE 2 — Refresh security token
# ══════════════════════════════════════════════════════════════════════════════
elif menu_choice == "2":

    if not already_applied:
        print(f"\n{LogColors.FAIL}Error: Godot Secure has not been applied to this source tree yet.{LogColors.ENDC}")
        print("Run option [1] first.")
        pause_exit(ni)
        sys.exit(1)

    prev_algorithm = state.get("algorithm", "AES-256")
    prev_version   = state.get("godot_version", "unknown")
    prev_token     = state.get("token_hex", "unknown")
    prev_applied   = state.get("applied_at", "unknown")

    # Guard: --algorithm is an apply-only flag. If the user passes it during a
    # refresh and it doesn't match the stored algorithm, they are probably
    # confused about which build they are operating on. Fail fast rather than
    # silently ignoring the flag and leaving them with an inconsistent state.
    _ALGO_NAME_MAP = {"aes": "AES-256", "camellia": "Camellia-256", "aria": "ARIA-256"}
    if args.algorithm:
        requested_name = _ALGO_NAME_MAP.get(args.algorithm, args.algorithm)
        if requested_name != prev_algorithm:
            print(f"\n{LogColors.FAIL}Error: --algorithm {args.algorithm!r} does not match the stored algorithm.{LogColors.ENDC}")
            print(f"  This source tree was patched with {LogColors.BOLD}{prev_algorithm}{LogColors.ENDC}.")
            print(f"  Refresh only rotates the security token — it does not change the")
            print(f"  encryption algorithm. Passing a mismatched --algorithm flag would")
            print(f"  leave the source tree in an inconsistent state.")
            print(f"\n  To switch to {requested_name}:")
            print(f"    1. Run option [3] to restore the original Godot source.")
            print(f"    2. Re-run option [1] and choose {requested_name}.")
            save_log(f"[ERROR] Refresh algorithm mismatch: state={prev_algorithm}, --algorithm={args.algorithm}. Aborting.")
            pause_exit(ni)
            sys.exit(1)
        log_print(MsgType.WARNING,
            f"--algorithm {args.algorithm!r} matches the stored algorithm and is ignored during refresh.")

    _REFRESH_LOG_SUFFIX = {"AES-256": "Refresh-AES", "Camellia-256": "Refresh-Camellia", "ARIA-256": "Refresh-ARIA"}
    init_log(_REFRESH_LOG_SUFFIX.get(prev_algorithm, "Refresh-AES"))
    save_log(f"Refresh mode. Previous: algorithm={prev_algorithm}, version={prev_version}, applied_at={prev_applied}")
    save_log(f"Mode: refresh | non-interactive: {ni}")

    print(f"\n  Previous run details:")
    print(f"    Algorithm   : {prev_algorithm}")
    print(f"    Godot ver.  : {prev_version}")
    print(f"    Last applied: {prev_applied}")
    print(f"    Prev token  : {prev_token}")

    encKey = resolve_encryption_key(godot_root, args)

    # New token
    security_token = generate_random_token()
    token_hex      = binascii.hexlify(security_token).decode('utf-8')

    if args.token:
        token_hex      = args.token.lower()
        security_token = bytes.fromhex(token_hex)
        save_log(f"Security token provided via --token argument: {token_hex}")
    else:
        ans = prompt(
            f"\n\n ℹ  {LogColors.OKBLUE}Use Custom Token {LogColors.ENDC}{LogColors.FAIL}(y/n)?{LogColors.ENDC}: ",
            "n", ni
        ).lower()
        save_log(f"\n[INFO] - Use Custom Token (y/n)?: {ans}")
        if ans in ('y', 'yes'):
            token_hex      = str(input("    Enter Custom Security Token: ")).lower()
            security_token = bytes.fromhex(token_hex)
            save_log(f"    Enter Custom Security Token: {token_hex}")

    token_c_array = ', '.join([f'0x{b:02X}' for b in security_token])

    log_print(MsgType.INFO, f"Refreshing security_token.h with new token: {token_hex}")
    try:
        path = write_security_token_header(godot_root, token_hex, token_c_array)
        log_print(MsgType.SUCCESS, f"security_token.h refreshed: {path}")
        save_log(f"\nNew Security Token: {token_hex}")
    except Exception as e:
        log_print(MsgType.ERROR, f"Failed to refresh security_token.h: {e}")
        pause_exit(ni)
        sys.exit(1)

    write_state_file(state_file_path, prev_algorithm, prev_version, token_hex)
    log_print(MsgType.SUCCESS, f"State file updated: {state_file_path}")
    save_log(f"State file updated at {state_file_path}")

    print(f"\n{LogColors.HEADER}=== Token Refresh Complete ==={LogColors.ENDC}")
    print(f"\n{LogColors.HEADER}{'─' * 54}{LogColors.ENDC}")
    print(f"{LogColors.BOLD}  SAVE THESE VALUES — YOU CANNOT RECOVER THEM LATER{LogColors.ENDC}")
    print(f"{LogColors.HEADER}{'─' * 54}{LogColors.ENDC}\n")
    print(f"{LogColors.BOLD}  New Security Token:{LogColors.ENDC}  {token_hex}")
    print(f"{LogColors.BOLD}  Encryption Key:    {LogColors.ENDC}  {encKey}")
    print(f"\n{LogColors.HEADER}{'─' * 54}{LogColors.ENDC}\n")
    log_print(MsgType.WARNING, "Rebuild Godot and re-export your project with the Encryption Key to apply the new token.")
    log_print(MsgType.WARNING, "Store both values in secure storage — they are required to re-export or rebuild.")
    save_log(f"\nNew Security Token: {token_hex}\nEncryption Key: {encKey}")
    save_log("\n[WARN] - Rebuild Godot and re-export with the Encryption Key to apply the new token.")

# ══════════════════════════════════════════════════════════════════════════════
# MODE 3 — Restore original Godot source
# ══════════════════════════════════════════════════════════════════════════════
elif menu_choice == "3":

    if not already_applied:
        print(f"\n{LogColors.FAIL}Error: Godot Secure has not been applied to this source tree yet.{LogColors.ENDC}")
        print("Nothing to restore.")
        pause_exit(ni)
        sys.exit(1)

    prev_algorithm = state.get("algorithm", "AES-256")
    prev_applied   = state.get("applied_at", "unknown")

    init_log("Restore")
    save_log(f"Restore mode. Previous: algorithm={prev_algorithm}, applied_at={prev_applied}")
    save_log(f"Mode: restore | non-interactive: {ni}")

    print(f"\n  This will restore original Godot source files from .backup copies")
    print(f"  and remove the generated security_token.h.")
    print(f"  Previous application: {prev_algorithm} on {prev_applied}\n")

    confirm = prompt(
        f" ⚠   {LogColors.WARNING}Restore original Godot source {LogColors.ENDC}{LogColors.FAIL}(y/n)?{LogColors.ENDC}: ",
        "y", ni
    ).lower()
    save_log(f"Restore original Godot source (y/n)?: {confirm}")
    if confirm not in ('y', 'yes'):
        print(save_log("Closing Setup..."))
        pause_exit(ni)
        sys.exit(1)

    ok = restore_backups(godot_root, state_file_path)

    print(f"\n{LogColors.HEADER}=== Restore {'Complete' if ok else 'Finished With Warnings'} ==={LogColors.ENDC}\n")
    if ok:
        log_print(MsgType.SUCCESS, "All files restored. Godot source is back to its original state.")
    else:
        log_print(MsgType.WARNING, "Some files could not be restored. Check the log for details.")

# ── Unknown choice ─────────────────────────────────────────────────────────────
else:
    print(f"\n{LogColors.FAIL}Invalid choice. Exiting.{LogColors.ENDC}")
    pause_exit(ni)
    sys.exit(1)

# ── Done ───────────────────────────────────────────────────────────────────────
pause_exit(ni)
sys.exit(0)
