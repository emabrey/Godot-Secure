import os
import sys
import json
import random
import string
import binascii
import secrets
import datetime

# ── Cosmetics ──────────────────────────────────────────────────────────────────

class LogColors:
    HEADER    = '\033[95m'
    OKBLUE    = '\033[94m'
    OKGREEN   = '\033[92m'
    WARNING   = '\033[93m'
    FAIL      = '\033[91m'
    ENDC      = '\033[0m'
    BOLD      = '\033[1m'
    UNDERLINE = '\033[4m'

# ── Generation helpers ─────────────────────────────────────────────────────────

def generate_random_tag(length=4):
    return ''.join(random.choices(string.ascii_uppercase, k=length))

def generate_random_token(length=32):
    return bytes([random.randint(0, 255) for _ in range(length)])

def hex_to_bytes(hex_string: str) -> bytes:
    return bytes.fromhex(hex_string)

def generate_magic_header(tag: str, endian='little') -> str:
    if len(tag) != 4:
        raise ValueError("Tag must be exactly 4 characters.")
    if endian == 'little':
        tag = tag[::-1]
    return "0x" + ''.join(f"{ord(c):02X}" for c in tag)

def build_random_key_derivation():
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

    def rotation():
        shift = secrets.randbelow(7) + 1
        return shift, 8 - shift

    def rand_const():
        return secrets.randbelow(255) + 1

    layers = secrets.randbelow(5) + 2
    a = secrets.choice(operands)
    b = operands[1] if a == operands[0] else operands[0]
    shift, rshift = rotation()
    expression = secrets.choice(base_ops).format(a=a, b=b, shift=shift, rshift=rshift, const=rand_const())

    for _ in range(layers - 1):
        shift, rshift = rotation()
        value = secrets.choice(operands)
        if value == expression:
            value = secrets.choice(operands)
        expression = secrets.choice(chain_ops).format(
            expr=expression, value=value, shift=shift, rshift=rshift, const=rand_const()
        )

    return f"token_key.write[i] = (uint8_t)({expression});"

# ── Logging ────────────────────────────────────────────────────────────────────

logFileName = None  # set before first save_log call

def save_log(message):
    if logFileName and not str(message).find("\033[") > 0:
        with open(logFileName, "a", encoding="utf-8") as lf:
            lf.write(f"{message}\n")
    return message

def print_success(message):
    save_log(f"      [✓] {message}")
    print(f"{LogColors.OKGREEN}      ✓{LogColors.ENDC} {message}")

def print_error(message):
    save_log(f"      [✗] {message}\n")
    print(f"{LogColors.FAIL}      ✗{LogColors.ENDC} {message}")

def print_info(message):
    save_log(f"\n[INFO] -   {message}")
    print(f"\n{LogColors.OKBLUE} ℹ {LogColors.ENDC} {message}")

def print_operation(message):
    save_log(f"   [=>] {message}")
    print(f"{LogColors.HEADER}   =>{LogColors.ENDC} {message}")

def print_warning(message):
    save_log(f"\n[WARN] -   {message}")
    print(f"\n{LogColors.WARNING} ⚠ {LogColors.ENDC} {message}")

def init_log(suffix):
    global logFileName
    logFileName = f"godot_secure_{suffix}_{current_dt}.log"
    with open(logFileName, "w", encoding="utf-8") as lf:
        lf.write(f"Created On - {current_dt}\nGodot-Secure log — SAVE IT.\n\n")

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

# ── File lists (mirrors restore_backup.py) ────────────────────────────────────

# All files that may have .backup copies after a Godot Secure run.
# security_token.h is created (not modified), so it is deleted on restore rather
# than swapped from a backup.
RESTORE_FILES = [
    "version.py",
    "editor/export/project_export.cpp",
    "core/io/file_access_pack.h",
    "core/io/file_access_encrypted.h",
    "core/io/file_access_encrypted.cpp",
    # Camellia-only — silently skipped when no backup exists
    "core/crypto/crypto_core.h",
    "core/crypto/crypto_core.cpp",
]

CAMELLIA_ONLY_FILES = {
    "core/crypto/crypto_core.h",
    "core/crypto/crypto_core.cpp",
}

CREATED_FILES = [
    "core/crypto/security_token.h",
]

# ── Restore ────────────────────────────────────────────────────────────────────

def restore_backups(root_dir, state_path):
    print_info("Restoring original Godot source files from backups...")

    all_ok = True

    for rel_path in RESTORE_FILES:
        file_path   = os.path.join(root_dir, rel_path)
        backup_path = file_path + ".backup"

        if not os.path.exists(backup_path):
            if rel_path not in CAMELLIA_ONLY_FILES:
                print_warning(f"Backup not found, skipping: {rel_path}")
                all_ok = False
            continue

        try:
            if os.path.exists(file_path):
                os.replace(backup_path, file_path)
                print_success(f"Restored: {rel_path}")
            else:
                os.rename(backup_path, file_path)
                print_success(f"Restored (from backup only): {rel_path}")
        except Exception as e:
            print_error(f"Failed to restore {rel_path}: {e}")
            all_ok = False

    for rel_path in CREATED_FILES:
        file_path = os.path.join(root_dir, rel_path)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print_success(f"Removed generated file: {rel_path}")
            except Exception as e:
                print_error(f"Failed to remove {rel_path}: {e}")
                all_ok = False

    if os.path.exists(state_path):
        try:
            os.remove(state_path)
            print_success(f"Removed state file: {STATE_FILE_NAME}")
        except Exception as e:
            print_error(f"Failed to remove state file: {e}")

    return all_ok

# ── apply_modifications engine ─────────────────────────────────────────────────

def apply_modifications(root_dir, MODIFICATIONS):
    quiz_override      = False
    override_backup    = True
    not_modify_on_error = True
    track_backup_file  = set()
    backup_path_ref    = [None]

    step = 0
    for mod in MODIFICATIONS:
        file_path = os.path.join(root_dir, mod["file"])
        step += 1

        # ── create_file ops ──────────────────────────────────────────────────
        if any(op.get("type") == "create_file" for op in mod["operations"]):
            print_info(f"Step {step} (Creating: {file_path}):")
            for op in mod["operations"]:
                if op["type"] != "create_file":
                    continue
                print_operation(f"Operation: {op['description']}")
                os.makedirs(os.path.dirname(file_path), exist_ok=True)

                if os.path.exists(file_path):
                    print_warning(f"File already exists: {file_path}")
                    choice = input("   Do you want to overwrite it? (y/n): ").strip().lower()
                    if not (choice == 'y' or choice == 'yes'):
                        print_operation("Skipping file creation.")
                        continue
                    bk = file_path + ".backup"
                    try:
                        os.replace(file_path, bk)
                        backup_path_ref[0] = bk
                        print_operation(f"Backup created at: {bk}")
                    except Exception as e:
                        print_error(f"Failed to create backup: {e}")
                        print_operation("Skipping file creation.")
                        continue

                try:
                    content = op["content"]
                    if isinstance(content, list):
                        content = "\n".join(content)
                    with open(file_path, "w") as f:
                        f.write(content)
                    print_success(f"File created: {file_path}")
                except Exception as e:
                    print_error(f"Failed to write file: {e}")
            continue

        # ── modification ops ─────────────────────────────────────────────────
        if not os.path.exists(file_path):
            print_error(f"File not found: {file_path}")
            continue

        local_backup = file_path + ".backup"
        if local_backup not in track_backup_file:
            track_backup_file.add(local_backup)
            create_backup = True

            if os.path.exists(local_backup):
                if not quiz_override:
                    quiz_override = True
                    print_warning("Backup of origin file already exists")
                    ans = input("   Do you want to overwrite it? (y/n): ").strip().lower()
                    override_backup = (ans == 'y' or ans == 'yes')
                create_backup = override_backup

            if create_backup:
                try:
                    with open(file_path, 'r') as f0:
                        content = f0.read()
                    with open(local_backup, "w") as f1:
                        f1.write(content)
                    print_success(f"Backup created: {local_backup}")
                except Exception as e:
                    print_error(f"Failed to create backup: {e}")
                    if not_modify_on_error:
                        print_operation("Skipping file modification.")
                        continue

        print_info(f"Step {step} (Processing: {file_path}):")

        with open(file_path, "r") as f:
            lines = f.readlines()

        modified = False
        for op in mod["operations"]:
            op_type     = op["type"]
            description = op.get("description", "")
            print_operation(f"Operation: {description}. (Type: {op_type})")

            if op_type == "replace_line":
                find    = op["find"].strip()
                replace = op["replace"] + "\n"
                found   = False
                for i in range(len(lines)):
                    if lines[i].strip() == find:
                        lines[i] = replace
                        print_success(f"Line replaced at line {i+1}")
                        found = modified = True
                        break
                if not found:
                    print_error(f"Target line not found: {find}")

            elif op_type == "replace_block":
                find_lines    = [ln.strip() for ln in op["find"]]
                replace_lines = [ln + "\n" for ln in op["replace"]]
                block_found   = False
                for i in range(len(lines) - len(find_lines) + 1):
                    if all(lines[i + j].strip() == find_lines[j] for j in range(len(find_lines))):
                        lines[i:i + len(find_lines)] = replace_lines
                        print_success(f"Block replaced starting at line {i+1}")
                        modified = block_found = True
                        break
                if not block_found:
                    print_error("Target block not found")

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
                            print_success(f"Inserted after line {i+1}")
                            modified = True
                        else:
                            print_success("Content already present, skipping insertion")
                        found = True
                        break
                if not found:
                    print_error(f"Insertion point not found: {find}")

            elif op_type == "append":
                replace_lines   = [ln + "\n" for ln in op["replace"]]
                already_present = (
                    len(lines) >= len(replace_lines)
                    and all(lines[-len(replace_lines) + i] == replace_lines[i] for i in range(len(replace_lines)))
                )
                if not already_present:
                    lines.extend(replace_lines)
                    print_success("Appended to end of file")
                    modified = True
                else:
                    print_success("Content already present at end, skipping append")

        if modified:
            with open(file_path, "w") as f:
                f.writelines(lines)
            print_success(f"File updated: {file_path}")
        else:
            print_warning(f"No changes made to file (Step {step})")

    return backup_path_ref[0]

# ── Token header writer (shared by apply and refresh) ─────────────────────────

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

# ── Shared token prompts ───────────────────────────────────────────────────────

def prompt_token_options(default_token_hex, default_security_token):
    """Ask the user about custom token and advanced key derivation.
    Returns (token_hex, security_token, token_c_array, key_derivation_algorithm)."""
    token_hex          = default_token_hex
    security_token     = default_security_token
    key_deriv          = "token_key.write[i] = key_ptr[i] ^ Security::TOKEN[i];"

    confirm = input(f"\n\n ℹ  {LogColors.OKBLUE}Use Custom Token {LogColors.ENDC}{LogColors.FAIL}(y/n)?{LogColors.ENDC}: ").strip().lower()
    save_log(f"\n[INFO] - Use Custom Token (y/n)?: {confirm}")
    if confirm in ('y', 'yes'):
        token_hex      = str(input("    Enter Custom Security Token: ")).lower()
        security_token = hex_to_bytes(token_hex)
        save_log(f"    Enter Custom Security Token: {token_hex}")

    token_c_array = ', '.join([f'0x{b:02X}' for b in security_token])

    confirm = input(f"\n\n ℹ  {LogColors.OKBLUE}Use Advanced Key Derivation {LogColors.ENDC}{LogColors.FAIL}(y/n)?{LogColors.ENDC}: ").strip().lower()
    save_log(f"\n[INFO] - Use Advanced Key Derivation (y/n)?: {confirm}")
    if confirm in ('y', 'yes'):
        key_deriv = build_random_key_derivation()
        save_log(f"    Generated Advanced Key Derivation Algorithm:\n            {key_deriv}")

    return token_hex, security_token, token_c_array, key_deriv

# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

current_dt = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f")

# ── Resolve Godot source root ──────────────────────────────────────────────────
if len(sys.argv) == 1:
    godot_root = os.getcwd()
    print("\nNo directory specified. Using current directory as Godot Source Root.")
elif len(sys.argv) == 2:
    godot_root = sys.argv[1]
else:
    print("\nUsage: python godot_secure.py <godot_source_root>")
    try:
        input("\nPress Enter key to exit...")
    except EOFError:
        pass
    sys.exit(1)

# ── Validate Godot source ──────────────────────────────────────────────────────
core_dir       = os.path.join(godot_root, "core")
sconstruct_file = os.path.join(godot_root, "SConstruct")

if not (os.path.isdir(core_dir) and os.path.isfile(sconstruct_file)):
    print(f"{LogColors.FAIL}Error: No valid Godot Source Detected in the Specified Directory.{LogColors.ENDC}")
    try:
        input("\nPress Enter key to exit...")
    except EOFError:
        pass
    sys.exit(1)

# ── Detect Godot version ───────────────────────────────────────────────────────
godot_minor        = 0
detected_version_str = "unknown"
version_py_path    = os.path.join(godot_root, "version.py")

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

# .ptr() on 4.6+, .ptrw() on older versions
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

# ── Main menu ──────────────────────────────────────────────────────────────────
print(f"\n{LogColors.HEADER}{'═' * 54}")
print(f"  Godot Secure")
print(f"{'═' * 54}{LogColors.ENDC}")
print(f"\n  Source root      : {godot_root}")
print(f"  Godot version    : {detected_version_str}")
if already_applied:
    print(f"  Status           : {LogColors.WARNING}Godot Secure already applied{LogColors.ENDC}")
    print(f"  Algorithm        : {state.get('algorithm', '?')}")
    print(f"  Last applied     : {state.get('applied_at', '?')}")
else:
    print(f"  Status           : {LogColors.OKGREEN}Clean Godot source{LogColors.ENDC}")

print(f"\n  What would you like to do?\n")

opt1_note = f" {LogColors.WARNING}(already applied — will re-apply){LogColors.ENDC}" if already_applied else ""
opt2_note = f" {LogColors.FAIL}(requires prior application){LogColors.ENDC}"         if not already_applied else ""
opt3_note = f" {LogColors.FAIL}(requires prior application){LogColors.ENDC}"         if not already_applied else ""

print(f"    [1] Apply Godot Secure to this source tree{opt1_note}")
print(f"    [2] Refresh security token{opt2_note}")
print(f"    [3] Restore original Godot source{opt3_note}")
print()

menu_choice = input(f"  {LogColors.FAIL}Enter choice [1/2/3]:{LogColors.ENDC} ").strip()

# ══════════════════════════════════════════════════════════════════════════════
# MODE 1 — Apply Godot Secure (full first-run flow)
# ══════════════════════════════════════════════════════════════════════════════
if menu_choice == "1":

    # ── Algorithm selection ────────────────────────────────────────────────────
    print(f"\n\n ℹ  {LogColors.OKBLUE}Choose Encryption Algorithm:{LogColors.ENDC}")
    print(f"     [1] AES-256  (default)")
    print(f"     [2] Camellia-256")
    algo_choice   = input(f"     {LogColors.FAIL}Enter choice [1/2]:{LogColors.ENDC} ").strip()
    use_aes       = algo_choice != "2"
    algorithm_name = "AES-256" if use_aes else "Camellia-256"
    ctx_class      = "CryptoCore::AESContext" if use_aes else "CryptoCore::CamelliaContext"
    export_title   = f"Export With Godot Secure ({algorithm_name})"

    init_log("AES" if use_aes else "Camellia")
    save_log(f"\nUsing Godot Source Root: {godot_root}")
    save_log(f"Detected Godot Version : {detected_version_str} (minor={godot_minor}, compress_ptr={compress_ptr})")
    save_log(f"Algorithm: {algorithm_name}")
    save_log(f"Menu choice: [1] Apply")
    save_log(f"Choose Encryption Algorithm [1/2]?: {algo_choice} -> {algorithm_name}")

    try:
        encKey = os.environ["SCRIPT_AES256_ENCRYPTION_KEY"]
    except Exception:
        encKey = "Can't Fetch Your Environment Variable \"SCRIPT_AES256_ENCRYPTION_KEY\""

    # ── Generate random initial values ────────────────────────────────────────
    baseTag        = generate_random_tag()
    encTag         = generate_random_tag()
    security_token = generate_random_token()
    token_hex      = binascii.hexlify(security_token).decode('utf-8')
    baseHeader     = generate_magic_header(baseTag)
    encHeader      = generate_magic_header(encTag)

    # ── Custom headers ─────────────────────────────────────────────────────────
    confirm = input(f"\n\n ℹ  {LogColors.OKBLUE}Use Custom Headers {LogColors.ENDC}{LogColors.FAIL}(y/n)?{LogColors.ENDC}: ").strip().lower()
    save_log(f"\n[INFO] - Use Custom Headers (y/n)?: {confirm}")
    if confirm in ('y', 'yes'):
        baseTag    = input("    Enter Custom Magic Header (e.g. GDPC): ").upper()
        baseHeader = generate_magic_header(baseTag)
        encTag     = input("    Enter Custom Encrypted Magic Header (e.g. GDEC): ").upper()
        encHeader  = generate_magic_header(encTag)
        save_log(f"    Enter Custom Magic Header: {baseTag}\n    Enter Custom Encrypted Magic Header: {encTag}")

    # ── Token + key derivation ─────────────────────────────────────────────────
    token_hex, security_token, token_c_array, key_derivation_algorithm = prompt_token_options(token_hex, security_token)

    # ── Build MODIFICATIONS ────────────────────────────────────────────────────
    MODIFICATIONS = [
        {
            "file": "version.py",
            "operations": [{
                "type": "replace_line",
                "description": "Modify Godot title to add Godot Secure",
                "find":    "name = \"Godot Engine\"",
                "replace": "name = \"Godot Engine (With Godot Secure)\""
            }]
        },
        {
            "file": "editor/export/project_export.cpp",
            "operations": [{
                "type": "replace_line",
                "description": "Modify Godot export popup title to add Godot Secure",
                "find":    "set_title(TTR(\"Export\"));",
                "replace": f"set_title(TTR(\"{export_title}\"));"
            }]
        },
        {
            "file": "core/crypto/security_token.h",
            "operations": [{
                "type": "create_file",
                "description": "Create security token header",
                "content": [
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
                    "#endif // SECURITY_TOKEN_H"
                ]
            }]
        },
        {
            "file": "core/io/file_access_pack.h",
            "operations": [{
                "type": "replace_line",
                "description": "Modify Packed File Header Magic",
                "find":    "#define PACK_HEADER_MAGIC 0x43504447",
                "replace": f"#define PACK_HEADER_MAGIC {baseHeader}  // Generated Tag: \"{baseTag}\""
            }]
        },
        {
            "file": "core/io/file_access_encrypted.h",
            "operations": [{
                "type": "replace_line",
                "description": "Modify Encrypted File Header Magic",
                "find":    "#define ENCRYPTED_HEADER_MAGIC 0x43454447",
                "replace": f"#define ENCRYPTED_HEADER_MAGIC {encHeader}  // Generated Tag: \"{encTag}\""
            }]
        },
        {
            "file": "core/io/file_access_encrypted.cpp",
            "operations": [
                {
                    "type": "insert_after",
                    "description": "Include security token header",
                    "find":    "#include \"file_access_encrypted.h\"",
                    "replace": "#include \"core/crypto/security_token.h\""
                },
                {
                    "type": "replace_block",
                    "description": "Add token obfuscation for decryption",
                    "find": [
                        "{",
                        "CryptoCore::AESContext ctx;",
                        "",
                        "ctx.set_encode_key(key.ptrw(), 256); // Due to the nature of CFB, same key schedule is used for both encryption and decryption!",
                        "ctx.decrypt_cfb(ds, iv.ptrw(), data.ptrw(), data.ptrw());",
                        "}"
                    ],
                    "replace": [
                        "{",
                        f"{ctx_class} ctx;",
                        "",
                        "    // Apply security token to key",
                        "    Vector<uint8_t> token_key;",
                        "    token_key.resize(32);",
                        "    const uint8_t *key_ptr = key.ptr();",
                        "    for (int i = 0; i < 32; i++) {",
                        f"        {key_derivation_algorithm}",
                        "    }",
                        "",
                        "    ctx.set_encode_key(token_key.ptrw(), 256); // Due to the nature of CFB, same key schedule is used for both encryption and decryption!",
                        "    ctx.decrypt_cfb(ds, iv.ptrw(), data.ptrw(), data.ptrw());",
                        "}"
                    ]
                }
            ]
        },
        {
            "file": "core/io/file_access_encrypted.cpp",
            "operations": [{
                "type": "replace_block",
                "description": "Add token obfuscation for encryption",
                "find": [
                    "CryptoCore::AESContext ctx;",
                    "ctx.set_encode_key(key.ptrw(), 256);",
                    "",
                    "if (use_magic) {",
                    "    file->store_32(ENCRYPTED_HEADER_MAGIC);",
                    "}",
                    "",
                    "file->store_buffer(hash, 16);",
                    "file->store_64(data.size());",
                    "file->store_buffer(iv.ptr(), 16);",
                    "",
                    f"ctx.encrypt_cfb(len, iv.ptrw(), {compress_ptr}, {compress_ptr});"
                ],
                "replace": [
                    f"{ctx_class} ctx;",
                    "",
                    "    // Apply security token to key",
                    "    Vector<uint8_t> token_key;",
                    "    token_key.resize(32);",
                    "    const uint8_t *key_ptr = key.ptr();",
                    "    for (int i = 0; i < 32; i++) {",
                    f"        {key_derivation_algorithm}",
                    "    }",
                    "",
                    "    ctx.set_encode_key(token_key.ptrw(), 256);",
                    "",
                    "if (use_magic) {",
                    "file->store_32(ENCRYPTED_HEADER_MAGIC);",
                    "}",
                    "",
                    "file->store_buffer(hash, 16);",
                    "file->store_64(data.size());",
                    "file->store_buffer(iv.ptr(), 16);",
                    "",
                    f"ctx.encrypt_cfb(len, iv.ptrw(), {compress_ptr}, {compress_ptr});"
                ]
            }]
        },
    ]

    if not use_aes:
        MODIFICATIONS += [
            {
                "file": "core/crypto/crypto_core.h",
                "operations": [{
                    "type": "insert_after",
                    "description": "Add CamelliaContext class declaration",
                    "find": "};",
                    "replace": [
                        "// Camellia-256 (via Mbed TLS)",
                        "class CamelliaContext {",
                        "private:",
                        "    void *ctx = nullptr;",
                        "",
                        "public:",
                        "    CamelliaContext();",
                        "    ~CamelliaContext();",
                        "",
                        "    Error set_encode_key(const uint8_t *p_key, size_t p_bits);",
                        "    Error set_decode_key(const uint8_t *p_key, size_t p_bits);",
                        "    Error encrypt_ecb(const uint8_t p_src[16], uint8_t r_dst[16]);",
                        "    Error decrypt_ecb(const uint8_t p_src[16], uint8_t r_dst[16]);",
                        "    Error encrypt_cbc(size_t p_length, uint8_t r_iv[16], const uint8_t *p_src, uint8_t *r_dst);",
                        "    Error decrypt_cbc(size_t p_length, uint8_t r_iv[16], const uint8_t *p_src, uint8_t *r_dst);",
                        "    Error encrypt_cfb(size_t p_length, uint8_t p_iv[16], const uint8_t *p_src, uint8_t *r_dst);",
                        "    Error decrypt_cfb(size_t p_length, uint8_t p_iv[16], const uint8_t *p_src, uint8_t *r_dst);",
                        "};",
                        ""
                    ]
                }]
            },
            {
                "file": "core/crypto/crypto_core.cpp",
                "operations": [
                    {
                        "type": "insert_after",
                        "description": "Add Camellia include",
                        "find":    "#include <mbedtls/aes.h>",
                        "replace": "#include <mbedtls/camellia.h>"
                    },
                    {
                        "type": "append",
                        "description": "Add Camellia implementation",
                        "replace": [
                            "// ----------------------------------------------------------------",
                            "// Camellia-256 implementation",
                            "",
                            "CryptoCore::CamelliaContext::CamelliaContext() {",
                            "    ctx = memalloc(sizeof(mbedtls_camellia_context));",
                            "    mbedtls_camellia_init((mbedtls_camellia_context *)ctx);",
                            "}",
                            "",
                            "CryptoCore::CamelliaContext::~CamelliaContext() {",
                            "    mbedtls_camellia_free((mbedtls_camellia_context *)ctx);",
                            "    memfree(ctx);",
                            "}",
                            "",
                            "Error CryptoCore::CamelliaContext::set_encode_key(const uint8_t *p_key, size_t p_bits) {",
                            "    int ret = mbedtls_camellia_setkey_enc((mbedtls_camellia_context *)ctx, p_key, p_bits);",
                            "    return ret ? FAILED : OK;",
                            "}",
                            "",
                            "Error CryptoCore::CamelliaContext::set_decode_key(const uint8_t *p_key, size_t p_bits) {",
                            "    int ret = mbedtls_camellia_setkey_dec((mbedtls_camellia_context *)ctx, p_key, p_bits);",
                            "    return ret ? FAILED : OK;",
                            "}",
                            "",
                            "Error CryptoCore::CamelliaContext::encrypt_ecb(const uint8_t p_src[16], uint8_t r_dst[16]) {",
                            "    int ret = mbedtls_camellia_crypt_ecb((mbedtls_camellia_context *)ctx, MBEDTLS_CAMELLIA_ENCRYPT, p_src, r_dst);",
                            "    return ret ? FAILED : OK;",
                            "}",
                            "",
                            "Error CryptoCore::CamelliaContext::decrypt_ecb(const uint8_t p_src[16], uint8_t r_dst[16]) {",
                            "    int ret = mbedtls_camellia_crypt_ecb((mbedtls_camellia_context *)ctx, MBEDTLS_CAMELLIA_DECRYPT, p_src, r_dst);",
                            "    return ret ? FAILED : OK;",
                            "}",
                            "",
                            "Error CryptoCore::CamelliaContext::encrypt_cbc(size_t p_length, uint8_t r_iv[16], const uint8_t *p_src, uint8_t *r_dst) {",
                            "    int ret = mbedtls_camellia_crypt_cbc((mbedtls_camellia_context *)ctx, MBEDTLS_CAMELLIA_ENCRYPT, p_length, r_iv, p_src, r_dst);",
                            "    return ret ? FAILED : OK;",
                            "}",
                            "",
                            "Error CryptoCore::CamelliaContext::decrypt_cbc(size_t p_length, uint8_t r_iv[16], const uint8_t *p_src, uint8_t *r_dst) {",
                            "    int ret = mbedtls_camellia_crypt_cbc((mbedtls_camellia_context *)ctx, MBEDTLS_CAMELLIA_DECRYPT, p_length, r_iv, p_src, r_dst);",
                            "    return ret ? FAILED : OK;",
                            "}",
                            "",
                            "Error CryptoCore::CamelliaContext::encrypt_cfb(size_t p_length, uint8_t p_iv[16], const uint8_t *p_src, uint8_t *r_dst) {",
                            "    size_t iv_off = 0;",
                            "    int ret = mbedtls_camellia_crypt_cfb128((mbedtls_camellia_context *)ctx, MBEDTLS_CAMELLIA_ENCRYPT, p_length, &iv_off, p_iv, p_src, r_dst);",
                            "    return ret ? FAILED : OK;",
                            "}",
                            "",
                            "Error CryptoCore::CamelliaContext::decrypt_cfb(size_t p_length, uint8_t p_iv[16], const uint8_t *p_src, uint8_t *r_dst) {",
                            "    size_t iv_off = 0;",
                            "    int ret = mbedtls_camellia_crypt_cfb128((mbedtls_camellia_context *)ctx, MBEDTLS_CAMELLIA_DECRYPT, p_length, &iv_off, p_iv, p_src, r_dst);",
                            "    return ret ? FAILED : OK;",
                            "}"
                        ]
                    }
                ]
            },
        ]

    log = save_log(f"\n=== Applying Enhanced {algorithm_name} Encryption For Godot ===")
    print(f"\n\n{LogColors.HEADER}{log}{LogColors.ENDC}")
    print_info(f"Generated PACK_HEADER_MAGIC      : {baseHeader}  // Tag: \"{baseTag}\"")
    print_info(f"Generated ENCRYPTED_HEADER_MAGIC : {encHeader}  // Tag: \"{encTag}\"")
    print_info(f"Security Token: {token_hex}")

    backup_path = apply_modifications(godot_root, MODIFICATIONS)

    write_state_file(state_file_path, algorithm_name, detected_version_str, token_hex)
    print_success(f"State file written: {state_file_path}")
    save_log(f"State file written at {state_file_path}")

    print(f"\n{LogColors.HEADER}=== Operation Complete (View Logs For Info) ==={LogColors.ENDC}\n")
    print(f"{LogColors.BOLD} Security Token:{LogColors.ENDC} {token_hex}\n")
    print(f"{LogColors.WARNING} Encryption Key: {LogColors.FAIL}{encKey}{LogColors.ENDC}")
    print_warning(
        f"{LogColors.WARNING} Security Token and Encryption Key are different. "
        f"Use {LogColors.FAIL}\"Encryption Key\"{LogColors.WARNING} During Export!{LogColors.ENDC}"
    )
    print_success(f"{LogColors.OKGREEN} Build is now Cryptographically Unique{LogColors.ENDC}")
    save_log(f"\nSecurity Token: {token_hex}\nEncryption Key: {encKey}")
    save_log("\n[WARN] - Security Token and Encryption Key are different. Use Encryption Key During Export!")
    if backup_path:
        save_log(f"\n[INFO] - Old Key Backup Created at: {backup_path}")
        print_info(f"{LogColors.OKGREEN} Old Key Backup Created at: {LogColors.ENDC}{LogColors.BOLD}{backup_path}{LogColors.ENDC}\n")

# ══════════════════════════════════════════════════════════════════════════════
# MODE 2 — Refresh security token
# ══════════════════════════════════════════════════════════════════════════════
elif menu_choice == "2":

    if not already_applied:
        print(f"\n{LogColors.FAIL}Error: Godot Secure has not been applied to this source tree yet.{LogColors.ENDC}")
        print("Run option [1] first.")
        try:
            input("\nPress Enter key to exit...")
        except EOFError:
            pass
        sys.exit(1)

    prev_algorithm = state.get("algorithm", "AES-256")
    prev_version   = state.get("godot_version", "unknown")
    prev_token     = state.get("token_hex", "unknown")
    prev_applied   = state.get("applied_at", "unknown")
    use_aes_prev   = prev_algorithm != "Camellia-256"

    init_log("Refresh-AES" if use_aes_prev else "Refresh-Camellia")
    save_log(f"Refresh mode. Previous: algorithm={prev_algorithm}, version={prev_version}, applied_at={prev_applied}")
    save_log(f"Menu choice: [2] Refresh token")

    print(f"\n  Previous run details:")
    print(f"    Algorithm   : {prev_algorithm}")
    print(f"    Godot ver.  : {prev_version}")
    print(f"    Last applied: {prev_applied}")
    print(f"    Prev token  : {prev_token}")

    try:
        encKey = os.environ["SCRIPT_AES256_ENCRYPTION_KEY"]
    except Exception:
        encKey = "Can't Fetch Your Environment Variable \"SCRIPT_AES256_ENCRYPTION_KEY\""

    # Generate default new token then let user override
    security_token = generate_random_token()
    token_hex      = binascii.hexlify(security_token).decode('utf-8')

    confirm = input(f"\n\n ℹ  {LogColors.OKBLUE}Use Custom Token {LogColors.ENDC}{LogColors.FAIL}(y/n)?{LogColors.ENDC}: ").strip().lower()
    save_log(f"\n[INFO] - Use Custom Token (y/n)?: {confirm}")
    if confirm in ('y', 'yes'):
        token_hex      = str(input("    Enter Custom Security Token: ")).lower()
        security_token = hex_to_bytes(token_hex)
        save_log(f"    Enter Custom Security Token: {token_hex}")
    token_c_array = ', '.join([f'0x{b:02X}' for b in security_token])

    print_info(f"Refreshing security_token.h with new token: {token_hex}")
    try:
        path = write_security_token_header(godot_root, token_hex, token_c_array)
        print_success(f"security_token.h refreshed: {path}")
        save_log(f"\nNew Security Token: {token_hex}")
    except Exception as e:
        print_error(f"Failed to refresh security_token.h: {e}")
        try:
            input("\nPress Enter key to exit...")
        except EOFError:
            pass
        sys.exit(1)

    write_state_file(state_file_path, prev_algorithm, prev_version, token_hex)
    print_success(f"State file updated: {state_file_path}")
    save_log(f"State file updated at {state_file_path}")

    print(f"\n{LogColors.HEADER}=== Token Refresh Complete (View Logs For Info) ==={LogColors.ENDC}\n")
    print(f"{LogColors.BOLD} New Security Token:{LogColors.ENDC} {token_hex}\n")
    print(f"{LogColors.WARNING} Encryption Key: {LogColors.FAIL}{encKey}{LogColors.ENDC}")
    print_warning(
        f"{LogColors.WARNING} Rebuild Godot and re-export your project with "
        f"{LogColors.FAIL}\"Encryption Key\"{LogColors.WARNING} to apply the new token.{LogColors.ENDC}"
    )
    save_log(f"\nEncryption Key: {encKey}")
    save_log("\n[WARN] - Rebuild Godot and re-export with the Encryption Key to apply the new token.")

# ══════════════════════════════════════════════════════════════════════════════
# MODE 3 — Restore original Godot source
# ══════════════════════════════════════════════════════════════════════════════
elif menu_choice == "3":

    if not already_applied:
        print(f"\n{LogColors.FAIL}Error: Godot Secure has not been applied to this source tree yet.{LogColors.ENDC}")
        print("Nothing to restore.")
        try:
            input("\nPress Enter key to exit...")
        except EOFError:
            pass
        sys.exit(1)

    prev_algorithm = state.get("algorithm", "AES-256")
    prev_applied   = state.get("applied_at", "unknown")

    init_log("Restore")
    save_log(f"Restore mode. Previous: algorithm={prev_algorithm}, applied_at={prev_applied}")
    save_log(f"Menu choice: [3] Restore")

    print(f"\n  This will restore original Godot source files from .backup copies")
    print(f"  and remove the generated security_token.h.")
    print(f"  Previous application: {prev_algorithm} on {prev_applied}\n")

    confirm = input(f" ⚠   {LogColors.WARNING}Restore original Godot source {LogColors.ENDC}{LogColors.FAIL}(y/n)?{LogColors.ENDC}: ").strip().lower()
    save_log(f"Restore original Godot source (y/n)?: {confirm}")
    if not (confirm in ('y', 'yes')):
        print(save_log("Closing Setup..."))
        try:
            input("\nPress Enter key to exit...")
        except EOFError:
            pass
        sys.exit(1)

    ok = restore_backups(godot_root, state_file_path)

    print(f"\n{LogColors.HEADER}=== Restore {'Complete' if ok else 'Finished With Warnings'} (View Logs For Info) ==={LogColors.ENDC}\n")
    if ok:
        print_success("All files restored. Godot source is back to its original state.")
    else:
        print_warning("Some files could not be restored. Check the log for details.")

# ── Unknown choice ─────────────────────────────────────────────────────────────
else:
    print(f"\n{LogColors.FAIL}Invalid choice. Exiting.{LogColors.ENDC}")
    try:
        input("\nPress Enter key to exit...")
    except EOFError:
        pass
    sys.exit(1)

# ── Done ───────────────────────────────────────────────────────────────────────
try:
    input("\nPress Enter key to exit...")
except EOFError:
    pass
sys.exit(0)
