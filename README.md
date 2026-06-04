<p align="center">
  <img src="Logos/PNGs/Godot Secure.png" alt="Godot Secure" width="360" />
</p>

# Godot Secure

Godot Secure patches the Godot Engine C++ source code to replace the default AES-256 encryption with a cryptographically unique build — one whose pack headers, encrypted-file headers, and key derivation are all randomized at patch time so that no two Godot Secure builds share the same encryption fingerprint.

Two algorithms are supported:

| Algorithm | Files modified |
|-----------|---------------|
| AES-256 | 6 source files |
| Camellia-256 | 8 source files (adds `CamelliaContext` to the crypto core) |

After patching you compile Godot from source exactly as you normally would.

---

## Requirements

- Python 3.8 or later
- The Godot Engine **C++ source tree** (not an exported project — the source you would compile yourself)
- Godot 4.x source is supported; the script auto-detects whether the source is 4.6+ or an older 4.x branch and selects the correct code paths

---

## Usage

Run the script from anywhere, passing the path to your Godot source root as the only argument. If no argument is given the current directory is used.

```
python godot_secure.py <path-to-godot-source>
```

The script validates that the target directory looks like a Godot source tree (presence of `core/` and `SConstruct`) and reads `version.py` to detect the engine version before presenting the menu.

---

## Main menu

Every run shows a status banner and then this menu:

```
══════════════════════════════════════════════════════
  Godot Secure

  Source root   : /path/to/godot
  Godot version : 4.6.0-stable
  Status        : Clean Godot source

  What would you like to do?

    [1] Apply Godot Secure to this source tree
    [2] Refresh security token
    [3] Restore original Godot source

  Enter choice [1/2/3]:
```

Options [2] and [3] show a note when Godot Secure has not yet been applied. Option [1] shows a warning when it has already been applied, but still allows re-application.

---

## Option 1 — Apply Godot Secure (first-time setup)

Use this on a clean Godot source tree before compiling for the first time.

**What happens:**

1. You choose an encryption algorithm — `[1] AES-256` (default) or `[2] Camellia-256`.
2. Optionally supply custom 4-character magic headers for pack files and encrypted files, or accept randomly generated ones.
3. Optionally supply a custom 32-byte security token (hex string), or accept a randomly generated one.
4. Optionally enable advanced key derivation, which generates a randomized multi-layer bitwise expression mixing the encryption key and the security token.
5. The script patches the Godot source files, creating a `.backup` copy of every file it modifies before touching it.
6. A `.godot_secure` state file is written to the Godot source root recording the algorithm, version, token, and timestamp.
7. A timestamped log file (`Log-<timestamp>-Godot-Secure-AES.txt` or `…-Camellia.txt`) is written next to the script. **Save this log** — it contains the security token and the generated header values you will need if you ever re-export your project.

**After patching**, compile Godot from source as normal and export your project using your `SCRIPT_AES256_ENCRYPTION_KEY` environment variable.

> **Important:** The Security Token and the Encryption Key are two different values. Use the **Encryption Key** (your `SCRIPT_AES256_ENCRYPTION_KEY` environment variable) during export, not the Security Token.

---

## Option 2 — Refresh security token

Use this when you want to rotate the security token on a source tree that already has Godot Secure applied — for example, when building a new release that should be incompatible with old exported projects.

**What happens:**

1. The script reads `.godot_secure` and shows you the algorithm and timestamp of the previous run.
2. You can supply a custom token or accept a newly generated random one.
3. Only `core/crypto/security_token.h` is rewritten — no other source files are touched.
4. `.godot_secure` is updated with the new token and the current timestamp.
5. A refresh log file is written.

After refreshing you must **rebuild Godot from source** and **re-export your project** with the same Encryption Key for the new token to take effect. Projects exported with the previous build will no longer be loadable by the new engine binary.

---

## Option 3 — Restore original Godot source

Use this to undo all Godot Secure patches and return the source tree to its unmodified state.

**What happens:**

1. The script reads `.godot_secure` and shows you the details of the previous run.
2. You confirm the restore.
3. For every modified file, the `.backup` copy is moved back over the current file.
4. The generated `core/crypto/security_token.h` file is deleted (it has no backup because it did not exist before Godot Secure was applied).
5. The `.godot_secure` state file is removed.
6. A restore log file is written.

If a `.backup` file is missing for any non-Camellia file, the script warns you but continues with the remaining files. Camellia-specific backup files that are absent are silently skipped (expected when AES-256 was used).

---

## Building after patching

Once the script has finished applying Godot Secure, you must compile both the **editor** and all **export templates** from source. The compiled editor binary and every export template must be built from the same patched source tree — mixing a patched build with stock templates (or vice versa) will cause encryption mismatches at runtime.

### 1 — Generate an encryption key

Godot's export encryption expects a 256-bit hex key in the `SCRIPT_AES256_ENCRYPTION_KEY` environment variable. Generate one with OpenSSL and set it before compiling:

```bash
# Generate a 256-bit key and save it somewhere safe
openssl rand -hex 32 > godot.gdkey
```

```bash
# Linux / macOS
export SCRIPT_AES256_ENCRYPTION_KEY=$(cat godot.gdkey)
```

```powershell
# Windows (PowerShell)
$env:SCRIPT_AES256_ENCRYPTION_KEY = Get-Content godot.gdkey
```

> **Keep this key.** You must use the same value every time you export your project. If you lose it, your exported projects cannot be decrypted.

### 2 — Compile the editor

```bash
# Windows
scons platform=windows target=editor

# Linux / BSD
scons platform=linuxbsd target=editor

# macOS
scons platform=macos target=editor
```

Add `use_mingw=yes` on Windows with MinGW, or `use_llvm=yes` on Linux/macOS with Clang, to select your preferred compiler toolchain.

### 3 — Compile export templates

Export templates must be compiled for every platform you intend to export to. Both `template_debug` and `template_release` are required.

```bash
# Windows templates
scons platform=windows target=template_debug
scons platform=windows target=template_release

# Linux / BSD templates
scons platform=linuxbsd target=template_debug
scons platform=linuxbsd target=template_release

# macOS templates
scons platform=macos target=template_debug
scons platform=macos target=template_release
```

### 4 — Install the custom templates in Godot

In the Godot editor, open **Editor → Manage Export Templates** and point it at the binaries you just compiled instead of the official release templates. The editor and templates must all come from the same Godot Secure build.

### 5 — Export your project

Export as normal. Enter your encryption key in the export preset's **Encryption** section — this is the value from `SCRIPT_AES256_ENCRYPTION_KEY`, **not** the Security Token printed by the script. The Security Token is embedded in the compiled binary; the Encryption Key is what you supply at export time.

> **Rebuild protocol** — always recompile the editor and all export templates when you:
> - Update the Godot source (e.g. a new patch release)
> - Refresh the security token via option [2]
> - Change any Godot Secure parameters

For full details on compiling Godot from source, see the [official Godot build documentation](https://docs.godotengine.org/en/stable/contributing/development/compiling/index.html).

---

## Protecting sensitive files

Godot Secure produces two files that **must never be committed** to your Godot source repository:

| File | What it contains |
|------|-----------------|
| `.godot_secure` | The algorithm, security token, and timestamp of your Godot Secure build |
| `godot.gdkey` | Your 256-bit encryption key |

If either file is pushed to a public (or compromised private) repository, an attacker can reconstruct the exact key derivation used by your engine build and decrypt your exported game assets. Treat them with the same care as a private key or a database password.

### Add them to your Godot source .gitignore

Open (or create) `.gitignore` in the root of your Godot source tree and add the following lines:

```gitignore
# Godot Secure — never commit these
.godot_secure
godot.gdkey

# Godot Secure log files
godot_secure_*.log
```

Verify the files are not already tracked before adding the ignore rules:

```bash
git -C /path/to/godot status .godot_secure godot.gdkey
```

If either file appears as tracked, remove it from the index without deleting it from disk:

```bash
git -C /path/to/godot rm --cached .godot_secure godot.gdkey
```

Then commit the updated `.gitignore`.

### Store them separately and securely

These files are the only way to re-export your project or reproduce your engine build after a source update. Store them somewhere that is:

- **Backed up** — losing them means you cannot re-export or re-build; existing exported projects will be permanently unloadable by any new engine binary
- **Access-controlled** — a password manager, an encrypted vault (e.g. VeraCrypt or Bitwarden), or a secrets manager appropriate for your team size
- **Separate from the source repository** — do not keep them in any folder that is part of a git working tree, even a private one

If you are working in a team, share these files through a dedicated secrets management system rather than through version control.

---

## State file

The `.godot_secure` file written to the Godot source root is a small JSON file:

```json
{
  "algorithm": "AES-256",
  "godot_version": "4.6.0-stable",
  "token_hex": "a1b2c3...",
  "applied_at": "2026-06-04_12-00-00-000000"
}
```

Its presence is what tells the script that Godot Secure has already been applied. Deleting it manually causes the next run to treat the source tree as clean and offer the full apply flow again.

---

## Log files

Every run writes a timestamped log file in the working directory from which you ran the script:

| Mode | Log file name |
|------|---------------|
| Apply (AES-256) | `godot_secure_AES_<timestamp>.log` |
| Apply (Camellia-256) | `godot_secure_Camellia_<timestamp>.log` |
| Refresh (AES-256) | `godot_secure_Refresh-AES_<timestamp>.log` |
| Refresh (Camellia-256) | `godot_secure_Refresh-Camellia_<timestamp>.log` |
| Restore | `godot_secure_Restore_<timestamp>.log` |

All log files share the `godot_secure_*.log` prefix, so a single line in `.gitignore` covers them all:

```gitignore
godot_secure_*.log
```

Keep the Apply log somewhere safe. It is the only record of the exact header magic values and security token used for a given build.

---

## Files modified by Godot Secure

### AES-256 (all builds)

| File | Change |
|------|--------|
| `version.py` | Appends `(With Godot Secure)` to the engine name |
| `editor/export/project_export.cpp` | Updates the export dialog title |
| `core/crypto/security_token.h` | **Created** — contains the randomized 32-byte token |
| `core/io/file_access_pack.h` | Replaces the default pack header magic |
| `core/io/file_access_encrypted.h` | Replaces the default encrypted-file header magic |
| `core/io/file_access_encrypted.cpp` | Injects the security token into the AES key derivation |

### Camellia-256 (additional files)

| File | Change |
|------|--------|
| `core/crypto/crypto_core.h` | Adds the `CamelliaContext` class declaration |
| `core/crypto/crypto_core.cpp` | Adds the full `CamelliaContext` implementation via mbedTLS |
