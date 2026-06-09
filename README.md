<p align="center">
  <img src="Logos/PNGs/Godot Secure.png" alt="Godot Secure" width="360" />
</p>

<p align="center">
  <a href="https://ko-fi.com/V7V41FR21F" target="_blank">
    <img height="36" src="https://storage.ko-fi.com/cdn/kofi5.png?v=6" border="0" alt="Buy Me a Coffee at ko-fi.com" />
  </a>
</p>

# Godot Secure

Godot Secure patches the Godot Engine C++ source code to replace the default AES-256 encryption with a cryptographically unique build — one whose pack headers, encrypted-file headers, and key derivation are all randomized at patch time so that no two Godot Secure builds share the same encryption fingerprint.

Three encryption algorithms are supported:

| Algorithm | Files modified |
|-----------|----------------|
| AES-256 | 6 source files |
| Camellia-256 | 8 source files (adds `CamelliaContext` to the crypto core) |
| ARIA-256 | 8 source files (adds `AriaContext` to the crypto core) |

After patching you compile Godot from source exactly as you normally would.

---

## Requirements

- Python 3.8 or later
- The Godot Engine **C++ source tree** (not an exported project — the source you would compile yourself)
- Godot 4.x source is supported; the script auto-detects whether the source is 4.6+ or an older 4.x branch and selects the correct code paths
- Build tools for compiling Godot (SCons, a C++ compiler); see the [official Godot build documentation](https://docs.godotengine.org/en/stable/contributing/development/compiling/index.html)

---

## Usage

```
python godot_secure.py [GODOT_SOURCE_ROOT] [options]
```

`GODOT_SOURCE_ROOT` is the path to your Godot C++ source tree. If omitted the current directory is used. The script validates that the target contains `core/` and `SConstruct`, then reads `version.py` to detect the engine version.

### Command-line options

All interactive prompts have a corresponding CLI option. When every required option is supplied alongside `--non-interactive` the script runs fully headlessly with no stdin required — suitable for GitHub Actions and other CI pipelines.

#### Mode

| Option | Values | Description |
|--------|--------|-------------|
| `--mode` | `apply` · `refresh` · `restore` | Operation to perform. Replaces the interactive main menu. |

#### Apply options

| Option | Values | Description |
|--------|--------|-------------|
| `--algorithm` | `aes` · `camellia` · `aria` | Encryption algorithm. Default: `aes`. |
| `--kdf-formula` | C statement | Expert override: supply an exact KDF formula from a pre-v1.3.0-alpha build. When omitted the formula is derived from the security token via HKDF automatically — no manual management required. |

#### Encryption key options *(apply and refresh)*

`--key` and `--generate-key` are mutually exclusive. If neither is supplied and `SCRIPT_AES256_ENCRYPTION_KEY` is not set, the script prompts interactively (or exits with an error under `--non-interactive`).

| Option | Values | Description |
|--------|--------|-------------|
| `--key` | 64-char hex | Supply an existing encryption key. Sets `SCRIPT_AES256_ENCRYPTION_KEY`. |
| `--generate-key` | *(flag)* | Generate a new 256-bit key, write it to `godot.gdkey`, and set `SCRIPT_AES256_ENCRYPTION_KEY`. |

#### Token option *(apply and refresh)*

| Option | Values | Description |
|--------|--------|-------------|
| `--token` | 64-char hex | Security token to embed in the engine binary. A random token is generated when omitted. |

#### Behaviour

| Option | Description |
|--------|-------------|
| `--non-interactive` | Skip all confirmation prompts and `Press Enter` pauses. All omitted values use their defaults. **Required for CI.** |

### Examples

```bash
# Interactive run (default — presents the menu)
python godot_secure.py /path/to/godot

# Non-interactive apply with AES-256 and an auto-generated key
python godot_secure.py /path/to/godot \
    --mode apply --algorithm aes \
    --generate-key \
    --non-interactive

# Non-interactive apply with Camellia-256
python godot_secure.py /path/to/godot \
    --mode apply --algorithm camellia \
    --generate-key \
    --non-interactive

# Non-interactive apply with ARIA-256
python godot_secure.py /path/to/godot \
    --mode apply --algorithm aria \
    --generate-key \
    --non-interactive

# Non-interactive apply with a key stored in an environment variable
export SCRIPT_AES256_ENCRYPTION_KEY=<your-64-char-hex-key>
python godot_secure.py /path/to/godot \
    --mode apply --algorithm aes \
    --non-interactive

# Refresh the security token (key read from SCRIPT_AES256_ENCRYPTION_KEY)
python godot_secure.py /path/to/godot --mode refresh --non-interactive

# Restore original source files
python godot_secure.py /path/to/godot --mode restore --non-interactive
```

### GitHub Actions example

```yaml
- name: Patch Godot source
  env:
    SCRIPT_AES256_ENCRYPTION_KEY: ${{ secrets.GODOT_ENCRYPTION_KEY }}
  run: |
    python godot_secure.py vendored/godot \
      --mode apply \
      --algorithm aes \
      --non-interactive
```

Store `GODOT_ENCRYPTION_KEY` as an [encrypted Actions secret](https://docs.github.com/en/actions/security-guides/encrypted-secrets). The log file written by the script contains the Security Token — upload it as a CI artifact or pipe it to a secrets store so the value is not lost.

For multi-OS builds where the same token must be shared across all runners, use a `setup` job with `--mode generate` to produce the token once and pass it via `--token`. See [GodotSecureAction](https://github.com/emabrey/GodotSecureAction) for a complete multi-OS CI workflow.

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

Options [2] and [3] show a note when Godot Secure has not yet been applied. Option [1] shows a warning when it has already been applied, but still allows re-application with the same algorithm.

---

## Option 1 — Apply Godot Secure (first-time setup)

Use this on a clean Godot source tree before compiling for the first time.

**What happens:**

1. You choose an encryption algorithm — `[1] AES-256` (default), `[2] Camellia-256`, or `[3] ARIA-256`.
2. Optionally supply a custom 32-byte security token (hex string), or accept a randomly generated one.
3. The security token is used to derive all other security parameters automatically:
   - **Pack magic headers** — derived via `chr(ord('A') + (byte % 26))` applied to token bytes 0–3 and 4–7.
   - **KDF formula** — derived via HKDF-SHA256 (RFC 5869), producing a unique multi-layer bitwise expression baked into the compiled binary.
4. The script patches the Godot source files, creating a `.backup` copy of every file it modifies before touching it.
5. A `.godot_secure` state file is written to the Godot source root recording the algorithm, version, token, and timestamp.
6. A timestamped log file is written next to the script. **Save this log** — it contains the security token you will need if you ever re-export or rebuild your project.

**After patching**, compile Godot from source as normal and export your project using your `SCRIPT_AES256_ENCRYPTION_KEY` environment variable.

> **Important:** The Security Token and the Encryption Key are two different values. Use the **Encryption Key** (your `SCRIPT_AES256_ENCRYPTION_KEY` environment variable) during export, not the Security Token.

### Switching algorithms

The script records which algorithm was used in `.godot_secure`. If you run option [1] again and select a different algorithm, the script will refuse to proceed — patching a source tree that already has one cipher's context class injected with a second cipher's patches would leave `crypto_core.h` and `crypto_core.cpp` in a broken state.

To switch algorithms, you must restore the original source first:

1. Run option [3] to restore all original Godot source files.
2. Run option [1] and choose the new algorithm.

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

> **Note:** Refresh only rotates the token. It does not change the encryption algorithm. If you pass `--algorithm` during a refresh and it does not match the algorithm recorded in `.godot_secure`, the script will abort with an error. To switch algorithms, restore the source tree with option [3] and re-apply with option [1].

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

If a `.backup` file is missing for any of the core files, the script warns you but continues with the remaining files. The `crypto_core.h` and `crypto_core.cpp` backup files are silently skipped when absent — they are only created for Camellia-256 and ARIA-256 builds.

---

## Building after patching

Once the script has finished applying Godot Secure, you must compile both the **editor** and all **export templates** from source. The compiled editor binary and every export template must be built from the same patched source tree — mixing a patched build with stock templates (or vice versa) will cause encryption mismatches at runtime.

### 1 — Set your encryption key

Godot's export encryption expects a 256-bit hex key in the `SCRIPT_AES256_ENCRYPTION_KEY` environment variable. The script checks this variable when you run option [1] or [2]. If it is not set, or is not a valid 64-character hex string, you will be prompted:

```
  How would you like to provide an encryption key?

    [1] Enter my own 64-character hex key
    [2] Generate a secure key automatically
    [3] Cancel
```

Choosing **[1]** lets you paste in an existing key — useful when you already have a key from a previous build and want to keep using it.

Choosing **[2]** generates a cryptographically secure 256-bit key using Python's `secrets` module, writes it to `godot.gdkey` in the Godot source root, and sets `SCRIPT_AES256_ENCRYPTION_KEY` for the remainder of the process.

Choosing **[3]** (or pressing Enter without a valid choice) exits the script — the operation cannot proceed without a key.

If you prefer to set the variable yourself before running the script:

```bash
# Linux / macOS
export SCRIPT_AES256_ENCRYPTION_KEY=<your-64-char-hex-key>
```

```powershell
# Windows (PowerShell)
$env:SCRIPT_AES256_ENCRYPTION_KEY = "<your-64-char-hex-key>"
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

Godot Secure produces three categories of files that **must never be committed** to your Godot source repository:

| File | What it contains |
|------|-----------------|
| `godot.gdkey` | Your 256-bit encryption key |
| `.godot_secure` | The algorithm, security token, and timestamp of your Godot Secure build |
| `godot_secure_*.log` | Full record of every token, header magic value, and key derivation formula generated for each run |

If any of these files is pushed to a public (or compromised private) repository, an attacker can reconstruct the exact key derivation used by your engine build and decrypt your exported game assets. Treat them with the same care as a private key or a database password.

### Add them to your Godot source .gitignore

Open (or create) `.gitignore` in the root of your Godot source tree and add the following lines:

```gitignore
# Godot Secure — never commit these
.godot_secure
godot.gdkey
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

The log files in particular are easy to overlook because they are written next to the script rather than inside the Godot source tree. Make a habit of moving each log file to secure storage immediately after reviewing it.

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

Its presence is what tells the script that Godot Secure has already been applied. The recorded algorithm is used to prevent accidental re-application with a mismatched cipher. Deleting the file manually causes the next run to treat the source tree as clean and offer the full apply flow again — only do this if you are certain the source files are also in their original state.

---

## Log files

Every run writes a timestamped log file in the working directory from which you ran the script:

| Mode | Log file name |
|------|---------------|
| Apply (AES-256) | `godot_secure_AES_<timestamp>.log` |
| Apply (Camellia-256) | `godot_secure_Camellia_<timestamp>.log` |
| Apply (ARIA-256) | `godot_secure_ARIA_<timestamp>.log` |
| Refresh (AES-256) | `godot_secure_Refresh-AES_<timestamp>.log` |
| Refresh (Camellia-256) | `godot_secure_Refresh-Camellia_<timestamp>.log` |
| Refresh (ARIA-256) | `godot_secure_Refresh-ARIA_<timestamp>.log` |
| Restore | `godot_secure_Restore_<timestamp>.log` |

All log files share the `godot_secure_*.log` prefix, so a single line in `.gitignore` covers them all:

```gitignore
godot_secure_*.log
```

Keep the Apply log somewhere safe. It is the only record of the exact header magic values and security token used for a given build.

---

## Files modified by Godot Secure

### All algorithms

| File | Change |
|------|--------|
| `version.py` | Appends `(With Godot Secure)` to the engine name |
| `editor/export/project_export.cpp` | Updates the export dialog title |
| `core/crypto/security_token.h` | **Created** — contains the randomized 32-byte token |
| `core/io/file_access_pack.h` | Replaces the default pack header magic |
| `core/io/file_access_encrypted.h` | Replaces the default encrypted-file header magic |
| `core/io/file_access_encrypted.cpp` | Injects the security token into the key derivation |

### Camellia-256 (additional files)

| File | Change |
|------|--------|
| `core/crypto/crypto_core.h` | Adds the `CamelliaContext` class declaration |
| `core/crypto/crypto_core.cpp` | Adds the full `CamelliaContext` implementation via mbedTLS |

### ARIA-256 (additional files)

| File | Change |
|------|--------|
| `core/crypto/crypto_core.h` | Adds the `AriaContext` class declaration |
| `core/crypto/crypto_core.cpp` | Adds the full `AriaContext` implementation via mbedTLS |

---

## Support

Godot Secure is free and open-source. If you find it useful, consider supporting its development:

<a href="https://ko-fi.com/V7V41FR21F" target="_blank">
  <img height="36" src="https://storage.ko-fi.com/cdn/kofi5.png?v=6" border="0" alt="Buy Me a Coffee at ko-fi.com" />
</a>
