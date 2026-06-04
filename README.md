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
