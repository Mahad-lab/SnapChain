#!/usr/bin/env python3
"""
Screenshot-blockchain verifier (fast + cache)

Features
--------
* Fast mode: only stat() → size + mtime
* Cache: hash_cache.json (auto-created/updated)
* Full mode (--full): re-hash every file
* Chain validation (prev → this)
* Colored, human-readable report
"""

import os
import sys
import json
import hashlib
import argparse
import mmh3
from datetime import datetime
from pathlib import Path

# ----------------------------------------------------------------------
# Configuration (mirrors the capturer)
# ----------------------------------------------------------------------
DEFAULT_LOG      = "hashes.txt"
DEFAULT_BASE_DIR = "."
CACHE_FILE       = "hash_cache.json"

# ----------------------------------------------------------------------
# Helper: colored output
# ----------------------------------------------------------------------
class Color:
    OK    = "\033[92m"   # green
    WARN  = "\033[93m"   # yellow
    ERR   = "\033[91m"   # red
    BOLD  = "\033[1m"
    END   = "\033[0m"

def cprint(msg: str, color: str = ""):
    print(f"{color}{msg}{Color.END}")

# ----------------------------------------------------------------------
# Cache handling
# ----------------------------------------------------------------------
def load_cache() -> dict:
    if not Path(CACHE_FILE).exists():
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        cprint(f"Warning: Could not read cache ({e}) – will rebuild.", Color.WARN)
        return {}

def save_cache(cache: dict):
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        cprint(f"Warning: Could not write cache: {e}", Color.WARN)

# ----------------------------------------------------------------------
# Hash recomputation (used only when needed)
# ----------------------------------------------------------------------
def sha256_file(path: Path, chunk_size: int = 8192) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()

def murmur3_file(path: Path, seed: int = 42) -> str:
    data = path.read_bytes()
    return mmh3.hash_bytes(data, seed).hex()

# ----------------------------------------------------------------------
# Main verification
# ----------------------------------------------------------------------
def verify(log_path: str, base_dir: str, full_verify: bool, quiet: bool):
    log_path = Path(log_path).resolve()
    base_dir = Path(base_dir).resolve()

    if not log_path.exists():
        cprint(f"Error: Log file not found: {log_path}", Color.ERR)
        sys.exit(1)

    cache = load_cache()
    lines = log_path.read_text(encoding="utf-8").splitlines()

    # Skip header / comment lines
    data_lines = [ln for ln in lines if ln.strip() and not ln.startswith("#")]
    if not data_lines:
        cprint("No data blocks to verify.", Color.WARN)
        return

    total = len(data_lines)
    ok_count = 0
    errors = []

    prev_record_hash = "0" * 64                     # genesis

    if not quiet:
        cprint(f"Verification started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", Color.BOLD)
        cprint("-" * 70, Color.BOLD)

    for idx, raw_line in enumerate(data_lines, start=1):
        line = raw_line.strip()
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 6:
            errors.append((idx, "Malformed line (expected 6 fields)"))
            if not quiet:
                cprint(f"[ERROR] Block {idx:>3} – malformed line", Color.ERR)
            continue

        ts, rel_path, stored_sha, stored_mur, prev_field, this_field = parts

        # ------------------------------------------------------------------
        # 1. Resolve file path
        # ------------------------------------------------------------------
        file_path = (base_dir / rel_path).resolve()

        # ------------------------------------------------------------------
        # 2. File existence
        # ------------------------------------------------------------------
        if not file_path.exists():
            errors.append((idx, f"File missing: {rel_path}"))
            if not quiet:
                cprint(f"[ERROR] Block {idx:>3} – {rel_path}", Color.ERR)
                cprint(f"        • File missing", Color.ERR)
            continue

        # ------------------------------------------------------------------
        # 3. Fast metadata check (size + mtime)
        # ------------------------------------------------------------------
        stat = file_path.stat()
        size = stat.st_size
        mtime = stat.st_mtime

        cache_key = str(file_path)
        cache_entry = cache.get(cache_key, {})

        need_rehash = full_verify
        if not need_rehash:
            if (cache_entry.get("size") == size and
                abs(cache_entry.get("mtime", 0) - mtime) < 1e-3):
                # Metadata unchanged → trust cache
                computed_sha = cache_entry.get("sha256")
                computed_mur = cache_entry.get("murmur")
            else:
                need_rehash = True

        # ------------------------------------------------------------------
        # 4. Re-hash if needed
        # ------------------------------------------------------------------
        if need_rehash:
            try:
                computed_sha = sha256_file(file_path)
                computed_mur = murmur3_file(file_path)
                # Update cache
                cache[cache_key] = {
                    "sha256": computed_sha,
                    "murmur": computed_mur,
                    "size": size,
                    "mtime": mtime
                }
            except Exception as e:
                errors.append((idx, f"Hash error: {e}"))
                if not quiet:
                    cprint(f"[ERROR] Block {idx:>3} – hash failed", Color.ERR)
                continue

        # ------------------------------------------------------------------
        # 5. Compare stored vs computed hashes
        # ------------------------------------------------------------------
        hash_ok = (computed_sha == stored_sha and computed_mur == stored_mur)
        if not hash_ok:
            errors.append((idx, f"Hash mismatch (SHA/Murmur)"))
            if not quiet:
                cprint(f"[ERROR] Block {idx:>3} – {rel_path}", Color.ERR)
                if computed_sha != stored_sha:
                    cprint(f"        • SHA-256 mismatch", Color.ERR)
                if computed_mur != stored_mur:
                    cprint(f"        • Murmur3 mismatch", Color.ERR)

        # ------------------------------------------------------------------
        # 6. Chain validation
        # ------------------------------------------------------------------
        expected_prev = prev_field.split(":", 1)[1] if ":" in prev_field else ""
        if idx == 1:
            # Genesis block must have prev = 64 zeros
            if expected_prev != "0" * 64:
                errors.append((idx, "Genesis prev hash not zero"))
                if not quiet:
                    cprint(f"        • Genesis prev ≠ 000...0", Color.ERR)
        else:
            if expected_prev != prev_record_hash:
                errors.append((idx, "Chain broken (prev ≠ previous this)"))
                if not quiet:
                    cprint(f"        • Chain broken (prev ≠ prev record)", Color.ERR)

        # Re-build the record **without** the `this:` field, using correct prev
        record_for_hash = f"{ts}|{rel_path}|{stored_sha}|{stored_mur}|prev:{prev_record_hash}"
        this_record_hash = hashlib.sha256(record_for_hash.encode("utf-8")).hexdigest()

        expected_this = this_field.split(":", 1)[1] if ":" in this_field else ""
        if this_record_hash != expected_this:
            errors.append((idx, "Current record hash invalid"))
            if not quiet:
                cprint(f"        • this: hash invalid", Color.ERR)

        # Update prev for next iteration
        prev_record_hash = this_record_hash

        # ------------------------------------------------------------------
        # 7. Final status
        # ------------------------------------------------------------------
        block_errors = [msg for i, msg in errors if i == idx]
        if not block_errors:
            ok_count += 1
            if not quiet:
                cprint(f"[OK] Block {idx:>3} – {rel_path}", Color.OK)
        else:
            if not quiet:
                for msg in block_errors:
                    cprint(f"        • {msg}", Color.ERR)

    # ----------------------------------------------------------------------
    # Summary
    # ----------------------------------------------------------------------
    save_cache(cache)

    if not quiet:
        cprint("-" * 70, Color.BOLD)
    cprint(f"Summary:", Color.BOLD)
    cprint(f"  Total blocks : {total}")
    cprint(f"  OK           : {ok_count}", Color.OK if ok_count == total else Color.WARN)
    cprint(f"  Errors       : {len(errors)}", Color.ERR if errors else Color.OK)

    if errors and not quiet:
        cprint("\nError details:", Color.ERR)
        for idx, msg in errors:
            cprint(f"  Block {idx:>3}: {msg}")

    if ok_count == total:
        cprint("\nAll checks passed!", Color.OK)
    else:
        sys.exit(1)

# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Verify screenshot blockchain (fast + cached)"
    )
    parser.add_argument(
        "--log", default=DEFAULT_LOG,
        help=f"Path to hashes.txt (default: {DEFAULT_LOG})"
    )
    parser.add_argument(
        "--dir", default=DEFAULT_BASE_DIR,
        help=f"Base directory for relative paths (default: {DEFAULT_BASE_DIR})"
    )
    parser.add_argument(
        "--full", action="store_true",
        help="Force full re-hash of every file (ignore cache)"
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Only print summary and errors"
    )
    args = parser.parse_args()

    verify(args.log, args.dir, args.full, args.quiet)

if __name__ == "__main__":
    main()