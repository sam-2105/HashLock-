#!/usr/bin/env python3
"""
HashLock - Lightweight File Integrity Checker (Final Version)
--------------------------------------------------------------
Modules:
1. Input & Storage
2. Hash Generation
3. Verification & Comparison
4. Alert & Notification (Cross-platform)
5. Reporting & Logs
6. Multi-Algorithm Support
7. Secure Baseline Storage (Encrypted)
8. SecureID Export Bridge (Blockchain-ready)
"""

import argparse
import hashlib
import json
import os
import csv
import datetime
from pathlib import Path
import platform

# -----------------------------
#  Notification Setup
# -----------------------------
def mac_notify(title: str, message: str):
    """macOS notification using pync (if available)."""
    try:
        from pync import Notifier
        Notifier.notify(message, title=title)
    except Exception:
        print(f"[NOTIFY] {title}: {message}")

def notify(title: str, message: str, duration: int = 5):
    """Cross-platform desktop notification"""
    system = platform.system().lower()
    if system == "windows":
        try:
            from win10toast import ToastNotifier
            ToastNotifier().show_toast(title, message, duration=duration, threaded=True)
        except Exception:
            print(f"[NOTIFY] {title}: {message}")
    elif system == "darwin":  # macOS
        mac_notify(title, message)
    else:  # Linux or fallback
        try:
            from plyer import notification
            notification.notify(title=title, message=message, timeout=duration)
        except Exception:
            print(f"[NOTIFY] {title}: {message}")

# -----------------------------
#  Encryption Setup
# -----------------------------
try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

# -----------------------------
#  File Paths
# -----------------------------
BASE_DIR = Path(".")
FILES_DIR = BASE_DIR / "files"
HASHES_DIR = BASE_DIR / "hashes"
REPORTS_DIR = BASE_DIR / "reports"

FILES_DIR.mkdir(exist_ok=True)
HASHES_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

ENCRYPTED_BASELINE = HASHES_DIR / "baseline.enc"
PLAIN_BASELINE = HASHES_DIR / "baseline.json"
KEY_FILE = HASHES_DIR / "secret.key"
CSV_REPORT = REPORTS_DIR / "report.csv"
SECUREID_OUT = REPORTS_DIR / "secureid_out.json"

# -----------------------------
#  Configuration
# -----------------------------
ALGORITHMS = {"md5", "sha1", "sha256", "sha512"}
DEFAULT_ALGO = "sha256"

# -----------------------------
#  Encryption Handling
# -----------------------------
def ensure_key():
    """Ensure Fernet encryption key exists."""
    if not CRYPTO_AVAILABLE:
        return None
    if not KEY_FILE.exists():
        key = Fernet.generate_key()
        KEY_FILE.write_bytes(key)
        return key
    return KEY_FILE.read_bytes()

def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(data)

def decrypt_bytes(token: bytes, key: bytes) -> bytes:
    return Fernet(key).decrypt(token)

# -----------------------------
#  Hash Calculation
# -----------------------------
def calculate_hash(file_path: str, algo: str = DEFAULT_ALGO) -> str:
    """Generate hash for file."""
    algo = algo.lower()
    if algo not in ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algo}")
    h = hashlib.new(algo)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

# -----------------------------
#  Baseline Storage
# -----------------------------
def load_baseline():
    """Load baseline data from encrypted or plain storage."""
    data = {}
    if CRYPTO_AVAILABLE and ENCRYPTED_BASELINE.exists():
        key = ensure_key()
        try:
            raw = decrypt_bytes(ENCRYPTED_BASELINE.read_bytes(), key)
            data = json.loads(raw.decode())
        except Exception:
            print("[!] Failed to decrypt baseline or wrong key.")
            return {}
    elif PLAIN_BASELINE.exists():
        try:
            data = json.loads(PLAIN_BASELINE.read_text(encoding="utf-8"))
        except Exception:
            return {}

    normalized = {}
    for fname, val in data.items():
        if isinstance(val, str):
            normalized[fname] = {DEFAULT_ALGO: val}
        elif isinstance(val, dict):
            normalized[fname] = val
        else:
            normalized[fname] = {}
    return normalized

def save_baseline_data(baseline_data: dict):
    """Save baseline data securely."""
    if CRYPTO_AVAILABLE:
        key = ensure_key()
        raw = json.dumps(baseline_data, indent=2).encode("utf-8")
        token = encrypt_bytes(raw, key)
        ENCRYPTED_BASELINE.write_bytes(token)
        if PLAIN_BASELINE.exists():
            PLAIN_BASELINE.unlink(missing_ok=True)
        print(f"[+] Baseline encrypted and saved at {ENCRYPTED_BASELINE}")
    else:
        PLAIN_BASELINE.write_text(json.dumps(baseline_data, indent=2), encoding="utf-8")
        print(f"[+] Baseline saved (unencrypted) at {PLAIN_BASELINE}")

# -----------------------------
#  Reporting
# -----------------------------
def append_csv_report(entry: dict):
    """Append results to CSV report."""
    header = ["timestamp", "file", "algo", "status", "baseline_hash", "current_hash"]
    exists = CSV_REPORT.exists()
    with open(CSV_REPORT, "a", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=header)
        if not exists:
            writer.writeheader()
        writer.writerow(entry)

# -----------------------------
#  Core Functions
# -----------------------------
def init_baseline(file_path: str, algo: str = DEFAULT_ALGO):
    """Initialize baseline hash for a file."""
    if not Path(file_path).exists():
        print(f"[!] File not found: {file_path}")
        return
    baseline = load_baseline()
    fname = Path(file_path).name
    file_hash = calculate_hash(file_path, algo)
    if fname not in baseline:
        baseline[fname] = {}
    baseline[fname][algo] = file_hash
    save_baseline_data(baseline)
    print(f"[INIT] {fname} ({algo}) -> {file_hash}")

def check_file(file_path: str, algo: str = DEFAULT_ALGO):
    """Verify integrity of a file."""
    if not Path(file_path).exists():
        print(f"[!] File not found: {file_path}")
        return
    baseline = load_baseline()
    fname = Path(file_path).name
    if fname not in baseline or algo not in baseline[fname]:
        print(f"[!] No baseline found for {fname} ({algo}). Run init first.")
        return
    baseline_hash = baseline[fname][algo]
    current_hash = calculate_hash(file_path, algo)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "timestamp": ts,
        "file": fname,
        "algo": algo,
        "baseline_hash": baseline_hash,
        "current_hash": current_hash,
    }
    if current_hash == baseline_hash:
        entry["status"] = "Safe"
        append_csv_report(entry)
        print(f"[OK] {fname} ({algo}) is intact ✅")
    else:
        entry["status"] = "Tampered"
        append_csv_report(entry)
        print(f"[ALERT] {fname} ({algo}) has been tampered ❌")
        notify("HashLock Alert ⚠️", f"File {fname} has been modified....", 5)

def export_for_secureid(file_path: str, algo: str = DEFAULT_ALGO):
    """Export hash for SecureID integration (blockchain-ready)."""
    if not Path(file_path).exists():
        print(f"[!] File not found: {file_path}")
        return
    fname = Path(file_path).name
    file_hash = calculate_hash(file_path, algo)
    payload = {
        "file": fname,
        "algo": algo,
        "hash": file_hash,
        "timestamp": datetime.datetime.now().isoformat()
    }
    old = []
    if SECUREID_OUT.exists():
        try:
            old = json.loads(SECUREID_OUT.read_text(encoding="utf-8"))
        except Exception:
            old = []
    old.append(payload)
    SECUREID_OUT.write_text(json.dumps(old, indent=2), encoding="utf-8")
    print(f"[EXPORT] SecureID payload saved to {SECUREID_OUT}")

# -----------------------------
#  CLI Interface
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="HashLock - File Integrity Checker (Final Version)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Create baseline for a file")
    p_init.add_argument("file", help="File path")
    p_init.add_argument("--algo", choices=list(ALGORITHMS), default=DEFAULT_ALGO)

    p_check = sub.add_parser("check", help="Check integrity of a file")
    p_check.add_argument("file", help="File path")
    p_check.add_argument("--algo", choices=list(ALGORITHMS), default=DEFAULT_ALGO)

    p_export = sub.add_parser("export", help="Export hash data for SecureID")
    p_export.add_argument("file", help="File path")
    p_export.add_argument("--algo", choices=list(ALGORITHMS), default=DEFAULT_ALGO)

    args = parser.parse_args()

    if args.cmd == "init":
        init_baseline(args.file, args.algo)
    elif args.cmd == "check":
        check_file(args.file, args.algo)
    elif args.cmd == "export":
        export_for_secureid(args.file, args.algo)

if __name__ == "__main__":
    main()
