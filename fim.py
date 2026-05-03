"""
File Integrity Monitor (FIM)
Usage:
    python fim.py init <folder> --password <pwd>
    python fim.py check <folder> --password <pwd>
"""

import os, json, hashlib, hmac, argparse, sys
from pathlib import Path

# Konstanta
BASELINE_FILE = "baseline.json"
HMAC_FILE = "baseline.hmac"
CHUNK_SIZE = 65536

def compute_sha256(filepath: str) -> str:
    """Menghitung SHA-256 dari file (streaming)."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()

def scan_folder(folder: str) -> dict:
    """Memindai semua file dalam folder (rekursif) dan mengembalikan dict {path: hash}."""
    results = {}
    folder = os.path.abspath(folder)
    for root, _, files in os.walk(folder):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, folder)
            print(f"  Memindai: {rel_path}")
            try: results[rel_path] = compute_sha256(full_path)
            except Exception as e: print(f"  [ERROR] Gagal membaca {rel_path}: {e}")
    return results

def save_baseline(baseline_data: dict, password: str, output_dir: str = "."):
    """Menyimpan baseline ke file JSON dan HMAC-nya."""
    baseline_path = os.path.join(output_dir, BASELINE_FILE)
    hmac_path = os.path.join(output_dir, HMAC_FILE)
    json_str = json.dumps(baseline_data, sort_keys=True, indent=2)
    with open(baseline_path, "w") as f: f.write(json_str)
    mac = hmac.new(password.encode("utf-8"), json_str.encode("utf-8"), hashlib.sha256)
    with open(hmac_path, "w") as f: f.write(mac.hexdigest())
    print(f"[INIT]  Baseline disimpan: {baseline_path} (HMAC dilindungi)")

def load_baseline(password: str, dir_path: str = "."):
    """Memuat baseline dan memverifikasi HMAC."""
    baseline_path = os.path.join(dir_path, BASELINE_FILE)
    hmac_path = os.path.join(dir_path, HMAC_FILE)
    if not os.path.exists(baseline_path) or not os.path.exists(hmac_path):
        print("[ERROR] Baseline tidak ditemukan. Jalankan 'init' terlebih dahulu.")
        return None, False
    with open(baseline_path, "r") as f: json_str = f.read()
    with open(hmac_path, "r") as f: stored_mac = f.read().strip()
    expected_mac = hmac.new(password.encode("utf-8"), json_str.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac, stored_mac):
        print("[ERROR] Baseline dimodifikasi! HMAC tidak valid — baseline tidak dipercaya.")
        return None, False
    return json.loads(json_str), True

def compare_and_report(current_scan: dict, baseline: dict, folder: str):
    """Membandingkan hasil scan dengan baseline dan melaporkan perubahan."""
    b_paths, c_paths = set(baseline.keys()), set(current_scan.keys())
    new_files, deleted_files, common_files = c_paths - b_paths, b_paths - c_paths, c_paths & b_paths
    modified = [(f, baseline[f], current_scan[f]) for f in common_files if baseline[f] != current_scan[f]]
    
    print(f"[CHECK] Memindai {len(current_scan)} file...\n[OK]    {len(common_files) - len(modified)} file tidak berubah")
    for f in new_files: print(f"[BARU]  {f}  (tidak ada di baseline)")
    for f in deleted_files: print(f"[HAPUS] {f}   (ada di baseline, sekarang hilang)")
    for f, old_hash, new_hash in modified:
        print(f"[UBAH]  {f}       (hash berubah — isi dimodifikasi!)")
        print(f"        Baseline: {old_hash[:16]}...\n        Sekarang: {new_hash[:16]}...")

def cmd_init(args):
    """Handler untuk perintah 'init'."""
    if not os.path.isdir(args.folder):
        print(f"[ERROR] Folder '{args.folder}' tidak ditemukan."); sys.exit(1)
    print(f"[INIT]  Memindai folder: {args.folder}")
    baseline_data = scan_folder(args.folder)
    print(f"[INIT]  {len(baseline_data)} file ditemukan.")
    save_baseline(baseline_data, args.password, output_dir=args.folder)

def cmd_check(args):
    """Handler untuk perintah 'check'."""
    if not os.path.isdir(args.folder):
        print(f"[ERROR] Folder '{args.folder}' tidak ditemukan."); sys.exit(1)
    baseline, ok = load_baseline(args.password, dir_path=args.folder)
    if not ok: sys.exit(1)
    print(f"[CHECK] Memindai folder: {args.folder}")
    current_scan = scan_folder(args.folder)
    print(f"[CHECK] {len(current_scan)} file ditemukan.")
    compare_and_report(current_scan, baseline, args.folder)

def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitor (FIM)")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    p_init = subparsers.add_parser("init", help="Buat baseline")
    p_init.add_argument("folder", help="Folder yang akan dipantau")
    p_init.add_argument("--password", required=True, help="Password untuk proteksi HMAC")
    p_init.set_defaults(func=cmd_init)
    
    p_check = subparsers.add_parser("check", help="Verifikasi integritas")
    p_check.add_argument("folder", help="Folder yang dipantau")
    p_check.add_argument("--password", required=True, help="Password untuk verifikasi HMAC")
    p_check.set_defaults(func=cmd_check)
    
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()