import sys
import binascii
import hashlib
import hmac
import os
import re
import time
import json
import argparse
from datetime import datetime

# ─────────────────────────────────────────────
#   AYHAM BELAL MEGDADI — Hash Detector Tool
#   Version: 2.0  |  Educational & Ethical Use
# ─────────────────────────────────────────────

BANNER = r"""
 $$$$$$\            
$$  __$$\           
$$ /  $$ |$$\   $$\ 
$$$$$$$$ |$$ |  $$ |
$$  __$$ |$$ |  $$ |
$$ |  $$ |$$ |  $$ |
$$ |  $$ |\$$$$$$$ |
\__|  \__| \____$$ |
          $$\   $$ |
          \$$$$$$  |
           \______/ 
"""

HEADER = """==============================================
     ETHICAL HASH DETECTOR TOOL - v2.0
        Developed by: Ayham Belal Megdadi
        For Educational & Ethical Use Only
=============================================="""

HASH_MAP = {
    32:  [("MD5",      "128-bit, fast but broken — avoid for security")],
    40:  [("SHA1",     "160-bit, deprecated for most security uses")],
    56:  [("SHA224",   "224-bit SHA-2 family variant")],
    64:  [("SHA256",   "256-bit SHA-2, industry standard"),
          ("SHA3-256", "256-bit SHA-3 (Keccak), same length as SHA-256")],
    96:  [("SHA384",   "384-bit SHA-2 family variant")],
    128: [("SHA512",   "512-bit SHA-2, strongest of the SHA-2 family"),
          ("SHA3-512", "512-bit SHA-3 (Keccak)")],
    # Other common formats
    8:   [("CRC32",    "32-bit checksum, not a cryptographic hash")],
    16:  [("MySQL323", "Old MySQL hash, extremely weak")],
    48:  [("Tiger192", "192-bit Tiger hash")],
}

SPECIAL_PATTERNS = {
    r"^\$2[aby]\$\d{2}\$.{53}$":        ("bcrypt",   "Adaptive hash, resistant to brute-force"),
    r"^\$argon2(id|i|d)\$":             ("Argon2",   "Memory-hard, winner of PHC — highly recommended"),
    r"^\$scrypt\$":                      ("scrypt",   "Memory-hard, highly resistant to GPU attacks"),
    r"^\$pbkdf2-sha(256|512)\$":        ("PBKDF2",   "Key derivation function, widely used"),
    r"^\$apr1\$":                        ("APR1-MD5", "Apache-style MD5 crypt"),
    r"^\$1\$":                           ("MD5-Crypt","Unix MD5 shadow password"),
    r"^\$5\$":                           ("SHA256-Crypt", "Unix SHA-256 shadow password"),
    r"^\$6\$":                           ("SHA512-Crypt", "Unix SHA-512 shadow password"),
    r"^[a-zA-Z0-9+/]{27}=$":            ("Base64-MD5","Base64-encoded MD5 (common in some apps)"),
}

COLORS = {
    "reset":  "\033[0m",
    "green":  "\033[92m",
    "red":    "\033[91m",
    "yellow": "\033[93m",
    "cyan":   "\033[96m",
    "blue":   "\033[94m",
    "bold":   "\033[1m",
    "dim":    "\033[2m",
}

def c(color, text):
    """Colorize text if stdout is a TTY."""
    if sys.stdout.isatty():
        return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"
    return text


def is_valid_hex(s):
    try:
        binascii.unhexlify(s)
        return True
    except Exception:
        return False

def detect_special_pattern(hash_str):
    """Check for non-hex hash formats like bcrypt, Argon2, etc."""
    for pattern, (name, desc) in SPECIAL_PATTERNS.items():
        if re.match(pattern, hash_str):
            return name, desc
    return None, None


def detect_hash_type(hash_str):
    """
    Returns a list of (name, description) tuples for all matching hash types,
    or an empty list if unknown.
    """
    name, desc = detect_special_pattern(hash_str)
    if name:
        return [(name, desc)]

    clean = hash_str.lower().strip()
    if not is_valid_hex(clean):
        return []

    length = len(clean)
    return HASH_MAP.get(length, [])

def analyze_hash(hash_str):
    """Full analysis report for a given hash string."""
    results = detect_hash_type(hash_str)
    length  = len(hash_str)
    print()
    print(c("cyan", f"  Hash     : ") + c("bold", hash_str[:64] + ("…" if len(hash_str) > 64 else "")))
    print(c("cyan", f"  Length   : ") + f"{length} chars / {length * 4} bits")

    if results:
        for name, desc in results:
            print(c("green", f"  ✔  Type  : ") + c("bold", name))
            print(c("dim",   f"     Info  : {desc}"))
    else:
        print(c("red", "  ✘  Type  : Unknown hash format"))

    strength = _strength(results, length)
    print(c("cyan", f"  Strength : ") + strength)
    print()

def _strength(results, length):
    strong = {"SHA256","SHA512","SHA384","SHA3-256","SHA3-512","Argon2","scrypt","bcrypt","PBKDF2"}
    weak   = {"MD5","SHA1","CRC32","MySQL323","MD5-Crypt","APR1-MD5","Base64-MD5"}
    medium = {"SHA224","Tiger192","SHA256-Crypt","SHA512-Crypt","PBKDF2"}
    if not results:
        return c("dim", "Unknown")
    names = {r[0] for r in results}
    if names & strong - weak:
        return c("green",  "✔ Strong")
    elif names & medium:
        return c("yellow", "~ Moderate")
    elif names & weak:
        return c("red",    "✘ Weak — do not use for new systems")
    return c("dim", "Unrated")


GENERATORS = {
    "MD5":     lambda t: hashlib.md5(t.encode()).hexdigest(),
    "SHA1":    lambda t: hashlib.sha1(t.encode()).hexdigest(),
    "SHA224":  lambda t: hashlib.sha224(t.encode()).hexdigest(),
    "SHA256":  lambda t: hashlib.sha256(t.encode()).hexdigest(),
    "SHA384":  lambda t: hashlib.sha384(t.encode()).hexdigest(),
    "SHA512":  lambda t: hashlib.sha512(t.encode()).hexdigest(),
    "SHA3-256":lambda t: hashlib.sha3_256(t.encode()).hexdigest(),
    "SHA3-512":lambda t: hashlib.sha3_512(t.encode()).hexdigest(),
}

def generate_hash(plaintext, algo="ALL"):
    """Generate one or all supported hash types from plaintext."""
    algo = algo.upper()
    targets = GENERATORS if algo == "ALL" else {algo: GENERATORS[algo]} if algo in GENERATORS else None
    if targets is None:
        print(c("red", f"\n  [!] Unknown algorithm: {algo}"))
        return
    print()
    print(c("cyan", f"  Plaintext: {plaintext}"))
    print(c("dim",  "  " + "─" * 50))
    for name, fn in targets.items():
        digest = fn(plaintext)
        print(c("green", f"  {name:<10}: ") + digest)
    print()


def generate_hmac(plaintext, key, algo="SHA256"):
    """Generate an HMAC for the given plaintext and secret key."""
    algo_map = {
        "MD5":    hashlib.md5,
        "SHA1":   hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
    }
    fn = algo_map.get(algo.upper())
    if not fn:
        print(c("red", f"\n  [!] Unsupported HMAC algorithm: {algo}"))
        return
    mac = hmac.new(key.encode(), plaintext.encode(), fn).hexdigest()
    print()
    print(c("cyan", f"  HMAC-{algo.upper()}: ") + mac)
    print()


def hash_file(filepath, algos=("MD5","SHA256","SHA512")):
    """Compute hashes of a file."""
    if not os.path.isfile(filepath):
        print(c("red", f"\n  [!] File not found: {filepath}"))
        return
    hashers = {a: hashlib.new(a.replace("-","").lower()) for a in algos}
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            for h in hashers.values():
                h.update(chunk)
    size = os.path.getsize(filepath)
    print()
    print(c("cyan", f"  File     : ") + filepath)
    print(c("cyan", f"  Size     : ") + f"{size:,} bytes")
    print(c("dim",  "  " + "─" * 50))
    for name, h in hashers.items():
        print(c("green", f"  {name:<10}: ") + h.hexdigest())
    print()


def batch_detect(filepath):
    """Detect hash types for every line in a text file."""
    if not os.path.isfile(filepath):
        print(c("red", f"\n  [!] File not found: {filepath}"))
        return
    results = []
    with open(filepath) as f:
        lines = [l.strip() for l in f if l.strip()]
    print()
    for i, line in enumerate(lines, 1):
        matches = detect_hash_type(line)
        names   = ", ".join(m[0] for m in matches) if matches else "Unknown"
        status  = c("green", f"✔ {names}") if matches else c("red", "✘ Unknown")
        print(f"  {c('dim', str(i).rjust(4))}  {line[:52]:<52}  {status}")
        results.append({"hash": line, "type": names})
    # Save JSON report
    out = filepath.rsplit(".", 1)[0] + "_report.json"
    with open(out, "w") as f:
        json.dump({"generated": datetime.now().isoformat(), "results": results}, f, indent=2)
    print(c("cyan", f"\n  Report saved → {out}\n"))


def compare_hashes(h1, h2):
    """Constant-time comparison to check if two hashes are equal."""
    print()
    match = hmac.compare_digest(h1.lower().strip(), h2.lower().strip())
    if match:
        print(c("green", "  ✔ Hashes MATCH"))
    else:
        print(c("red", "  ✘ Hashes do NOT match"))
    print()


MENU = """
  ╔════════════════════════════════════════╗
  ║          SELECT AN OPTION             ║
  ╠════════════════════════════════════════╣
  ║  1)  Detect hash type                 ║
  ║  2)  Generate hash from plaintext     ║
  ║  3)  Generate HMAC                    ║
  ║  4)  Hash a file                      ║
  ║  5)  Batch detect from file           ║
  ║  6)  Compare two hashes               ║
  ║  7)  Exit                             ║
  ╚════════════════════════════════════════╝"""

def interactive_mode():
    print(c("cyan", BANNER))
    print(c("bold", HEADER))
    while True:
        print(MENU)
        choice = input(c("cyan", "\n  Enter choice: ")).strip()

        if choice == "1":
            h = input("  Enter hash: ").strip()
            analyze_hash(h)

        elif choice == "2":
            pt = input("  Enter plaintext: ").strip()
            print("\n  Algorithms: " + ", ".join(GENERATORS.keys()) + ", ALL")
            algo = input("  Choose algorithm [ALL]: ").strip() or "ALL"
            generate_hash(pt, algo)

        elif choice == "3":
            pt  = input("  Enter plaintext: ").strip()
            key = input("  Enter secret key: ").strip()
            print("\n  Algorithms: MD5, SHA1, SHA256, SHA512")
            algo = input("  Choose algorithm [SHA256]: ").strip() or "SHA256"
            generate_hmac(pt, key, algo)

        elif choice == "4":
            fp = input("  Enter file path: ").strip()
            hash_file(fp)

        elif choice == "5":
            fp = input("  Enter file path (one hash per line): ").strip()
            batch_detect(fp)

        elif choice == "6":
            h1 = input("  Enter first hash : ").strip()
            h2 = input("  Enter second hash: ").strip()
            compare_hashes(h1, h2)

        elif choice == "7":
            print(c("cyan", "\n  Goodbye — stay ethical.\n"))
            break

        else:
            print(c("red", "\n  [!] Invalid option, try again."))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="Ayham",
        description="Ethical Hash Detector Tool v2.0 — by Ayham Belal Megdadi",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd")

    p_det = sub.add_parser("detect", help="Detect hash type")
    p_det.add_argument("hash", help="Hash string to analyze")

    p_gen = sub.add_parser("generate", help="Generate hash from plaintext")
    p_gen.add_argument("plaintext")
    p_gen.add_argument("-a", "--algo", default="ALL",
                       help="Algorithm: MD5, SHA1, SHA256, SHA512, SHA3-256, SHA3-512, ALL (default)")

    p_hmac = sub.add_parser("hmac", help="Generate HMAC")
    p_hmac.add_argument("plaintext")
    p_hmac.add_argument("key", help="Secret key")
    p_hmac.add_argument("-a", "--algo", default="SHA256",
                        help="Algorithm: MD5, SHA1, SHA256, SHA512 (default: SHA256)")

    p_file = sub.add_parser("hashfile", help="Hash a file")
    p_file.add_argument("filepath")

    p_bat = sub.add_parser("batch", help="Batch detect from a text file")
    p_bat.add_argument("filepath")

    p_cmp = sub.add_parser("compare", help="Compare two hashes (constant-time)")
    p_cmp.add_argument("hash1")
    p_cmp.add_argument("hash2")

    return parser

def cli_mode(args):
    parser = build_parser()
    parsed = parser.parse_args(args)

    if parsed.cmd == "detect":
        analyze_hash(parsed.hash)
    elif parsed.cmd == "generate":
        generate_hash(parsed.plaintext, parsed.algo)
    elif parsed.cmd == "hmac":
        generate_hmac(parsed.plaintext, parsed.key, parsed.algo)
    elif parsed.cmd == "hashfile":
        hash_file(parsed.filepath)
    elif parsed.cmd == "batch":
        batch_detect(parsed.filepath)
    elif parsed.cmd == "compare":
        compare_hashes(parsed.hash1, parsed.hash2)
    else:
        parser.print_help()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        interactive_mode()
    else:
        cli_mode(sys.argv[1:])
