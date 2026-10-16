#!/usr/bin/env python3
"""
nginx-config-auditor: a small, free, stdlib-only static analyzer for nginx
configuration files. It does NOT connect to any network service or require
nginx to be running -- it just parses config files/directories you point it
at and flags common misconfigurations.

Usage:
    python3 nginx_config_auditor.py /etc/nginx/nginx.conf
    python3 nginx_config_auditor.py /etc/nginx/            # scans *.conf recursively
    python3 nginx_config_auditor.py --docker <container>   # docker cp's the config out and scans it

No dependencies beyond the Python 3 standard library. Read-only: never
modifies any file it scans. Exit code is 0 if no HIGH-severity findings, 1
if any HIGH-severity finding is present (useful in CI).
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_TOKENS = [
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "aNULL", "eNULL", "ADH", "PSK",
]
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
]


def strip_comments(text):
    """Remove '#' comments, honouring single/double quotes (a '#' inside a
    quoted string is data, not a comment). Line structure is preserved."""
    out = []
    quote = None
    i = 0
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\" and i + 1 < len(text):
                out.append(text[i:i + 2])
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == "#":
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def statements(clean):
    """Yield (line_no, statement) for every ';'-terminated directive, joining
    directives that span several lines (e.g. a long ssl_ciphers list) and
    dropping block openers/closers. Whitespace is collapsed to single spaces."""
    buf = []
    start_line = None
    line = 1
    quote = None
    for c in clean:
        if c == "\n":
            line += 1
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            continue
        if c in "\"'":
            quote = c
        if c in "{}":
            buf, start_line = [], None
            continue
        if c == ";":
            stmt = " ".join("".join(buf).split())
            if stmt:
                yield start_line, stmt + ";"
            buf, start_line = [], None
            continue
        if start_line is None and not c.isspace():
            start_line = line
        buf.append(c)


def weak_cipher_hits(cipherspec):
    """Weak tokens actually ENABLED by an OpenSSL cipher string. Excluded
    entries ("!aNULL", "-MD5") are the fix, not the problem -- the stock
    `HIGH:!aNULL:!MD5` must not be reported as weak."""
    hits = []
    for tok in cipherspec.strip("\"'").replace(",", ":").replace(" ", ":").split(":"):
        if not tok or tok[0] in "!-" or tok.startswith("@"):
            continue
        tok = tok.lstrip("+")
        parts = set(tok.split("-")) | {tok}
        for weak in WEAK_CIPHER_TOKENS:
            matched = weak in parts or (weak == "3DES" and "CBC3" in tok)
            if matched and weak not in hits:
                hits.append(weak)
    return hits


def find_files(path):
    if os.path.isfile(path):
        return [path]
    files = []
    for root, _dirs, names in os.walk(path):
        for n in names:
            if n.endswith(".conf") or n == "nginx.conf":
                files.append(os.path.join(root, n))
    return sorted(files)


def audit_text(path, text):
    findings = []
    raw = text
    clean = strip_comments(text)

    def add(sev, rule, msg, line_no=None):
        findings.append({
            "file": path, "severity": sev, "rule": rule, "message": msg,
            "line": line_no,
        })

    http2_directive = re.search(r"(^|[;{}\s])http2\s+on\s*;", clean) is not None

    for i, l in statements(clean):

        # server_tokens on (or missing -> handled globally below)
        m = re.match(r"server_tokens\s+(\S+)\s*;", l)
        if m and m.group(1).rstrip(";").lower() == "on":
            add("LOW", "server_tokens", "server_tokens on; leaks nginx version in headers/error pages", i)

        # autoindex on
        m = re.match(r"autoindex\s+(\S+)\s*;", l)
        if m and m.group(1).lower() == "on":
            add("HIGH", "autoindex", "autoindex on; exposes directory listing", i)

        # ssl_protocols with weak versions
        m = re.match(r"ssl_protocols\s+(.+?)\s*;", l)
        if m:
            protos = m.group(1).split()
            weak = [p for p in protos if p in WEAK_PROTOCOLS]
            if weak:
                add("HIGH", "ssl_protocols", f"weak TLS/SSL protocol(s) enabled: {', '.join(weak)}", i)

        # ssl_ciphers weak tokens
        m = re.match(r"ssl_ciphers\s+(.+?)\s*;", l)
        if m:
            hits = weak_cipher_hits(m.group(1))
            if hits:
                add("HIGH", "ssl_ciphers", f"weak cipher token(s) present in ssl_ciphers: {', '.join(hits)}", i)

        # add_header with always missing on security headers (checked globally too)
        # ssl_prefer_server_ciphers off (weaker, not fatal)
        m = re.match(r"ssl_prefer_server_ciphers\s+(\S+)\s*;", l)
        if m and m.group(1).lower() == "off":
            add("LOW", "ssl_prefer_server_ciphers", "ssl_prefer_server_ciphers off; client can pick weak cipher order", i)

        # proxy_pass to plain http for what looks like a backend (informational)
        if re.match(r"proxy_pass\s+http://", l):
            add("INFO", "proxy_pass_plaintext", "proxy_pass targets plain http:// backend (fine if backend is same-host/internal, verify network path)", i)

        # listen ... ssl missing http2/modern (informational only)
        if re.match(r"listen\s+.*\bssl\b", l) and "http2" not in l and not http2_directive:
            add("INFO", "listen_no_http2", "listen ... ssl without http2 -- consider enabling HTTP/2 for perf (not a security issue)", i)

        # root/alias pointing at overly broad paths
        m = re.match(r"(root|alias)\s+/\s*;", l)
        if m:
            add("MEDIUM", "root_alias_slash", f"{m.group(1)} / ; serves entire filesystem root -- almost certainly unintended", i)

        # X-Powered-By or Server header manually leaking version
        if re.search(r"add_header\s+Server\s+", l, re.I):
            add("LOW", "custom_server_header", "manually setting Server header -- double-check it's not leaking version info", i)

        # SSI / autoindex format exposing directory
        if re.match(r"ssi\s+on\s*;", l, re.I):
            add("INFO", "ssi_enabled", "SSI (Server Side Includes) enabled -- only a risk if untrusted users can upload content served by this block", i)

        # basic auth file check (presence, not content -- can't verify strength safely/statically)
        if re.match(r"auth_basic_user_file\s+", l):
            add("INFO", "auth_basic_present", "auth_basic_user_file configured -- verify the htpasswd file uses bcrypt, not crypt/MD5", i)

    # Global (whole-file) checks
    if not re.search(r"\bssl_protocols\s", clean):
        add("INFO", "ssl_protocols_unset", "no explicit ssl_protocols directive found in this file (may be set elsewhere / using nginx defaults)")

    if not re.search(r"\bserver_tokens\s", clean):
        add("LOW", "server_tokens_default", "server_tokens not set explicitly -- nginx defaults to 'on' (version disclosure) unless set elsewhere")

    for header in SECURITY_HEADERS:
        if not re.search(r"\badd_header\s+[\"']?" + re.escape(header) + r"[\"']?\s", clean, re.I):
            add("MEDIUM", "missing_header", f"no add_header for {header} found in this file (may be set in an included file -- re-check merged config)")

    if re.search(r"\bssl_certificate\s+\S+\s*;", clean) and not re.search(r"\bssl_dhparam\s", clean):
        add("LOW", "no_dhparam", "ssl_certificate present but no ssl_dhparam directive -- relying on nginx/OpenSSL default DH params")

    return findings


def docker_extract(container):
    tmpdir = tempfile.mkdtemp(prefix="nginx-audit-")
    try:
        subprocess.run(
            ["docker", "cp", f"{container}:/etc/nginx", tmpdir + "/nginx"],
            check=True, capture_output=True, text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        print(f"docker cp failed: {getattr(e, 'stderr', None) or e}", file=sys.stderr)
        sys.exit(2)
    return tmpdir + "/nginx"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", help="config file or directory to scan")
    ap.add_argument("--docker", metavar="CONTAINER", help="docker cp /etc/nginx out of this running container and scan it")
    ap.add_argument("--json", action="store_true", help="output findings as JSON instead of text")
    ap.add_argument("--min-severity", default="INFO", choices=list(SEVERITY_ORDER), help="only show findings at or above this severity")
    args = ap.parse_args()

    tmp_root = None
    if args.docker:
        scan_path = docker_extract(args.docker)
        tmp_root = os.path.dirname(scan_path)
    elif args.path:
        scan_path = args.path
    else:
        ap.print_help()
        sys.exit(2)

    if not os.path.exists(scan_path):
        print(f"path not found: {scan_path}", file=sys.stderr)
        sys.exit(2)

    files = find_files(scan_path)
    if not files:
        print(f"no .conf files found under {scan_path}", file=sys.stderr)
        sys.exit(2)

    all_findings = []
    try:
        all_findings = scan(files)
    finally:
        if tmp_root:
            shutil.rmtree(tmp_root, ignore_errors=True)
    if tmp_root:
        prefix = os.path.join(tmp_root, "nginx")
        for f in all_findings:
            f["file"] = f"{args.docker}:/etc/nginx" + f["file"][len(prefix):]
    report(args, files, all_findings)


def scan(files):
    all_findings = []
    for f in files:
        try:
            with open(f, "r", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            print(f"skip {f}: {e}", file=sys.stderr)
            continue
        all_findings.extend(audit_text(f, text))
    return all_findings


def report(args, files, all_findings):
    min_sev = SEVERITY_ORDER[args.min_severity]
    shown = [f for f in all_findings if SEVERITY_ORDER[f["severity"]] <= min_sev]
    shown.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["file"], f["line"] or 0))

    if args.json:
        import json
        print(json.dumps(shown, indent=2))
    else:
        print(f"nginx-config-auditor: scanned {len(files)} file(s), {len(shown)} finding(s)\n")
        for f in shown:
            loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            print(f"[{f['severity']:6}] {f['rule']:24} {loc}\n         {f['message']}\n")

    high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")
    sys.exit(1 if high_count else 0)


if __name__ == "__main__":
    main()
