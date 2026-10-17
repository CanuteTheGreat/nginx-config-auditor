#!/usr/bin/env python3
"""
nginx-config-auditor: a small, free, stdlib-only static analyzer for nginx
configuration. It parses the config the way nginx does -- blocks, quoting,
and `include` directives followed (globs too) -- so headers or TLS settings
set in an included file count for the servers that include them, and checks
are made per server and per location on the merged tree.

Usage:
    nginx-config-auditor /etc/nginx/nginx.conf       # follows every include
    nginx-config-auditor /etc/nginx/                 # uses nginx.conf there; else each *.conf
    nginx-config-auditor --local                     # audits `nginx -T` output on this host
    nginx-config-auditor --dump nginx-T.txt          # a saved `nginx -T` dump ('-' = stdin)
    nginx-config-auditor --docker <container>        # `nginx -T` inside the container (docker cp fallback)

Checks include weak ssl_protocols/ssl_ciphers, autoindex, server_tokens,
missing security headers per server (http-level headers inherited the way
nginx inherits them), add_header in a location silently dropping inherited
security headers, security headers without `always`, alias path traversal
(location without trailing slash + alias with one), `valid_referers none`,
Host taken from $http_host, $uri/$document_uri in response headers (header
splitting), multi-line header values and unanchored Origin/Referer regexes.

No dependencies beyond the Python 3 standard library. Read-only: never
modifies any file it scans. Exit codes: 0 = no finding at or above
--fail-on (default: high), 1 = at least one, 2 = nothing to scan / usage error.
"""
__version__ = "1.2.1"

import argparse
import fnmatch
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_TOKENS = [
    "RC4", "DES", "3DES", "MD5", "EXPORT", "EXP", "LOW", "NULL", "aNULL", "eNULL", "ADH", "AECDH", "PSK",
]
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
]
SPLITTING_VARS = ("$uri", "$document_uri", "$path_info", "${uri}", "${document_uri}")
RAW_BLOCKS = re.compile(r"_by_lua_block$|^perl_set$|_by_njs_block$")


class ParseError(ValueError):
    pass


# --------------------------------------------------------------------------- parsing

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


def tokenize(text):
    """Yield (token, line, kind) with kind in {'word', 'quoted', '{', '}', ';'}."""
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c.isspace():
            i += 1
        elif c == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif c in "{};":
            yield c, line, c
            i += 1
        elif c in "\"'":
            q, j, buf, start = c, i + 1, [], line
            while j < n and text[j] != q:
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j + 1] if text[j + 1] in "\"'\\" else text[j:j + 2])
                    j += 2
                    continue
                if text[j] == "\n":
                    line += 1
                buf.append(text[j])
                j += 1
            if j >= n:
                raise ParseError("unterminated quoted string starting on line %d" % start)
            yield "".join(buf), start, "quoted"
            i = j + 1
        else:
            j, buf = i, []
            while j < n and not text[j].isspace() and text[j] not in ";\"'":
                if text[j] == "{":
                    if j > i and text[j - 1] == "$":      # ${var}
                        k = text.find("}", j)
                        if k < 0:
                            break
                        buf.append(text[j:k + 1])
                        j = k + 1
                        continue
                    break
                if text[j] == "}":
                    break
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j:j + 2])
                    j += 2
                    continue
                buf.append(text[j])
                j += 1
            yield "".join(buf), line, "word"
            i = j


def _skip_raw_block(text_tokens):
    depth = 1
    for tok, _, kind in text_tokens:
        if kind == "{":
            depth += 1
        elif kind == "}":
            depth -= 1
            if depth == 0:
                return


def parse(text, path):
    """Parse one file into a list of nodes {name, args, line, file, block}."""
    tokens = iter(tokenize(text))

    def block(depth):
        nodes, cur = [], None
        for tok, line, kind in tokens:
            if kind == "}":
                if cur:
                    raise ParseError("%s:%d: missing ';' before '}'" % (path, line))
                if depth == 0:
                    raise ParseError("%s:%d: unexpected '}'" % (path, line))
                return nodes
            if kind == ";":
                if cur:
                    nodes.append(cur)
                cur = None
                continue
            if kind == "{":
                if not cur:
                    raise ParseError("%s:%d: block without a directive name" % (path, line))
                if RAW_BLOCKS.search(cur["name"]):
                    _skip_raw_block(tokens)
                    cur["block"] = []
                else:
                    cur["block"] = block(depth + 1)
                nodes.append(cur)
                cur = None
                continue
            if cur is None:
                cur = {"name": tok, "args": [], "line": line, "file": path, "block": None}
            else:
                cur["args"].append(tok)
        if depth:
            raise ParseError("%s: unexpected end of file, a '{' is not closed" % path)
        if cur:
            raise ParseError("%s: unexpected end of file, missing ';'" % path)
        return nodes

    return block(0)


class Source:
    """Where included files come from: the filesystem, or the file map of an `nginx -T` dump."""

    def __init__(self, files=None):
        self.files = files  # {path: text} or None for the real filesystem
        self.read = []

    def text(self, path):
        if self.files is not None:
            return self.files[path]
        with open(path, "r", errors="replace") as fh:
            return fh.read()

    def glob(self, pattern):
        if self.files is not None:
            return sorted(p for p in self.files if fnmatch.fnmatch(p, pattern))
        return sorted(glob.glob(pattern))


def load(path, source, base_dir, findings, depth=0, stack=()):
    """Parse path and splice every `include` in place."""
    if depth > 32 or path in stack:
        findings.append(_f(path, None, "MEDIUM", "include_loop", "include loop or nesting deeper than 32 levels"))
        return []
    source.read.append(path)
    nodes = parse(source.text(path), path)
    return _expand(nodes, source, base_dir, findings, depth, stack + (path,))


def _expand(nodes, source, base_dir, findings, depth, stack):
    out = []
    for n in nodes:
        if n["name"] == "include" and n["block"] is None and n["args"]:
            pattern = n["args"][0]
            if not os.path.isabs(pattern):
                pattern = os.path.join(base_dir, pattern)
            matches = source.glob(pattern)
            if not matches and not glob.has_magic(pattern):
                findings.append(_f(n["file"], n["line"], "INFO", "include_missing",
                                   "include %s matches no file (nginx -t would fail)" % n["args"][0]))
            for m in matches:
                try:
                    out.extend(load(m, source, base_dir, findings, depth + 1, stack))
                except OSError as e:
                    findings.append(_f(n["file"], n["line"], "INFO", "include_unreadable", "cannot read %s: %s" % (m, e)))
            continue
        if n["block"] is not None:
            n["block"] = _expand(n["block"], source, base_dir, findings, depth, stack)
        out.append(n)
    return out


def parse_dump(text):
    """Split `nginx -T` output into {path: text} (first file = the main config)."""
    files, order, cur = {}, [], None
    for line in text.splitlines(keepends=True):
        m = re.match(r"# configuration file (.+):\s*$", line)
        if m:
            cur = m.group(1)
            files[cur] = ""
            order.append(cur)
        elif cur is not None:
            files[cur] += line
    if not order:
        raise ParseError("not an `nginx -T` dump (no '# configuration file ...:' headers)")
    return files, order[0]


# --------------------------------------------------------------------------- checks

def _f(path, line, sev, rule, msg):
    return {"file": path, "line": line, "severity": sev, "rule": rule, "message": msg}


# OpenSSL cipher-string aliases that include ANONYMOUS suites (no server authentication: anyone on
# the path can intercept) unless a "!aNULL" (or narrower "!ADH"/"!AECDH") removes them. ADH =
# anonymous DH suites, AECDH = anonymous ECDH suites. OpenSSL >= 1.1.0 refuses anonymous suites at
# its default security level, so they are only live when the string also says @SECLEVEL=0.
# Measured with `openssl ciphers` (OpenSSL 3.0); tests/test_accuracy.py checks every entry against
# a real nginx handshake.
_BOTH, _ADH, _AECDH = frozenset({"ADH", "AECDH"}), frozenset({"ADH"}), frozenset({"AECDH"})
ANON_ALIASES = {
    "ALL": _BOTH, "HIGH": _BOTH, "COMPLEMENTOFDEFAULT": _BOTH, "COMPLEMENTOFALL": _AECDH, "FIPS": _BOTH,
    "ANULL": _BOTH, "ADH": _ADH, "AECDH": _AECDH, "DH": _ADH, "KDHE": _ADH, "KEDH": _ADH,
    "ECDH": _AECDH, "KECDHE": _AECDH, "KEECDH": _AECDH, "AES": _BOTH, "AES128": _BOTH, "AES256": _BOTH,
    "AESGCM": _ADH, "CAMELLIA": _ADH, "CAMELLIA128": _ADH, "CAMELLIA256": _ADH, "SHA": _BOTH, "SHA1": _BOTH,
    "SHA256": _ADH, "SSLV3": _ADH, "TLSV1": _AECDH, "TLSV1.0": _AECDH, "TLSV1.2": _ADH,
    "ENULL": _AECDH, "NULL": _AECDH,
}


def _anon_of(token):
    """Anonymous suite families a positive cipher-string token enables ('A+B' = intersection)."""
    fams = None
    for part in token.split("+"):
        up = part.upper()
        if up.startswith("ADH-"):
            f = _ADH
        elif up.startswith("AECDH-"):
            f = _AECDH
        else:
            f = ANON_ALIASES.get(up, frozenset())
        fams = f if fams is None else fams & f
    return fams or frozenset()


def weak_cipher_hits(cipherspec):
    """Weak ciphers actually ENABLED by an OpenSSL cipher string. Excluded
    entries ("!aNULL", "-MD5") are the fix, not the problem -- the stock
    `HIGH:!aNULL:!MD5` must not be reported as weak -- but with @SECLEVEL=0,
    aliases like `HIGH` or `ALL` enable anonymous suites, and that is reported."""
    hits = []
    anon, banned, seclevel0 = set(), set(), False
    for tok in cipherspec.strip("\"'").replace(",", ":").replace(" ", ":").split(":"):
        if tok.upper().replace(" ", "") == "@SECLEVEL=0":
            seclevel0 = True
        if not tok or tok.startswith("@"):
            continue
        if tok[0] in "!-":
            fams = _anon_of(tok[1:])
            anon -= fams
            if tok[0] == "!":
                banned |= fams
            continue
        tok = tok.lstrip("+")
        anon |= _anon_of(tok) - banned
        parts = set(tok.split("-")) | {tok}
        for weak in WEAK_CIPHER_TOKENS:
            matched = weak in parts or (weak == "3DES" and "CBC3" in tok)
            if matched and weak not in hits:
                hits.append(weak)
    if seclevel0 and anon and not any(h in hits for h in ("aNULL", "ADH", "AECDH")):
        hits.append("anonymous (%s) suites: @SECLEVEL=0 plus an alias without !aNULL" % "/".join(sorted(anon)))
    return hits


def walk(nodes):
    for n in nodes:
        yield n
        if n["block"]:
            yield from walk(n["block"])


def headers_at(nodes):
    """add_header directives directly at this level: {lower name: node}."""
    return {n["args"][0].lower(): n for n in nodes if n["name"] == "add_header" and n["args"]}


def check_directives(tree, add):
    http2_directive = any(n["name"] == "http2" and n["args"][:1] == ["on"] for n in walk(tree))
    for n in walk(tree):
        name, args, line, path = n["name"], n["args"], n["line"], n["file"]
        a0 = args[0] if args else ""
        if name == "server_tokens" and a0.lower() == "on":
            add(path, line, "LOW", "server_tokens", "server_tokens on; leaks nginx version in headers/error pages")
        elif name == "autoindex" and a0.lower() == "on":
            add(path, line, "HIGH", "autoindex", "autoindex on; exposes directory listing")
        elif name == "ssl_protocols":
            weak = [p for p in args if p in WEAK_PROTOCOLS]
            if weak:
                add(path, line, "HIGH", "ssl_protocols", f"weak TLS/SSL protocol(s) enabled: {', '.join(weak)}")
        elif name == "ssl_ciphers":
            hits = weak_cipher_hits(" ".join(args))
            if hits:
                add(path, line, "HIGH", "ssl_ciphers", f"weak cipher token(s) present in ssl_ciphers: {', '.join(hits)}")
        elif name == "ssl_prefer_server_ciphers" and a0.lower() == "off":
            add(path, line, "LOW", "ssl_prefer_server_ciphers", "ssl_prefer_server_ciphers off; client can pick weak cipher order")
        elif name == "proxy_pass" and a0.startswith("http://"):
            add(path, line, "INFO", "proxy_pass_plaintext", "proxy_pass targets plain http:// backend (fine if backend is "
                                                             "same-host/internal, verify network path)")
        elif name == "listen" and "ssl" in args and "http2" not in args and not http2_directive:
            add(path, line, "INFO", "listen_no_http2", "listen ... ssl without http2 -- consider enabling HTTP/2 for perf "
                                                        "(not a security issue)")
        elif name in ("root", "alias") and a0 == "/":
            add(path, line, "MEDIUM", "root_alias_slash", f"{name} / ; serves entire filesystem root -- almost certainly unintended")
        elif name == "add_header" and a0.lower() == "server":
            add(path, line, "LOW", "custom_server_header", "manually setting Server header -- double-check it's not leaking version info")
        elif name == "ssi" and a0.lower() == "on":
            add(path, line, "INFO", "ssi_enabled", "SSI (Server Side Includes) enabled -- only a risk if untrusted users can "
                                                   "upload content served by this block")
        elif name == "auth_basic_user_file":
            add(path, line, "INFO", "auth_basic_present", "auth_basic_user_file configured -- verify the htpasswd file uses "
                                                          "bcrypt, not crypt/MD5")
        elif name == "add_header" and a0.lower() == "strict-transport-security" and len(args) > 1:
            m = re.search(r"max-age=\"?(\d+)", args[1], re.I)
            if not m or int(m.group(1)) < 15552000:
                add(path, line, "LOW", "hsts_short", "Strict-Transport-Security max-age is under 180 days "
                                                     "(recommended >= 15552000, 31536000 for preload)")
        elif name == "valid_referers" and "none" in args:
            add(path, line, "MEDIUM", "valid_referers_none", "valid_referers includes 'none': requests without a Referer "
                                                            "pass the check, so it doesn't protect anything on its own")
        elif name == "proxy_set_header" and a0.lower() == "host" and len(args) > 1 and args[1] in ("$http_host", "${http_host}"):
            add(path, line, "MEDIUM", "host_spoofing", "proxy_set_header Host $http_host forwards the client's raw Host "
                                                      "header; use $host (validated against server_name)")
        if name in ("add_header", "proxy_set_header", "more_set_headers") or (
                name == "return" and a0 in ("301", "302", "303", "307", "308")):
            value = " ".join(args[1:]) if name != "more_set_headers" else " ".join(args)
            if any(v in value for v in SPLITTING_VARS):
                add(path, line, "MEDIUM", "header_splitting", f"{name} uses $uri/$document_uri, which are URL-decoded and can "
                                                              "carry a CR/LF into the response headers; use $request_uri")
            if name == "add_header" and "\n" in value:
                add(path, line, "LOW", "multiline_header", "add_header value spans several lines; most clients reject or "
                                                           "mis-parse folded header values")
        if name == "if" and len(args) >= 3 and args[0].strip("(") in ("$http_origin", "$http_referer") and \
                args[1] in ("~", "~*"):
            rx = args[2].rstrip(")")
            if not rx.startswith("^") or not rx.endswith("$") or re.search(r"(?<!\\)\.", rx.replace(".*", "")):
                add(path, line, "MEDIUM", "origin_regex", f"{args[0].strip('(')} regex '{rx}' is not anchored (^...$) or has "
                                                           "unescaped dots, so look-alike origins/referers can match")


def _contexts(nodes, parent_headers, server, out, depth=0):
    """Walk server/location blocks applying add_header inheritance (a level with any add_header
    of its own inherits none from above)."""
    for n in nodes:
        if n["block"] is None:
            continue
        if n["name"] == "server" and depth >= 0:
            own = headers_at(n["block"])
            eff = own if own else parent_headers
            out.append(("server", n, eff, n))
            _contexts(n["block"], eff, n, out, depth + 1)
        elif n["name"] in ("location", "if", "limit_except") and server is not None:
            own = headers_at(n["block"])
            eff = own if own else parent_headers
            out.append((n["name"], n, eff, server, parent_headers, own))
            _contexts(n["block"], eff, server, out, depth + 1)
        elif n["name"] in ("http",):
            own = headers_at(n["block"])
            _contexts(n["block"], own or parent_headers, server, out, depth)


def server_label(server):
    names = [a for n in server["block"] if n["name"] == "server_name" for a in n["args"]]
    listen = [n["args"][0] for n in server["block"] if n["name"] == "listen" and n["args"]]
    return (names[0] if names and names[0] not in ("_", '""') else "default") + (" (%s)" % listen[0] if listen else "")


def check_headers(tree, add, root_file):
    found = []
    _contexts(tree, headers_at(tree), None, found)
    servers = [c for c in found if c[0] == "server"]
    sec = [h.lower() for h in SECURITY_HEADERS]
    if not servers:
        present = {n["args"][0].lower() for n in walk(tree) if n["name"] == "add_header" and n["args"]}
        for header in SECURITY_HEADERS:
            if header.lower() not in present:
                add(root_file, None, "MEDIUM", "missing_header", f"no add_header for {header} found (no server blocks here "
                                                                 "to check inheritance against)")
        return
    for _, node, eff, _ in servers:
        is_ssl = any(n["name"] == "listen" and "ssl" in n["args"] for n in node["block"]) or any(
            n["name"] == "ssl" and n["args"][:1] == ["on"] for n in node["block"])
        for header in SECURITY_HEADERS:
            if header == "Strict-Transport-Security" and not is_ssl:
                continue
            if header.lower() not in eff:
                add(node["file"], node["line"], "MEDIUM", "missing_header",
                    f"server {server_label(node)}: no add_header for {header} (effective at server level, including "
                    "headers inherited from http)")
            elif "always" not in eff[header.lower()]["args"][2:]:
                h = eff[header.lower()]
                add(h["file"], h["line"], "LOW", "header_not_always",
                    f"add_header {header} without 'always' is not sent on error responses (4xx/5xx)")
    for c in found:
        if c[0] == "server":
            continue
        kind, node, eff, server, parent, own = c
        if not own:
            continue
        dropped = [h for h in SECURITY_HEADERS if h.lower() in parent and h.lower() not in own]
        if dropped:
            where = " ".join([kind] + node["args"])
            add(node["file"], node["line"], "MEDIUM", "add_header_redefinition",
                f"{where} in server {server_label(server)} sets its own add_header, so nginx drops the inherited "
                f"{', '.join(dropped)} for these responses")


def check_alias(tree, add):
    for n in walk(tree):
        if n["name"] != "location" or not n["block"] or not n["args"]:
            continue
        if n["args"][0] in ("~", "~*", "=", "@") or n["args"][0].startswith("@"):
            continue
        prefix = n["args"][-1]
        for d in n["block"]:
            if d["name"] == "alias" and d["args"] and not prefix.endswith("/") and d["args"][0].endswith("/"):
                add(d["file"], d["line"], "HIGH", "alias_traversal",
                    f"location {prefix} (no trailing slash) with alias {d['args'][0]} (trailing slash): requests for "
                    f"{prefix}../ map outside the aliased directory -- end both with '/' or neither")


def audit_tree(tree, root_file, files_read):
    findings = []

    def add(path, line, sev, rule, msg):
        findings.append(_f(path, line, sev, rule, msg))

    check_directives(tree, add)
    check_headers(tree, add, root_file)
    check_alias(tree, add)
    names = {n["name"] for n in walk(tree)}
    if "ssl_protocols" not in names:
        add(root_file, None, "INFO", "ssl_protocols_unset", "no explicit ssl_protocols directive found (nginx defaults apply)")
    if "server_tokens" not in names:
        add(root_file, None, "LOW", "server_tokens_default",
            "server_tokens not set -- nginx defaults to 'on' (version disclosure)")
    if "ssl_certificate" in names and "ssl_dhparam" not in names:
        add(root_file, None, "LOW", "no_dhparam", "ssl_certificate present but no ssl_dhparam directive -- relying on "
                                                  "nginx/OpenSSL default DH params")
    return findings


# --------------------------------------------------------------------------- inputs

def find_files(path):
    if os.path.isfile(path):
        return [path]
    files = []
    for root, _dirs, names in os.walk(path):
        for n in names:
            if n.endswith(".conf") or n == "nginx.conf":
                files.append(os.path.join(root, n))
    return sorted(files)


def scan_paths(path):
    """Returns (files_read, findings). A file -> one tree with includes followed. A directory with an
    nginx.conf -> that tree (plus a note for .conf files it never includes). Otherwise each *.conf alone."""
    findings = []
    if os.path.isfile(path):
        roots = [path]
    else:
        main = os.path.join(path, "nginx.conf")
        roots = [main] if os.path.isfile(main) else find_files(path)
    if not roots:
        return [], None
    read = []
    for root in roots:
        source = Source()
        tree = load(root, source, os.path.dirname(os.path.abspath(root)), findings)
        read += [p for p in source.read if p not in read]
        findings += audit_tree(tree, root, source.read)
    if os.path.isdir(path) and os.path.isfile(os.path.join(path, "nginx.conf")):
        for f in find_files(path):
            if os.path.abspath(f) not in {os.path.abspath(r) for r in read}:
                findings.append(_f(f, None, "INFO", "not_included", "not included from nginx.conf, so not active "
                                                                     "(not audited)"))
    return read, findings


def scan_dump(text, label=None):
    files, root = parse_dump(text)
    findings = []
    source = Source(files)
    tree = load(root, source, os.path.dirname(root), findings)
    findings += audit_tree(tree, root, source.read)
    if label:
        for f in findings:
            f["file"] = f"{label}:{f['file']}"
    return [f"{label}:{p}" if label else p for p in source.read], findings


def docker_dump(container):
    """`nginx -T` inside the container; None if that isn't possible (no shell/nginx binary)."""
    try:
        p = subprocess.run(["docker", "exec", container, "nginx", "-T"], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True, timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"docker failed: {e}")
    if p.returncode == 0 and "# configuration file" in p.stdout:
        return p.stdout
    if "No such container" in p.stderr or "is not running" in p.stderr:
        raise RuntimeError(f"docker failed: {p.stderr.strip()}")
    return None


def docker_extract(container):
    tmpdir = tempfile.mkdtemp(prefix="nginx-audit-")
    try:
        subprocess.run(["docker", "cp", f"{container}:/etc/nginx", tmpdir + "/nginx"], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise RuntimeError(f"docker cp failed: {getattr(e, 'stderr', None) or e}")
    return tmpdir


def main(argv=None):
    ap = argparse.ArgumentParser(prog="nginx-config-auditor", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    ap.add_argument("path", nargs="?", help="config file or directory to scan")
    ap.add_argument("--docker", metavar="CONTAINER", help="audit the config of this running container (nginx -T, "
                                                          "or docker cp of /etc/nginx)")
    ap.add_argument("--local", action="store_true", help="run `nginx -T` on this host and audit the merged config")
    ap.add_argument("--dump", metavar="FILE", help="audit saved `nginx -T` output ('-' for stdin)")
    ap.add_argument("--json", action="store_true", help="output findings as JSON instead of text")
    ap.add_argument("--min-severity", default="INFO", choices=list(SEVERITY_ORDER),
                    help="only show findings at or above this severity")
    ap.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high",
                    help="lowest severity that makes the exit code 1 (default: high)")
    args = ap.parse_args(argv)

    if sum(bool(x) for x in (args.path, args.docker, args.local, args.dump)) != 1:
        ap.print_help(sys.stderr)
        return 2
    try:
        if args.docker:
            text = docker_dump(args.docker)
            if text is not None:
                files, findings = scan_dump(text, args.docker)
            else:
                tmp = docker_extract(args.docker)
                try:
                    files, findings = scan_paths(os.path.join(tmp, "nginx"))
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)
                findings = findings or []
                prefix = os.path.join(tmp, "nginx")
                for f in findings:
                    f["file"] = f"{args.docker}:/etc/nginx" + f["file"][len(prefix):]
                files = [f"{args.docker}:/etc/nginx" + p[len(prefix):] for p in files]
        elif args.local or args.dump:
            if args.local:
                try:
                    p = subprocess.run(["nginx", "-T"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       universal_newlines=True)
                except FileNotFoundError:
                    raise RuntimeError("`nginx` not found on PATH (try /usr/sbin, or run as root)")
                if p.returncode != 0:
                    raise RuntimeError(f"`nginx -T` failed: {p.stderr.strip()}")
                text = p.stdout
            else:
                text = sys.stdin.read() if args.dump == "-" else open(args.dump, errors="replace").read()
            files, findings = scan_dump(text)
        else:
            if not os.path.exists(args.path):
                print(f"path not found: {args.path}", file=sys.stderr)
                return 2
            files, findings = scan_paths(args.path)
            if files == [] and findings is None:
                print(f"no .conf files found under {args.path}", file=sys.stderr)
                return 2
    except (RuntimeError, OSError) as e:
        print(f"nginx-config-auditor: ERROR -- {e}", file=sys.stderr)
        return 2
    except ParseError as e:
        print(f"nginx-config-auditor: parse error -- {e}", file=sys.stderr)
        return 2
    return report(args, files, findings)


def report(args, files, all_findings):
    min_sev = SEVERITY_ORDER[args.min_severity]
    shown = [f for f in all_findings if SEVERITY_ORDER[f["severity"]] <= min_sev]
    shown.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["file"], f["line"] or 0))

    if args.json:
        print(json.dumps(shown, indent=2))
    else:
        print(f"nginx-config-auditor: scanned {len(files)} file(s), {len(shown)} finding(s)\n")
        for f in shown:
            loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            print(f"[{f['severity']:6}] {f['rule']:24} {loc}\n         {f['message']}\n")

    if args.fail_on == "never":
        return 0
    gate = SEVERITY_ORDER[args.fail_on.upper()]
    return 1 if any(SEVERITY_ORDER[f["severity"]] <= gate for f in all_findings) else 0


if __name__ == "__main__":
    sys.exit(main())
