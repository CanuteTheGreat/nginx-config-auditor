"""Golden (exact-output) tests: every parser, check and report path pinned to its precise result.

`observe()` runs the tool over hand-built inputs (token streams, parse trees and errors, include
splicing, cipher strings, one config per rule, the CLI's text/JSON/exit-code paths with a fake
`docker` and `nginx` on PATH) and returns plain data; EXPECTED is that data, reviewed by hand
against nginx's own semantics. A changed message, severity, line number, separator, count or exit
code in any of them fails here (mutation testing found each of these unasserted).
"""
import contextlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import nginx_config_auditor as n  # noqa: E402

STRIP_IN = [
    "", "plain", "a # c\nb", "# only\n", "x '#not' y # c", 'x "#no" # yes\nz', "a\\\\#b",
    "'a\\'#b' # c", "\"q\\\"#\" #c", "q 'open # here", "line1 # c1\nline2 # c2\nline3",
    "a#b", "'\\", "# c", "a\\", "'x'#y\n", "\"x\"#y\n",
]
TOK_IN = [
    "", "a;", "a b;\nc d;", "server {\n listen 80;\n}", "a {b;}", "x \"q s\" 'p q';",
    "x 'a\\'b' \"c\\\"d\" 'e\\\\f' 'g\\nh';", "x 'multi\nline' y;", "# c\na; # d\nb;",
    "set $x ${var}suffix;", "set $x ${open", "a}b", "a\\;b c\\ d;", "a\\", "if ($a ~ ^x$) {",
    "log_format m '$a'\n  '$b';", "x 'unterminated", "x \"unterminated\n\n",
    "a;b;{}", "  \t a  ;", "a\r\nb;", "word{", "$x{y}", "${v}", "$", "q'x'", 'q"x"',
    "a\n\n\nb ;\n", "x 'a\nb' c;\nd;", "x\\\\y;", "'\\\\'",
]
PARSE_OK = [
    "", "a b c;", "http {\n server {\n listen 80;\n }\n}", "a;\nb {\n c d;\n e {\n f;\n }\n}\n",
    "content_by_lua_block { local x = {1,{2}} }\nafter;", "perl_set $v { if (1) { x } }\nafter;",
    "init_by_njs_block { a { b } }\nlast;", "a 'q;q' \"r{r\";", "location / {}", "events {}\nhttp {}",
]
PARSE_ERR = [
    "a b", "a b }", "}", "{", "a {", "a { b;", "a { b }", "x;\n}", "{ a; }", "a;\n\n b c }",
    "a 'unterminated", "a {\n b;\n\n", "a;\nb", "a { b { c; }",
]
CIPHERS = [
    "HIGH:!aNULL:!MD5", "RC4", "DES-CBC3-SHA", "ECDHE-RSA-AES128-GCM-SHA256:RC4-SHA", "!RC4:HIGH",
    "-RC4:HIGH", "+RC4", "EXPORT:LOW:NULL:aNULL:eNULL:ADH:AECDH:PSK", "EXP-RC4-MD5", "MD5:SHA",
    "\"HIGH:RC4\"", "HIGH RC4", "HIGH,MD5", "@SECLEVEL=0:ALL", "ALL:@SECLEVEL=0", "@seclevel=0:HIGH",
    "@SECLEVEL=0:HIGH:!aNULL", "@SECLEVEL=0:ALL:!ADH", "@SECLEVEL=0:ALL:!AECDH", "@SECLEVEL=0:ALL:-ADH",
    "@SECLEVEL=0:ADH", "@SECLEVEL=0:AECDH:ADH", "@SECLEVEL=0:ECDH", "@SECLEVEL=0:AES128+SHA",
    "@SECLEVEL=0:ADH-AES128-SHA", "@SECLEVEL=0:AECDH-NULL-SHA", "@SECLEVEL=0:DH+AES",
    "@SECLEVEL=1:ALL", "@STRENGTH:ALL", "TLSv1.2", "@SECLEVEL=0:TLSv1.2:!ADH", "@SECLEVEL=0:AES+ECDH",
    "ALL:!ALL", "kEDH+AESGCM", "@SECLEVEL=0:!aNULL:ALL", "@SECLEVEL=0:ALL:!aNULL:RC4", "AES128-CBC3-SHA",
    "ECDHE-ECDSA-3DES-EDE-CBC-SHA", "NULL-MD5", "RC4-MD5:DES-CBC-SHA", "ADH-AES256-SHA", "aNULL:eNULL",
    "@SECLEVEL=0:COMPLEMENTOFALL", "@SECLEVEL=0:ENULL", "@SECLEVEL=0:SSLv3", "a::b", "",
    "@SECLEVEL=0 : ALL", "HIGH:+MD5", "!MD5:RC4:MD5", "ECDHE-RSA-RC4-SHA",
]

CONFIGS = {
    "bare": "http {\n}\n",
    "tokens_default": "events {}\nhttp {\n  server {\n    listen 80;\n  }\n}\n",
    "everything": """http {
  server_tokens on;
  autoindex on;
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  ssl_ciphers HIGH:RC4:!MD5;
  ssl_prefer_server_ciphers off;
  ssl_certificate /etc/ssl/a.pem;
  add_header Strict-Transport-Security "max-age=300";
  server {
    listen 443 ssl;
    server_name a.example;
    root /;
    location /x { alias /; proxy_pass http://127.0.0.1:8080; }
    location /y { ssi on; auth_basic_user_file /etc/htpasswd; add_header Server "x"; }
    location /z { valid_referers none blocked a.example; proxy_set_header Host $http_host; }
    location /h { add_header X-Redir $uri; return 301 $uri; add_header X-Y "a
b"; }
    location /o { if ($http_origin ~ example.com) { return 403; } if ($http_referer ~* ^https://a.example.com$) { x; } }
    location /files { alias /srv/files/; }
    location /files2/ { alias /srv/files; }
    location ~ /re { alias /srv/re/; }
    location @named { alias /srv/n/; }
  }
}
""",
    "hsts_long": "http {\n server_tokens off;\n ssl_protocols TLSv1.2 TLSv1.3;\n server {\n  listen 443 ssl http2;\n  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n  add_header X-Content-Type-Options nosniff always;\n  add_header X-Frame-Options DENY always;\n  add_header Content-Security-Policy \"default-src 'self'\" always;\n  add_header Referrer-Policy no-referrer always;\n }\n}\n",
    "hsts_forms": "http { server_tokens off; server { listen 443 ssl; add_header Strict-Transport-Security \"max-age=15552000\" always; add_header Strict-Transport-Security 'max-age=15551999' always; add_header Strict-Transport-Security \"preload\" always; add_header Strict-Transport-Security max-age=\"99999999\" always; add_header Strict-Transport-Security; } }\n",
    "inherit": """http {
  server_tokens off;
  add_header X-Frame-Options DENY always;
  add_header X-Content-Type-Options nosniff;
  server {
    listen 80;
    server_name _;
    location /a { add_header X-Other 1; }
    location /b { add_header X-Frame-Options SAMEORIGIN always; add_header Referrer-Policy origin always; }
    if ($x) { add_header Y 1; }
    location /c { limit_except GET { add_header Z 1; } }
  }
  server {
    listen 8080;
    server_name "";
    add_header Content-Security-Policy "x" always;
    location / { add_header Q 1; }
  }
  server {
    server_name b.example c.example;
    ssl on;
  }
  server {
    listen 443 ssl;
    server_name d.example;
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Content-Security-Policy "c" always;
    add_header Referrer-Policy x always;
    add_header Y 1;
  }
}
""",
    "http2_directive": "http {\n server_tokens off;\n http2 on;\n server { listen 443 ssl; }\n server { listen 80; }\n}\n",
    "listen_variants": "http { server_tokens off; server { listen 443 ssl; } server { listen 443 ssl http2; } server { listen 80 ssl; listen 443; } }\n",
    "no_servers": "http { add_header X-Frame-Options DENY always; add_header Referrer-Policy x; }\n",
    "no_servers_all": "http { server_tokens off; add_header Strict-Transport-Security x always; add_header X-Content-Type-Options x always; add_header X-Frame-Options x always; add_header Content-Security-Policy x always; add_header Referrer-Policy x always; }\n",
    "dhparam": "http { server_tokens off; ssl_protocols TLSv1.3; ssl_certificate /a; ssl_dhparam /d; }\n",
    "splitting": "http { server_tokens off; server { listen 80; add_header X-A ${uri}; add_header X-B $document_uri; proxy_set_header X-C $path_info; more_set_headers \"X-D: $uri\"; return 302 /x$document_uri; return 200 $uri; return 404 $uri; add_header X-OK $request_uri; add_header $uri x; } }\n",
    "origin": "http { server_tokens off; server { listen 80; if ($http_origin ~ ^https://a\\.example$) { x; } if ($http_origin ~* ^https://a.example$) { x; } if ($http_origin ~ ^https://.*\\.example$) { x; } if ($http_origin = x) { y; } if ($http_origin ~ x) { y; } if ($http_origin ~ ^x) { y; } if ($http_referer ~ ^https://a\\.example$) { x; } if ($other ~ bad) { x; } if (($http_origin ~ y$)) { x; } if ($http_origin ~) { x; } } }\n",
    "alias_cases": "http { server_tokens off; server { listen 80; location /a { alias /x/; } location /b/ { alias /x/; } location /c { alias /x; } location = /d { alias /x/; } location ~* /e { alias /x/; } location @f { alias /x/; } location / { alias /x/; } location ^~ /g { alias /x/; } location /h { } location { alias /x/; } } }\n",
    "include_main": "include conf.d/*.conf;\ninclude missing.conf;\ninclude nothing/*.conf;\nhttp {\n  include \"common.conf\";\n  server { listen 80; include /etc/nginx/srv.conf; }\n}\n",
    "lua": "http { server_tokens off; server { listen 80; content_by_lua_block { autoindex on; } } }\n",
}
INC_FILES = {
    "/etc/nginx/nginx.conf": CONFIGS["include_main"],
    "/etc/nginx/conf.d/a.conf": "server_tokens on;\n",
    "/etc/nginx/conf.d/b.conf": "autoindex on;\n",
    "/etc/nginx/conf.d/c.txt": "ssi on;\n",
    "/etc/nginx/common.conf": "ssl_protocols SSLv3;\n",
    "/etc/nginx/srv.conf": "root /;\n",
}
LOOP_FILES = {
    "/a.conf": "include b.conf;\nx;\n", "/b.conf": "include a.conf;\ny;\n",
}
DEEP_FILES = dict(("/d%d.conf" % i, "include d%d.conf;\nn%d;\n" % (i + 1, i)) for i in range(40))
DUMP = (
    "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n"
    "# configuration file /etc/nginx/nginx.conf:\n"
    "events {}\nhttp {\n  include /etc/nginx/mime.types;\n  include /etc/nginx/sites/*;\n}\n"
    "# configuration file /etc/nginx/mime.types:\n"
    "types { text/html html; }\n"
    "# configuration file /etc/nginx/sites/x:\n"
    "server { listen 80; autoindex on; }\n"
)


def run_main(argv, stdin=None, path_dirs=()):
    out, err = io.StringIO(), io.StringIO()
    old_in, old_path = sys.stdin, os.environ.get("PATH", "")
    if stdin is not None:
        sys.stdin = io.StringIO(stdin)
    if path_dirs:
        os.environ["PATH"] = os.pathsep.join(path_dirs)  # exactly these: no real nginx/docker may leak in
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = n.main(argv)
            except SystemExit as e:
                rc = ["exit", e.code]
    finally:
        sys.stdin = old_in
        os.environ["PATH"] = old_path
    fix = lambda s: s.replace("optional arguments:", "options:").replace("'docker': 'docker'", "'docker'")  # Python < 3.10 / 3.7 word these differently
    return [rc, fix(out.getvalue()), fix(err.getvalue())]


def script(dirpath, name, body):
    p = os.path.join(dirpath, name)
    with open(p, "w") as f:
        f.write("#!/bin/sh\n" + body)
    os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)


def audit_text(text):
    files, findings = n.scan_dump("# configuration file /etc/nginx/nginx.conf:\n" + text)
    return findings


def listing(findings):
    return [[f["file"], f["line"], f["severity"], f["rule"], f["message"]] for f in findings]


def observe():
    o = {}
    o["strip"] = [n.strip_comments(s) for s in STRIP_IN]
    toks = []
    for s in TOK_IN:
        try:
            toks.append([list(t) for t in n.tokenize(s)])
        except n.ParseError as e:
            toks.append("ParseError: %s" % e)
    o["tokenize"] = toks
    po = []
    for s in PARSE_OK:
        po.append(json.loads(json.dumps(n.parse(s, "p.conf"))))
    o["parse_ok"] = po
    pe = []
    for s in PARSE_ERR:
        try:
            n.parse(s, "p.conf")
            pe.append("no error")
        except n.ParseError as e:
            pe.append(str(e))
    o["parse_err"] = pe
    o["ciphers"] = [n.weak_cipher_hits(c) for c in CIPHERS]
    o["anon_of"] = [sorted(n._anon_of(t)) for t in ("ALL", "adh-x", "AECDH-y", "AES+ECDH", "SHA+NULL", "zzz", "HIGH+zzz", "ADH", "tlsv1")]
    for name, text in CONFIGS.items():
        if name == "include_main":
            continue
        o["audit_" + name] = listing(audit_text(text))
    # include splicing
    findings = []
    src = n.Source(INC_FILES)
    tree = n.load("/etc/nginx/nginx.conf", src, "/etc/nginx", findings)
    o["inc_tree"] = [[x["name"], x["args"], x["line"], x["file"], None if x["block"] is None else [y["name"] for y in x["block"]]] for x in tree]
    o["inc_findings"] = listing(findings)
    o["inc_read"] = src.read
    findings = []
    src = n.Source(LOOP_FILES)
    tree = n.load("/a.conf", src, "/", findings)
    o["loop_tree"] = [[x["name"], x["file"]] for x in tree]
    o["loop_findings"] = listing(findings)
    o["loop_read"] = src.read
    findings = []
    src = n.Source(DEEP_FILES)
    tree = n.load("/d0.conf", src, "/", findings)
    o["deep_tree"] = [x["name"] for x in tree]
    o["deep_findings"] = listing(findings)
    o["deep_read"] = len(src.read)
    o["source_glob"] = [n.Source(INC_FILES).glob("/etc/nginx/conf.d/*.conf"), n.Source(INC_FILES).glob("/etc/nginx/*.conf"),
                        n.Source(INC_FILES).glob("/etc/nginx/conf.d/[ab].conf")]
    # dumps
    files, root = n.parse_dump(DUMP)
    o["dump"] = [files, root]
    try:
        n.parse_dump("nothing here\n")
        o["dump_err"] = "no error"
    except n.ParseError as e:
        o["dump_err"] = str(e)
    rd, fd = n.scan_dump(DUMP)
    o["scan_dump"] = [rd, listing(fd)]
    rd, fd = n.scan_dump(DUMP, "web1")
    o["scan_dump_label"] = [rd, listing(fd)]
    o["server_label"] = [n.server_label(x) for x in (
        {"block": []}, {"block": [{"name": "server_name", "args": ["a", "b"]}]},
        {"block": [{"name": "server_name", "args": ["_"]}, {"name": "listen", "args": ["80"]}]},
        {"block": [{"name": "server_name", "args": ['""']}, {"name": "listen", "args": ["443", "ssl"]}, {"name": "listen", "args": ["8"]}]},
        {"block": [{"name": "listen", "args": []}, {"name": "listen", "args": ["81"]}]},
        {"block": [{"name": "server_name", "args": []}, {"name": "server_name", "args": ["x"]}]})]
    # filesystem scans
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "conf.d"))
        os.makedirs(os.path.join(d, "alone"))
        os.makedirs(os.path.join(d, "empty"))
        def w(rel, text):
            with open(os.path.join(d, rel), "w") as fh:
                fh.write(text)
        w("nginx.conf", "http {\n  include conf.d/*.conf;\n}\n")
        w("conf.d/a.conf", "server { listen 80; autoindex on; }\n")
        w("conf.d/b.conf", "server_tokens on;\n")
        w("stray.conf", "ssi on;\n")
        w("notes.txt", "x")
        w("alone/one.conf", "autoindex on;\n")
        w("alone/two.conf", "server_tokens off;\n")
        w("alone/nginx.txt", "x")
        w("solo.conf", "root /;\n")
        def rel(s):
            return s.replace(d, "<D>")
        r, f = n.scan_paths(d)
        o["scan_dir_main"] = [[rel(x) for x in r], [[rel(a) if isinstance(a, str) else a for a in x] for x in listing(f)]]
        r, f = n.scan_paths(os.path.join(d, "alone"))
        o["scan_dir_alone"] = [[rel(x) for x in r], [[rel(a) if isinstance(a, str) else a for a in x] for x in listing(f)]]
        r, f = n.scan_paths(os.path.join(d, "solo.conf"))
        o["scan_file"] = [[rel(x) for x in r], [[rel(a) if isinstance(a, str) else a for a in x] for x in listing(f)]]
        r, f = n.scan_paths(os.path.join(d, "empty"))
        o["scan_empty"] = [r, f]
        o["find_files"] = [rel(x) for x in n.find_files(d)] + [rel(x) for x in n.find_files(os.path.join(d, "solo.conf"))]
        # CLI
        def rr(res):
            return [res[0], rel(res[1]), rel(res[2])]
        o["cli_noargs"] = run_main([])
        o["cli_two"] = run_main(["x", "--local"])
        o["cli_version"] = run_main(["--version"])
        o["cli_missing"] = rr(run_main([os.path.join(d, "nope")]))
        o["cli_empty"] = rr(run_main([os.path.join(d, "empty")]))
        o["cli_text_dir"] = rr(run_main([d]))
        o["cli_json_file"] = rr(run_main(["--json", os.path.join(d, "solo.conf")]))
        o["cli_min_high"] = rr(run_main(["--min-severity", "HIGH", d]))
        o["cli_min_medium"] = rr(run_main(["--min-severity", "MEDIUM", d]))
        o["cli_min_low"] = rr(run_main(["--min-severity", "LOW", d]))
        for fo in ("high", "medium", "low", "never"):
            for cfg in ("bare", "hsts_long", "everything", "origin", "listen_variants"):
                p = os.path.join(d, "c-%s.conf" % cfg)
                with open(p, "w") as fh:
                    fh.write(CONFIGS[cfg])
                o["cli_fail_%s_%s" % (fo, cfg)] = run_main(["--fail-on", fo, "--min-severity", "HIGH", p])[0]
        w("broken.conf", "a {\n")
        o["cli_parse_error"] = rr(run_main([os.path.join(d, "broken.conf")]))
        w("dump.txt", DUMP)
        o["cli_dump_file"] = rr(run_main(["--dump", os.path.join(d, "dump.txt")]))
        o["cli_dump_stdin"] = rr(run_main(["--dump", "-"], stdin=DUMP))
        o["cli_dump_bad"] = rr(run_main(["--dump", os.path.join(d, "notes.txt")]))
        o["cli_dump_missing"] = rr(run_main(["--dump", os.path.join(d, "absent.txt")]))
        # fake nginx for --local
        bindir = os.path.join(d, "bin")
        os.makedirs(bindir)
        script(bindir, "nginx", "cat <<'EOF'\n" + DUMP + "EOF\n")
        o["cli_local"] = rr(run_main(["--local", "--min-severity", "MEDIUM"], path_dirs=[bindir, "/usr/bin", "/bin"]))
        bin2 = os.path.join(d, "bin2")
        os.makedirs(bin2)
        script(bin2, "nginx", "echo 'boom: cannot open' >&2\nexit 1\n")
        o["cli_local_fail"] = rr(run_main(["--local"], path_dirs=[bin2, "/usr/bin", "/bin"]))
        o["cli_local_missing"] = rr(run_main(["--local"], path_dirs=[os.path.join(d, "no-such-bin")]))
        # fake docker: nginx -T works / container missing / cp fallback
        b3 = os.path.join(d, "bin3")
        os.makedirs(b3)
        script(b3, "docker", 'if [ "$1" = exec ]; then cat <<\'EOF\'\n' + DUMP + "EOF\nexit 0; fi\nexit 1\n")
        o["cli_docker_dump"] = rr(run_main(["--docker", "web1"], path_dirs=[b3, "/usr/bin", "/bin"]))
        b4 = os.path.join(d, "bin4")
        os.makedirs(b4)
        script(b4, "docker", 'echo "Error: No such container: $3" >&2\nexit 1\n')
        o["cli_docker_nocontainer"] = rr(run_main(["--docker", "ghost"], path_dirs=[b4, "/usr/bin", "/bin"]))
        b5 = os.path.join(d, "bin5")
        os.makedirs(b5)
        script(b5, "docker", 'echo "Error response: container x is not running" >&2\nexit 1\n')
        o["cli_docker_notrunning"] = rr(run_main(["--docker", "x"], path_dirs=[b5, "/usr/bin", "/bin"]))
        b6 = os.path.join(d, "bin6")
        os.makedirs(b6)
        script(b6, "docker", 'if [ "$1" = exec ]; then echo "exec failed: no nginx" >&2; exit 126; fi\n'
                             'if [ "$1" = cp ]; then mkdir -p "$3"; printf "server { listen 80; autoindex on; }\\n" > "$3/nginx.conf"; exit 0; fi\nexit 1\n')
        o["cli_docker_cp"] = rr(run_main(["--docker", "web2"], path_dirs=[b6, "/usr/bin", "/bin"]))
        b7 = os.path.join(d, "bin7")
        os.makedirs(b7)
        script(b7, "docker", 'if [ "$1" = exec ]; then exit 126; fi\necho "cp denied" >&2\nexit 1\n')
        o["cli_docker_cp_fail"] = rr(run_main(["--docker", "web3"], path_dirs=[b7, "/usr/bin", "/bin"]))
        o["cli_docker_nodocker"] = rr(run_main(["--docker", "web3"], path_dirs=[os.path.join(d, "none")]))
    # help text (whitespace-squashed, section title removed: it differs across Pythons)
    h = run_main(["--help"])
    body = " ".join(h[1].split())
    body = body.replace("options:", "").replace("optional arguments:", "")
    o["help"] = " ".join(body.split())
    return o


EXPECTED = {'anon_of': [['ADH', 'AECDH'], ['ADH'], ['AECDH'], ['AECDH'], ['AECDH'], [], [], ['ADH'], ['AECDH']],
 'audit_alias_cases': [['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                        'server default (80): no add_header for X-Content-Type-Options (effective at server level, including '
                        'headers inherited from http)'],
                       ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                        'server default (80): no add_header for X-Frame-Options (effective at server level, including headers '
                        'inherited from http)'],
                       ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                        'server default (80): no add_header for Content-Security-Policy (effective at server level, including '
                        'headers inherited from http)'],
                       ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                        'server default (80): no add_header for Referrer-Policy (effective at server level, including headers '
                        'inherited from http)'],
                       ['/etc/nginx/nginx.conf', 1, 'HIGH', 'alias_traversal',
                        'location /a (no trailing slash) with alias /x/ (trailing slash): requests for /a../ map outside the '
                        "aliased directory -- end both with '/' or neither"],
                       ['/etc/nginx/nginx.conf', 1, 'HIGH', 'alias_traversal',
                        'location /g (no trailing slash) with alias /x/ (trailing slash): requests for /g../ map outside the '
                        "aliased directory -- end both with '/' or neither"],
                       ['/etc/nginx/nginx.conf', None, 'INFO', 'ssl_protocols_unset',
                        'no explicit ssl_protocols directive found (nginx defaults apply)']],
 'audit_bare': [['/etc/nginx/nginx.conf', None, 'MEDIUM', 'missing_header',
                 'no add_header for Strict-Transport-Security found (no server blocks here to check inheritance against)'],
                ['/etc/nginx/nginx.conf', None, 'MEDIUM', 'missing_header',
                 'no add_header for X-Content-Type-Options found (no server blocks here to check inheritance against)'],
                ['/etc/nginx/nginx.conf', None, 'MEDIUM', 'missing_header',
                 'no add_header for X-Frame-Options found (no server blocks here to check inheritance against)'],
                ['/etc/nginx/nginx.conf', None, 'MEDIUM', 'missing_header',
                 'no add_header for Content-Security-Policy found (no server blocks here to check inheritance against)'],
                ['/etc/nginx/nginx.conf', None, 'MEDIUM', 'missing_header',
                 'no add_header for Referrer-Policy found (no server blocks here to check inheritance against)'],
                ['/etc/nginx/nginx.conf', None, 'INFO', 'ssl_protocols_unset',
                 'no explicit ssl_protocols directive found (nginx defaults apply)'],
                ['/etc/nginx/nginx.conf', None, 'LOW', 'server_tokens_default',
                 "server_tokens not set -- nginx defaults to 'on' (version disclosure)"]],
 'audit_dhparam': [['/etc/nginx/nginx.conf', None, 'MEDIUM', 'missing_header',
                    'no add_header for Strict-Transport-Security found (no server blocks here to check inheritance against)'],
                   ['/etc/nginx/nginx.conf', None, 'MEDIUM', 'missing_header',
                    'no add_header for X-Content-Type-Options found (no server blocks here to check inheritance against)'],
                   ['/etc/nginx/nginx.conf', None, 'MEDIUM', 'missing_header',
                    'no add_header for X-Frame-Options found (no server blocks here to check inheritance against)'],
                   ['/etc/nginx/nginx.conf', None, 'MEDIUM', 'missing_header',
                    'no add_header for Content-Security-Policy found (no server blocks here to check inheritance against)'],
                   ['/etc/nginx/nginx.conf', None, 'MEDIUM', 'missing_header',
                    'no add_header for Referrer-Policy found (no server blocks here to check inheritance against)']],
 'audit_everything': [['/etc/nginx/nginx.conf', 2, 'LOW', 'server_tokens',
                       'server_tokens on; leaks nginx version in headers/error pages'],
                      ['/etc/nginx/nginx.conf', 3, 'HIGH', 'autoindex', 'autoindex on; exposes directory listing'],
                      ['/etc/nginx/nginx.conf', 4, 'HIGH', 'ssl_protocols', 'weak TLS/SSL protocol(s) enabled: TLSv1, TLSv1.1'],
                      ['/etc/nginx/nginx.conf', 5, 'HIGH', 'ssl_ciphers', 'weak cipher token(s) present in ssl_ciphers: RC4'],
                      ['/etc/nginx/nginx.conf', 6, 'LOW', 'ssl_prefer_server_ciphers',
                       'ssl_prefer_server_ciphers off; client can pick weak cipher order'],
                      ['/etc/nginx/nginx.conf', 8, 'LOW', 'hsts_short',
                       'Strict-Transport-Security max-age is under 180 days (recommended >= 15552000, 31536000 for preload)'],
                      ['/etc/nginx/nginx.conf', 10, 'INFO', 'listen_no_http2',
                       'listen ... ssl without http2 -- consider enabling HTTP/2 for perf (not a security issue)'],
                      ['/etc/nginx/nginx.conf', 12, 'MEDIUM', 'root_alias_slash',
                       'root / ; serves entire filesystem root -- almost certainly unintended'],
                      ['/etc/nginx/nginx.conf', 13, 'MEDIUM', 'root_alias_slash',
                       'alias / ; serves entire filesystem root -- almost certainly unintended'],
                      ['/etc/nginx/nginx.conf', 13, 'INFO', 'proxy_pass_plaintext',
                       'proxy_pass targets plain http:// backend (fine if backend is same-host/internal, verify network path)'],
                      ['/etc/nginx/nginx.conf', 14, 'INFO', 'ssi_enabled',
                       'SSI (Server Side Includes) enabled -- only a risk if untrusted users can upload content served by this '
                       'block'],
                      ['/etc/nginx/nginx.conf', 14, 'INFO', 'auth_basic_present',
                       'auth_basic_user_file configured -- verify the htpasswd file uses bcrypt, not crypt/MD5'],
                      ['/etc/nginx/nginx.conf', 14, 'LOW', 'custom_server_header',
                       "manually setting Server header -- double-check it's not leaking version info"],
                      ['/etc/nginx/nginx.conf', 15, 'MEDIUM', 'valid_referers_none',
                       "valid_referers includes 'none': requests without a Referer pass the check, so it doesn't protect "
                       'anything on its own'],
                      ['/etc/nginx/nginx.conf', 15, 'MEDIUM', 'host_spoofing',
                       "proxy_set_header Host $http_host forwards the client's raw Host header; use $host (validated against "
                       'server_name)'],
                      ['/etc/nginx/nginx.conf', 16, 'MEDIUM', 'header_splitting',
                       'add_header uses $uri/$document_uri, which are URL-decoded and can carry a CR/LF into the response '
                       'headers; use $request_uri'],
                      ['/etc/nginx/nginx.conf', 16, 'MEDIUM', 'header_splitting',
                       'return uses $uri/$document_uri, which are URL-decoded and can carry a CR/LF into the response headers; '
                       'use $request_uri'],
                      ['/etc/nginx/nginx.conf', 16, 'LOW', 'multiline_header',
                       'add_header value spans several lines; most clients reject or mis-parse folded header values'],
                      ['/etc/nginx/nginx.conf', 18, 'MEDIUM', 'origin_regex',
                       "$http_origin regex 'example.com' is not anchored (^...$) or has unescaped dots, so look-alike "
                       'origins/referers can match'],
                      ['/etc/nginx/nginx.conf', 18, 'MEDIUM', 'origin_regex',
                       "$http_referer regex '^https://a.example.com$' is not anchored (^...$) or has unescaped dots, so "
                       'look-alike origins/referers can match'],
                      ['/etc/nginx/nginx.conf', 8, 'LOW', 'header_not_always',
                       "add_header Strict-Transport-Security without 'always' is not sent on error responses (4xx/5xx)"],
                      ['/etc/nginx/nginx.conf', 9, 'MEDIUM', 'missing_header',
                       'server a.example (443): no add_header for X-Content-Type-Options (effective at server level, including '
                       'headers inherited from http)'],
                      ['/etc/nginx/nginx.conf', 9, 'MEDIUM', 'missing_header',
                       'server a.example (443): no add_header for X-Frame-Options (effective at server level, including headers '
                       'inherited from http)'],
                      ['/etc/nginx/nginx.conf', 9, 'MEDIUM', 'missing_header',
                       'server a.example (443): no add_header for Content-Security-Policy (effective at server level, including '
                       'headers inherited from http)'],
                      ['/etc/nginx/nginx.conf', 9, 'MEDIUM', 'missing_header',
                       'server a.example (443): no add_header for Referrer-Policy (effective at server level, including headers '
                       'inherited from http)'],
                      ['/etc/nginx/nginx.conf', 14, 'MEDIUM', 'add_header_redefinition',
                       'location /y in server a.example (443) sets its own add_header, so nginx drops the inherited '
                       'Strict-Transport-Security for these responses'],
                      ['/etc/nginx/nginx.conf', 16, 'MEDIUM', 'add_header_redefinition',
                       'location /h in server a.example (443) sets its own add_header, so nginx drops the inherited '
                       'Strict-Transport-Security for these responses'],
                      ['/etc/nginx/nginx.conf', 13, 'HIGH', 'alias_traversal',
                       'location /x (no trailing slash) with alias / (trailing slash): requests for /x../ map outside the '
                       "aliased directory -- end both with '/' or neither"],
                      ['/etc/nginx/nginx.conf', 19, 'HIGH', 'alias_traversal',
                       'location /files (no trailing slash) with alias /srv/files/ (trailing slash): requests for /files../ map '
                       "outside the aliased directory -- end both with '/' or neither"],
                      ['/etc/nginx/nginx.conf', None, 'LOW', 'no_dhparam',
                       'ssl_certificate present but no ssl_dhparam directive -- relying on nginx/OpenSSL default DH params']],
 'audit_hsts_forms': [['/etc/nginx/nginx.conf', 1, 'INFO', 'listen_no_http2',
                       'listen ... ssl without http2 -- consider enabling HTTP/2 for perf (not a security issue)'],
                      ['/etc/nginx/nginx.conf', 1, 'LOW', 'hsts_short',
                       'Strict-Transport-Security max-age is under 180 days (recommended >= 15552000, 31536000 for preload)'],
                      ['/etc/nginx/nginx.conf', 1, 'LOW', 'hsts_short',
                       'Strict-Transport-Security max-age is under 180 days (recommended >= 15552000, 31536000 for preload)'],
                      ['/etc/nginx/nginx.conf', 1, 'LOW', 'hsts_short',
                       'Strict-Transport-Security max-age is under 180 days (recommended >= 15552000, 31536000 for preload)'],
                      ['/etc/nginx/nginx.conf', 1, 'LOW', 'header_not_always',
                       "add_header Strict-Transport-Security without 'always' is not sent on error responses (4xx/5xx)"],
                      ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                       'server default (443): no add_header for X-Content-Type-Options (effective at server level, including '
                       'headers inherited from http)'],
                      ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                       'server default (443): no add_header for X-Frame-Options (effective at server level, including headers '
                       'inherited from http)'],
                      ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                       'server default (443): no add_header for Content-Security-Policy (effective at server level, including '
                       'headers inherited from http)'],
                      ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                       'server default (443): no add_header for Referrer-Policy (effective at server level, including headers '
                       'inherited from http)'],
                      ['/etc/nginx/nginx.conf', None, 'INFO', 'ssl_protocols_unset',
                       'no explicit ssl_protocols directive found (nginx defaults apply)']],
 'audit_hsts_long': [],
 'audit_http2_directive': [['/etc/nginx/nginx.conf', 4, 'MEDIUM', 'missing_header',
                            'server default (443): no add_header for Strict-Transport-Security (effective at server level, '
                            'including headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 4, 'MEDIUM', 'missing_header',
                            'server default (443): no add_header for X-Content-Type-Options (effective at server level, '
                            'including headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 4, 'MEDIUM', 'missing_header',
                            'server default (443): no add_header for X-Frame-Options (effective at server level, including '
                            'headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 4, 'MEDIUM', 'missing_header',
                            'server default (443): no add_header for Content-Security-Policy (effective at server level, '
                            'including headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 4, 'MEDIUM', 'missing_header',
                            'server default (443): no add_header for Referrer-Policy (effective at server level, including '
                            'headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 5, 'MEDIUM', 'missing_header',
                            'server default (80): no add_header for X-Content-Type-Options (effective at server level, including '
                            'headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 5, 'MEDIUM', 'missing_header',
                            'server default (80): no add_header for X-Frame-Options (effective at server level, including '
                            'headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 5, 'MEDIUM', 'missing_header',
                            'server default (80): no add_header for Content-Security-Policy (effective at server level, '
                            'including headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 5, 'MEDIUM', 'missing_header',
                            'server default (80): no add_header for Referrer-Policy (effective at server level, including '
                            'headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', None, 'INFO', 'ssl_protocols_unset',
                            'no explicit ssl_protocols directive found (nginx defaults apply)']],
 'audit_inherit': [['/etc/nginx/nginx.conf', 24, 'INFO', 'listen_no_http2',
                    'listen ... ssl without http2 -- consider enabling HTTP/2 for perf (not a security issue)'],
                   ['/etc/nginx/nginx.conf', 4, 'LOW', 'header_not_always',
                    "add_header X-Content-Type-Options without 'always' is not sent on error responses (4xx/5xx)"],
                   ['/etc/nginx/nginx.conf', 5, 'MEDIUM', 'missing_header',
                    'server default (80): no add_header for Content-Security-Policy (effective at server level, including '
                    'headers inherited from http)'],
                   ['/etc/nginx/nginx.conf', 5, 'MEDIUM', 'missing_header',
                    'server default (80): no add_header for Referrer-Policy (effective at server level, including headers '
                    'inherited from http)'],
                   ['/etc/nginx/nginx.conf', 13, 'MEDIUM', 'missing_header',
                    'server  (8080): no add_header for X-Content-Type-Options (effective at server level, including headers '
                    'inherited from http)'],
                   ['/etc/nginx/nginx.conf', 13, 'MEDIUM', 'missing_header',
                    'server  (8080): no add_header for X-Frame-Options (effective at server level, including headers inherited '
                    'from http)'],
                   ['/etc/nginx/nginx.conf', 13, 'MEDIUM', 'missing_header',
                    'server  (8080): no add_header for Referrer-Policy (effective at server level, including headers inherited '
                    'from http)'],
                   ['/etc/nginx/nginx.conf', 19, 'MEDIUM', 'missing_header',
                    'server b.example: no add_header for Strict-Transport-Security (effective at server level, including headers '
                    'inherited from http)'],
                   ['/etc/nginx/nginx.conf', 4, 'LOW', 'header_not_always',
                    "add_header X-Content-Type-Options without 'always' is not sent on error responses (4xx/5xx)"],
                   ['/etc/nginx/nginx.conf', 19, 'MEDIUM', 'missing_header',
                    'server b.example: no add_header for Content-Security-Policy (effective at server level, including headers '
                    'inherited from http)'],
                   ['/etc/nginx/nginx.conf', 19, 'MEDIUM', 'missing_header',
                    'server b.example: no add_header for Referrer-Policy (effective at server level, including headers inherited '
                    'from http)'],
                   ['/etc/nginx/nginx.conf', 8, 'MEDIUM', 'add_header_redefinition',
                    'location /a in server default (80) sets its own add_header, so nginx drops the inherited '
                    'X-Content-Type-Options, X-Frame-Options for these responses'],
                   ['/etc/nginx/nginx.conf', 9, 'MEDIUM', 'add_header_redefinition',
                    'location /b in server default (80) sets its own add_header, so nginx drops the inherited '
                    'X-Content-Type-Options for these responses'],
                   ['/etc/nginx/nginx.conf', 10, 'MEDIUM', 'add_header_redefinition',
                    'if ($x) in server default (80) sets its own add_header, so nginx drops the inherited '
                    'X-Content-Type-Options, X-Frame-Options for these responses'],
                   ['/etc/nginx/nginx.conf', 11, 'MEDIUM', 'add_header_redefinition',
                    'limit_except GET in server default (80) sets its own add_header, so nginx drops the inherited '
                    'X-Content-Type-Options, X-Frame-Options for these responses'],
                   ['/etc/nginx/nginx.conf', 17, 'MEDIUM', 'add_header_redefinition',
                    'location / in server  (8080) sets its own add_header, so nginx drops the inherited Content-Security-Policy '
                    'for these responses'],
                   ['/etc/nginx/nginx.conf', None, 'INFO', 'ssl_protocols_unset',
                    'no explicit ssl_protocols directive found (nginx defaults apply)']],
 'audit_listen_variants': [['/etc/nginx/nginx.conf', 1, 'INFO', 'listen_no_http2',
                            'listen ... ssl without http2 -- consider enabling HTTP/2 for perf (not a security issue)'],
                           ['/etc/nginx/nginx.conf', 1, 'INFO', 'listen_no_http2',
                            'listen ... ssl without http2 -- consider enabling HTTP/2 for perf (not a security issue)'],
                           ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                            'server default (443): no add_header for Strict-Transport-Security (effective at server level, '
                            'including headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                            'server default (443): no add_header for X-Content-Type-Options (effective at server level, '
                            'including headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                            'server default (443): no add_header for X-Frame-Options (effective at server level, including '
                            'headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                            'server default (443): no add_header for Content-Security-Policy (effective at server level, '
                            'including headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                            'server default (443): no add_header for Referrer-Policy (effective at server level, including '
                            'headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                            'server default (443): no add_header for Strict-Transport-Security (effective at server level, '
                            'including headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                            'server default (443): no add_header for X-Content-Type-Options (effective at server level, '
                            'including headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                            'server default (443): no add_header for X-Frame-Options (effective at server level, including '
                            'headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                            'server default (443): no add_header for Content-Security-Policy (effective at server level, '
                            'including headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                            'server default (443): no add_header for Referrer-Policy (effective at server level, including '
                            'headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                            'server default (80): no add_header for Strict-Transport-Security (effective at server level, '
                            'including headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                            'server default (80): no add_header for X-Content-Type-Options (effective at server level, including '
                            'headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                            'server default (80): no add_header for X-Frame-Options (effective at server level, including '
                            'headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                            'server default (80): no add_header for Content-Security-Policy (effective at server level, '
                            'including headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                            'server default (80): no add_header for Referrer-Policy (effective at server level, including '
                            'headers inherited from http)'],
                           ['/etc/nginx/nginx.conf', None, 'INFO', 'ssl_protocols_unset',
                            'no explicit ssl_protocols directive found (nginx defaults apply)']],
 'audit_lua': [['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                'server default (80): no add_header for X-Content-Type-Options (effective at server level, including headers '
                'inherited from http)'],
               ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                'server default (80): no add_header for X-Frame-Options (effective at server level, including headers inherited '
                'from http)'],
               ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                'server default (80): no add_header for Content-Security-Policy (effective at server level, including headers '
                'inherited from http)'],
               ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                'server default (80): no add_header for Referrer-Policy (effective at server level, including headers inherited '
                'from http)'],
               ['/etc/nginx/nginx.conf', None, 'INFO', 'ssl_protocols_unset',
                'no explicit ssl_protocols directive found (nginx defaults apply)']],
 'audit_no_servers': [['/etc/nginx/nginx.conf', None, 'MEDIUM', 'missing_header',
                       'no add_header for Strict-Transport-Security found (no server blocks here to check inheritance against)'],
                      ['/etc/nginx/nginx.conf', None, 'MEDIUM', 'missing_header',
                       'no add_header for X-Content-Type-Options found (no server blocks here to check inheritance against)'],
                      ['/etc/nginx/nginx.conf', None, 'MEDIUM', 'missing_header',
                       'no add_header for Content-Security-Policy found (no server blocks here to check inheritance against)'],
                      ['/etc/nginx/nginx.conf', None, 'INFO', 'ssl_protocols_unset',
                       'no explicit ssl_protocols directive found (nginx defaults apply)'],
                      ['/etc/nginx/nginx.conf', None, 'LOW', 'server_tokens_default',
                       "server_tokens not set -- nginx defaults to 'on' (version disclosure)"]],
 'audit_no_servers_all': [['/etc/nginx/nginx.conf', 1, 'LOW', 'hsts_short',
                           'Strict-Transport-Security max-age is under 180 days (recommended >= 15552000, 31536000 for preload)'],
                          ['/etc/nginx/nginx.conf', None, 'INFO', 'ssl_protocols_unset',
                           'no explicit ssl_protocols directive found (nginx defaults apply)']],
 'audit_origin': [['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'origin_regex',
                   "$http_origin regex '^https://a.example$' is not anchored (^...$) or has unescaped dots, so look-alike "
                   'origins/referers can match'],
                  ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'origin_regex',
                   "$http_origin regex 'x' is not anchored (^...$) or has unescaped dots, so look-alike origins/referers can "
                   'match'],
                  ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'origin_regex',
                   "$http_origin regex '^x' is not anchored (^...$) or has unescaped dots, so look-alike origins/referers can "
                   'match'],
                  ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'origin_regex',
                   "$http_origin regex 'y$' is not anchored (^...$) or has unescaped dots, so look-alike origins/referers can "
                   'match'],
                  ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                   'server default (80): no add_header for X-Content-Type-Options (effective at server level, including headers '
                   'inherited from http)'],
                  ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                   'server default (80): no add_header for X-Frame-Options (effective at server level, including headers '
                   'inherited from http)'],
                  ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                   'server default (80): no add_header for Content-Security-Policy (effective at server level, including headers '
                   'inherited from http)'],
                  ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                   'server default (80): no add_header for Referrer-Policy (effective at server level, including headers '
                   'inherited from http)'],
                  ['/etc/nginx/nginx.conf', None, 'INFO', 'ssl_protocols_unset',
                   'no explicit ssl_protocols directive found (nginx defaults apply)']],
 'audit_splitting': [['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'header_splitting',
                      'add_header uses $uri/$document_uri, which are URL-decoded and can carry a CR/LF into the response '
                      'headers; use $request_uri'],
                     ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'header_splitting',
                      'add_header uses $uri/$document_uri, which are URL-decoded and can carry a CR/LF into the response '
                      'headers; use $request_uri'],
                     ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'header_splitting',
                      'proxy_set_header uses $uri/$document_uri, which are URL-decoded and can carry a CR/LF into the response '
                      'headers; use $request_uri'],
                     ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'header_splitting',
                      'more_set_headers uses $uri/$document_uri, which are URL-decoded and can carry a CR/LF into the response '
                      'headers; use $request_uri'],
                     ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'header_splitting',
                      'return uses $uri/$document_uri, which are URL-decoded and can carry a CR/LF into the response headers; '
                      'use $request_uri'],
                     ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                      'server default (80): no add_header for X-Content-Type-Options (effective at server level, including '
                      'headers inherited from http)'],
                     ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                      'server default (80): no add_header for X-Frame-Options (effective at server level, including headers '
                      'inherited from http)'],
                     ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                      'server default (80): no add_header for Content-Security-Policy (effective at server level, including '
                      'headers inherited from http)'],
                     ['/etc/nginx/nginx.conf', 1, 'MEDIUM', 'missing_header',
                      'server default (80): no add_header for Referrer-Policy (effective at server level, including headers '
                      'inherited from http)'],
                     ['/etc/nginx/nginx.conf', None, 'INFO', 'ssl_protocols_unset',
                      'no explicit ssl_protocols directive found (nginx defaults apply)']],
 'audit_tokens_default': [['/etc/nginx/nginx.conf', 3, 'MEDIUM', 'missing_header',
                           'server default (80): no add_header for X-Content-Type-Options (effective at server level, including '
                           'headers inherited from http)'],
                          ['/etc/nginx/nginx.conf', 3, 'MEDIUM', 'missing_header',
                           'server default (80): no add_header for X-Frame-Options (effective at server level, including headers '
                           'inherited from http)'],
                          ['/etc/nginx/nginx.conf', 3, 'MEDIUM', 'missing_header',
                           'server default (80): no add_header for Content-Security-Policy (effective at server level, including '
                           'headers inherited from http)'],
                          ['/etc/nginx/nginx.conf', 3, 'MEDIUM', 'missing_header',
                           'server default (80): no add_header for Referrer-Policy (effective at server level, including headers '
                           'inherited from http)'],
                          ['/etc/nginx/nginx.conf', None, 'INFO', 'ssl_protocols_unset',
                           'no explicit ssl_protocols directive found (nginx defaults apply)'],
                          ['/etc/nginx/nginx.conf', None, 'LOW', 'server_tokens_default',
                           "server_tokens not set -- nginx defaults to 'on' (version disclosure)"]],
 'ciphers': [[], ['RC4'], ['DES', '3DES'], ['RC4'], [], [], ['RC4'],
             ['EXPORT', 'LOW', 'NULL', 'aNULL', 'eNULL', 'ADH', 'AECDH', 'PSK'], ['RC4', 'MD5', 'EXP'], ['MD5'], ['RC4'], ['RC4'],
             ['MD5'], ['anonymous (ADH/AECDH) suites: @SECLEVEL=0 plus an alias without !aNULL'],
             ['anonymous (ADH/AECDH) suites: @SECLEVEL=0 plus an alias without !aNULL'],
             ['anonymous (ADH/AECDH) suites: @SECLEVEL=0 plus an alias without !aNULL'], [],
             ['anonymous (AECDH) suites: @SECLEVEL=0 plus an alias without !aNULL'],
             ['anonymous (ADH) suites: @SECLEVEL=0 plus an alias without !aNULL'],
             ['anonymous (AECDH) suites: @SECLEVEL=0 plus an alias without !aNULL'], ['ADH'], ['AECDH', 'ADH'],
             ['anonymous (AECDH) suites: @SECLEVEL=0 plus an alias without !aNULL'],
             ['anonymous (ADH/AECDH) suites: @SECLEVEL=0 plus an alias without !aNULL'], ['ADH'], ['NULL', 'AECDH'],
             ['anonymous (ADH) suites: @SECLEVEL=0 plus an alias without !aNULL'], [], [], [], [],
             ['anonymous (AECDH) suites: @SECLEVEL=0 plus an alias without !aNULL'], [], [], [], ['RC4'], ['3DES'], ['3DES'],
             ['MD5', 'NULL'], ['RC4', 'MD5', 'DES'], ['ADH'], ['aNULL', 'eNULL'],
             ['anonymous (AECDH) suites: @SECLEVEL=0 plus an alias without !aNULL'],
             ['anonymous (AECDH) suites: @SECLEVEL=0 plus an alias without !aNULL'],
             ['anonymous (ADH) suites: @SECLEVEL=0 plus an alias without !aNULL'], [], [],
             ['anonymous (ADH/AECDH) suites: @SECLEVEL=0 plus an alias without !aNULL'], ['MD5'], ['RC4', 'MD5'], ['RC4']],
 'cli_docker_cp': [1,
                   'nginx-config-auditor: scanned 1 file(s), 7 finding(s)\n'
                   '\n'
                   '[HIGH  ] autoindex                web2:/etc/nginx/nginx.conf:1\n'
                   '         autoindex on; exposes directory listing\n'
                   '\n'
                   '[MEDIUM] missing_header           web2:/etc/nginx/nginx.conf:1\n'
                   '         server default (80): no add_header for X-Content-Type-Options (effective at server level, including '
                   'headers inherited from http)\n'
                   '\n'
                   '[MEDIUM] missing_header           web2:/etc/nginx/nginx.conf:1\n'
                   '         server default (80): no add_header for X-Frame-Options (effective at server level, including '
                   'headers inherited from http)\n'
                   '\n'
                   '[MEDIUM] missing_header           web2:/etc/nginx/nginx.conf:1\n'
                   '         server default (80): no add_header for Content-Security-Policy (effective at server level, '
                   'including headers inherited from http)\n'
                   '\n'
                   '[MEDIUM] missing_header           web2:/etc/nginx/nginx.conf:1\n'
                   '         server default (80): no add_header for Referrer-Policy (effective at server level, including '
                   'headers inherited from http)\n'
                   '\n'
                   '[LOW   ] server_tokens_default    web2:/etc/nginx/nginx.conf\n'
                   "         server_tokens not set -- nginx defaults to 'on' (version disclosure)\n"
                   '\n'
                   '[INFO  ] ssl_protocols_unset      web2:/etc/nginx/nginx.conf\n'
                   '         no explicit ssl_protocols directive found (nginx defaults apply)\n'
                   '\n',
                   ''],
 'cli_docker_cp_fail': [2, '', 'nginx-config-auditor: ERROR -- docker cp failed: cp denied\n\n'],
 'cli_docker_dump': [1,
                     'nginx-config-auditor: scanned 3 file(s), 7 finding(s)\n'
                     '\n'
                     '[HIGH  ] autoindex                web1:/etc/nginx/sites/x:1\n'
                     '         autoindex on; exposes directory listing\n'
                     '\n'
                     '[MEDIUM] missing_header           web1:/etc/nginx/sites/x:1\n'
                     '         server default (80): no add_header for X-Content-Type-Options (effective at server level, '
                     'including headers inherited from http)\n'
                     '\n'
                     '[MEDIUM] missing_header           web1:/etc/nginx/sites/x:1\n'
                     '         server default (80): no add_header for X-Frame-Options (effective at server level, including '
                     'headers inherited from http)\n'
                     '\n'
                     '[MEDIUM] missing_header           web1:/etc/nginx/sites/x:1\n'
                     '         server default (80): no add_header for Content-Security-Policy (effective at server level, '
                     'including headers inherited from http)\n'
                     '\n'
                     '[MEDIUM] missing_header           web1:/etc/nginx/sites/x:1\n'
                     '         server default (80): no add_header for Referrer-Policy (effective at server level, including '
                     'headers inherited from http)\n'
                     '\n'
                     '[LOW   ] server_tokens_default    web1:/etc/nginx/nginx.conf\n'
                     "         server_tokens not set -- nginx defaults to 'on' (version disclosure)\n"
                     '\n'
                     '[INFO  ] ssl_protocols_unset      web1:/etc/nginx/nginx.conf\n'
                     '         no explicit ssl_protocols directive found (nginx defaults apply)\n'
                     '\n',
                     ''],
 'cli_docker_nocontainer': [2, '', 'nginx-config-auditor: ERROR -- docker failed: Error: No such container: nginx\n'],
 'cli_docker_nodocker': [2, '', "nginx-config-auditor: ERROR -- docker failed: [Errno 2] No such file or directory: 'docker'\n"],
 'cli_docker_notrunning': [2, '', 'nginx-config-auditor: ERROR -- docker failed: Error response: container x is not running\n'],
 'cli_dump_bad': [2, '',
                  "nginx-config-auditor: parse error -- not an `nginx -T` dump (no '# configuration file ...:' headers)\n"],
 'cli_dump_file': [1,
                   'nginx-config-auditor: scanned 3 file(s), 7 finding(s)\n'
                   '\n'
                   '[HIGH  ] autoindex                /etc/nginx/sites/x:1\n'
                   '         autoindex on; exposes directory listing\n'
                   '\n'
                   '[MEDIUM] missing_header           /etc/nginx/sites/x:1\n'
                   '         server default (80): no add_header for X-Content-Type-Options (effective at server level, including '
                   'headers inherited from http)\n'
                   '\n'
                   '[MEDIUM] missing_header           /etc/nginx/sites/x:1\n'
                   '         server default (80): no add_header for X-Frame-Options (effective at server level, including '
                   'headers inherited from http)\n'
                   '\n'
                   '[MEDIUM] missing_header           /etc/nginx/sites/x:1\n'
                   '         server default (80): no add_header for Content-Security-Policy (effective at server level, '
                   'including headers inherited from http)\n'
                   '\n'
                   '[MEDIUM] missing_header           /etc/nginx/sites/x:1\n'
                   '         server default (80): no add_header for Referrer-Policy (effective at server level, including '
                   'headers inherited from http)\n'
                   '\n'
                   '[LOW   ] server_tokens_default    /etc/nginx/nginx.conf\n'
                   "         server_tokens not set -- nginx defaults to 'on' (version disclosure)\n"
                   '\n'
                   '[INFO  ] ssl_protocols_unset      /etc/nginx/nginx.conf\n'
                   '         no explicit ssl_protocols directive found (nginx defaults apply)\n'
                   '\n',
                   ''],
 'cli_dump_missing': [2, '', "nginx-config-auditor: ERROR -- [Errno 2] No such file or directory: '<D>/absent.txt'\n"],
 'cli_dump_stdin': [1,
                    'nginx-config-auditor: scanned 3 file(s), 7 finding(s)\n'
                    '\n'
                    '[HIGH  ] autoindex                /etc/nginx/sites/x:1\n'
                    '         autoindex on; exposes directory listing\n'
                    '\n'
                    '[MEDIUM] missing_header           /etc/nginx/sites/x:1\n'
                    '         server default (80): no add_header for X-Content-Type-Options (effective at server level, '
                    'including headers inherited from http)\n'
                    '\n'
                    '[MEDIUM] missing_header           /etc/nginx/sites/x:1\n'
                    '         server default (80): no add_header for X-Frame-Options (effective at server level, including '
                    'headers inherited from http)\n'
                    '\n'
                    '[MEDIUM] missing_header           /etc/nginx/sites/x:1\n'
                    '         server default (80): no add_header for Content-Security-Policy (effective at server level, '
                    'including headers inherited from http)\n'
                    '\n'
                    '[MEDIUM] missing_header           /etc/nginx/sites/x:1\n'
                    '         server default (80): no add_header for Referrer-Policy (effective at server level, including '
                    'headers inherited from http)\n'
                    '\n'
                    '[LOW   ] server_tokens_default    /etc/nginx/nginx.conf\n'
                    "         server_tokens not set -- nginx defaults to 'on' (version disclosure)\n"
                    '\n'
                    '[INFO  ] ssl_protocols_unset      /etc/nginx/nginx.conf\n'
                    '         no explicit ssl_protocols directive found (nginx defaults apply)\n'
                    '\n',
                    ''],
 'cli_empty': [2, '', 'no .conf files found under <D>/empty\n'],
 'cli_fail_high_bare': 0,
 'cli_fail_high_everything': 1,
 'cli_fail_high_hsts_long': 0,
 'cli_fail_high_listen_variants': 0,
 'cli_fail_high_origin': 0,
 'cli_fail_low_bare': 1,
 'cli_fail_low_everything': 1,
 'cli_fail_low_hsts_long': 0,
 'cli_fail_low_listen_variants': 1,
 'cli_fail_low_origin': 1,
 'cli_fail_medium_bare': 1,
 'cli_fail_medium_everything': 1,
 'cli_fail_medium_hsts_long': 0,
 'cli_fail_medium_listen_variants': 1,
 'cli_fail_medium_origin': 1,
 'cli_fail_never_bare': 0,
 'cli_fail_never_everything': 0,
 'cli_fail_never_hsts_long': 0,
 'cli_fail_never_listen_variants': 0,
 'cli_fail_never_origin': 0,
 'cli_json_file': [0,
                   '[\n'
                   '  {\n'
                   '    "file": "<D>/solo.conf",\n'
                   '    "line": null,\n'
                   '    "severity": "MEDIUM",\n'
                   '    "rule": "missing_header",\n'
                   '    "message": "no add_header for Strict-Transport-Security found (no server blocks here to check '
                   'inheritance against)"\n'
                   '  },\n'
                   '  {\n'
                   '    "file": "<D>/solo.conf",\n'
                   '    "line": null,\n'
                   '    "severity": "MEDIUM",\n'
                   '    "rule": "missing_header",\n'
                   '    "message": "no add_header for X-Content-Type-Options found (no server blocks here to check inheritance '
                   'against)"\n'
                   '  },\n'
                   '  {\n'
                   '    "file": "<D>/solo.conf",\n'
                   '    "line": null,\n'
                   '    "severity": "MEDIUM",\n'
                   '    "rule": "missing_header",\n'
                   '    "message": "no add_header for X-Frame-Options found (no server blocks here to check inheritance '
                   'against)"\n'
                   '  },\n'
                   '  {\n'
                   '    "file": "<D>/solo.conf",\n'
                   '    "line": null,\n'
                   '    "severity": "MEDIUM",\n'
                   '    "rule": "missing_header",\n'
                   '    "message": "no add_header for Content-Security-Policy found (no server blocks here to check inheritance '
                   'against)"\n'
                   '  },\n'
                   '  {\n'
                   '    "file": "<D>/solo.conf",\n'
                   '    "line": null,\n'
                   '    "severity": "MEDIUM",\n'
                   '    "rule": "missing_header",\n'
                   '    "message": "no add_header for Referrer-Policy found (no server blocks here to check inheritance '
                   'against)"\n'
                   '  },\n'
                   '  {\n'
                   '    "file": "<D>/solo.conf",\n'
                   '    "line": 1,\n'
                   '    "severity": "MEDIUM",\n'
                   '    "rule": "root_alias_slash",\n'
                   '    "message": "root / ; serves entire filesystem root -- almost certainly unintended"\n'
                   '  },\n'
                   '  {\n'
                   '    "file": "<D>/solo.conf",\n'
                   '    "line": null,\n'
                   '    "severity": "LOW",\n'
                   '    "rule": "server_tokens_default",\n'
                   '    "message": "server_tokens not set -- nginx defaults to \'on\' (version disclosure)"\n'
                   '  },\n'
                   '  {\n'
                   '    "file": "<D>/solo.conf",\n'
                   '    "line": null,\n'
                   '    "severity": "INFO",\n'
                   '    "rule": "ssl_protocols_unset",\n'
                   '    "message": "no explicit ssl_protocols directive found (nginx defaults apply)"\n'
                   '  }\n'
                   ']\n',
                   ''],
 'cli_local': [1,
               'nginx-config-auditor: scanned 3 file(s), 5 finding(s)\n'
               '\n'
               '[HIGH  ] autoindex                /etc/nginx/sites/x:1\n'
               '         autoindex on; exposes directory listing\n'
               '\n'
               '[MEDIUM] missing_header           /etc/nginx/sites/x:1\n'
               '         server default (80): no add_header for X-Content-Type-Options (effective at server level, including '
               'headers inherited from http)\n'
               '\n'
               '[MEDIUM] missing_header           /etc/nginx/sites/x:1\n'
               '         server default (80): no add_header for X-Frame-Options (effective at server level, including headers '
               'inherited from http)\n'
               '\n'
               '[MEDIUM] missing_header           /etc/nginx/sites/x:1\n'
               '         server default (80): no add_header for Content-Security-Policy (effective at server level, including '
               'headers inherited from http)\n'
               '\n'
               '[MEDIUM] missing_header           /etc/nginx/sites/x:1\n'
               '         server default (80): no add_header for Referrer-Policy (effective at server level, including headers '
               'inherited from http)\n'
               '\n',
               ''],
 'cli_local_fail': [2, '', 'nginx-config-auditor: ERROR -- `nginx -T` failed: boom: cannot open\n'],
 'cli_local_missing': [2, '', 'nginx-config-auditor: ERROR -- `nginx` not found on PATH (try /usr/sbin, or run as root)\n'],
 'cli_min_high': [1,
                  'nginx-config-auditor: scanned 3 file(s), 1 finding(s)\n'
                  '\n'
                  '[HIGH  ] autoindex                <D>/conf.d/a.conf:1\n'
                  '         autoindex on; exposes directory listing\n'
                  '\n',
                  ''],
 'cli_min_low': [1,
                 'nginx-config-auditor: scanned 3 file(s), 6 finding(s)\n'
                 '\n'
                 '[HIGH  ] autoindex                <D>/conf.d/a.conf:1\n'
                 '         autoindex on; exposes directory listing\n'
                 '\n'
                 '[MEDIUM] missing_header           <D>/conf.d/a.conf:1\n'
                 '         server default (80): no add_header for X-Content-Type-Options (effective at server level, including '
                 'headers inherited from http)\n'
                 '\n'
                 '[MEDIUM] missing_header           <D>/conf.d/a.conf:1\n'
                 '         server default (80): no add_header for X-Frame-Options (effective at server level, including headers '
                 'inherited from http)\n'
                 '\n'
                 '[MEDIUM] missing_header           <D>/conf.d/a.conf:1\n'
                 '         server default (80): no add_header for Content-Security-Policy (effective at server level, including '
                 'headers inherited from http)\n'
                 '\n'
                 '[MEDIUM] missing_header           <D>/conf.d/a.conf:1\n'
                 '         server default (80): no add_header for Referrer-Policy (effective at server level, including headers '
                 'inherited from http)\n'
                 '\n'
                 '[LOW   ] server_tokens            <D>/conf.d/b.conf:1\n'
                 '         server_tokens on; leaks nginx version in headers/error pages\n'
                 '\n',
                 ''],
 'cli_min_medium': [1,
                    'nginx-config-auditor: scanned 3 file(s), 5 finding(s)\n'
                    '\n'
                    '[HIGH  ] autoindex                <D>/conf.d/a.conf:1\n'
                    '         autoindex on; exposes directory listing\n'
                    '\n'
                    '[MEDIUM] missing_header           <D>/conf.d/a.conf:1\n'
                    '         server default (80): no add_header for X-Content-Type-Options (effective at server level, '
                    'including headers inherited from http)\n'
                    '\n'
                    '[MEDIUM] missing_header           <D>/conf.d/a.conf:1\n'
                    '         server default (80): no add_header for X-Frame-Options (effective at server level, including '
                    'headers inherited from http)\n'
                    '\n'
                    '[MEDIUM] missing_header           <D>/conf.d/a.conf:1\n'
                    '         server default (80): no add_header for Content-Security-Policy (effective at server level, '
                    'including headers inherited from http)\n'
                    '\n'
                    '[MEDIUM] missing_header           <D>/conf.d/a.conf:1\n'
                    '         server default (80): no add_header for Referrer-Policy (effective at server level, including '
                    'headers inherited from http)\n'
                    '\n',
                    ''],
 'cli_missing': [2, '', 'path not found: <D>/nope\n'],
 'cli_noargs': [2, '',
                'usage: nginx-config-auditor [-h] [--version] [--docker CONTAINER] [--local]\n'
                '                            [--dump FILE] [--json]\n'
                '                            [--min-severity {HIGH,MEDIUM,LOW,INFO}]\n'
                '                            [--fail-on {high,medium,low,never}]\n'
                '                            [path]\n'
                '\n'
                'nginx-config-auditor: a small, free, stdlib-only static analyzer for nginx\n'
                'configuration. It parses the config the way nginx does -- blocks, quoting,\n'
                'and `include` directives followed (globs too) -- so headers or TLS settings\n'
                'set in an included file count for the servers that include them, and checks\n'
                'are made per server and per location on the merged tree.\n'
                '\n'
                'Usage:\n'
                '    nginx-config-auditor /etc/nginx/nginx.conf       # follows every include\n'
                '    nginx-config-auditor /etc/nginx/                 # uses nginx.conf there; else each *.conf\n'
                '    nginx-config-auditor --local                     # audits `nginx -T` output on this host\n'
                "    nginx-config-auditor --dump nginx-T.txt          # a saved `nginx -T` dump ('-' = stdin)\n"
                '    nginx-config-auditor --docker <container>        # `nginx -T` inside the container (docker cp fallback)\n'
                '\n'
                'Checks include weak ssl_protocols/ssl_ciphers, autoindex, server_tokens,\n'
                'missing security headers per server (http-level headers inherited the way\n'
                'nginx inherits them), add_header in a location silently dropping inherited\n'
                'security headers, security headers without `always`, alias path traversal\n'
                '(location without trailing slash + alias with one), `valid_referers none`,\n'
                'Host taken from $http_host, $uri/$document_uri in response headers (header\n'
                'splitting), multi-line header values and unanchored Origin/Referer regexes.\n'
                '\n'
                'No dependencies beyond the Python 3 standard library. Read-only: never\n'
                'modifies any file it scans. Exit codes: 0 = no finding at or above\n'
                '--fail-on (default: high), 1 = at least one, 2 = nothing to scan / usage error.\n'
                '\n'
                'positional arguments:\n'
                '  path                  config file or directory to scan\n'
                '\n'
                'options:\n'
                '  -h, --help            show this help message and exit\n'
                "  --version             show program's version number and exit\n"
                '  --docker CONTAINER    audit the config of this running container (nginx -T,\n'
                '                        or docker cp of /etc/nginx)\n'
                '  --local               run `nginx -T` on this host and audit the merged\n'
                '                        config\n'
                "  --dump FILE           audit saved `nginx -T` output ('-' for stdin)\n"
                '  --json                output findings as JSON instead of text\n'
                '  --min-severity {HIGH,MEDIUM,LOW,INFO}\n'
                '                        only show findings at or above this severity\n'
                '  --fail-on {high,medium,low,never}\n'
                '                        lowest severity that makes the exit code 1 (default:\n'
                '                        high)\n'],
 'cli_parse_error': [2, '',
                     "nginx-config-auditor: parse error -- <D>/broken.conf: unexpected end of file, a '{' is not closed\n"],
 'cli_text_dir': [1,
                  'nginx-config-auditor: scanned 3 file(s), 11 finding(s)\n'
                  '\n'
                  '[HIGH  ] autoindex                <D>/conf.d/a.conf:1\n'
                  '         autoindex on; exposes directory listing\n'
                  '\n'
                  '[MEDIUM] missing_header           <D>/conf.d/a.conf:1\n'
                  '         server default (80): no add_header for X-Content-Type-Options (effective at server level, including '
                  'headers inherited from http)\n'
                  '\n'
                  '[MEDIUM] missing_header           <D>/conf.d/a.conf:1\n'
                  '         server default (80): no add_header for X-Frame-Options (effective at server level, including headers '
                  'inherited from http)\n'
                  '\n'
                  '[MEDIUM] missing_header           <D>/conf.d/a.conf:1\n'
                  '         server default (80): no add_header for Content-Security-Policy (effective at server level, including '
                  'headers inherited from http)\n'
                  '\n'
                  '[MEDIUM] missing_header           <D>/conf.d/a.conf:1\n'
                  '         server default (80): no add_header for Referrer-Policy (effective at server level, including headers '
                  'inherited from http)\n'
                  '\n'
                  '[LOW   ] server_tokens            <D>/conf.d/b.conf:1\n'
                  '         server_tokens on; leaks nginx version in headers/error pages\n'
                  '\n'
                  '[INFO  ] not_included             <D>/alone/one.conf\n'
                  '         not included from nginx.conf, so not active (not audited)\n'
                  '\n'
                  '[INFO  ] not_included             <D>/alone/two.conf\n'
                  '         not included from nginx.conf, so not active (not audited)\n'
                  '\n'
                  '[INFO  ] ssl_protocols_unset      <D>/nginx.conf\n'
                  '         no explicit ssl_protocols directive found (nginx defaults apply)\n'
                  '\n'
                  '[INFO  ] not_included             <D>/solo.conf\n'
                  '         not included from nginx.conf, so not active (not audited)\n'
                  '\n'
                  '[INFO  ] not_included             <D>/stray.conf\n'
                  '         not included from nginx.conf, so not active (not audited)\n'
                  '\n',
                  ''],
 'cli_two': [2, '',
             'usage: nginx-config-auditor [-h] [--version] [--docker CONTAINER] [--local]\n'
             '                            [--dump FILE] [--json]\n'
             '                            [--min-severity {HIGH,MEDIUM,LOW,INFO}]\n'
             '                            [--fail-on {high,medium,low,never}]\n'
             '                            [path]\n'
             '\n'
             'nginx-config-auditor: a small, free, stdlib-only static analyzer for nginx\n'
             'configuration. It parses the config the way nginx does -- blocks, quoting,\n'
             'and `include` directives followed (globs too) -- so headers or TLS settings\n'
             'set in an included file count for the servers that include them, and checks\n'
             'are made per server and per location on the merged tree.\n'
             '\n'
             'Usage:\n'
             '    nginx-config-auditor /etc/nginx/nginx.conf       # follows every include\n'
             '    nginx-config-auditor /etc/nginx/                 # uses nginx.conf there; else each *.conf\n'
             '    nginx-config-auditor --local                     # audits `nginx -T` output on this host\n'
             "    nginx-config-auditor --dump nginx-T.txt          # a saved `nginx -T` dump ('-' = stdin)\n"
             '    nginx-config-auditor --docker <container>        # `nginx -T` inside the container (docker cp fallback)\n'
             '\n'
             'Checks include weak ssl_protocols/ssl_ciphers, autoindex, server_tokens,\n'
             'missing security headers per server (http-level headers inherited the way\n'
             'nginx inherits them), add_header in a location silently dropping inherited\n'
             'security headers, security headers without `always`, alias path traversal\n'
             '(location without trailing slash + alias with one), `valid_referers none`,\n'
             'Host taken from $http_host, $uri/$document_uri in response headers (header\n'
             'splitting), multi-line header values and unanchored Origin/Referer regexes.\n'
             '\n'
             'No dependencies beyond the Python 3 standard library. Read-only: never\n'
             'modifies any file it scans. Exit codes: 0 = no finding at or above\n'
             '--fail-on (default: high), 1 = at least one, 2 = nothing to scan / usage error.\n'
             '\n'
             'positional arguments:\n'
             '  path                  config file or directory to scan\n'
             '\n'
             'options:\n'
             '  -h, --help            show this help message and exit\n'
             "  --version             show program's version number and exit\n"
             '  --docker CONTAINER    audit the config of this running container (nginx -T,\n'
             '                        or docker cp of /etc/nginx)\n'
             '  --local               run `nginx -T` on this host and audit the merged\n'
             '                        config\n'
             "  --dump FILE           audit saved `nginx -T` output ('-' for stdin)\n"
             '  --json                output findings as JSON instead of text\n'
             '  --min-severity {HIGH,MEDIUM,LOW,INFO}\n'
             '                        only show findings at or above this severity\n'
             '  --fail-on {high,medium,low,never}\n'
             '                        lowest severity that makes the exit code 1 (default:\n'
             '                        high)\n'],
 'cli_version': [['exit', 0], 'nginx-config-auditor 1.2.1\n', ''],
 'deep_findings': [['/d33.conf', None, 'MEDIUM', 'include_loop', 'include loop or nesting deeper than 32 levels']],
 'deep_read': 33,
 'deep_tree': ['n32', 'n31', 'n30', 'n29', 'n28', 'n27', 'n26', 'n25', 'n24', 'n23', 'n22', 'n21', 'n20', 'n19', 'n18', 'n17',
               'n16', 'n15', 'n14', 'n13', 'n12', 'n11', 'n10', 'n9', 'n8', 'n7', 'n6', 'n5', 'n4', 'n3', 'n2', 'n1', 'n0'],
 'dump': [{'/etc/nginx/mime.types': 'types { text/html html; }\n',
           '/etc/nginx/nginx.conf': 'events {}\nhttp {\n  include /etc/nginx/mime.types;\n  include /etc/nginx/sites/*;\n}\n',
           '/etc/nginx/sites/x': 'server { listen 80; autoindex on; }\n'},
          '/etc/nginx/nginx.conf'],
 'dump_err': "not an `nginx -T` dump (no '# configuration file ...:' headers)",
 'find_files': ['<D>/alone/one.conf', '<D>/alone/two.conf', '<D>/conf.d/a.conf', '<D>/conf.d/b.conf', '<D>/nginx.conf',
                '<D>/solo.conf', '<D>/stray.conf', '<D>/solo.conf'],
 'help': 'usage: nginx-config-auditor [-h] [--version] [--docker CONTAINER] [--local] [--dump FILE] [--json] [--min-severity '
         '{HIGH,MEDIUM,LOW,INFO}] [--fail-on {high,medium,low,never}] [path] nginx-config-auditor: a small, free, stdlib-only '
         'static analyzer for nginx configuration. It parses the config the way nginx does -- blocks, quoting, and `include` '
         'directives followed (globs too) -- so headers or TLS settings set in an included file count for the servers that '
         'include them, and checks are made per server and per location on the merged tree. Usage: nginx-config-auditor '
         '/etc/nginx/nginx.conf # follows every include nginx-config-auditor /etc/nginx/ # uses nginx.conf there; else each '
         '*.conf nginx-config-auditor --local # audits `nginx -T` output on this host nginx-config-auditor --dump nginx-T.txt # '
         "a saved `nginx -T` dump ('-' = stdin) nginx-config-auditor --docker <container> # `nginx -T` inside the container "
         '(docker cp fallback) Checks include weak ssl_protocols/ssl_ciphers, autoindex, server_tokens, missing security headers '
         'per server (http-level headers inherited the way nginx inherits them), add_header in a location silently dropping '
         'inherited security headers, security headers without `always`, alias path traversal (location without trailing slash + '
         'alias with one), `valid_referers none`, Host taken from $http_host, $uri/$document_uri in response headers (header '
         'splitting), multi-line header values and unanchored Origin/Referer regexes. No dependencies beyond the Python 3 '
         'standard library. Read-only: never modifies any file it scans. Exit codes: 0 = no finding at or above --fail-on '
         '(default: high), 1 = at least one, 2 = nothing to scan / usage error. positional arguments: path config file or '
         "directory to scan -h, --help show this help message and exit --version show program's version number and exit --docker "
         'CONTAINER audit the config of this running container (nginx -T, or docker cp of /etc/nginx) --local run `nginx -T` on '
         "this host and audit the merged config --dump FILE audit saved `nginx -T` output ('-' for stdin) --json output findings "
         'as JSON instead of text --min-severity {HIGH,MEDIUM,LOW,INFO} only show findings at or above this severity --fail-on '
         '{high,medium,low,never} lowest severity that makes the exit code 1 (default: high)',
 'inc_findings': [['/etc/nginx/nginx.conf', 2, 'INFO', 'include_missing',
                   'include missing.conf matches no file (nginx -t would fail)']],
 'inc_read': ['/etc/nginx/nginx.conf', '/etc/nginx/conf.d/a.conf', '/etc/nginx/conf.d/b.conf', '/etc/nginx/common.conf',
              '/etc/nginx/srv.conf'],
 'inc_tree': [['server_tokens', ['on'], 1, '/etc/nginx/conf.d/a.conf', None],
              ['autoindex', ['on'], 1, '/etc/nginx/conf.d/b.conf', None],
              ['http', [], 4, '/etc/nginx/nginx.conf', ['ssl_protocols', 'server']]],
 'loop_findings': [['/a.conf', None, 'MEDIUM', 'include_loop', 'include loop or nesting deeper than 32 levels']],
 'loop_read': ['/a.conf', '/b.conf'],
 'loop_tree': [['y', '/b.conf'], ['x', '/a.conf']],
 'parse_err': ["p.conf: unexpected end of file, missing ';'", "p.conf:1: missing ';' before '}'", "p.conf:1: unexpected '}'",
               'p.conf:1: block without a directive name', "p.conf: unexpected end of file, a '{' is not closed",
               "p.conf: unexpected end of file, a '{' is not closed", "p.conf:1: missing ';' before '}'",
               "p.conf:2: unexpected '}'", 'p.conf:1: block without a directive name', "p.conf:3: missing ';' before '}'",
               'unterminated quoted string starting on line 1', "p.conf: unexpected end of file, a '{' is not closed",
               "p.conf: unexpected end of file, missing ';'", "p.conf: unexpected end of file, a '{' is not closed"],
 'parse_ok': [[], [{'args': ['b', 'c'], 'block': None, 'file': 'p.conf', 'line': 1, 'name': 'a'}],
              [{'args': [],
                'block': [{'args': [],
                           'block': [{'args': ['80'], 'block': None, 'file': 'p.conf', 'line': 3, 'name': 'listen'}],
                           'file': 'p.conf',
                           'line': 2,
                           'name': 'server'}],
                'file': 'p.conf',
                'line': 1,
                'name': 'http'}],
              [{'args': [], 'block': None, 'file': 'p.conf', 'line': 1, 'name': 'a'},
               {'args': [],
                'block': [{'args': ['d'], 'block': None, 'file': 'p.conf', 'line': 3, 'name': 'c'},
                          {'args': [],
                           'block': [{'args': [], 'block': None, 'file': 'p.conf', 'line': 5, 'name': 'f'}],
                           'file': 'p.conf',
                           'line': 4,
                           'name': 'e'}],
                'file': 'p.conf',
                'line': 2,
                'name': 'b'}],
              [{'args': [], 'block': [], 'file': 'p.conf', 'line': 1, 'name': 'content_by_lua_block'},
               {'args': [], 'block': None, 'file': 'p.conf', 'line': 2, 'name': 'after'}],
              [{'args': ['$v'], 'block': [], 'file': 'p.conf', 'line': 1, 'name': 'perl_set'},
               {'args': [], 'block': None, 'file': 'p.conf', 'line': 2, 'name': 'after'}],
              [{'args': [], 'block': [], 'file': 'p.conf', 'line': 1, 'name': 'init_by_njs_block'},
               {'args': [], 'block': None, 'file': 'p.conf', 'line': 2, 'name': 'last'}],
              [{'args': ['q;q', 'r{r'], 'block': None, 'file': 'p.conf', 'line': 1, 'name': 'a'}],
              [{'args': ['/'], 'block': [], 'file': 'p.conf', 'line': 1, 'name': 'location'}],
              [{'args': [], 'block': [], 'file': 'p.conf', 'line': 1, 'name': 'events'},
               {'args': [], 'block': [], 'file': 'p.conf', 'line': 2, 'name': 'http'}]],
 'scan_dir_alone': [['<D>/alone/one.conf', '<D>/alone/two.conf'],
                    [['<D>/alone/one.conf', 1, 'HIGH', 'autoindex', 'autoindex on; exposes directory listing'],
                     ['<D>/alone/one.conf', None, 'MEDIUM', 'missing_header',
                      'no add_header for Strict-Transport-Security found (no server blocks here to check inheritance against)'],
                     ['<D>/alone/one.conf', None, 'MEDIUM', 'missing_header',
                      'no add_header for X-Content-Type-Options found (no server blocks here to check inheritance against)'],
                     ['<D>/alone/one.conf', None, 'MEDIUM', 'missing_header',
                      'no add_header for X-Frame-Options found (no server blocks here to check inheritance against)'],
                     ['<D>/alone/one.conf', None, 'MEDIUM', 'missing_header',
                      'no add_header for Content-Security-Policy found (no server blocks here to check inheritance against)'],
                     ['<D>/alone/one.conf', None, 'MEDIUM', 'missing_header',
                      'no add_header for Referrer-Policy found (no server blocks here to check inheritance against)'],
                     ['<D>/alone/one.conf', None, 'INFO', 'ssl_protocols_unset',
                      'no explicit ssl_protocols directive found (nginx defaults apply)'],
                     ['<D>/alone/one.conf', None, 'LOW', 'server_tokens_default',
                      "server_tokens not set -- nginx defaults to 'on' (version disclosure)"],
                     ['<D>/alone/two.conf', None, 'MEDIUM', 'missing_header',
                      'no add_header for Strict-Transport-Security found (no server blocks here to check inheritance against)'],
                     ['<D>/alone/two.conf', None, 'MEDIUM', 'missing_header',
                      'no add_header for X-Content-Type-Options found (no server blocks here to check inheritance against)'],
                     ['<D>/alone/two.conf', None, 'MEDIUM', 'missing_header',
                      'no add_header for X-Frame-Options found (no server blocks here to check inheritance against)'],
                     ['<D>/alone/two.conf', None, 'MEDIUM', 'missing_header',
                      'no add_header for Content-Security-Policy found (no server blocks here to check inheritance against)'],
                     ['<D>/alone/two.conf', None, 'MEDIUM', 'missing_header',
                      'no add_header for Referrer-Policy found (no server blocks here to check inheritance against)'],
                     ['<D>/alone/two.conf', None, 'INFO', 'ssl_protocols_unset',
                      'no explicit ssl_protocols directive found (nginx defaults apply)']]],
 'scan_dir_main': [['<D>/nginx.conf', '<D>/conf.d/a.conf', '<D>/conf.d/b.conf'],
                   [['<D>/conf.d/a.conf', 1, 'HIGH', 'autoindex', 'autoindex on; exposes directory listing'],
                    ['<D>/conf.d/b.conf', 1, 'LOW', 'server_tokens',
                     'server_tokens on; leaks nginx version in headers/error pages'],
                    ['<D>/conf.d/a.conf', 1, 'MEDIUM', 'missing_header',
                     'server default (80): no add_header for X-Content-Type-Options (effective at server level, including '
                     'headers inherited from http)'],
                    ['<D>/conf.d/a.conf', 1, 'MEDIUM', 'missing_header',
                     'server default (80): no add_header for X-Frame-Options (effective at server level, including headers '
                     'inherited from http)'],
                    ['<D>/conf.d/a.conf', 1, 'MEDIUM', 'missing_header',
                     'server default (80): no add_header for Content-Security-Policy (effective at server level, including '
                     'headers inherited from http)'],
                    ['<D>/conf.d/a.conf', 1, 'MEDIUM', 'missing_header',
                     'server default (80): no add_header for Referrer-Policy (effective at server level, including headers '
                     'inherited from http)'],
                    ['<D>/nginx.conf', None, 'INFO', 'ssl_protocols_unset',
                     'no explicit ssl_protocols directive found (nginx defaults apply)'],
                    ['<D>/alone/one.conf', None, 'INFO', 'not_included',
                     'not included from nginx.conf, so not active (not audited)'],
                    ['<D>/alone/two.conf', None, 'INFO', 'not_included',
                     'not included from nginx.conf, so not active (not audited)'],
                    ['<D>/solo.conf', None, 'INFO', 'not_included', 'not included from nginx.conf, so not active (not audited)'],
                    ['<D>/stray.conf', None, 'INFO', 'not_included',
                     'not included from nginx.conf, so not active (not audited)']]],
 'scan_dump': [['/etc/nginx/nginx.conf', '/etc/nginx/mime.types', '/etc/nginx/sites/x'],
               [['/etc/nginx/sites/x', 1, 'HIGH', 'autoindex', 'autoindex on; exposes directory listing'],
                ['/etc/nginx/sites/x', 1, 'MEDIUM', 'missing_header',
                 'server default (80): no add_header for X-Content-Type-Options (effective at server level, including headers '
                 'inherited from http)'],
                ['/etc/nginx/sites/x', 1, 'MEDIUM', 'missing_header',
                 'server default (80): no add_header for X-Frame-Options (effective at server level, including headers inherited '
                 'from http)'],
                ['/etc/nginx/sites/x', 1, 'MEDIUM', 'missing_header',
                 'server default (80): no add_header for Content-Security-Policy (effective at server level, including headers '
                 'inherited from http)'],
                ['/etc/nginx/sites/x', 1, 'MEDIUM', 'missing_header',
                 'server default (80): no add_header for Referrer-Policy (effective at server level, including headers inherited '
                 'from http)'],
                ['/etc/nginx/nginx.conf', None, 'INFO', 'ssl_protocols_unset',
                 'no explicit ssl_protocols directive found (nginx defaults apply)'],
                ['/etc/nginx/nginx.conf', None, 'LOW', 'server_tokens_default',
                 "server_tokens not set -- nginx defaults to 'on' (version disclosure)"]]],
 'scan_dump_label': [['web1:/etc/nginx/nginx.conf', 'web1:/etc/nginx/mime.types', 'web1:/etc/nginx/sites/x'],
                     [['web1:/etc/nginx/sites/x', 1, 'HIGH', 'autoindex', 'autoindex on; exposes directory listing'],
                      ['web1:/etc/nginx/sites/x', 1, 'MEDIUM', 'missing_header',
                       'server default (80): no add_header for X-Content-Type-Options (effective at server level, including '
                       'headers inherited from http)'],
                      ['web1:/etc/nginx/sites/x', 1, 'MEDIUM', 'missing_header',
                       'server default (80): no add_header for X-Frame-Options (effective at server level, including headers '
                       'inherited from http)'],
                      ['web1:/etc/nginx/sites/x', 1, 'MEDIUM', 'missing_header',
                       'server default (80): no add_header for Content-Security-Policy (effective at server level, including '
                       'headers inherited from http)'],
                      ['web1:/etc/nginx/sites/x', 1, 'MEDIUM', 'missing_header',
                       'server default (80): no add_header for Referrer-Policy (effective at server level, including headers '
                       'inherited from http)'],
                      ['web1:/etc/nginx/nginx.conf', None, 'INFO', 'ssl_protocols_unset',
                       'no explicit ssl_protocols directive found (nginx defaults apply)'],
                      ['web1:/etc/nginx/nginx.conf', None, 'LOW', 'server_tokens_default',
                       "server_tokens not set -- nginx defaults to 'on' (version disclosure)"]]],
 'scan_empty': [[], None],
 'scan_file': [['<D>/solo.conf'],
               [['<D>/solo.conf', 1, 'MEDIUM', 'root_alias_slash',
                 'root / ; serves entire filesystem root -- almost certainly unintended'],
                ['<D>/solo.conf', None, 'MEDIUM', 'missing_header',
                 'no add_header for Strict-Transport-Security found (no server blocks here to check inheritance against)'],
                ['<D>/solo.conf', None, 'MEDIUM', 'missing_header',
                 'no add_header for X-Content-Type-Options found (no server blocks here to check inheritance against)'],
                ['<D>/solo.conf', None, 'MEDIUM', 'missing_header',
                 'no add_header for X-Frame-Options found (no server blocks here to check inheritance against)'],
                ['<D>/solo.conf', None, 'MEDIUM', 'missing_header',
                 'no add_header for Content-Security-Policy found (no server blocks here to check inheritance against)'],
                ['<D>/solo.conf', None, 'MEDIUM', 'missing_header',
                 'no add_header for Referrer-Policy found (no server blocks here to check inheritance against)'],
                ['<D>/solo.conf', None, 'INFO', 'ssl_protocols_unset',
                 'no explicit ssl_protocols directive found (nginx defaults apply)'],
                ['<D>/solo.conf', None, 'LOW', 'server_tokens_default',
                 "server_tokens not set -- nginx defaults to 'on' (version disclosure)"]]],
 'server_label': ['default', 'a', 'default (80)', 'default (443)', 'default (81)', 'x'],
 'source_glob': [['/etc/nginx/conf.d/a.conf', '/etc/nginx/conf.d/b.conf'],
                 ['/etc/nginx/common.conf', '/etc/nginx/conf.d/a.conf', '/etc/nginx/conf.d/b.conf', '/etc/nginx/nginx.conf',
                  '/etc/nginx/srv.conf'],
                 ['/etc/nginx/conf.d/a.conf', '/etc/nginx/conf.d/b.conf']],
 'strip': ['', 'plain', 'a \nb', '\n', "x '#not' y ", 'x "#no" \nz', 'a\\\\', "'a\\'#b' ", '"q\\"#" ', "q 'open # here",
           'line1 \nline2 \nline3', 'a', "'\\", '', 'a\\', "'x'\n", '"x"\n'],
 'tokenize': [[], [['a', 1, 'word'], [';', 1, ';']],
              [['a', 1, 'word'], ['b', 1, 'word'], [';', 1, ';'], ['c', 2, 'word'], ['d', 2, 'word'], [';', 2, ';']],
              [['server', 1, 'word'], ['{', 1, '{'], ['listen', 2, 'word'], ['80', 2, 'word'], [';', 2, ';'], ['}', 3, '}']],
              [['a', 1, 'word'], ['{', 1, '{'], ['b', 1, 'word'], [';', 1, ';'], ['}', 1, '}']],
              [['x', 1, 'word'], ['q s', 1, 'quoted'], ['p q', 1, 'quoted'], [';', 1, ';']],
              [['x', 1, 'word'], ["a'b", 1, 'quoted'], ['c"d', 1, 'quoted'], ['e\\f', 1, 'quoted'], ['g\\nh', 1, 'quoted'],
               [';', 1, ';']],
              [['x', 1, 'word'], ['multi\nline', 1, 'quoted'], ['y', 2, 'word'], [';', 2, ';']],
              [['a', 2, 'word'], [';', 2, ';'], ['b', 3, 'word'], [';', 3, ';']],
              [['set', 1, 'word'], ['$x', 1, 'word'], ['${var}suffix', 1, 'word'], [';', 1, ';']],
              [['set', 1, 'word'], ['$x', 1, 'word'], ['$', 1, 'word'], ['{', 1, '{'], ['open', 1, 'word']],
              [['a', 1, 'word'], ['}', 1, '}'], ['b', 1, 'word']], [['a\\;b', 1, 'word'], ['c\\ d', 1, 'word'], [';', 1, ';']],
              [['a\\', 1, 'word']], [['if', 1, 'word'], ['($a', 1, 'word'], ['~', 1, 'word'], ['^x$)', 1, 'word'], ['{', 1, '{']],
              [['log_format', 1, 'word'], ['m', 1, 'word'], ['$a', 1, 'quoted'], ['$b', 2, 'quoted'], [';', 2, ';']],
              'ParseError: unterminated quoted string starting on line 1',
              'ParseError: unterminated quoted string starting on line 1',
              [['a', 1, 'word'], [';', 1, ';'], ['b', 1, 'word'], [';', 1, ';'], ['{', 1, '{'], ['}', 1, '}']],
              [['a', 1, 'word'], [';', 1, ';']], [['a', 1, 'word'], ['b', 2, 'word'], [';', 2, ';']],
              [['word', 1, 'word'], ['{', 1, '{']], [['$x', 1, 'word'], ['{', 1, '{'], ['y', 1, 'word'], ['}', 1, '}']],
              [['${v}', 1, 'word']], [['$', 1, 'word']], [['q', 1, 'word'], ['x', 1, 'quoted']],
              [['q', 1, 'word'], ['x', 1, 'quoted']], [['a', 1, 'word'], ['b', 4, 'word'], [';', 4, ';']],
              [['x', 1, 'word'], ['a\nb', 1, 'quoted'], ['c', 2, 'word'], [';', 2, ';'], ['d', 3, 'word'], [';', 3, ';']],
              [['x\\\\y', 1, 'word'], [';', 1, ';']], [['\\', 1, 'quoted']]]}


class TestGolden(unittest.TestCase):
    maxDiff = None

    def test_observations_match(self):
        got = observe()
        self.assertEqual(sorted(got), sorted(EXPECTED))
        for key in sorted(EXPECTED):
            with self.subTest(key):
                self.assertEqual(got[key], EXPECTED[key])


if __name__ == "__main__":
    unittest.main()
