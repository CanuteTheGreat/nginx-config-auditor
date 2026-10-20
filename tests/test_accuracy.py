"""Detection accuracy against real nginx behaviour, not against this tool's own idea of it.

* add_header inheritance differential: a seeded random corpus of 30 servers (http-, server- and
  location-level add_header sets, some through include files, with and without `always`) is
  loaded into a REAL nginx and every server and location is requested. What nginx actually sends
  is the reference: a server's missing security headers (200 response), headers that vanish on
  a 404 (no `always`), and the security headers a location drops compared with its parent.
  The tool's missing_header / header_not_always / add_header_redefinition findings must match
  exactly -> false negatives and false positives in one suite. The same config through
  `nginx -T` (--dump) must give identical findings.
* anonymous cipher suites: 40 real-world and adversarial `ssl_ciphers` strings, with and without
  @SECLEVEL=0 (80 servers), each on its own
  real nginx TLS server; an `openssl s_client` offering only anonymous (aNULL) suites decides
  whether nginx really negotiates one. The tool must report exactly those strings.
* Mozilla SSL Configuration Generator (nginx, 5.7): "modern" and "intermediate" must have no
  HIGH TLS finding; "old" must report its TLSv1/TLSv1.1 and DES-CBC3-SHA as HIGH.
"""
import http.client
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "nginx_config_auditor.py")
NGINX = shutil.which("nginx") or "/usr/sbin/nginx"
SEED = 20261016
SEC = {"Strict-Transport-Security": "max-age=31536000", "X-Content-Type-Options": "nosniff",
       "X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'self'", "Referrer-Policy": "no-referrer"}
NON_TLS_REQUIRED = [h for h in SEC if h != "Strict-Transport-Security"]
# Listen ports are picked free at setUpModule time, never fixed: mutation testing runs this module in
# several processes at once (mutmut --max-children), and with fixed ports (18100+/18500+) the second
# nginx failed to bind while its tests silently talked to the FIRST process's nginx and corpus - which
# could be torn down mid-test. Mutants were then killed or kept at random (about 100 flipped between
# two full runs of the same code, 2026-10-20) instead of by what the tool does.
HTTP_PORTS, TLS_PORTS = [], []


def free_ports(n):
    """n distinct TCP ports on 127.0.0.1 that are free right now (all held open until all are chosen)."""
    socks = []
    try:
        for _ in range(n):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))
            socks.append(s)
        return [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            s.close()

CIPHERS = [
    "HIGH:!aNULL:!MD5", "HIGH", "ALL", "ALL:!aNULL", "ALL:!ADH", "ALL:!AECDH", "ALL:!ADH:!AECDH", "DEFAULT",
    "AES", "AES:!aNULL", "AES128", "AES256:!ADH", "AESGCM", "CAMELLIA", "SHA", "SHA256", "SHA384",
    "kEDH+AESGCM", "EDH+AESGCM", "ECDHE+AESGCM", "EECDH+AESGCM:EDH+AESGCM", "kEECDH+AES", "ECDH+AESGCM",
    "aNULL", "ADH", "AECDH", "ADH-AES256-GCM-SHA384", "AECDH-AES128-SHA", "HIGH:-aNULL:aNULL",
    "HIGH:-aNULL", "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK", "TLSv1.2", "TLSv1.2:!aNULL",
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305",
    "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH", "FIPS", "FIPS:!aNULL", "COMPLEMENTOFDEFAULT",
    "DH+AESGCM", "AES128-SHA:AES256-SHA",
]
# OpenSSL >= 1.1 only negotiates anonymous suites at security level 0: every string again with it
CIPHERS += [c + ":@SECLEVEL=0" for c in CIPHERS]

MOZILLA = {
    "modern": ("TLSv1.3", None),
    "intermediate": ("TLSv1.2 TLSv1.3",
                     "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
                     "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
                     "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"),
    "old": ("TLSv1 TLSv1.1 TLSv1.2 TLSv1.3",
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
            "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:"
            "DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:"
            "AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA"),
}


def run(*args, **kw):
    return subprocess.run([sys.executable, TOOL] + list(args), capture_output=True, text=True, timeout=300, **kw)


def add_headers(rnd, indent):
    names = rnd.sample(list(SEC), rnd.randint(0, len(SEC)))
    lines = ['%sadd_header %s "%s"%s;' % (indent, h, SEC[h], " always" if rnd.random() < 0.6 else "") for h in names]
    if rnd.random() < 0.25:  # a non-security header alone still cancels inheritance
        lines.append('%sadd_header X-Custom "1";' % indent)
    return lines


def header_corpus():
    rnd = random.Random(SEED)
    files, servers = {}, []
    http_lines = add_headers(rnd, "    ")
    if rnd.random() < 0.5 and http_lines:
        files["http-headers.inc"] = "\n".join(l.strip() for l in http_lines) + "\n"
        http_lines = ["    include %(tmp)s/http-headers.inc;"]
    body = []
    for i in range(30):
        port = HTTP_PORTS[i]
        srv = ["    server {", "        listen 127.0.0.1:%d;" % port, "        server_name s%d.test;" % i,
               "        root %(tmp)s/www;"]
        own = add_headers(rnd, "        ") if rnd.random() < 0.7 else []
        if own and rnd.random() < 0.3:
            files["srv%d.inc" % i] = "\n".join(l.strip() for l in own) + "\n"
            own = ["        include %%(tmp)s/srv%d.inc;" % i]
        srv += own
        locs = []
        for k in range(rnd.randint(0, 3)):
            loc = "/l%d/" % k
            srv.append("        location %s {" % loc)
            srv += add_headers(rnd, "            ") if rnd.random() < 0.6 else []
            srv += ['            return 200 "ok";', "        }"]
            locs.append(loc)
        srv.append("    }")
        body += srv
        servers.append({"name": "s%d.test" % i, "port": port, "locations": locs})
    main = "\n".join([
        "pid %(tmp)s/nginx.pid;", "error_log %(tmp)s/error.log;", "events { worker_connections 256; }", "http {",
        "    access_log off;", "    server_tokens off;",
        "    client_body_temp_path %(tmp)s/cb; proxy_temp_path %(tmp)s/pt; fastcgi_temp_path %(tmp)s/ft;",
        "    uwsgi_temp_path %(tmp)s/ut; scgi_temp_path %(tmp)s/st;"] + http_lines + body + ["}"]) + "\n"
    return main, files, servers


def tls_conf(cert, key, dh):
    out = []
    for j, c in enumerate(CIPHERS):
        out += ["    server {", "        listen 127.0.0.1:%d ssl;" % TLS_PORTS[j], "        server_name c%d.test;" % j,
                "        ssl_certificate %s; ssl_certificate_key %s; ssl_dhparam %s;" % (cert, key, dh),
                "        ssl_protocols TLSv1.2;", '        ssl_ciphers "%s";' % c, '        return 200 "ok";', "    }"]
    return out


def setUpModule():
    global TMP, MAIN, SERVERS, NGX, CERT, KEY, DH
    TMP = tempfile.mkdtemp()
    os.chmod(TMP, 0o755)
    os.makedirs(os.path.join(TMP, "www"))
    with open(os.path.join(TMP, "www", "index.html"), "w") as f:
        # unique per process: the startup probe below must reach THIS module's nginx
        f.write("index %s\n" % TMP)
    os.chmod(os.path.join(TMP, "www"), 0o755)
    CERT, KEY, DH = (os.path.join(TMP, n) for n in ("c.pem", "k.pem", "dh.pem"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", KEY, "-out", CERT,
                    "-subj", "/CN=c.test", "-days", "2"], check=True, capture_output=True)
    subprocess.run(["openssl", "dhparam", "-dsaparam", "-out", DH, "2048"], check=True, capture_output=True)
    # a free port can still be taken by a parallel run between free_ports() and nginx's bind():
    # then nginx exits with "Address already in use" and we try again on fresh ports
    for _ in range(10):
        if start_nginx():
            return
    raise RuntimeError("nginx could not bind its ports in 10 attempts")


def start_nginx():
    global MAIN, SERVERS, NGX
    ports = free_ports(30 + len(CIPHERS))
    HTTP_PORTS[:], TLS_PORTS[:] = ports[:30], ports[30:]
    main, files, SERVERS = header_corpus()
    main = main.rstrip().rstrip("}") + "\n".join(tls_conf(CERT, KEY, DH)) + "\n}\n"
    for name, text in files.items():
        with open(os.path.join(TMP, name), "w") as f:
            f.write(text % {"tmp": TMP})
    MAIN = os.path.join(TMP, "nginx.conf")
    with open(MAIN, "w") as f:
        f.write(main % {"tmp": TMP})
    p = subprocess.run([NGINX, "-t", "-c", MAIN], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError("corpus rejected by nginx -t: " + p.stderr)
    errlog = os.path.join(TMP, "nginx-stderr.log")
    with open(errlog, "w") as err:
        NGX = subprocess.Popen([NGINX, "-c", MAIN, "-g", "daemon off;"], stdout=subprocess.DEVNULL, stderr=err)
    for _ in range(100):
        if NGX.poll() is not None:
            with open(errlog) as f:
                err = f.read()
            if "Address already in use" in err:
                return False
            raise RuntimeError("nginx exited with %s: %s" % (NGX.returncode, err[-500:]))
        try:
            c = http.client.HTTPConnection("127.0.0.1", SERVERS[0]["port"], timeout=10)
            c.request("GET", "/index.html", headers={"Host": SERVERS[0]["name"]})
            body = c.getresponse().read().decode()
            c.close()
        except OSError:
            time.sleep(0.1)
            continue
        if body != "index %s\n" % TMP:
            raise RuntimeError("port %d answered with another server's page: %r" % (SERVERS[0]["port"], body[:80]))
        return True
    raise RuntimeError("nginx did not start")


def tearDownModule():
    NGX.terminate()
    NGX.wait(10)
    shutil.rmtree(TMP, ignore_errors=True)


def fetch(server, path):
    c = http.client.HTTPConnection("127.0.0.1", server["port"], timeout=10)
    c.request("GET", path, headers={"Host": server["name"]})
    r = c.getresponse()
    r.read()
    c.close()
    return r.status, {k.lower() for k, _ in r.getheaders()}


def sec_present(headers):
    return {h for h in SEC if h.lower() in headers}


def label(server):
    return "%s (127.0.0.1:%d)" % (server["name"], server["port"])


class TestHeaderInheritanceAgainstNginx(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = run("--json", MAIN)
        cls.findings = json.loads(p.stdout)
        cls.ref = {}
        for s in SERVERS:
            st200, h200 = fetch(s, "/index.html")
            st404, h404 = fetch(s, "/no-such-file.html")
            assert (st200, st404) == (200, 404), (st200, st404)
            locs = {}
            for loc in s["locations"]:
                st, h = fetch(s, loc)
                assert st == 200
                locs[loc] = sec_present(h)
            cls.ref[s["name"]] = (sec_present(h200), sec_present(h404), locs)

    def by_rule(self, rule):
        return [f for f in self.findings if f["rule"] == rule]

    def test_corpus_exercises_every_case(self):
        missing = sum(len(set(NON_TLS_REQUIRED) - r[0]) for r in self.ref.values())
        not_always = sum(len(r[0] - r[1]) for r in self.ref.values())
        dropped = sum(1 for r in self.ref.values() for l in r[2].values() if r[0] - l)
        self.assertTrue(missing > 10 and not_always > 10 and dropped > 5, (missing, not_always, dropped))

    def test_missing_headers_match_what_nginx_sends(self):
        tool = set()
        for f in self.by_rule("missing_header"):
            m = re.match(r"server (\S+) \(.*?\): no add_header for (\S+)", f["message"])
            if m.group(1) in self.ref:  # (not the TLS servers of the cipher test)
                tool.add((m.group(1), m.group(2)))
        ref = {(name, h) for name, r in self.ref.items() for h in NON_TLS_REQUIRED if h not in r[0]}
        self.assertEqual(sorted(tool - ref), [], "false positives: nginx does send these")
        self.assertEqual(sorted(ref - tool), [], "false negatives: nginx does not send these")

    def test_headers_without_always_match_404_behaviour(self):
        tool = sorted(re.match(r"add_header (\S+) without", f["message"]).group(1)
                      for f in self.by_rule("header_not_always"))
        ref = sorted(h for r in self.ref.values() for h in r[0] - r[1] if h in NON_TLS_REQUIRED)
        self.assertEqual(tool, ref)

    def test_location_redefinitions_match_dropped_headers(self):
        tool = {}
        for f in self.by_rule("add_header_redefinition"):
            m = re.match(r"location (\S+) in server (\S+) .*drops the inherited (.*) for these", f["message"])
            tool[(m.group(2), m.group(1))] = set(m.group(3).split(", "))
        ref = {}
        for name, (srv, _, locs) in self.ref.items():
            for loc, got in locs.items():
                if srv - got:
                    ref[(name, loc)] = srv - got
        self.assertEqual(tool, ref)

    def test_nginx_T_dump_gives_identical_findings(self):
        dump = subprocess.run([NGINX, "-T", "-c", MAIN], capture_output=True, text=True, check=True).stdout
        p = run("--json", "--dump", "-", input=dump)
        key = lambda f: (f["rule"], f["message"])
        self.assertEqual(sorted(map(key, json.loads(p.stdout))), sorted(map(key, self.findings)))


def negotiates_anonymous(port):
    p = subprocess.run(["openssl", "s_client", "-connect", "127.0.0.1:%d" % port, "-tls1_2",
                        "-cipher", "aNULL:@SECLEVEL=0"], input="", capture_output=True, text=True, timeout=30)
    m = re.search(r"Cipher (?:is|\s*:) (\S+)", p.stdout)
    return bool(m and m.group(1).startswith(("ADH-", "AECDH-")))


class TestAnonymousCiphersAgainstHandshake(unittest.TestCase):
    def test_tool_reports_exactly_the_configs_that_negotiate_anonymous_suites(self):
        live = {c for j, c in enumerate(CIPHERS) if negotiates_anonymous(TLS_PORTS[j])}
        self.assertGreater(len(live), 8)
        self.assertGreater(len(CIPHERS) - len(live), 30)
        # a string that explicitly ENABLES anonymous suites by name is reported even where today's
        # OpenSSL refuses them at its default security level (they are live on OpenSSL 1.0.x)
        explicit = {c for c in CIPHERS if any(t.split("+")[0] in ("aNULL", "ADH", "AECDH") or t.startswith(("ADH-", "AECDH-"))
                                             for t in c.split(":"))}
        ref = live | explicit
        flagged = set()
        for f in json.loads(run("--json", MAIN).stdout):
            if f["rule"] == "ssl_ciphers" and re.search(r"anonymous|aNULL|ADH|AECDH", f["message"]):
                with open(f["file"]) as fh:
                    flagged.add(re.search(r'ssl_ciphers "(.*)";', fh.read().splitlines()[f["line"] - 1]).group(1))
        self.assertEqual(sorted(flagged - ref), [], "flagged, but nginx refuses every anonymous suite")
        self.assertEqual(sorted(ref - flagged), [], "nginx negotiates an anonymous suite, tool silent")


class TestMozillaGenerator(unittest.TestCase):
    def audit(self, level):
        protocols, ciphers = MOZILLA[level]
        d = tempfile.mkdtemp(dir=TMP)
        conf = os.path.join(d, "site.conf")
        with open(conf, "w") as f:
            f.write("server {\n listen 443 ssl;\n ssl_certificate %s;\n ssl_certificate_key %s;\n ssl_dhparam %s;\n"
                    " ssl_protocols %s;\n%s ssl_prefer_server_ciphers off;\n}\n"
                    % (CERT, KEY, DH, protocols, " ssl_ciphers %s;\n" % ciphers if ciphers else ""))
        main = os.path.join(d, "main.conf")
        with open(main, "w") as f:
            f.write("pid %s/n.pid; error_log stderr; events {} http { include %s; }\n" % (d, conf))
        p = subprocess.run([NGINX, "-t", "-c", main], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        return [(f["rule"], f["message"]) for f in json.loads(run("--json", conf).stdout) if f["severity"] == "HIGH"]

    def test_modern_and_intermediate_have_no_high_tls_finding(self):
        self.assertEqual(self.audit("modern"), [])
        self.assertEqual(self.audit("intermediate"), [])

    def test_old_reports_its_legacy_protocols_and_3des(self):
        high = self.audit("old")
        self.assertEqual(sorted(r for r, _ in high), ["ssl_ciphers", "ssl_protocols"])
        msgs = " | ".join(m for _, m in high)
        self.assertIn("TLSv1, TLSv1.1", msgs)
        self.assertIn("3DES", msgs)


if __name__ == "__main__":
    unittest.main()
