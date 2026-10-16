"""End-to-end tests for nginx_config_auditor.py.

Every fixture is first validated by the real nginx binary (`nginx -t`,
installed by ci/setup.sh) so the tool is exercised on configs nginx itself
accepts, then audited by running the tool as a subprocess. The --docker
tests run a real (resource-capped) nginx container on the CI host's Docker
engine and audit it through `docker cp`.
"""
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "nginx_config_auditor.py")
NGINX = shutil.which("nginx") or "/usr/sbin/nginx"

HARDENED_SERVER = """
server_tokens off;
server {
    listen 8443 ssl http2;
    server_name example.test;
    ssl_certificate     %(cert)s;
    ssl_certificate_key %(key)s;
    ssl_dhparam         %(dh)s;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;   # nginx's own default: excludes, doesn't enable
    ssl_prefer_server_ciphers on;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Content-Security-Policy "default-src 'self'" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    location / { root /usr/share/nginx/html; }
}
"""

WEAK_SERVER = """
server_tokens on;
server {
    listen 8444 ssl;
    server_name weak.test;
    ssl_certificate     %(cert)s;
    ssl_certificate_key %(key)s;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers HIGH:
                RC4-SHA:
                !aNULL;
    ssl_prefer_server_ciphers off;
    add_header Server "nginx-custom";
    location / { root /; }
    location /files/ { alias /srv/files/; autoindex on; }
    location /api/ { proxy_pass http://127.0.0.1:8080; }
    location /inc/ { ssi on; }
    location /admin/ { auth_basic "admin"; auth_basic_user_file /etc/nginx/htpasswd; }
}
"""


def run(*args):
    return subprocess.run([sys.executable, TOOL] + list(args), capture_output=True, text=True, timeout=120)


def setUpModule():
    global TMP, PARAMS
    TMP = tempfile.mkdtemp()
    cert, key, dh = (os.path.join(TMP, n) for n in ("c.pem", "k.pem", "dh.pem"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                    "-subj", "/CN=example.test", "-days", "30"], check=True, capture_output=True)
    subprocess.run(["openssl", "dhparam", "-dsaparam", "-out", dh, "2048"], check=True, capture_output=True)
    PARAMS = {"cert": cert, "key": key, "dh": dh}


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=TMP)

    def conf(self, body, name="site.conf", validate=True):
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(body % PARAMS if "%(" in body else body)
        if validate:
            main = os.path.join(self.dir, "_nginx_test_main")
            with open(main, "w") as f:
                f.write(f"pid {self.dir}/nginx.pid;\nerror_log stderr;\nevents {{}}\n"
                        f"http {{\n access_log off;\n include {path};\n}}\n")
            p = subprocess.run([NGINX, "-t", "-c", main], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, "fixture rejected by real nginx: " + p.stderr)
        return path

    def findings(self, *args):
        p = run("--json", *args)
        self.assertIn(p.returncode, (0, 1), p.stderr)
        return p.returncode, json.loads(p.stdout)

    @staticmethod
    def rules(findings):
        return sorted(f["rule"] for f in findings)


class TestChecks(Base):
    def test_hardened_config_is_clean(self):
        code, f = self.findings(self.conf(HARDENED_SERVER))
        self.assertEqual(code, 0)
        self.assertEqual(f, [])

    def test_weak_config_reports_every_rule(self):
        code, f = self.findings(self.conf(WEAK_SERVER))
        self.assertEqual(code, 1)
        by_rule = {}
        for x in f:
            by_rule.setdefault(x["rule"], []).append(x)
        expected = {"autoindex": "HIGH", "ssl_protocols": "HIGH", "ssl_ciphers": "HIGH",
                    "server_tokens": "LOW", "ssl_prefer_server_ciphers": "LOW",
                    "proxy_pass_plaintext": "INFO", "listen_no_http2": "INFO", "root_alias_slash": "MEDIUM",
                    "custom_server_header": "LOW", "ssi_enabled": "INFO", "auth_basic_present": "INFO",
                    "missing_header": "MEDIUM", "no_dhparam": "LOW"}
        for rule, sev in expected.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, by_rule)
                self.assertEqual(by_rule[rule][0]["severity"], sev)
        self.assertEqual(len(by_rule["missing_header"]), 5)
        self.assertIn("TLSv1, TLSv1.1", by_rule["ssl_protocols"][0]["message"])
        self.assertIn("RC4", by_rule["ssl_ciphers"][0]["message"])
        self.assertNotIn("aNULL", by_rule["ssl_ciphers"][0]["message"])  # excluded with '!'
        self.assertEqual(by_rule["ssl_ciphers"][0]["line"], 9)            # multi-line directive start
        self.assertEqual(by_rule["autoindex"][0]["line"], 15)

    def test_unset_defaults_reported(self):
        _, f = self.findings(self.conf("server { listen 8080; location / { return 204; } }\n"))
        self.assertIn("ssl_protocols_unset", self.rules(f))
        self.assertIn("server_tokens_default", self.rules(f))

    def test_stock_cipher_string_not_flagged(self):
        _, f = self.findings(self.conf("server { listen 8443 ssl; ssl_certificate %(cert)s; "
                                       "ssl_certificate_key %(key)s; ssl_ciphers HIGH:!aNULL:!MD5; }\n"))
        self.assertNotIn("ssl_ciphers", self.rules(f))

    def test_hash_inside_quotes_is_not_a_comment(self):
        _, f = self.findings(self.conf('server { listen 8080; location / { return 200 "#1 pick"; autoindex on; } }\n'))
        self.assertIn("autoindex", self.rules(f))

    def test_commented_out_directives_ignored(self):
        _, f = self.findings(self.conf("server {\n listen 8080;\n # autoindex on;\n location / { return 204; }\n}\n"))
        self.assertNotIn("autoindex", self.rules(f))

    def test_http2_on_directive_counts_as_http2(self):
        # nginx >= 1.25.1 syntax (newer than the distro nginx used to validate fixtures)
        _, f = self.findings(self.conf("server { listen 8443 ssl; http2 on; }\n", validate=False))
        self.assertNotIn("listen_no_http2", self.rules(f))
        _, f = self.findings(self.conf("server { listen 8443 ssl; }\n", "b.conf", validate=False))
        self.assertIn("listen_no_http2", self.rules(f))

    def test_header_named_elsewhere_is_still_missing(self):
        _, f = self.findings(self.conf("server { listen 8080; proxy_hide_header X-Frame-Options; }\n"))
        self.assertIn("no add_header for X-Frame-Options", " ".join(x["message"] for x in f))


class TestCli(Base):
    def test_directory_scan_min_severity_and_text(self):
        self.conf(HARDENED_SERVER, "conf.d/good.conf")
        self.conf(WEAK_SERVER, "sites/deep/weak.conf")
        with open(os.path.join(self.dir, "notes.txt"), "w") as f:
            f.write("autoindex on;\n")  # not a .conf file: ignored
        p = run(self.dir)
        self.assertEqual(p.returncode, 1)
        self.assertIn("scanned 2 file(s)", p.stdout)
        self.assertIn("weak.conf:15", p.stdout)
        code, f = self.findings(self.dir, "--min-severity", "HIGH")
        self.assertEqual(code, 1)
        self.assertEqual({x["severity"] for x in f}, {"HIGH"})
        self.assertNotIn("notes.txt", json.dumps(f))

    def test_usage_errors(self):
        self.assertEqual(run().returncode, 2)
        p = run(os.path.join(self.dir, "missing.conf"))
        self.assertEqual(p.returncode, 2)
        self.assertIn("path not found", p.stderr)
        empty = tempfile.mkdtemp(dir=TMP)
        p = run(empty)
        self.assertEqual(p.returncode, 2)
        self.assertIn("no .conf files", p.stderr)


class TestDocker(Base):
    """--docker against a real nginx container on the CI host's engine."""

    def setUp(self):
        super().setUp()
        self.name = f"nca-test-{uuid.uuid4().hex[:8]}"
        subprocess.run(["docker", "run", "-d", "--name", self.name, "--memory", "64m", "--cpus", "0.2",
                        "--pids-limit", "64", "nginx:alpine"], check=True, capture_output=True)

    def tearDown(self):
        subprocess.run(["docker", "rm", "-f", "-v", self.name], capture_output=True)

    def test_docker_mode(self):
        weak = self.conf("server { listen 8081; location / { autoindex on; } }\n", "weak.conf")
        subprocess.run(["docker", "cp", weak, f"{self.name}:/etc/nginx/conf.d/weak.conf"], check=True)
        before = set(glob.glob(os.path.join(tempfile.gettempdir(), "nginx-audit-*")))
        p = run("--docker", self.name, "--json")
        self.assertEqual(p.returncode, 1, p.stderr)
        f = json.loads(p.stdout)
        auto = [x for x in f if x["rule"] == "autoindex"]
        self.assertEqual(auto[0]["file"], f"{self.name}:/etc/nginx/conf.d/weak.conf")
        self.assertIn(f"{self.name}:/etc/nginx/nginx.conf", {x["file"] for x in f})
        after = set(glob.glob(os.path.join(tempfile.gettempdir(), "nginx-audit-*")))
        self.assertEqual(after, before, "temporary copy of the container config was left behind")

    def test_docker_missing_container(self):
        p = run("--docker", self.name + "-nope")
        self.assertEqual(p.returncode, 2)
        self.assertIn("docker cp failed", p.stderr)


if __name__ == "__main__":
    unittest.main()
