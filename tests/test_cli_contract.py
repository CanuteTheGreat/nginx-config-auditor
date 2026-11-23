"""CLI contract tests (docs/CLI-CONTRACT.md): exit codes, --json shape, --quiet, errors on stderr.

Offline and self-contained: no nginx or docker is needed (the tool parses configs itself; the
--local/--docker paths are exercised with an empty PATH so the tools are missing).
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from contract_support import run_cli, validate  # noqa: E402

ROOT = os.path.dirname(HERE)
TOOL = os.path.join(ROOT, "nginx_config_auditor.py")
with open(os.path.join(ROOT, "schema", "nginx-config-auditor.schema.json")) as _f:
    SCHEMA = json.load(_f)

CLEAN = """
server_tokens off;
server {
    listen 443 ssl http2;
    server_name example.test;
    ssl_certificate /x.pem;
    ssl_certificate_key /x.key;
    ssl_dhparam /dh.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Content-Security-Policy "default-src 'self'" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    location / { root /srv; }
}
"""
WEAK = CLEAN.replace("TLSv1.2 TLSv1.3", "SSLv3 TLSv1")
BROKEN = "server {\n  listen 80;\n"


class ContractBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="nca-contract-")
        cls.clean = cls.write("clean.conf", CLEAN)
        cls.weak = cls.write("weak.conf", WEAK)
        cls.broken = cls.write("broken.conf", BROKEN)
        cls.empty = os.path.join(cls.dir, "empty")
        os.mkdir(cls.empty)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    @classmethod
    def write(cls, name, text):
        p = os.path.join(cls.dir, name)
        with open(p, "w") as f:
            f.write(text)
        return p

    def cli(self, *args, **kw):
        return run_cli(TOOL, args, **kw)


class TestExitCodes(ContractBase):
    def test_clean_input_exits_0(self):
        rc, out, err = self.cli(self.clean)
        self.assertEqual(rc, 0, err)
        self.assertTrue(out.startswith("nginx-config-auditor: scanned 1 file(s)"))

    def test_findings_exit_1(self):
        rc, out, err = self.cli(self.weak)
        self.assertEqual(rc, 1, err)
        self.assertIn("finding(s)", out)

    def test_unknown_flag_exits_2_with_empty_stdout(self):
        rc, out, err = self.cli("--no-such-flag")
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("unrecognized arguments", err)

    def test_missing_required_argument_exits_2(self):
        rc, out, err = self.cli()
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("usage:", err)

    def test_missing_input_file_exits_2(self):
        rc, out, err = self.cli(os.path.join(self.dir, "nope.conf"))
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("path not found", err)

    def test_missing_dump_file_exits_2(self):
        rc, out, err = self.cli("--dump", os.path.join(self.dir, "nope.txt"))
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("ERROR", err)

    def test_unparseable_config_exits_2(self):
        rc, out, err = self.cli(self.broken)
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("parse error", err)

    def test_nothing_to_scan_exits_2(self):
        rc, out, err = self.cli(self.empty)
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("no .conf files", err)

    def test_missing_nginx_binary_is_legacy_exit_2(self):
        rc, out, err = self.cli("--local", env={"PATH": self.empty})
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("`nginx` not found", err)

    def test_missing_docker_binary_is_legacy_exit_2(self):
        rc, out, err = self.cli("--docker", "nope", env={"PATH": self.empty})
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("docker failed", err)

    def test_unexpected_error_exits_3_not_a_traceback(self):
        wrapper = self.write("boom.py", (
            "import sys\nsys.path.insert(0, %r)\nimport nginx_config_auditor as n\n"
            "def boom(*a, **k):\n    raise ValueError('kaboom')\n"
            "n.scan_paths = boom\nsys.exit(n.main(sys.argv[1:]))\n") % ROOT)
        rc, out, err = run_cli(wrapper, [self.clean, "--json"])
        self.assertEqual((rc, out), (3, ""))
        self.assertIn("unexpected error -- ValueError: kaboom", err)
        self.assertNotIn("Traceback", err)

    def test_fail_on_never_exits_0_with_findings(self):
        rc, _out, err = self.cli("--fail-on", "never", self.weak)
        self.assertEqual(rc, 0, err)


class TestJson(ContractBase):
    def doc(self, *args):
        rc, out, err = self.cli("--json", *args)
        self.assertEqual(err, "")
        d = json.loads(out)  # exactly one document, nothing else on stdout
        self.assertEqual(validate(d, SCHEMA), [])
        self.assertEqual(d["exit_code"], rc)
        return rc, d

    def test_clean_validates_against_schema(self):
        rc, d = self.doc(self.clean)
        self.assertEqual(rc, 0)
        self.assertEqual((d["schema_version"], d["tool"]), (1, "nginx-config-auditor"))
        self.assertTrue(all(f["severity"] != "HIGH" for f in d["results"]))

    def test_findings_validate_against_schema(self):
        rc, d = self.doc(self.weak)
        self.assertEqual(rc, 1)
        self.assertTrue(any(f["severity"] == "HIGH" for f in d["results"]))

    def test_version_matches_module(self):
        _rc, d = self.doc(self.clean)
        rc, out, _ = self.cli("--version")
        self.assertEqual(out.split()[-1], d["version"])

    def test_results_respect_min_severity(self):
        _rc, d = self.doc("--min-severity", "HIGH", self.weak)
        self.assertTrue(d["results"])
        self.assertEqual({f["severity"] for f in d["results"]}, {"HIGH"})

    def test_fail_on_never_reports_exit_code_0(self):
        rc, d = self.doc("--fail-on", "never", self.weak)
        self.assertEqual((rc, d["exit_code"]), (0, 0))

    def test_dump_from_stdin(self):
        dump = "# configuration file /etc/nginx/nginx.conf:\n" + WEAK
        rc, out, err = self.cli("--json", "--dump", "-", stdin=dump)
        self.assertEqual((rc, err), (1, ""))
        self.assertEqual(validate(json.loads(out), SCHEMA), [])

    def test_errors_leave_stdout_empty(self):
        rc, out, err = self.cli("--json", os.path.join(self.dir, "nope.conf"))
        self.assertEqual((rc, out), (2, ""))
        self.assertTrue(err)


class TestQuiet(ContractBase):
    def test_quiet_clean(self):
        for flag in ("--quiet", "-q"):
            rc, out, err = self.cli(flag, self.clean)
            self.assertEqual((rc, out, err), (0, "", ""))

    def test_quiet_findings_keep_exit_code(self):
        for flag in ("--quiet", "-q"):
            rc, out, err = self.cli(flag, self.weak)
            self.assertEqual((rc, out, err), (1, "", ""))

    def test_quiet_suppresses_json_too(self):
        rc, out, _err = self.cli("-q", "--json", self.weak)
        self.assertEqual((rc, out), (1, ""))

    def test_quiet_still_reports_errors_on_stderr(self):
        rc, out, err = self.cli("-q", os.path.join(self.dir, "nope.conf"))
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("path not found", err)

    def test_not_quiet_prints_report(self):
        _rc, out, _err = self.cli(self.weak)
        self.assertTrue(out.startswith("nginx-config-auditor: scanned 1 file(s)"))


class TestSchemaFile(unittest.TestCase):
    def test_schema_rejects_missing_contract_keys(self):
        for key in ("schema_version", "tool", "version", "exit_code", "results"):
            d = {"schema_version": 1, "tool": "nginx-config-auditor", "version": "1", "exit_code": 0,
                 "results": []}
            del d[key]
            self.assertTrue(validate(d, SCHEMA), key)

    def test_schema_rejects_old_list_shape(self):
        self.assertTrue(validate([], SCHEMA))


if __name__ == "__main__":
    unittest.main()
