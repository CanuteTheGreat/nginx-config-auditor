# Changelog

All notable changes. Versions are git tags; each tag has a Forgejo release with checksums.

## 1.2.1 - 2026-10-17

- `ssl_ciphers`: anonymous (unauthenticated) suites that aliases such as `HIGH`, `ALL`, `AES` or `kEDH`
  enable are reported when the string also sets `@SECLEVEL=0` (the only way current OpenSSL negotiates
  them; checked against real nginx handshakes); `LOW`, `EXP` and `AECDH` tokens are weak too.

## 1.2.0 - 2026-10-16

- **Includes are followed** (globs too) and the merged tree is audited, so headers or TLS settings set in an
  included snippet no longer produce false "missing" findings in every file. A directory with an
  `nginx.conf` is audited from it (files it never includes are listed as INFO); `--local` and `--dump`
  audit `nginx -T` output; `--docker` now runs `nginx -T` inside the container (docker cp as fallback).
- Security headers are checked **per server**, with http-level headers inherited exactly as nginx does.
- New checks: `add_header` redefinition in a location dropping inherited security headers, alias path
  traversal (location/alias trailing-slash mismatch), `valid_referers none`, `Host $http_host`,
  `$uri`/`$document_uri` in headers or redirects, unanchored Origin/Referer regexes, multi-line header
  values, security headers without `always`, short HSTS max-age.
- A real parser (quotes, escapes, `${var}`, multi-line directives); a config nginx can't parse exits 2.
- `--fail-on` (default `high`, the previous behaviour).
- Installable as a package: `pipx install git+https://git.canutethegreat.com/CanuteTheGreat/nginx-config-auditor.git`
  puts a `nginx-config-auditor` command on PATH (pyproject.toml, MIT license metadata).
- `--version` flag.
- Exit codes follow the shared convention: 0 = clean, 1 = findings at/above the gate, 2 = error or bad usage.
- Every tag now publishes a Forgejo release with this changelog, the wheel, the sdist and SHA256SUMS.
- CI installs the package with pip in a clean venv and checks `--version`/`--help` on every push.

## 1.1.0 - 2026-10-16

- Stop flagging nginx's stock cipher string, parse statements properly, add CI tests
- Add MIT LICENSE file

## 1.0.0 - 2026-09-15

- First public release.
