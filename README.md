# nginx-config-auditor

A small, free, stdlib-only Python 3 static analyzer for nginx configuration.
No network calls, no dependencies, read-only. It parses the config the way
nginx does (blocks, quoting, `include` with globs) and audits the **merged
tree**, so a header or TLS setting that lives in an included snippet counts
for every server that includes it. Point it at `nginx.conf`, a directory, a
saved `nginx -T` dump, this host's nginx, or a running Docker container.

| Finding | Severity |
|---|---|
| `autoindex on` (directory listing) | HIGH |
| weak TLS protocols (SSLv2/3, TLSv1, TLSv1.1) in `ssl_protocols` | HIGH |
| weak cipher tokens (RC4, DES, 3DES, MD5, EXPORT, LOW, NULL, ADH/AECDH, PSK) enabled in `ssl_ciphers`, and anonymous suites that aliases like `HIGH`/`ALL` pull in when the string also lowers `@SECLEVEL=0` | HIGH |
| **alias traversal**: `location /static` (no trailing slash) with `alias /srv/static/` | HIGH |
| missing security headers per server (HSTS on TLS servers, X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy), with http-level headers inherited exactly as nginx inherits them | MEDIUM |
| **`add_header` redefinition**: a location with its own `add_header` silently drops every inherited header | MEDIUM |
| `valid_referers none`, `proxy_set_header Host $http_host` (Host spoofing), `$uri`/`$document_uri` in response headers or redirects (header splitting), unanchored `$http_origin`/`$http_referer` regexes | MEDIUM |
| `root` / `alias` pointing at `/` | MEDIUM |
| security header without `always` (not sent on 4xx/5xx), HSTS max-age under 180 days, multi-line header values | LOW |
| `server_tokens` on/unset, `ssl_prefer_server_ciphers off`, missing `ssl_dhparam`, custom `Server` header | LOW |
| plaintext `proxy_pass`, SSI, `auth_basic_user_file`, no HTTP/2, includes that match nothing, `.conf` files nginx.conf never includes | INFO |

The header-inheritance, alias, referer, Host, header-splitting and origin checks are the
same classes of problems [gixy](https://github.com/yandex/gixy) looks for.

## Install

```sh
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/nginx-config-auditor.git        # latest release branch; puts `nginx-config-auditor` on PATH
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/nginx-config-auditor.git@v1.2.1  # a pinned release
brew install canutethegreat/errant-tools/nginx-config-auditor   # after: brew tap canutethegreat/errant-tools https://git.canutethegreat.com/CanuteTheGreat/homebrew-errant-tools
scoop install errant-tools/nginx-config-auditor                 # after: scoop bucket add errant-tools https://git.canutethegreat.com/CanuteTheGreat/scoop-errant-tools
```

Or download the single file (stdlib-only Python 3.8+) and run it directly:
`curl -fsSLO https://errant.solutions/downloads/nginx_config_auditor.py && python3 nginx_config_auditor.py --help`.
Every [release](https://git.canutethegreat.com/CanuteTheGreat/nginx-config-auditor/releases) has a changelog, the wheel, the sdist and a `SHA256SUMS` file.
Not on PyPI yet, so plain `pipx install nginx-config-auditor` doesn't work until it's published there.

## Usage

```
nginx-config-auditor /etc/nginx/nginx.conf          # follows every include
nginx-config-auditor /etc/nginx/                    # nginx.conf there if present, else each *.conf on its own
sudo nginx-config-auditor --local                   # runs `nginx -T` and audits exactly what nginx loaded
nginx -T | nginx-config-auditor --dump -            # or a saved dump file
nginx-config-auditor --docker my-nginx-container    # `nginx -T` inside it (docker cp of /etc/nginx as fallback)
nginx-config-auditor /etc/nginx/ --json --min-severity MEDIUM
nginx-config-auditor /etc/nginx/ --fail-on medium   # CI gate
```

Exit codes (same convention as every Errant Solutions tool):

| Code | Meaning |
|---|---|
| 0 | no finding at or above `--fail-on` (default `high`) |
| 1 | at least one |
| 2 | nothing to scan, a parse error, `nginx -T`/docker failed, or bad usage |

## Limitations

- It flags patterns, it does not prove exploitability: every HIGH/MEDIUM finding is worth a
  human look.
- Relative `include` paths are resolved against the directory of the file you point it at
  (nginx uses its configured prefix); `--local`/`--dump` avoid the question entirely.
- `*_by_lua_block` bodies are skipped, not parsed.

## License

MIT

## Tests

`tests/` exercises every option and check end-to-end (fixtures validated by real `nginx -t`, plus `--docker` against a real nginx container) in Forgejo CI on
Python 3.8 and current Python; `sh ci/run-tests.sh 3.13` reproduces it locally (needs docker).
