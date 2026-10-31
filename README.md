# seat-admin-lite

A tiny self-hosted account and device-seat license server for PHP 8 and SQLite. It provides
username/password accounts, feature modules, optional expiry, one active device, batch staff
creation, password reset, and an ECDSA P-256 entitlement that clients can verify offline.

## Why this exists

Keygen, Keygate, laravel-ready license-server, and f-license are useful license-key or seat
platforms. This project stays deliberately small: username/password accounts plus a device seat,
signed JSON, SQLite, no Composer dependencies, and `php -S` for a drop-in deployment.

## How it works

```text
desktop app / extension  <-->  public/api.php  <-->  SQLite accounts + sessions
          |                                      |
          +---- verify signed entitlement offline (public key) ----+
```

The API issues a device-bound signed entitlement. A client can validate its signature and expiry
without a network connection; server-side `check` remains the source of truth for revocation.

## Comparison

| Project | Language | Dependencies | Model | Offline signed entitlement | Device seat | Batch staff accounts |
|---|---|---|---|---|---|---|
| Keygen CE | API service | database and service runtime | license keys | yes | yes | limited by plan/integration |
| Keygate | API service | service runtime | license keys | varies | yes | integration work |
| laravel-ready license-server | PHP/Laravel | Laravel and Composer | license keys | varies | yes | application-specific |
| f-license | PHP | framework/database setup | license keys | varies | yes | application-specific |
| this project | PHP + SQLite | PHP extensions only | username/password accounts | yes, ECDSA P-256 | one device | built in, capped at 200 |

## Quick start

Requirements: PHP 8.1+ with `pdo_sqlite` and `openssl` enabled. `mbstring` is optional. On a
PHP build without `php.ini`, pass `-d extension_dir=PATH\\ext -d extension=pdo_sqlite -d extension=openssl`.

```sh
php bin/seat.php init
php -S 127.0.0.1:8080 -t public
# Keep admin separate: php -S 127.0.0.1:8081 -t admin
```

`init` creates `data/keys/`, the SQLite database, and a one-time admin password in
`admin-password.txt`. Keep `data/` and that file private.

## API

Send form or JSON fields to `public/api.php`:

- `login` (POST only): `username`, `password`, `device_id`, `device_name`.
- `check`: `token`; returns account state and a fresh signed entitlement.
- `change-password` (POST only): `token`, `new_password` (8+ characters).
- `logout`: `token`.
- `public-key`: returns the PEM public key.

Errors include `method_not_allowed`, `invalid_credentials`, `account_disabled`,
`account_expired`, `session_expired`, `invalid_token`, and `rate_limited`.

The entitlement payload is `{device_id, expires_at, issued_at, modules, username}`. Its signature
is base64 ECDSA-SHA256 over canonical JSON (lexicographically sorted object keys). An account with
blank or `never` expiry has `expires_at: null`.

## Admin and CLI

Open the admin server and sign in with the first-run password. The UI supports single and batch
creation, one-time tab-separated credentials with a client-side CSV download, reset (which clears
sessions), enable/disable, unbind, delete, and module/expiry flags. Batch creation skips existing
usernames and is capped at 200. Blank expiry means never. Modules are configured in `config.php`.

```sh
php bin/seat.php list
php bin/seat.php create alice 'a-strong-password' 2030-01-01T00:00:00Z basic,pro
php bin/seat.php batch-create staff 20 1
php bin/seat.php reset-password alice 'another-strong-password'
```

## Security notes

Use HTTPS in production. Keep the admin surface on localhost or behind your own authentication
layer. The login limiter uses only `REMOTE_ADDR`; when a trusted reverse proxy is used, configure
that proxy to pass the real client address safely rather than trusting arbitrary forwarded headers.
Deny access to `/data` and never commit keys, the database, or the first-run password. Offline
verification proves integrity and expiry claims; it does not replace server-side revocation checks.

## Support / 打赏

If this project saved you time, you can buy the author a coffee in crypto. Thank you!
如果这个项目帮到了你，欢迎用加密货币打赏支持，谢谢！

| Network | Asset | Address |
|---|---|---|
| TRON (TRC20) | USDT | `TNGdTwE6opH6rmUyoG1JUR7FSyEb4k273R` |
| Ethereum / BNB Chain / Polygon | USDT | `0x59c43144a862b351fa1086ae842d1327c9d91613` |
| Ethereum / Arbitrum / Base | ETH | `0x59c43144a862b351fa1086ae842d1327c9d91613` |
| Bitcoin | BTC | `1RS6tWXHregLfEsiPzVUCUBuhgDg5uTSV` |
| Solana | USDT | `HZguEXfTtLChNdJTxAYCbcGscaqikz8JYrEpUhEyeVd9` |

Please send only the listed asset on the listed network — other tokens or networks may be lost.
请按表中对应的网络转对应的币种，转错币种或网络可能无法找回。

License: MIT. Copyright tommyapi.com.
