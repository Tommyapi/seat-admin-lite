# seat-admin-lite（中文说明）

一个小型、自托管的 PHP 8 + SQLite 账号与设备席位授权服务。它为桌面软件或浏览器扩展
提供用户名/密码、模块、可选到期时间、单设备登录、员工批量建号、重置密码，以及可离线
验证的 ECDSA P-256 签名 entitlement。

## 工作方式

```text
桌面软件 / 扩展  <-->  public/api.php  <-->  SQLite 账号与会话
       |                                      |
       +------ 使用公钥离线验证签名 entitlement ------+
```

服务端签发绑定设备的签名 entitlement。客户端无需联网即可验证签名和到期时间；联网时仍应
使用 `check` 作为吊销状态的权威来源。

## 对比

| 项目 | 语言 | 依赖 | 授权模型 | 离线签名 entitlement | 设备席位 | 员工批量账号 |
|---|---|---|---|---|---|---|
| Keygen CE | API 服务 | 数据库与服务运行时 | license key | 有 | 有 | 取决于方案/集成 |
| Keygate | API 服务 | 服务运行时 | license key | 视配置 | 有 | 需要集成 |
| laravel-ready license-server | PHP/Laravel | Laravel 与 Composer | license key | 视配置 | 有 | 按应用实现 |
| f-license | PHP | 框架/数据库配置 | license key | 视配置 | 有 | 按应用实现 |
| 本项目 | PHP + SQLite | 仅 PHP 扩展 | 用户名/密码账号 | 有，ECDSA P-256 | 单设备 | 内置，最多 200 个 |

## 快速开始

需要 PHP 8.1+，启用 `pdo_sqlite` 与 `openssl`（`mbstring` 可选）。没有 `php.ini` 的 PHP
可以传入 `-d extension_dir=PATH\\ext -d extension=pdo_sqlite -d extension=openssl`。

```sh
php bin/seat.php init
php -S 127.0.0.1:8080 -t public
php -S 127.0.0.1:8081 -t admin
```

首次 `init` 会生成 `data/keys/`、SQLite 数据库，并将一次性管理员密码写入
`admin-password.txt`。请保护 `data/` 和该文件。

## API

请求 `public/api.php`，可发送表单或 JSON：

- `login`（仅 POST）：`username`、`password`、`device_id`、`device_name`；新设备登录会踢掉旧设备。
- `check`：`token`；返回账号状态和新的签名 entitlement。
- `change-password`（仅 POST）：`token`、`new_password`（至少 8 位）。
- `logout`：`token`。
- `public-key`：返回 PEM 公钥。

常见错误码包括 `method_not_allowed`、`invalid_credentials`、`account_disabled`、
`account_expired`、`session_expired`、`invalid_token`、`rate_limited`。空白或 `never`
到期时间会在 entitlement 中表示为 `expires_at: null`。

## 管理与 CLI

管理页支持单个/批量建号、一次性显示可复制的制表符凭据并在浏览器生成 CSV、重置密码并
清除会话、启停、解绑设备、删除、模块和到期编辑。批量建号会跳过已存在用户名，最多 200
个；空白到期时间表示永不过期。模块在 `config.php` 配置。

```sh
php bin/seat.php list
php bin/seat.php create alice 'a-strong-password' 2030-01-01T00:00:00Z basic,pro
php bin/seat.php batch-create staff 20 1
php bin/seat.php reset-password alice 'another-strong-password'
```

## 安全说明

生产环境请使用 HTTPS；管理页只监听 localhost 或置于额外认证之后；通过 Caddy/Nginx 拒绝
`/data`；不要提交密钥、数据库和首次密码。登录限流只使用 `REMOTE_ADDR`，如果前面有可信
反向代理，请由代理安全地传递真实客户端地址，不要信任任意转发头。离线签名验证只证明
entitlement 未被篡改，不能代替服务端吊销检查。

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
