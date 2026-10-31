<?php
declare(strict_types=1);

require_once dirname(__DIR__) . DIRECTORY_SEPARATOR . 'config.php';

function seat_cfg(): array
{
    static $config;
    return $config ??= seat_config();
}

function seat_data_dir(): string
{
    $path = seat_cfg()['data_dir'];
    if (!is_dir($path)) {
        mkdir($path, 0700, true);
    }
    return $path;
}

function seat_db(?PDO $db = null): PDO
{
    if ($db !== null) {
        return $db;
    }
    seat_data_dir();
    $pdo = new PDO('sqlite:' . seat_cfg()['db_path']);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    init_schema($pdo);
    return $pdo;
}

function init_schema(PDO $db): void
{
    $db->exec(
        'CREATE TABLE IF NOT EXISTS accounts (' .
        'id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, ' .
        'password_hash TEXT NOT NULL, modules_json TEXT NOT NULL, expires_at TEXT NULL, ' .
        'enabled INTEGER NOT NULL DEFAULT 1, must_change_password INTEGER NOT NULL DEFAULT 0, ' .
        'device_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)'
    );
    migrate_nullable_expiry($db);
    $db->exec(
        'CREATE TABLE IF NOT EXISTS sessions (' .
        'id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER NOT NULL, ' .
        'token_hash TEXT NOT NULL UNIQUE, device_id TEXT NOT NULL, device_name TEXT NOT NULL, ' .
        'created_at TEXT NOT NULL, FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE)'
    );
    $db->exec(
        'CREATE TABLE IF NOT EXISTS rate_limits (' .
        'ip TEXT PRIMARY KEY, window_start INTEGER NOT NULL, attempts INTEGER NOT NULL)'
    );
    $db->exec('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
}

function migrate_nullable_expiry(PDO $db): void
{
    $columns = $db->query('PRAGMA table_info(accounts)')->fetchAll();
    foreach ($columns as $column) {
        if ($column['name'] !== 'expires_at' || (int) $column['notnull'] === 0) {
            continue;
        }
        $db->exec('PRAGMA foreign_keys=OFF');
        $db->beginTransaction();
        try {
            $db->exec(
                'CREATE TABLE accounts_migration (' .
                'id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, ' .
                'password_hash TEXT NOT NULL, modules_json TEXT NOT NULL, expires_at TEXT NULL, ' .
                'enabled INTEGER NOT NULL DEFAULT 1, must_change_password INTEGER NOT NULL DEFAULT 0, ' .
                'device_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)'
            );
            $db->exec('INSERT INTO accounts_migration SELECT * FROM accounts');
            $db->exec('DROP TABLE accounts');
            $db->exec('ALTER TABLE accounts_migration RENAME TO accounts');
            $db->commit();
        } catch (Throwable $error) {
            $db->rollBack();
            throw $error;
        } finally {
            $db->exec('PRAGMA foreign_keys=ON');
        }
        break;
    }
}

function utc_now(): string
{
    return gmdate('c');
}

function normalize_modules($modules): array
{
    if (is_string($modules)) {
        $modules = preg_split('/[,\s]+/', trim($modules), -1, PREG_SPLIT_NO_EMPTY);
    }
    if (!is_array($modules)) {
        $modules = [];
    }
    $allowed = seat_cfg()['modules'];
    $normalized = [];
    foreach ($modules as $module) {
        $module = (string) $module;
        if (in_array($module, $allowed, true) && !in_array($module, $normalized, true)) {
            $normalized[] = $module;
        }
    }
    return array_values($normalized);
}

function normalize_expiry($expiry): ?string
{
    if ($expiry === null) {
        return null;
    }
    $value = trim((string) $expiry);
    return $value === '' || strtolower($value) === 'never' ? null : $value;
}

function canonical_json(array $value): string
{
    $sort = function ($current) use (&$sort) {
        if (is_array($current)) {
            $is_list = array_keys($current) === range(0, count($current) - 1);
            if (!$is_list) {
                ksort($current);
            }
            foreach ($current as $key => $item) {
                $current[$key] = $sort($item);
            }
        }
        return $current;
    };
    return json_encode(
        $sort($value),
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION |
        JSON_THROW_ON_ERROR
    );
}

function key_paths(): array
{
    $directory = seat_cfg()['keys_dir'];
    return [
        $directory . DIRECTORY_SEPARATOR . 'private.pem',
        $directory . DIRECTORY_SEPARATOR . 'public.pem',
    ];
}

function ensure_keys(): void
{
    if (!getenv('OPENSSL_CONF')) {
        $config = dirname(PHP_BINARY) . DIRECTORY_SEPARATOR . 'extras' . DIRECTORY_SEPARATOR .
            'ssl' . DIRECTORY_SEPARATOR . 'openssl.cnf';
        if (is_file($config)) {
            putenv('OPENSSL_CONF=' . $config);
        }
    }
    if (!getenv('RANDFILE')) {
        $random_file = seat_data_dir() . DIRECTORY_SEPARATOR . '.rand';
        if (!is_file($random_file)) {
            file_put_contents($random_file, '');
        }
        putenv('RANDFILE=' . $random_file);
    }
    [$private_path, $public_path] = key_paths();
    if (is_file($private_path) && is_file($public_path)) {
        return;
    }
    if (!is_dir(dirname($private_path))) {
        mkdir(dirname($private_path), 0700, true);
    }
    $key = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_EC,
        'curve_name' => 'prime256v1',
    ]);
    if ($key && openssl_pkey_export($key, $private)) {
        $details = openssl_pkey_get_details($key);
        if (!$details || empty($details['key'])) {
            throw new RuntimeException('public_key_failed');
        }
        file_put_contents($private_path, $private, LOCK_EX);
        chmod($private_path, 0600);
        file_put_contents($public_path, $details['key'], LOCK_EX);
        chmod($public_path, 0644);
        return;
    }
    $quoted_private = str_replace('"', '\\"', $private_path);
    $quoted_public = str_replace('"', '\\"', $public_path);
    $environment = getenv();
    $environment['OPENSSL_CONF'] = getenv('OPENSSL_CONF') ?: '';
    $environment['RANDFILE'] = getenv('RANDFILE') ?: '';
    $command = 'openssl ecparam -name prime256v1 -genkey -noout -out "' . $quoted_private .
        '" && openssl ec -in "' . $quoted_private . '" -pubout -out "' . $quoted_public . '"';
    $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $environment);
    $exit_code = -1;
    if (is_resource($process)) {
        stream_get_contents($pipes[1]);
        stream_get_contents($pipes[2]);
        $exit_code = proc_close($process);
    }
    if ($exit_code !== 0 || !is_file($private_path) || !is_file($public_path)) {
        throw new RuntimeException('key_generation_failed');
    }
    chmod($private_path, 0600);
    chmod($public_path, 0644);
}

function public_key_pem(): string
{
    ensure_keys();
    return (string) file_get_contents(key_paths()[1]);
}

function admin_password_hash(?PDO $db = null): ?string
{
    $row = seat_db($db)->query("SELECT value FROM settings WHERE key='admin_hash'")->fetch();
    return $row['value'] ?? null;
}

function ensure_admin(PDO $db): ?string
{
    $hash = admin_password_hash($db);
    if ($hash) {
        return null;
    }
    $password = bin2hex(random_bytes(8));
    $statement = $db->prepare("INSERT OR REPLACE INTO settings(key,value) VALUES('admin_hash',?)");
    $statement->execute([password_hash($password, PASSWORD_DEFAULT)]);
    $file = seat_cfg()['admin_password_file'];
    if (!is_file($file)) {
        file_put_contents($file, "Seat Admin first-run password\n\n$password\n", LOCK_EX);
    }
    return $password;
}

function random_password(int $length = 10): string
{
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    $password = '';
    for ($index = 0; $index < $length; $index++) {
        $password .= $alphabet[random_int(0, strlen($alphabet) - 1)];
    }
    return $password;
}

function account_row(PDO $db, string $username): ?array
{
    $statement = $db->prepare('SELECT * FROM accounts WHERE username=?');
    $statement->execute([$username]);
    return $statement->fetch() ?: null;
}

function account_by_token(PDO $db, string $token): ?array
{
    $token_hash = hash('sha256', $token);
    $statement = $db->prepare(
        'SELECT a.*, s.device_id AS session_device_id, s.device_name, s.token_hash, '
        . 's.created_at AS session_created_at FROM sessions s '
        . 'JOIN accounts a ON a.id=s.account_id WHERE s.token_hash=?'
    );
    $statement->execute([$token_hash]);
    $account = $statement->fetch();
    if (!$account) {
        return null;
    }
    $ttl = (int) seat_cfg()['session_ttl'];
    $created_at = strtotime((string) $account['session_created_at']);
    if ($ttl > 0 && $created_at !== false && $created_at + $ttl <= time()) {
        $db->prepare('DELETE FROM sessions WHERE token_hash=?')->execute([$token_hash]);
        return [
            'ok' => false,
            'error' => 'session_expired',
            'message' => 'Session has expired',
            'token_hash' => $token_hash,
        ];
    }
    return $account;
}

function account_error(array $account): ?array
{
    if (!(int) $account['enabled']) {
        return ['ok' => false, 'error' => 'account_disabled', 'message' => 'Account is disabled'];
    }
    $expiry = normalize_expiry($account['expires_at'] ?? null);
    if ($expiry !== null && (($timestamp = strtotime($expiry)) !== false) && $timestamp < time()) {
        return ['ok' => false, 'error' => 'account_expired', 'message' => 'Account has expired'];
    }
    return null;
}

function entitlement(array $account, string $device): array
{
    $payload = [
        'device_id' => $device,
        'expires_at' => normalize_expiry($account['expires_at'] ?? null),
        'issued_at' => utc_now(),
        'modules' => json_decode($account['modules_json'], true) ?: [],
        'username' => $account['username'],
    ];
    $data = canonical_json($payload);
    ensure_keys();
    $key = openssl_pkey_get_private((string) file_get_contents(key_paths()[0]));
    if (!$key || !openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA256)) {
        throw new RuntimeException('sign_failed');
    }
    return [
        'payload' => $payload,
        'signature' => base64_encode($signature),
        'algorithm' => 'ECDSA-SHA256',
    ];
}

function rate_limit_status(PDO $db, string $ip): ?array
{
    $statement = $db->prepare('SELECT * FROM rate_limits WHERE ip=?');
    $statement->execute([$ip]);
    $row = $statement->fetch();
    if (!$row || time() - (int) $row['window_start'] >= 60) {
        return null;
    }
    if ((int) $row['attempts'] >= 10) {
        return ['ok' => false, 'error' => 'rate_limited', 'message' => 'Too many login attempts'];
    }
    return null;
}

function record_failed_login(PDO $db, string $ip): void
{
    $now = time();
    $statement = $db->prepare('SELECT * FROM rate_limits WHERE ip=?');
    $statement->execute([$ip]);
    $row = $statement->fetch();
    if (!$row || $now - (int) $row['window_start'] >= 60) {
        $db->prepare('INSERT OR REPLACE INTO rate_limits(ip,window_start,attempts) VALUES(?,?,1)')
            ->execute([$ip, $now]);
        return;
    }
    $db->prepare('UPDATE rate_limits SET attempts=? WHERE ip=?')
        ->execute([(int) $row['attempts'] + 1, $ip]);
}

function reset_login_rate(PDO $db, string $ip): void
{
    $db->prepare('DELETE FROM rate_limits WHERE ip=?')->execute([$ip]);
}

function dummy_password_hash(): string
{
    static $hash;
    return $hash ??= password_hash('seat-dummy', PASSWORD_DEFAULT);
}

/** Handle one JSON API action and return a serializable result. */
function api_action(
    string $action,
    array $input,
    string $ip = '0.0.0.0',
    ?PDO $db = null,
    string $method = 'POST'
): array {
    $db = seat_db($db);
    ensure_keys();
    if (in_array($action, ['login', 'change-password'], true) && strtoupper($method) !== 'POST') {
        return [
            'ok' => false,
            'error' => 'method_not_allowed',
            'message' => 'This action requires POST',
        ];
    }
    if ($action === 'public-key') {
        return ['ok' => true, 'public_key' => public_key_pem()];
    }

    if ($action === 'login') {
        if (($limited = rate_limit_status($db, $ip)) !== null) {
            return $limited;
        }
        $username = trim((string) ($input['username'] ?? ''));
        $password = (string) ($input['password'] ?? '');
        $device = trim((string) ($input['device_id'] ?? ''));
        $device_name = trim((string) ($input['device_name'] ?? ''));
        if ($username === '' || $password === '' || $device === '') {
            return [
                'ok' => false,
                'error' => 'invalid_request',
                'message' => 'username, password and device_id are required',
            ];
        }
        $account = account_row($db, $username);
        $valid_password = $account
            ? password_verify($password, $account['password_hash'])
            : password_verify($password, dummy_password_hash());
        if (!$account || !$valid_password) {
            record_failed_login($db, $ip);
            return [
                'ok' => false,
                'error' => 'invalid_credentials',
                'message' => 'Invalid username or password',
            ];
        }
        if (($error = account_error($account)) !== null) {
            return $error;
        }
        reset_login_rate($db, $ip);
        $db->prepare('DELETE FROM sessions WHERE account_id=?')->execute([$account['id']]);
        $now = utc_now();
        $db->prepare('UPDATE accounts SET device_id=?,updated_at=? WHERE id=?')
            ->execute([$device, $now, $account['id']]);
        $token = bin2hex(random_bytes(32));
        $db->prepare(
            'INSERT INTO sessions(account_id,token_hash,device_id,device_name,created_at) VALUES(?,?,?,?,?)'
        )->execute([$account['id'], hash('sha256', $token), $device, $device_name, $now]);
        return [
            'ok' => true,
            'token' => $token,
            'username' => $username,
            'must_change_password' => (bool) $account['must_change_password'],
            'entitlement' => entitlement(array_merge($account, ['device_id' => $device]), $device),
        ];
    }

    $token = (string) ($input['token'] ?? '');
    $account = $token !== '' ? account_by_token($db, $token) : null;
    if (!$account) {
        return ['ok' => false, 'error' => 'invalid_token', 'message' => 'Invalid session token'];
    }
    if (($account['error'] ?? '') === 'session_expired') {
        return $account;
    }
    if (($error = account_error($account)) !== null) {
        $db->prepare('DELETE FROM sessions WHERE token_hash=?')->execute([$account['token_hash']]);
        return $error;
    }
    if ($action === 'check') {
        return [
            'ok' => true,
            'username' => $account['username'],
            'enabled' => (bool) $account['enabled'],
            'expires_at' => normalize_expiry($account['expires_at'] ?? null),
            'must_change_password' => (bool) $account['must_change_password'],
            'entitlement' => entitlement($account, $account['session_device_id']),
        ];
    }
    if ($action === 'change-password') {
        $new_password = (string) ($input['new_password'] ?? '');
        if (strlen($new_password) < 8) {
            return [
                'ok' => false,
                'error' => 'weak_password',
                'message' => 'Password must be at least 8 characters',
            ];
        }
        $db->prepare('UPDATE accounts SET password_hash=?,must_change_password=0,updated_at=? WHERE id=?')
            ->execute([password_hash($new_password, PASSWORD_DEFAULT), utc_now(), $account['id']]);
        return ['ok' => true];
    }
    if ($action === 'logout') {
        $db->prepare('DELETE FROM sessions WHERE token_hash=?')->execute([$account['token_hash']]);
        return ['ok' => true];
    }
    return ['ok' => false, 'error' => 'unknown_action', 'message' => 'Unknown action'];
}

/** Create one account with normalized modules and optional expiry. */
function create_account(
    PDO $db,
    string $username,
    string $password,
    array $modules,
    ?string $expires = null,
    bool $must_change = false
): bool {
    $now = utc_now();
    $statement = $db->prepare(
        'INSERT INTO accounts(username,password_hash,modules_json,expires_at,must_change_password,created_at,updated_at) '
        . 'VALUES(?,?,?,?,?,?,?)'
    );
    return $statement->execute([
        $username,
        password_hash($password, PASSWORD_DEFAULT),
        json_encode(normalize_modules($modules), JSON_UNESCAPED_UNICODE),
        normalize_expiry($expires),
        $must_change ? 1 : 0,
        $now,
        $now,
    ]);
}

/** Replace a password and revoke every active session for the account. */
function reset_account_password(PDO $db, int $id, string $password): void
{
    $db->prepare('UPDATE accounts SET password_hash=?,must_change_password=1,updated_at=? WHERE id=?')
        ->execute([password_hash($password, PASSWORD_DEFAULT), utc_now(), $id]);
    $db->prepare('DELETE FROM sessions WHERE account_id=?')->execute([$id]);
}
