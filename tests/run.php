<?php
declare(strict_types=1);

putenv('SEAT_DATA_DIR=' . dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data-test');
require_once dirname(__DIR__) . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'lib.php';

function remove_tree(string $path): void
{
    if (!is_dir($path)) {
        return;
    }
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $file) {
        $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
    }
    rmdir($path);
}

remove_tree(seat_cfg()['data_dir']);
@unlink(seat_cfg()['admin_password_file']);
$db = seat_db();
ensure_keys();
ensure_admin($db);
$passed = 0;
$failed = 0;

function check(bool $condition, string $message): void
{
    global $passed, $failed;
    if ($condition) {
        $passed++;
        echo "PASS $message\n";
        return;
    }
    $failed++;
    echo "FAIL $message\n";
}

$method_get = api_action('login', [], '10.0.0.1', $db, 'GET');
check(($method_get['error'] ?? '') === 'method_not_allowed', 'login rejects GET');
$dummy_change = api_action('change-password', [], '10.0.0.1', $db, 'GET');
check(($dummy_change['error'] ?? '') === 'method_not_allowed', 'change-password rejects GET');

$invalid = api_action(
    'login',
    ['username' => 'none', 'password' => 'bad', 'device_id' => 'd'],
    '10.0.0.2',
    $db
);
check(($invalid['error'] ?? '') === 'invalid_credentials', 'invalid login');

create_account($db, 'alice', 'Password123', ['basic', 'pro'], gmdate('c', time() + 3600));
$login = api_action(
    'login',
    ['username' => 'alice', 'password' => 'Password123', 'device_id' => 'dev-a', 'device_name' => 'Laptop'],
    '10.0.0.3',
    $db
);
check($login['ok'] ?? false, 'login');
$token_one = $login['token'];
$public_key = public_key_pem();
$entitlement = $login['entitlement'];
$verified = openssl_verify(
    canonical_json($entitlement['payload']),
    base64_decode($entitlement['signature']),
    openssl_pkey_get_public($public_key),
    OPENSSL_ALGO_SHA256
);
check($verified === 1, 'ECDSA signature verifies');
$fixture = json_encode(
    ['public_key' => $public_key, 'entitlement' => $entitlement],
    JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT
);
file_put_contents(
    dirname(__DIR__) . DIRECTORY_SEPARATOR . 'examples' . DIRECTORY_SEPARATOR . 'fixture.json',
    $fixture
);

$login_two = api_action(
    'login',
    ['username' => 'alice', 'password' => 'Password123', 'device_id' => 'dev-b', 'device_name' => 'Desktop'],
    '10.0.0.3',
    $db
);
check($login_two['ok'] ?? false, 'second device login');
$old = api_action('check', ['token' => $token_one], '10.0.0.3', $db);
check(($old['error'] ?? '') === 'invalid_token', 'old device kicked');
$token_two = $login_two['token'];
$current = api_action('check', ['token' => $token_two], '10.0.0.3', $db);
check($current['ok'] ?? false, 'check');
$changed = api_action(
    'change-password',
    ['token' => $token_two, 'new_password' => 'NewPassword123'],
    '10.0.0.3',
    $db
);
check($changed['ok'] ?? false, 'change password');
api_action('logout', ['token' => $token_two], '10.0.0.3', $db);
$login_three = api_action(
    'login',
    ['username' => 'alice', 'password' => 'NewPassword123', 'device_id' => 'dev-c'],
    '10.0.0.3',
    $db
);
check($login_three['ok'] ?? false, 'new password works');

$alice = account_row($db, 'alice');
$db->prepare('UPDATE sessions SET created_at=? WHERE account_id=?')
    ->execute([gmdate('c', time() - (int) seat_cfg()['session_ttl'] - 1), $alice['id']]);
$session_expired = api_action('check', ['token' => $login_three['token']], '10.0.0.3', $db);
check(($session_expired['error'] ?? '') === 'session_expired', 'session TTL expires token');

create_account($db, 'never-empty', 'NeverPass123', ['basic'], '');
create_account($db, 'never-word', 'NeverPass123', ['basic'], 'never');
$never_login = api_action(
    'login',
    ['username' => 'never-empty', 'password' => 'NeverPass123', 'device_id' => 'never-device'],
    '10.0.0.4',
    $db
);
check($never_login['ok'] ?? false, 'empty expiry does not expire');
check($never_login['entitlement']['payload']['expires_at'] === null, 'empty expiry entitlement is null');
$never_word_login = api_action(
    'login',
    ['username' => 'never-word', 'password' => 'NeverPass123', 'device_id' => 'never-device'],
    '10.0.0.5',
    $db
);
check($never_word_login['ok'] ?? false, 'never expiry does not expire');

create_account($db, 'existing', 'Password123', ['basic'], null);
define('SEAT_ADMIN_LIBRARY_ONLY', true);
require dirname(__DIR__) . DIRECTORY_SEPARATOR . 'admin' . DIRECTORY_SEPARATOR . 'index.php';
$batch = admin_process($db, [
    '_csrf' => 'known',
    'action' => 'batch_create',
    'prefix' => 'staff',
    'count' => '3',
    'start' => '1',
    'modules' => 'basic',
], 'known');
check(($batch['ok'] ?? false) && ($batch['created_count'] ?? 0) === 3, 'batch creates three');
$batch_rows = explode("\n", $batch['credentials']);
$staff_two_password = explode("\t", $batch_rows[1])[1];
check(
    password_verify($staff_two_password, account_row($db, 'staff2')['password_hash']),
    'batch password works'
);
$batch_again = admin_process($db, [
    '_csrf' => 'known',
    'action' => 'batch_create',
    'prefix' => 'staff',
    'count' => '3',
    'start' => '1',
], 'known');
check(count($batch_again['skipped'] ?? []) === 3, 'batch skips existing usernames');
$batch_cap = admin_process($db, [
    '_csrf' => 'known',
    'action' => 'batch_create',
    'prefix' => 'cap',
    'count' => '999',
    'start' => '1',
], 'known');
check(($batch_cap['created_count'] ?? 0) === 200, 'batch cap is 200');

$account = account_row($db, 'alice');
reset_account_password($db, (int) $account['id'], 'ResetPass123');
check(account_by_token($db, $login_three['token']) === null, 'reset clears session');

create_account($db, 'disabled', 'Password123', ['basic'], null);
$disabled = account_row($db, 'disabled');
$db->prepare('UPDATE accounts SET enabled=0 WHERE id=?')->execute([$disabled['id']]);
$disabled_login = api_action(
    'login',
    ['username' => 'disabled', 'password' => 'Password123', 'device_id' => 'd'],
    '10.0.0.6',
    $db
);
check(($disabled_login['error'] ?? '') === 'account_disabled', 'disabled refused');
create_account($db, 'expired', 'Password123', ['basic'], gmdate('c', time() - 60));
$expired_login = api_action(
    'login',
    ['username' => 'expired', 'password' => 'Password123', 'device_id' => 'd'],
    '10.0.0.7',
    $db
);
check(($expired_login['error'] ?? '') === 'account_expired', 'expired refused');

$db->exec('DELETE FROM rate_limits');
for ($index = 0; $index < 10; $index++) {
    api_action(
        'login',
        ['username' => 'none', 'password' => 'bad', 'device_id' => 'd'],
        '10.0.0.8',
        $db
    );
}
$limited = api_action(
    'login',
    ['username' => 'none', 'password' => 'bad', 'device_id' => 'd'],
    '10.0.0.8',
    $db
);
check(($limited['error'] ?? '') === 'rate_limited', 'rate limit');
$db->exec('DELETE FROM rate_limits');
api_action(
    'login',
    ['username' => 'none', 'password' => 'bad', 'device_id' => 'd'],
    '10.0.0.9',
    $db
);
$success = api_action(
    'login',
    ['username' => 'never-empty', 'password' => 'NeverPass123', 'device_id' => 'd'],
    '10.0.0.9',
    $db
);
$after_success = api_action(
    'login',
    ['username' => 'none', 'password' => 'bad', 'device_id' => 'd'],
    '10.0.0.9',
    $db
);
check(($success['ok'] ?? false) && ($after_success['error'] ?? '') === 'invalid_credentials', 'success resets rate limit');
$csrf = admin_process($db, ['action' => 'create', 'username' => 'csrf-test', 'password' => 'Password123'], 'known');
check(($csrf['error'] ?? '') === 'csrf_rejected', 'CSRF rejection');

echo "PASS_COUNT=$passed FAIL_COUNT=$failed\n";
exit($failed ? 1 : 0);
