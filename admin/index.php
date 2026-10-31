<?php
declare(strict_types=1);

require_once dirname(__DIR__) . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'lib.php';

/** Validate CSRF and execute one admin form action. */
function admin_process(PDO $db, array $post, string $csrf): array
{
    if (!hash_equals($csrf, (string) ($post['_csrf'] ?? ''))) {
        return [
            'ok' => false,
            'error' => 'csrf_rejected',
            'message' => 'CSRF token rejected',
        ];
    }

    $action = (string) ($post['action'] ?? '');
    try {
        if ($action === 'create') {
            $username = trim((string) ($post['username'] ?? ''));
            $password = (string) ($post['password'] ?? '');
            if ($username === '' || strlen($password) < 8) {
                throw new InvalidArgumentException('Username and 8+ character password required');
            }
            create_account(
                $db,
                $username,
                $password,
                normalize_modules($post['modules'] ?? []),
                normalize_expiry($post['expires_at'] ?? null),
                !empty($post['must_change'])
            );
            return ['ok' => true, 'message' => 'Account created'];
        }

        if ($action === 'batch_create') {
            $prefix = trim((string) ($post['prefix'] ?? ''));
            $count = min(200, max(0, (int) ($post['count'] ?? 0)));
            $start = (int) ($post['start'] ?? 1);
            $expiry = normalize_expiry($post['expires_at'] ?? null);
            $credentials = [];
            $skipped = [];
            for ($index = 0; $index < $count; $index++) {
                $username = $prefix . ($start + $index);
                if (account_row($db, $username)) {
                    $skipped[] = $username;
                    continue;
                }
                $password = random_password();
                create_account(
                    $db,
                    $username,
                    $password,
                    normalize_modules($post['modules'] ?? []),
                    $expiry,
                    !empty($post['must_change'])
                );
                $credentials[] = $username . "\t" . $password;
            }
            return [
                'ok' => true,
                'message' => 'Batch created',
                'credentials' => implode("\n", $credentials),
                'skipped' => $skipped,
                'created_count' => count($credentials),
            ];
        }

        $id = (int) ($post['id'] ?? 0);
        $statement = $db->prepare('SELECT * FROM accounts WHERE id=?');
        $statement->execute([$id]);
        $account = $statement->fetch();
        if (!$account) {
            throw new RuntimeException('Account not found');
        }

        if ($action === 'reset_pw') {
            $password = (string) ($post['password'] ?? random_password());
            if (strlen($password) < 8) {
                throw new InvalidArgumentException('Password too short');
            }
            reset_account_password($db, $id, $password);
            return [
                'ok' => true,
                'password' => $password,
                'message' => 'Password reset; active sessions cleared',
            ];
        }
        if ($action === 'toggle_status') {
            $db->prepare('UPDATE accounts SET enabled=1-enabled,updated_at=? WHERE id=?')
                ->execute([utc_now(), $id]);
            return ['ok' => true, 'message' => 'Account status updated'];
        }
        if ($action === 'unbind') {
            $db->prepare('UPDATE accounts SET device_id=NULL,updated_at=? WHERE id=?')
                ->execute([utc_now(), $id]);
            $db->prepare('DELETE FROM sessions WHERE account_id=?')->execute([$id]);
            return ['ok' => true, 'message' => 'Device unbound'];
        }
        if ($action === 'delete') {
            $db->prepare('DELETE FROM sessions WHERE account_id=?')->execute([$id]);
            $db->prepare('DELETE FROM accounts WHERE id=?')->execute([$id]);
            return ['ok' => true, 'message' => 'Account deleted'];
        }
        if ($action === 'save_account') {
            $db->prepare(
                'UPDATE accounts SET modules_json=?,expires_at=?,must_change_password=?,updated_at=? WHERE id=?'
            )->execute([
                json_encode(normalize_modules($post['modules'] ?? []), JSON_UNESCAPED_UNICODE),
                normalize_expiry($post['expires_at'] ?? null),
                !empty($post['must_change']) ? 1 : 0,
                utc_now(),
                $id,
            ]);
            return ['ok' => true, 'message' => 'Account saved'];
        }
        return ['ok' => false, 'error' => 'unknown_action', 'message' => 'Unknown action'];
    } catch (Throwable $error) {
        return [
            'ok' => false,
            'error' => 'operation_failed',
            'message' => $error->getMessage(),
        ];
    }
}

function admin_escape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

if (defined('SEAT_ADMIN_LIBRARY_ONLY')) {
    return;
}

session_start();
$db = seat_db();
$first_run_password = ensure_admin($db);
$message = $first_run_password
    ? 'First-run password saved to ' . seat_cfg()['admin_password_file']
    : '';
$result = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $hash = admin_password_hash($db);
    if ($hash && password_verify((string) ($_POST['password'] ?? ''), $hash)) {
        session_regenerate_id(true);
        $_SESSION['seat_admin'] = 1;
        header('Location: index.php');
        exit;
    }
    $message = 'Invalid admin password';
}

if (empty($_SESSION['seat_admin'])) {
    ?>
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Seat Admin sign in</title>
        <style>
            body { font: 16px system-ui, sans-serif; max-width: 34rem; margin: 5rem auto; padding: 0 1rem; }
            .card { border: 1px solid #d9e0ea; border-radius: 12px; padding: 1.5rem; box-shadow: 0 8px 24px #20304012; }
            input, button { font: inherit; padding: .65rem; margin-top: .5rem; width: 100%; box-sizing: border-box; }
            button { background: #2257d6; color: white; border: 0; border-radius: 7px; cursor: pointer; }
            .hint { color: #637083; }
        </style>
    </head>
    <body>
        <main class="card">
            <h1>Seat Admin</h1>
            <p class="hint">Account and device-seat management</p>
            <?php if ($message !== ''): ?>
                <p><?= admin_escape($message) ?></p>
            <?php endif; ?>
            <form method="post">
                <label>Admin password
                    <input type="password" name="password" autocomplete="current-password" required>
                </label>
                <button type="submit" name="login" value="1">Sign in</button>
            </form>
        </main>
    </body>
    </html>
    <?php
    exit;
}

if (!isset($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['login'])) {
    $result = admin_process($db, $_POST, (string) $_SESSION['csrf']);
    $message = (string) ($result['message'] ?? ($result['ok'] ? 'OK' : 'Error'));
}

$accounts = $db->query('SELECT * FROM accounts ORDER BY username')->fetchAll();
$modules = seat_cfg()['modules'];
$csrf = admin_escape((string) $_SESSION['csrf']);
$credentials = is_array($result) ? (string) ($result['credentials'] ?? '') : '';
$skipped = is_array($result) ? ($result['skipped'] ?? []) : [];
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Seat Admin</title>
    <style>
        :root { color-scheme: light; font: 15px system-ui, sans-serif; }
        body { max-width: 1180px; margin: 2rem auto; padding: 0 1rem; color: #172033; background: #f6f8fb; }
        h1 { margin-bottom: .25rem; }
        .muted { color: #637083; }
        .card { background: white; border: 1px solid #d9e0ea; border-radius: 12px; padding: 1rem; margin: 1rem 0; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr)); gap: .75rem; }
        label { display: block; color: #4b5870; }
        input, button, textarea { font: inherit; padding: .5rem; box-sizing: border-box; }
        input, textarea { width: 100%; border: 1px solid #bdc8d8; border-radius: 6px; }
        button { border: 0; border-radius: 6px; background: #2257d6; color: white; cursor: pointer; }
        button.secondary { background: #5c6a7d; }
        .actions { display: flex; flex-wrap: wrap; gap: .35rem; align-items: end; }
        .notice { background: #e9f4ff; border-left: 4px solid #2257d6; padding: .75rem; white-space: pre-wrap; }
        .warning { color: #9b3b00; }
        table { width: 100%; border-collapse: collapse; background: white; }
        th, td { text-align: left; vertical-align: top; border-bottom: 1px solid #e7ebf1; padding: .6rem; }
        td form { min-width: 22rem; }
        @media (max-width: 800px) { table { display: block; overflow-x: auto; } }
    </style>
</head>
<body>
    <header>
        <h1>Seat Admin <span class="muted">账号管理</span></h1>
        <p class="muted">Create accounts, manage modules, and control one active device per account.</p>
    </header>

    <?php if ($message !== ''): ?>
        <div class="card notice"><?= admin_escape($message) ?></div>
    <?php endif; ?>

    <?php if ($credentials !== ''): ?>
        <section class="card">
            <h2>One-time credentials</h2>
            <p class="muted">Copy this tab-separated list now. It is not stored in the page after reload.</p>
            <textarea id="credentials" rows="8" readonly><?= admin_escape($credentials) ?></textarea>
            <p class="actions">
                <button type="button" onclick="copyCredentials()">Copy</button>
                <a id="downloadCsv" download="seat-accounts.csv">
                    <button type="button" class="secondary">Download CSV</button>
                </a>
            </p>
            <?php if ($skipped !== []): ?>
                <p class="warning">Skipped existing: <?= admin_escape(implode(', ', $skipped)) ?></p>
            <?php endif; ?>
        </section>
    <?php elseif ($skipped !== []): ?>
        <section class="card warning">Skipped existing: <?= admin_escape(implode(', ', $skipped)) ?></section>
    <?php endif; ?>

    <section class="card">
        <h2>Create account</h2>
        <form method="post">
            <input type="hidden" name="_csrf" value="<?= $csrf ?>">
            <input type="hidden" name="action" value="create">
            <div class="grid">
                <label>Username<input name="username" required></label>
                <label>Password (8+)<input name="password" type="password" required></label>
                <label>Expiry (blank = never)<input name="expires_at" placeholder="never"></label>
                <label>Modules (comma separated)
                    <input name="modules" value="<?= admin_escape(implode(',', $modules)) ?>">
                </label>
            </div>
            <label><input type="checkbox" name="must_change"> Require password change</label>
            <p><button type="submit">Create account</button></p>
        </form>
    </section>

    <section class="card">
        <h2>Batch create (maximum 200)</h2>
        <form method="post">
            <input type="hidden" name="_csrf" value="<?= $csrf ?>">
            <input type="hidden" name="action" value="batch_create">
            <div class="grid">
                <label>Prefix<input name="prefix" required></label>
                <label>Count<input name="count" type="number" min="1" max="200" value="5" required></label>
                <label>Start number<input name="start" type="number" value="1" required></label>
                <label>Expiry (blank = never)<input name="expires_at" placeholder="never"></label>
                <label>Modules<input name="modules" value="<?= admin_escape(implode(',', $modules)) ?>"></label>
            </div>
            <label><input type="checkbox" name="must_change" checked> Require password change</label>
            <p><button type="submit">Create batch</button></p>
        </form>
    </section>

    <section class="card">
        <h2>Accounts</h2>
        <table>
            <thead><tr><th>User</th><th>Modules</th><th>Expiry</th><th>Status</th><th>Device</th><th>Actions</th></tr></thead>
            <tbody>
            <?php foreach ($accounts as $account): ?>
                <?php $account_modules = json_decode($account['modules_json'], true) ?: []; ?>
                <tr>
                    <td><?= admin_escape($account['username']) ?></td>
                    <td><?= admin_escape(implode(',', $account_modules)) ?></td>
                    <td><?= admin_escape((string) ($account['expires_at'] ?: 'never')) ?></td>
                    <td>
                        <?= (int) $account['enabled'] ? 'enabled' : 'disabled' ?>
                        <?= (int) $account['must_change_password'] ? ' / change password' : '' ?>
                    </td>
                    <td><?= admin_escape((string) ($account['device_id'] ?: 'unbound')) ?></td>
                    <td>
                        <form method="post">
                            <input type="hidden" name="_csrf" value="<?= $csrf ?>">
                            <input type="hidden" name="id" value="<?= (int) $account['id'] ?>">
                            <label>Modules
                                <input name="modules" value="<?= admin_escape(implode(',', $account_modules)) ?>">
                            </label>
                            <label>Expiry
                                <input name="expires_at" value="<?= admin_escape((string) ($account['expires_at'] ?: '')) ?>">
                            </label>
                            <label>
                                <input type="checkbox" name="must_change"
                                    <?= (int) $account['must_change_password'] ? 'checked' : '' ?>> Require change
                            </label>
                            <p class="actions">
                                <button name="action" value="save_account">Save</button>
                                <button name="action" value="toggle_status" class="secondary">Enable/disable</button>
                                <button name="action" value="unbind" class="secondary">Unbind</button>
                                <button name="action" value="reset_pw">Reset password</button>
                                <button name="action" value="delete" class="secondary"
                                    onclick="return confirm('Delete account?')">Delete</button>
                            </p>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </section>

    <script>
        function copyCredentials() {
            navigator.clipboard.writeText(document.getElementById('credentials').value);
        }
        const source = document.getElementById('credentials');
        const download = document.getElementById('downloadCsv');
        if (source && download) {
            const csv = 'username,password\n' + source.value.split('\n').map(row => row.replace('\t', ',')).join('\n');
            download.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
        }
    </script>
</body>
</html>
