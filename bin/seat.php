<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

require_once dirname(__DIR__) . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'lib.php';

function cli_json($value): void
{
    echo json_encode($value, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . PHP_EOL;
}

function cli_expiry(?string $value): ?string
{
    return normalize_expiry($value);
}

function cli_usage(): void
{
    echo "Usage: seat.php init|list|create|batch-create|reset-password\n";
}

$command = $argv[1] ?? 'help';
$db = seat_db();

try {
    if ($command === 'init') {
        ensure_keys();
        $password = ensure_admin($db);
        echo "Initialized\n";
        if ($password !== null) {
            echo "Admin password (save now): $password\n";
        }
        exit(0);
    }

    if ($command === 'list') {
        cli_json($db->query(
            'SELECT username,modules_json,expires_at,enabled,must_change_password,device_id '
            . 'FROM accounts ORDER BY username'
        )->fetchAll());
        exit(0);
    }

    if ($command === 'create') {
        if (count($argv) < 4) {
            throw new InvalidArgumentException('create USER PASSWORD [expiry] [modules]');
        }
        $username = $argv[2];
        $password = $argv[3];
        $expiry = cli_expiry($argv[4] ?? null);
        $modules = isset($argv[5]) ? explode(',', $argv[5]) : seat_cfg()['modules'];
        create_account($db, $username, $password, $modules, $expiry);
        echo "created $username\n";
        exit(0);
    }

    if ($command === 'batch-create') {
        if (count($argv) < 4) {
            throw new InvalidArgumentException('batch-create PREFIX COUNT [START]');
        }
        $prefix = $argv[2];
        $count = min(200, max(0, (int) $argv[3]));
        $start = (int) ($argv[4] ?? 1);
        $rows = [];
        $skipped = [];
        for ($index = 0; $index < $count; $index++) {
            $username = $prefix . ($start + $index);
            if (account_row($db, $username)) {
                $skipped[] = $username;
                continue;
            }
            $password = random_password();
            create_account($db, $username, $password, seat_cfg()['modules'], null, true);
            $rows[] = ['username' => $username, 'password' => $password];
        }
        cli_json(['created' => $rows, 'skipped' => $skipped]);
        exit(0);
    }

    if ($command === 'reset-password') {
        if (count($argv) < 4) {
            throw new InvalidArgumentException('reset-password USER PASSWORD');
        }
        $account = account_row($db, $argv[2]);
        if (!$account) {
            throw new RuntimeException('not_found');
        }
        reset_account_password($db, (int) $account['id'], $argv[3]);
        echo "reset {$argv[2]}\n";
        exit(0);
    }

    cli_usage();
    exit($command === 'help' ? 0 : 1);
} catch (Throwable $error) {
    fwrite(STDERR, $error->getMessage() . "\n");
    exit(1);
}
