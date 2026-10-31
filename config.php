<?php
declare(strict_types=1);

function seat_config(): array
{
    $base = __DIR__;
    $data = getenv('SEAT_DATA_DIR') ?: ($base . DIRECTORY_SEPARATOR . 'data');
    return [
        'base_dir' => $base,
        'data_dir' => $data,
        'db_path' => $data . DIRECTORY_SEPARATOR . 'seat.sqlite',
        'keys_dir' => $data . DIRECTORY_SEPARATOR . 'keys',
        'admin_password_file' => $base . DIRECTORY_SEPARATOR . 'admin-password.txt',
        'modules' => ['basic', 'pro', 'export'],
        'session_ttl' => 86400 * 30,
    ];
}
