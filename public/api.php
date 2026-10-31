<?php
declare(strict_types=1);
require_once dirname(__DIR__) . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'lib.php';
header('Content-Type: application/json; charset=utf-8');
$json = json_decode((string) file_get_contents('php://input'), true);
$input = $_POST ?: (is_array($json) ? $json : $_GET);
$action = (string) ($input['action'] ?? '');
$method = (string) ($_SERVER['REQUEST_METHOD'] ?? 'GET');
$ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
$result = api_action($action, $input, $ip, null, $method);
http_response_code(($result['ok'] ?? false) ? 200 : 400);
echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
