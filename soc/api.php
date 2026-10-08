<?php
require_once __DIR__ . '/bootstrap.php';

header('Content-Type: application/json; charset=utf-8');

if (!soc_is_admin()) {
    http_response_code(403);
    echo json_encode(['error' => 'forbidden']);
    exit;
}

$filters = soc_normalize_filters($_GET);
$selectedId = (int)($_GET['id'] ?? 0);
$mode = (string)($_GET['mode'] ?? 'dashboard');

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'update_status') {
    if (!soc_verify_post_csrf()) {
        http_response_code(403);
        echo json_encode(['error' => 'csrf']);
        exit;
    }

    $id = (int)($_POST['id'] ?? 0);
    $status = (string)($_POST['status'] ?? '');
    soc_update_alert_status($id, $status);

    $runner = soc_ensure_siem_running();
    $payload = soc_dashboard_payload($filters, $id);
    $payload['siem_runner'] = $runner;

    echo json_encode(
        $payload,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );
    exit;
}

if ($mode === 'detail') {
    echo json_encode(
        [
            'selected_alert' => soc_alert_payload(soc_fetch_alert_by_id($selectedId)),
            'unread_count' => soc_unread_alert_count(),
        ],
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );
    exit;
}

$runner = soc_ensure_siem_running();
$payload = soc_dashboard_payload($filters, $selectedId);
$payload['siem_runner'] = $runner;

echo json_encode(
    $payload,
    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
);
