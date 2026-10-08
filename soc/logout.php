<?php
require_once __DIR__ . '/bootstrap.php';

if (!soc_verify_csrf($_GET['csrf'] ?? null)) {
    http_response_code(403);
    exit('CSRF token invalid');
}

soc_logout();
header('Location: login.php');
exit;
