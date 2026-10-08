<?php
require_once __DIR__ . '/app.php';

mysqli_report(MYSQLI_REPORT_OFF);

$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);

if (!$conn) {
    http_response_code(500);
    echo '<h1>Erreur de connexion MySQL</h1>';
    echo '<p>Importez <code>database/schema.sql</code> puis vérifiez <code>config/app.php</code>.</p>';
    if (DEBUG_SQL_ERRORS) {
        echo '<pre>' . htmlspecialchars(mysqli_connect_error(), ENT_QUOTES, 'UTF-8') . '</pre>';
    }
    exit;
}

mysqli_set_charset($conn, 'utf8mb4');

function sql_debug_box(string $sql): void
{
    global $conn;
    if (!DEBUG_SQL_ERRORS) {
        return;
    }
    echo '<div class="sql-debug-box">';
    echo '<strong>Erreur SQL laboratoire :</strong> ' . htmlspecialchars(mysqli_error($conn), ENT_QUOTES, 'UTF-8');
    echo '<pre>' . htmlspecialchars($sql, ENT_QUOTES, 'UTF-8') . '</pre>';
    echo '</div>';
}

function db_query(string $sql)
{
    global $conn;
    $result = mysqli_query($conn, $sql);
    if (!$result) {
        sql_debug_box($sql);
    }
    return $result;
}

function db_one(string $sql): ?array
{
    $result = db_query($sql);
    if ($result && mysqli_num_rows($result) > 0) {
        return mysqli_fetch_assoc($result);
    }
    return null;
}

function db_all(string $sql): array
{
    $rows = [];
    $result = db_query($sql);
    if ($result) {
        while ($row = mysqli_fetch_assoc($result)) {
            $rows[] = $row;
        }
    }
    return $rows;
}
