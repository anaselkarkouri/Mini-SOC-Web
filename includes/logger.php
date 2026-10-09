<?php
/* Collecteur initial: Omar Babba; extension personnelle documentée. */
require_once __DIR__.'/../config/db.php';
require_once __DIR__.'/log_fields.php';
function log_http_request(): void {
    register_shutdown_function(function () {
        $user=getenv('MINISOC_COLLECTOR_DB_USER') ?: DB_USER;
        $pass=getenv('MINISOC_COLLECTOR_DB_PASSWORD') ?: DB_PASS;
        $logConn=mysqli_connect(DB_HOST,$user,$pass,DB_NAME,DB_PORT);
        if (!$logConn) { error_log('Mini-SOC: collecteur indisponible');return; }
        mysqli_set_charset($logConn,'utf8mb4');mysqli_query($logConn,"SET time_zone='+00:00'");
        $id=bin2hex(random_bytes(16));$ip=substr($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',0,45);
        $method=substr($_SERVER['REQUEST_METHOD'] ?? 'GET',0,10);
        $url=substr($_SERVER['PHP_SELF'] ?? '/',0,255);$params=minisoc_log_params($_GET,$_POST);
        $agent=substr($_SERVER['HTTP_USER_AGENT'] ?? '',0,512);$code=(int)(http_response_code() ?: 200);
        $stmt=mysqli_prepare($logConn,'INSERT INTO http_logs
            (event_id,timestamp,ip_source,method,url,params,user_agent,response_code,processed)
            VALUES (?,UTC_TIMESTAMP(),?,?,?,?,?,?,0)');
        if (!$stmt) { error_log('Mini-SOC: préparation collecte échouée');mysqli_close($logConn);return; }
        mysqli_stmt_bind_param($stmt,'ssssssi',$id,$ip,$method,$url,$params,$agent,$code);
        if (!mysqli_stmt_execute($stmt)) error_log('Mini-SOC: écriture collecte échouée');
        mysqli_stmt_close($stmt);mysqli_close($logConn);
    });
}
