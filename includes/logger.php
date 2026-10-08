<?php
/*
 * Mini-SOC Web — Module M2
 * Collecteur de logs HTTP
 * Responsable : Omar Babba
 *
 * Ce module enregistre chaque requete importante dans la table http_logs.
 * Les logs sont lus ensuite par le moteur Python Mini-SIEM (Module M3 - Fadoua).
 */

require_once __DIR__ . '/../config/db.php';

/**
 * Enregistre la requete HTTP courante dans la table http_logs.
 *
 * L insertion est effectuee via register_shutdown_function afin de capturer
 * le code de reponse HTTP reel (ex : 401 sur login echoue) apres execution
 * complete de la page.
 */
function log_http_request(): void
{
    register_shutdown_function(function () {
        global $conn;

        if (!$conn) {
            return;
        }

        /* ip_source : adresse IP de l attaquant ou de l utilisateur */
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        /* method : GET ou POST */
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

        /* url : chemin de la page ciblee (ex: /login.php) */
        $url = $_SERVER['PHP_SELF'] ?? '/';

        /* params : fusion des parametres GET et POST prefixes par GET_ / POST_
           Important pour le Mini-SIEM : les payloads SQLi/XSS sont ici. */
        $allParams = [];
        foreach ($_GET as $key => $value) {
            $allParams['GET_' . $key] = (string)$value;
        }
        foreach ($_POST as $key => $value) {
            $allParams['POST_' . $key] = (string)$value;
        }
        $params = json_encode($allParams, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        /* user_agent : outil utilise (navigateur, sqlmap, Hydra, curl, etc.) */
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        /* response_code : code HTTP retourne par l application apres traitement */
        $responseCode = http_response_code();
        if ($responseCode === false || $responseCode === null) {
            $responseCode = 200;
        }
        $responseCode = (int)$responseCode;

        /* Echappement des chaines avant insertion */
        $ip        = mysqli_real_escape_string($conn, $ip);
        $method    = mysqli_real_escape_string($conn, $method);
        $url       = mysqli_real_escape_string($conn, $url);
        $params    = mysqli_real_escape_string($conn, $params);
        $userAgent = mysqli_real_escape_string($conn, $userAgent);

        /* processed = 0 : le log n a pas encore ete analyse par le Mini-SIEM */
        mysqli_query(
            $conn,
            "INSERT INTO http_logs
                 (timestamp, ip_source, method, url, params, user_agent, response_code, processed)
             VALUES
                 (NOW(), '$ip', '$method', '$url', '$params', '$userAgent', $responseCode, 0)"
        );
    });
}
