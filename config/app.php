<?php
/*
 * Mini-SOC Web — M1 VulnShop
 * Configuration principale.
 * Application volontairement vulnérable pour laboratoire local uniquement.
 */

const APP_NAME = 'Atlas MiniShop';
const APP_TAGLINE = 'Boutique locale de gadgets, accessoires et équipements connectés';

/* Base de données MySQL locale. Adapter si votre XAMPP/WAMP utilise un autre compte. */
define('DB_HOST', getenv('MINISOC_DB_HOST') ?: '127.0.0.1');
define('DB_PORT', (int)(getenv('MINISOC_DB_PORT') ?: '3306'));
$role = defined('MINISOC_DB_ROLE') ? MINISOC_DB_ROLE : 'WEB';
define('DB_USER', getenv('MINISOC_'.$role.'_DB_USER') ?: (getenv('MINISOC_DB_USER') ?: 'root'));
define('DB_PASS', getenv('MINISOC_'.$role.'_DB_PASSWORD') ?: (getenv('MINISOC_DB_PASSWORD') ?: ''));
define('DB_NAME', getenv('MINISOC_DB_NAME') ?: 'minisoc_shop');

/* Affiche les erreurs SQL et les requêtes problématiques pour faciliter les tests SQLi. */
// Correction ciblée SQLi/XSS; le reste de la boutique reste pédagogique.
define('MINISOC_HARDENED', getenv('MINISOC_HARDENED') === '1');
define('DEBUG_SQL_ERRORS', !MINISOC_HARDENED);

/* Protection minimale contre une exposition accidentelle hors laboratoire. */
const LOCAL_ONLY = true;

function enforce_local_environment(): void
{
    if (!LOCAL_ONLY) {
        return;
    }

    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    $isLoopback = in_array($remote, ['127.0.0.1', '::1'], true) || str_starts_with($remote, '127.');
    // Réseau explicite du laboratoire Docker; aucun en-tête proxy accepté.
    $trusted = false;
    foreach (explode(',', getenv('MINISOC_TRUSTED_NETWORKS') ?: '') as $cidr) {
        $parts = explode('/', trim($cidr));
        if (count($parts) !== 2 || !ctype_digit($parts[1]) || (int)$parts[1] < 8 || (int)$parts[1] > 32) continue;
        $address = ip2long($remote); $network = ip2long($parts[0]);
        if ($address === false || $network === false) continue;
        $mask = -1 << (32-(int)$parts[1]);
        if (($address & $mask) === ($network & $mask)) $trusted = true;
    }

    // Ne pas faire confiance à Host ni exposer le laboratoire à tout le LAN.
    if (PHP_SAPI !== 'cli' && !$isLoopback && !$trusted) {
        http_response_code(403);
        echo 'Mini-SOC M1 est configuré pour un laboratoire local uniquement.';
        exit;
    }
}

enforce_local_environment();

/* Cookie de session volontairement accessible au JS pour permettre les scénarios XSS. */
if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => false,
        'httponly' => MINISOC_HARDENED,
        'samesite' => 'Lax',
    ]);
    session_start();
}
