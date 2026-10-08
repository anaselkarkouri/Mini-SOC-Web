<?php
function soc_start_secure_session(): void
{
    if (session_status() !== PHP_SESSION_NONE) {
        return;
    }

    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') === '443');
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_name('MINI_SOC_SESSION');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

soc_start_secure_session();
require_once __DIR__ . '/../config/db.php';
soc_send_security_headers();

const SOC_ATTACK_FILTERS = ['all', 'sqli', 'xss', 'bruteforce'];
const SOC_SEVERITIES = ['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SOC_STATUSES = [
    'all' => 'Tous',
    'nouveau' => 'Nouveau',
    'en_cours' => 'En cours',
    'resolu' => 'Résolu',
    'faux_positif' => 'Faux positif',
];
const SOC_INACTIVE_STATUSES = ['resolu', 'faux_positif'];
const SOC_DEFAULT_RANGE_DAYS = 7;
const SOC_LOGIN_USERNAME = 'admin';
define('SOC_PASSWORD_HASH', getenv('MINISOC_SOC_PASSWORD_HASH') ?: '');
const SOC_SESSION_TIMEOUT = 3600;
const SOC_SESSION_ROTATE_SECONDS = 900;
const SOC_LOGIN_MAX_ATTEMPTS = 5;
const SOC_LOGIN_LOCK_SECONDS = 300;

function soc_send_security_headers(): void
{
    if (headers_sent()) {
        return;
    }

    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: same-origin');
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
}

function soc_settings_file(): string
{
    return __DIR__ . '/settings.local.php';
}

function soc_default_app_settings(): array
{
    return [
        'language' => 'fr',
        'password_hash' => SOC_PASSWORD_HASH,
        'report_limit' => 12,
        'report_include_mitre' => true,
        'report_include_response' => true,
        'alert_page_size' => 12,
        'alert_sort' => 'newest',
        'min_severity' => 'all',
        'hide_resolved' => false,
        'show_false_positive' => true,
        'show_mitre_id' => true,
        'show_mitre_tactic' => true,
        'show_mitre_technique' => true,
        'show_recommended_response' => true,
        'privacy_mode' => false,
        'mask_ip' => false,
        'mask_payload' => false,
        'mask_url' => false,
    ];
}

function soc_app_settings(bool $fresh = false): array
{
    static $settings = null;
    if ($settings !== null && !$fresh) {
        return $settings;
    }

    $settings = soc_default_app_settings();
    $file = soc_settings_file();
    if (is_file($file)) {
        $loaded = include $file;
        if (is_array($loaded)) {
            $settings = array_merge($settings, $loaded);
        }
    }

    $settings['language'] = in_array($settings['language'] ?? '', ['fr', 'en'], true) ? $settings['language'] : 'fr';
    $settings['password_hash'] = is_string($settings['password_hash'] ?? null) && $settings['password_hash'] !== ''
        ? $settings['password_hash']
        : SOC_PASSWORD_HASH;
    $settings['report_limit'] = in_array((int)($settings['report_limit'] ?? 12), [5, 10, 12, 20, 50], true)
        ? (int)$settings['report_limit']
        : 12;
    $settings['report_include_mitre'] = !empty($settings['report_include_mitre']);
    $settings['report_include_response'] = !empty($settings['report_include_response']);
    $settings['alert_page_size'] = in_array((int)($settings['alert_page_size'] ?? 12), [5, 10, 12, 20, 50], true)
        ? (int)$settings['alert_page_size']
        : 12;
    $settings['alert_sort'] = in_array($settings['alert_sort'] ?? '', ['newest', 'oldest', 'severity', 'attack'], true)
        ? $settings['alert_sort']
        : 'newest';
    $settings['min_severity'] = in_array(strtoupper((string)($settings['min_severity'] ?? 'all')), SOC_SEVERITIES, true)
        ? strtoupper((string)$settings['min_severity'])
        : 'all';
    $settings['hide_resolved'] = !empty($settings['hide_resolved']);
    $settings['show_false_positive'] = !empty($settings['show_false_positive']);
    $settings['show_mitre_id'] = !empty($settings['show_mitre_id']);
    $settings['show_mitre_tactic'] = !empty($settings['show_mitre_tactic']);
    $settings['show_mitre_technique'] = !empty($settings['show_mitre_technique']);
    $settings['show_recommended_response'] = !empty($settings['show_recommended_response']);
    $settings['privacy_mode'] = !empty($settings['privacy_mode']);
    $settings['mask_ip'] = !empty($settings['mask_ip']);
    $settings['mask_payload'] = !empty($settings['mask_payload']);
    $settings['mask_url'] = !empty($settings['mask_url']);

    return $settings;
}

function soc_save_app_settings(array $updates): bool
{
    $settings = array_merge(soc_app_settings(true), $updates);
    $settings['language'] = in_array($settings['language'] ?? '', ['fr', 'en'], true) ? $settings['language'] : 'fr';
    $settings['password_hash'] = is_string($settings['password_hash'] ?? null) && $settings['password_hash'] !== ''
        ? $settings['password_hash']
        : SOC_PASSWORD_HASH;
    $settings['report_limit'] = in_array((int)($settings['report_limit'] ?? 12), [5, 10, 12, 20, 50], true)
        ? (int)$settings['report_limit']
        : 12;
    $settings['report_include_mitre'] = !empty($settings['report_include_mitre']);
    $settings['report_include_response'] = !empty($settings['report_include_response']);
    $settings['alert_page_size'] = in_array((int)($settings['alert_page_size'] ?? 12), [5, 10, 12, 20, 50], true)
        ? (int)$settings['alert_page_size']
        : 12;
    $settings['alert_sort'] = in_array($settings['alert_sort'] ?? '', ['newest', 'oldest', 'severity', 'attack'], true)
        ? $settings['alert_sort']
        : 'newest';
    $settings['min_severity'] = in_array(strtoupper((string)($settings['min_severity'] ?? 'all')), SOC_SEVERITIES, true)
        ? strtoupper((string)$settings['min_severity'])
        : 'all';
    $settings['hide_resolved'] = !empty($settings['hide_resolved']);
    $settings['show_false_positive'] = !empty($settings['show_false_positive']);
    $settings['show_mitre_id'] = !empty($settings['show_mitre_id']);
    $settings['show_mitre_tactic'] = !empty($settings['show_mitre_tactic']);
    $settings['show_mitre_technique'] = !empty($settings['show_mitre_technique']);
    $settings['show_recommended_response'] = !empty($settings['show_recommended_response']);
    $settings['privacy_mode'] = !empty($settings['privacy_mode']);
    $settings['mask_ip'] = !empty($settings['mask_ip']);
    $settings['mask_payload'] = !empty($settings['mask_payload']);
    $settings['mask_url'] = !empty($settings['mask_url']);

    $content = "<?php\nreturn " . var_export($settings, true) . ";\n";
    $ok = file_put_contents(soc_settings_file(), $content, LOCK_EX) !== false;
    soc_app_settings(true);
    return $ok;
}

function soc_current_language(): string
{
    return soc_app_settings()['language'] ?? 'fr';
}

function soc_translations(): array
{
    return [
        'fr' => [
            'security_operations' => 'Opérations de sécurité',
            'soc_center' => 'Centre SOC',
            'overview' => 'Vue globale',
            'alerts' => 'Alertes',
            'reports' => 'Rapports',
            'settings' => 'Paramètres',
            'guide' => 'Guide',
            'logout' => 'Déconnexion',
            'critical' => 'Critique',
            'high' => 'Haute',
            'medium' => 'Moyenne',
            'low' => 'Basse',
            'dashboard_title' => 'Dashboard SOC',
            'dashboard_hello' => 'Bonjour Admin, bon retour !',
            'dashboard_intro' => 'Surveillance en temps réel des alertes générées par le moteur Mini-SIEM.',
            'search_placeholder' => 'Rechercher alertes, IPs, URLs, payloads...',
            'search' => 'Rechercher',
            'from' => 'Du',
            'to' => 'Au',
            'apply' => 'Appliquer',
            'reset' => 'Réinitialiser',
            'auto_refresh' => 'Rafraîchissement auto',
            'total_alerts' => 'Total Alertes',
            'sqli_alerts' => 'Alertes SQLi',
            'xss_alerts' => 'Alertes XSS',
            'brute_force_alerts' => 'Alertes Brute Force',
            'score_global' => 'Score global',
            'analytics_label' => 'Analyse des alertes',
            'stats_label' => 'Statistiques alertes',
            'alert_trend' => 'Tendance des alertes',
            'alerts_detected_per_day' => 'Alertes détectées par jour',
            'detected_alerts' => 'Alertes détectées',
            'trend_aria' => 'Tendance des alertes',
            'severity_distribution' => 'Distribution par gravité',
            'alerts_by_source' => 'Alertes par source',
            'recent_alerts' => 'Alertes récentes',
            'alerts_found' => 'alerte(s) trouvée(s)',
            'filters' => 'Filtres',
            'attack_filter' => 'Attaque',
            'severity_filter' => 'Gravité',
            'all_feminine' => 'Toutes',
            'status_filter' => 'Statut',
            'filter' => 'Filtrer',
            'time' => 'Temps',
            'type' => 'Type',
            'severity' => 'Gravité',
            'detail' => 'Détail',
            'view' => 'Voir',
            'alerts_lower' => 'alertes',
            'top_5' => 'Top 5',
            'status_all' => 'Tous',
            'status_new' => 'Nouveau',
            'status_progress' => 'En cours',
            'status_resolved' => 'Résolu',
            'status_false_positive' => 'Faux positif',
            'empty_sources' => 'Aucune source détectée.',
            'empty_alerts' => 'Aucune alerte ne correspond aux filtres.',
            'detail_title' => 'Détail alerte',
            'no_alert_selected' => 'Aucune alerte sélectionnée.',
            'detail_page' => 'Page détail',
            'source_ip' => 'IP source',
            'target_url' => 'URL ciblée',
            'payload' => 'Payload',
            'triggered_rule' => 'Règle déclenchée',
            'mitre_id' => 'MITRE ID',
            'tactic' => 'Tactique',
            'technique' => 'Technique',
            'recommended_response' => 'Réponse recommandée',
            'status' => 'Statut',
            'update' => 'Mettre à jour',
            'save' => 'Enregistrer',
            'change_status' => 'Changer le statut',
            'back_dashboard' => 'Retour dashboard',
            'date' => 'Date',
            'source_log' => 'Log source',
            'mitre_information' => 'Informations MITRE',
            'alert_not_found' => 'Alerte introuvable',
            'alert_not_found_text' => "Cette alerte n'existe pas ou n'est plus disponible.",
            'detail_intro' => "Vue complète de l'alerte Mini-SIEM avec enrichissement MITRE.",
            'history_title' => 'Historique Alertes',
            'history_h1' => 'Historique des alertes',
            'history_intro' => 'Toutes les alertes Mini-SIEM, sans panneau détail pour garder une lecture rapide.',
            'history_count' => "alerte(s) dans l'historique",
            'empty_history' => "Aucune alerte dans l'historique.",
            'mitre_title' => 'MITRE',
            'mitre_h1' => 'MITRE ATT&CK utilisé',
            'mitre_intro' => 'Explication des mappings MITRE intégrés au Mini-SIEM pour ce projet Mini-SOC.',
            'default_severity' => 'Gravité par défaut',
            'project_surface' => 'Surface projet',
            'mini_siem_usage' => 'Utilisation dans le Mini-SIEM',
            'read_mitre_alert' => 'Comment lire une alerte MITRE',
            'attack_type' => 'Type attaque',
            'mitre_id_help' => 'MITRE ID',
            'response' => 'Réponse',
            'guide_title' => 'Guide utilisation',
            'guide_h1' => "Guide d'utilisation",
            'guide_intro' => 'Procédure courte pour tester et présenter le dashboard SOC.',
            'guide_prepare' => '1. Préparer le laboratoire',
            'guide_detect' => '2. Activer la détection',
            'guide_read' => '3. Lire le dashboard',
            'guide_document' => '4. Traiter et documenter',
            'report_pdf' => 'Rapport PDF',
            'live_active' => 'Temps réel actif',
            'live_recent' => 'Activité récente',
            'live_idle' => 'En attente de nouvelles alertes',
            'alerts_settings' => 'Alertes',
            'alerts_per_page' => 'Nombre d’alertes par page',
            'default_sort' => 'Tri par défaut',
            'min_level_displayed' => 'Niveau minimal affiché',
            'hide_resolved' => 'Masquer alertes résolues',
            'show_false_positive' => 'Afficher faux positifs',
            'mitre_settings' => 'MITRE ATT&CK',
            'show_mitre_id' => 'Afficher MITRE ID',
            'show_tactic' => 'Afficher tactique',
            'show_technique' => 'Afficher technique',
            'show_recommended_response' => 'Afficher réponse recommandée',
            'privacy' => 'Confidentialité',
            'privacy_mode' => 'Mode confidentialité',
            'mask_ip' => 'Masquer IP',
            'mask_payload' => 'Masquer payload',
            'mask_full_url' => 'Masquer URL complète',
            'sort_newest' => 'Plus récentes',
            'sort_oldest' => 'Plus anciennes',
            'sort_severity' => 'Gravité',
            'sort_attack' => 'Type attaque',
            'all_levels' => 'Tous les niveaux',
            'masked_ip' => '[IP masquée]',
            'masked_payload' => '[Payload masqué]',
            'masked_url' => '[URL masquée]',
        ],
        'en' => [
            'security_operations' => 'Security Operations',
            'soc_center' => 'SOC Center',
            'overview' => 'Overview',
            'alerts' => 'Alerts',
            'reports' => 'Reports',
            'settings' => 'Settings',
            'guide' => 'Guide',
            'logout' => 'Log out',
            'critical' => 'Critical',
            'high' => 'High',
            'medium' => 'Medium',
            'low' => 'Low',
            'dashboard_title' => 'SOC Dashboard',
            'dashboard_hello' => 'Hello Admin, Welcome back!',
            'dashboard_intro' => 'Real-time monitoring of alerts generated by the Mini-SIEM engine.',
            'search_placeholder' => 'Search alerts, IPs, URLs, payloads...',
            'search' => 'Search',
            'from' => 'From',
            'to' => 'To',
            'apply' => 'Apply',
            'reset' => 'Reset',
            'auto_refresh' => 'Auto-refresh',
            'total_alerts' => 'Total Alerts',
            'sqli_alerts' => 'SQLi Alerts',
            'xss_alerts' => 'XSS Alerts',
            'brute_force_alerts' => 'Brute Force Alerts',
            'score_global' => 'Global score',
            'analytics_label' => 'Alert analytics',
            'stats_label' => 'Alert statistics',
            'alert_trend' => 'Alert Trend',
            'alerts_detected_per_day' => 'Detected alerts per day',
            'detected_alerts' => 'Detected alerts',
            'trend_aria' => 'Alert trend',
            'severity_distribution' => 'Severity Distribution',
            'alerts_by_source' => 'Alerts by Source',
            'recent_alerts' => 'Recent alerts',
            'alerts_found' => 'alert(s) found',
            'filters' => 'Filters',
            'attack_filter' => 'Attack',
            'severity_filter' => 'Severity',
            'all_feminine' => 'All',
            'status_filter' => 'Status',
            'filter' => 'Filter',
            'time' => 'Time',
            'type' => 'Type',
            'severity' => 'Severity',
            'detail' => 'Detail',
            'view' => 'View',
            'alerts_lower' => 'alerts',
            'top_5' => 'Top 5',
            'status_all' => 'All',
            'status_new' => 'New',
            'status_progress' => 'In progress',
            'status_resolved' => 'Resolved',
            'status_false_positive' => 'False positive',
            'empty_sources' => 'No source detected.',
            'empty_alerts' => 'No alert matches the filters.',
            'detail_title' => 'Alert details',
            'no_alert_selected' => 'No alert selected.',
            'detail_page' => 'Detail page',
            'source_ip' => 'Source IP',
            'target_url' => 'Target URL',
            'payload' => 'Payload',
            'triggered_rule' => 'Triggered rule',
            'mitre_id' => 'MITRE ID',
            'tactic' => 'Tactic',
            'technique' => 'Technique',
            'recommended_response' => 'Recommended response',
            'status' => 'Status',
            'update' => 'Update',
            'save' => 'Save',
            'change_status' => 'Change status',
            'back_dashboard' => 'Back to dashboard',
            'date' => 'Date',
            'source_log' => 'Source log',
            'mitre_information' => 'MITRE information',
            'alert_not_found' => 'Alert not found',
            'alert_not_found_text' => 'This alert does not exist or is no longer available.',
            'detail_intro' => 'Full Mini-SIEM alert view with MITRE enrichment.',
            'history_title' => 'Alert History',
            'history_h1' => 'Alert history',
            'history_intro' => 'All Mini-SIEM alerts, without a detail panel to keep the view readable.',
            'history_count' => 'alert(s) in history',
            'empty_history' => 'No alert in history.',
            'mitre_title' => 'MITRE',
            'mitre_h1' => 'MITRE ATT&CK in use',
            'mitre_intro' => 'Explanation of MITRE mappings integrated into Mini-SIEM for this Mini-SOC project.',
            'default_severity' => 'Default severity',
            'project_surface' => 'Project surface',
            'mini_siem_usage' => 'Use in Mini-SIEM',
            'read_mitre_alert' => 'How to read a MITRE alert',
            'attack_type' => 'Attack type',
            'mitre_id_help' => 'MITRE ID',
            'response' => 'Response',
            'guide_title' => 'Usage Guide',
            'guide_h1' => 'Usage guide',
            'guide_intro' => 'Short procedure to test and present the SOC dashboard.',
            'guide_prepare' => '1. Prepare the lab',
            'guide_detect' => '2. Enable detection',
            'guide_read' => '3. Read the dashboard',
            'guide_document' => '4. Handle and document',
            'report_pdf' => 'PDF Report',
            'live_active' => 'Real-time active',
            'live_recent' => 'Recent activity',
            'live_idle' => 'Waiting for new alerts',
            'alerts_settings' => 'Alerts',
            'alerts_per_page' => 'Alerts per page',
            'default_sort' => 'Default sort',
            'min_level_displayed' => 'Minimum displayed level',
            'hide_resolved' => 'Hide resolved alerts',
            'show_false_positive' => 'Show false positives',
            'mitre_settings' => 'MITRE ATT&CK',
            'show_mitre_id' => 'Show MITRE ID',
            'show_tactic' => 'Show tactic',
            'show_technique' => 'Show technique',
            'show_recommended_response' => 'Show recommended response',
            'privacy' => 'Privacy',
            'privacy_mode' => 'Privacy mode',
            'mask_ip' => 'Mask IP',
            'mask_payload' => 'Mask payload',
            'mask_full_url' => 'Mask full URL',
            'sort_newest' => 'Newest first',
            'sort_oldest' => 'Oldest first',
            'sort_severity' => 'Severity',
            'sort_attack' => 'Attack type',
            'all_levels' => 'All levels',
            'masked_ip' => '[IP hidden]',
            'masked_payload' => '[Payload hidden]',
            'masked_url' => '[URL hidden]',
        ],
    ];
}

function soc_t(string $key): string
{
    $lang = soc_current_language();
    $translations = soc_translations();
    return $translations[$lang][$key] ?? $translations['fr'][$key] ?? $key;
}

function soc_client_i18n(): array
{
    $keys = [
        'empty_sources',
        'empty_alerts',
        'detail_title',
        'no_alert_selected',
        'detail_page',
        'source_ip',
        'target_url',
        'payload',
        'triggered_rule',
        'mitre_id',
        'tactic',
        'technique',
        'recommended_response',
        'status',
        'update',
        'status_new',
        'status_progress',
        'status_resolved',
        'status_false_positive',
        'view',
        'alerts_lower',
        'trend_aria',
    ];
    $values = [];
    foreach ($keys as $key) {
        $values[$key] = soc_t($key);
    }
    return $values;
}

function soc_e($value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function soc_alert_display_settings(): array
{
    $settings = soc_app_settings();
    $privacyMode = !empty($settings['privacy_mode']);

    return [
        'alert_page_size' => (int)$settings['alert_page_size'],
        'alert_sort' => (string)$settings['alert_sort'],
        'min_severity' => (string)$settings['min_severity'],
        'hide_resolved' => !empty($settings['hide_resolved']),
        'show_false_positive' => !empty($settings['show_false_positive']),
        'show_mitre_id' => !empty($settings['show_mitre_id']),
        'show_mitre_tactic' => !empty($settings['show_mitre_tactic']),
        'show_mitre_technique' => !empty($settings['show_mitre_technique']),
        'show_recommended_response' => !empty($settings['show_recommended_response']),
        'privacy_mode' => $privacyMode,
        'mask_ip' => $privacyMode || !empty($settings['mask_ip']),
        'mask_payload' => $privacyMode || !empty($settings['mask_payload']),
        'mask_url' => $privacyMode || !empty($settings['mask_url']),
    ];
}

function soc_severity_rank(string $severity): int
{
    return [
        'LOW' => 1,
        'MEDIUM' => 2,
        'HIGH' => 3,
        'CRITICAL' => 4,
    ][strtoupper($severity)] ?? 0;
}

function soc_min_severity_values(string $minSeverity): array
{
    $rank = soc_severity_rank($minSeverity);
    if ($rank <= 0) {
        return [];
    }

    $values = [];
    foreach (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as $severity) {
        if (soc_severity_rank($severity) >= $rank) {
            $values[] = $severity;
        }
    }
    return $values;
}

function soc_alert_order_sql(?string $sort = null): string
{
    $sort = $sort ?: soc_alert_display_settings()['alert_sort'];
    return match ($sort) {
        'oldest' => 'timestamp ASC, id ASC',
        'severity' => "CASE UPPER(severity) WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC, timestamp DESC, id DESC",
        'attack' => 'attack_type ASC, timestamp DESC, id DESC',
        default => 'timestamp DESC, id DESC',
    };
}

function soc_masked_label(string $field): string
{
    return match ($field) {
        'payload' => soc_t('masked_payload'),
        'url' => soc_t('masked_url'),
        default => soc_t('masked_ip'),
    };
}

function soc_mask_alert_value(string $field, string $value): string
{
    return $value === '' ? '' : soc_masked_label($field);
}

function soc_display_alert(array $alert): array
{
    $display = soc_alert_display_settings();

    if ($display['mask_ip']) {
        $alert['source_ip'] = soc_mask_alert_value('ip', (string)($alert['source_ip'] ?? ''));
    }
    if ($display['mask_url']) {
        $alert['url'] = soc_mask_alert_value('url', (string)($alert['url'] ?? ''));
    }
    if ($display['mask_payload']) {
        $alert['payload'] = soc_mask_alert_value('payload', (string)($alert['payload'] ?? ''));
    }
    if (!$display['show_mitre_id']) {
        $alert['mitre_id'] = '';
    }
    if (!$display['show_mitre_tactic']) {
        $alert['mitre_tactic'] = '';
    }
    if (!$display['show_mitre_technique']) {
        $alert['mitre_technique'] = '';
    }
    if (!$display['show_recommended_response']) {
        $alert['recommended_response'] = '';
    }

    $alert['_display'] = $display;
    return $alert;
}

function soc_icon(string $name, string $class = 'icon'): string
{
    $icons = [
        'shield' => '<path d="M12 3l7 3v5c0 5-3.2 8.6-7 10-3.8-1.4-7-5-7-10V6l7-3z"/><path d="M12 8v8"/><path d="M9 11l3 3 4-5"/>',
        'grid' => '<rect x="4" y="4" width="6" height="6" rx="1.5"/><rect x="14" y="4" width="6" height="6" rx="1.5"/><rect x="4" y="14" width="6" height="6" rx="1.5"/><rect x="14" y="14" width="6" height="6" rx="1.5"/>',
        'bell' => '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/>',
        'crosshair' => '<circle cx="12" cy="12" r="8"/><path d="M12 2v4"/><path d="M12 18v4"/><path d="M2 12h4"/><path d="M18 12h4"/><circle cx="12" cy="12" r="2"/>',
        'chart' => '<path d="M4 19V5"/><path d="M4 19h16"/><path d="M8 16v-5"/><path d="M12 16V8"/><path d="M16 16v-9"/>',
        'settings' => '<path d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z"/><path d="M19.4 15a1.8 1.8 0 0 0 .3 2l.1.1-2.1 2.1-.1-.1a1.8 1.8 0 0 0-2-.3 1.8 1.8 0 0 0-1 1.6V21h-3v-.6a1.8 1.8 0 0 0-1-1.6 1.8 1.8 0 0 0-2 .3l-.1.1-2.1-2.1.1-.1a1.8 1.8 0 0 0 .3-2 1.8 1.8 0 0 0-1.6-1H4v-3h.6a1.8 1.8 0 0 0 1.6-1 1.8 1.8 0 0 0-.3-2l-.1-.1 2.1-2.1.1.1a1.8 1.8 0 0 0 2 .3 1.8 1.8 0 0 0 1-1.6V3h3v.6a1.8 1.8 0 0 0 1 1.6 1.8 1.8 0 0 0 2-.3l.1-.1 2.1 2.1-.1.1a1.8 1.8 0 0 0-.3 2 1.8 1.8 0 0 0 1.6 1h.6v3h-.6a1.8 1.8 0 0 0-1.6 1z"/>',
        'logout' => '<path d="M10 17l5-5-5-5"/><path d="M15 12H3"/><path d="M21 19V5a2 2 0 0 0-2-2h-6"/><path d="M13 21h6a2 2 0 0 0 2-2"/>',
        'database' => '<ellipse cx="12" cy="5" rx="7" ry="3"/><path d="M5 5v6c0 1.7 3.1 3 7 3s7-1.3 7-3V5"/><path d="M5 11v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/>',
        'code' => '<path d="M8 9l-4 3 4 3"/><path d="M16 9l4 3-4 3"/><path d="M14 4l-4 16"/>',
        'lock' => '<rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
        'calendar' => '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M16 3v4"/><path d="M8 3v4"/><path d="M3 11h18"/>',
        'search' => '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
        'file' => '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/><path d="M8 13h8"/><path d="M8 17h6"/>',
        'activity' => '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
        'filter' => '<path d="M4 5h16"/><path d="M7 12h10"/><path d="M10 19h4"/>',
        'user' => '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
        'book' => '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M4 4.5A2.5 2.5 0 0 1 6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5z"/>',
    ];

    $path = $icons[$name] ?? $icons['shield'];
    return '<svg class="' . soc_e($class) . '" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' . $path . '</svg>';
}

function soc_current_user(): ?array
{
    return $_SESSION['soc_user'] ?? null;
}

function soc_client_ip(): string
{
    return (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
}

function soc_session_fingerprint(): string
{
    $agent = substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 180);
    return hash('sha256', soc_client_ip() . '|' . $agent);
}

function soc_clear_session(): void
{
    unset(
        $_SESSION['soc_authenticated'],
        $_SESSION['soc_user'],
        $_SESSION['soc_fingerprint'],
        $_SESSION['soc_last_activity'],
        $_SESSION['soc_rotated_at'],
        $_SESSION['soc_csrf']
    );
}

function soc_is_admin(): bool
{
    if (empty($_SESSION['soc_authenticated']) || ($_SESSION['soc_user']['username'] ?? '') !== SOC_LOGIN_USERNAME) {
        return false;
    }

    $now = time();
    $lastActivity = (int)($_SESSION['soc_last_activity'] ?? 0);
    if ($lastActivity <= 0 || ($now - $lastActivity) > SOC_SESSION_TIMEOUT) {
        soc_clear_session();
        return false;
    }

    if (!hash_equals((string)($_SESSION['soc_fingerprint'] ?? ''), soc_session_fingerprint())) {
        soc_clear_session();
        return false;
    }

    $_SESSION['soc_last_activity'] = $now;
    if (($now - (int)($_SESSION['soc_rotated_at'] ?? 0)) > SOC_SESSION_ROTATE_SECONDS) {
        session_regenerate_id(true);
        $_SESSION['soc_rotated_at'] = $now;
    }

    return true;
}

function soc_user_name(): string
{
    return 'Admin';
}

function soc_verify_admin_password(string $password): bool
{
    if ($password === '' || strlen($password) > 512) {
        return false;
    }
    return password_verify($password, soc_app_settings()['password_hash'] ?? SOC_PASSWORD_HASH);
}

function soc_safe_redirect_path(string $next, string $fallback = 'index.php'): string
{
    $next = trim(str_replace('\\', '/', $next));
    if ($next === '' || preg_match('/[\r\n\x00-\x1F\x7F]/', $next)) {
        return $fallback;
    }

    if (preg_match('/^[a-z][a-z0-9+.-]*:/i', $next) || str_starts_with($next, '//')) {
        return $fallback;
    }

    $parts = parse_url($next);
    if (!is_array($parts)) {
        return $fallback;
    }

    $path = (string)($parts['path'] ?? '');
    $page = basename($path);
    $allowedPages = ['index.php', 'alerts.php', 'detail.php', 'mitre.php', 'report.php', 'settings.php', 'guide.php'];
    if (!in_array($page, $allowedPages, true)) {
        return $fallback;
    }

    $query = (string)($parts['query'] ?? '');
    if ($query !== '' && preg_match('/[\r\n\x00-\x1F\x7F]/', $query)) {
        return $fallback;
    }

    return $page . ($query !== '' ? '?' . $query : '');
}

function soc_require_admin(): void
{
    if (soc_is_admin()) {
        return;
    }

    $next = $_SERVER['REQUEST_URI'] ?? '/';
    header('Location: login.php?next=' . urlencode($next));
    exit;
}

function soc_csrf_token(): string
{
    if (empty($_SESSION['soc_csrf']) || !is_string($_SESSION['soc_csrf'])) {
        $_SESSION['soc_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['soc_csrf'];
}

function soc_csrf_field(): void
{
    echo '<input type="hidden" name="csrf" value="' . soc_e(soc_csrf_token()) . '">';
}

function soc_verify_csrf(?string $token): bool
{
    return is_string($token)
        && isset($_SESSION['soc_csrf'])
        && hash_equals((string)$_SESSION['soc_csrf'], $token);
}

function soc_verify_post_csrf(): bool
{
    return soc_verify_csrf($_POST['csrf'] ?? null);
}

function soc_login_table(): void
{
    static $done = false;
    if ($done) {
        return;
    }
    $done = true;
    db_query(
        "CREATE TABLE IF NOT EXISTS soc_login_attempts (
            ip_hash VARCHAR(64) NOT NULL PRIMARY KEY,
            attempts INT NOT NULL DEFAULT 0,
            last_attempt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            locked_until DATETIME NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
    );
}

function soc_login_key(): string
{
    $agent = substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 180);
    return hash('sha256', soc_client_ip() . '|' . $agent);
}

function soc_login_lock_remaining(): int
{
    global $conn;
    soc_login_table();
    $key = soc_login_key();
    $stmt = mysqli_prepare($conn, "SELECT locked_until FROM soc_login_attempts WHERE ip_hash = ? LIMIT 1");
    if (!$stmt) {
        return 0;
    }
    mysqli_stmt_bind_param($stmt, 's', $key);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $row = $result ? mysqli_fetch_assoc($result) : null;
    mysqli_stmt_close($stmt);

    $lockedUntil = strtotime((string)($row['locked_until'] ?? ''));
    return $lockedUntil && $lockedUntil > time() ? $lockedUntil - time() : 0;
}

function soc_record_login_failure(): void
{
    global $conn;
    soc_login_table();
    $key = soc_login_key();
    $remaining = soc_login_lock_remaining();
    if ($remaining > 0) {
        return;
    }

    $stmt = mysqli_prepare(
        $conn,
        "INSERT INTO soc_login_attempts (ip_hash, attempts, last_attempt, locked_until)
         VALUES (?, 1, NOW(), NULL)
         ON DUPLICATE KEY UPDATE
            attempts = IF(last_attempt < DATE_SUB(NOW(), INTERVAL 15 MINUTE), 1, attempts + 1),
            last_attempt = NOW(),
            locked_until = IF(
                IF(last_attempt < DATE_SUB(NOW(), INTERVAL 15 MINUTE), 1, attempts + 1) >= ?,
                DATE_ADD(NOW(), INTERVAL ? SECOND),
                NULL
            )"
    );
    if (!$stmt) {
        return;
    }
    $max = SOC_LOGIN_MAX_ATTEMPTS;
    $lockSeconds = SOC_LOGIN_LOCK_SECONDS;
    mysqli_stmt_bind_param($stmt, 'sii', $key, $max, $lockSeconds);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);
}

function soc_clear_login_failures(): void
{
    global $conn;
    soc_login_table();
    $key = soc_login_key();
    $stmt = mysqli_prepare($conn, "DELETE FROM soc_login_attempts WHERE ip_hash = ?");
    if (!$stmt) {
        return;
    }
    mysqli_stmt_bind_param($stmt, 's', $key);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);
}

function soc_login_attempt(string $username, string $password): bool
{
    $username = trim($username);
    if (strlen($username) > 64 || soc_login_lock_remaining() > 0) {
        return false;
    }

    if (!hash_equals(SOC_LOGIN_USERNAME, $username) || !soc_verify_admin_password($password)) {
        soc_record_login_failure();
        return false;
    }

    soc_clear_login_failures();
    session_regenerate_id(true);
    $_SESSION['soc_authenticated'] = true;
    $_SESSION['soc_user'] = [
        'username' => SOC_LOGIN_USERNAME,
        'name' => 'Admin',
        'logged_at' => date('Y-m-d H:i:s'),
    ];
    $_SESSION['soc_fingerprint'] = soc_session_fingerprint();
    $_SESSION['soc_last_activity'] = time();
    $_SESSION['soc_rotated_at'] = time();
    unset($_SESSION['soc_csrf']);
    soc_csrf_token();
    return true;
}

function soc_logout(): void
{
    soc_clear_session();
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_regenerate_id(true);
    }
}

function soc_db_select(string $sql, string $types = '', array $params = []): array
{
    global $conn;

    if ($types === '') {
        $result = mysqli_query($conn, $sql);
    } else {
        $stmt = mysqli_prepare($conn, $sql);
        if (!$stmt) {
            sql_debug_box($sql);
            return [];
        }
        mysqli_stmt_bind_param($stmt, $types, ...$params);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        mysqli_stmt_close($stmt);
    }

    if (!$result) {
        sql_debug_box($sql);
        return [];
    }

    $rows = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $rows[] = $row;
    }
    return $rows;
}

function soc_db_one(string $sql, string $types = '', array $params = []): ?array
{
    $rows = soc_db_select($sql, $types, $params);
    return $rows[0] ?? null;
}

function soc_db_execute(string $sql, string $types, array $params): bool
{
    global $conn;

    $stmt = mysqli_prepare($conn, $sql);
    if (!$stmt) {
        sql_debug_box($sql);
        return false;
    }
    mysqli_stmt_bind_param($stmt, $types, ...$params);
    $ok = mysqli_stmt_execute($stmt);
    if (!$ok) {
        sql_debug_box($sql);
    }
    mysqli_stmt_close($stmt);
    return $ok;
}

function soc_ensure_reads_table(): void
{
    static $done = false;
    if ($done) {
        return;
    }
    $done = true;

    db_query(
        "CREATE TABLE IF NOT EXISTS soc_alert_reads (
            alert_id INT NOT NULL PRIMARY KEY,
            read_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
    );
}

function soc_mark_alert_read(int $id): void
{
    if ($id <= 0) {
        return;
    }

    soc_ensure_reads_table();
    soc_db_execute(
        "INSERT INTO soc_alert_reads (alert_id, read_at)
         VALUES (?, NOW())
         ON DUPLICATE KEY UPDATE read_at = read_at",
        'i',
        [$id]
    );
}

function soc_mark_all_alerts_read(): void
{
    soc_ensure_reads_table();
    db_query(
        "INSERT INTO soc_alert_reads (alert_id, read_at)
         SELECT id, NOW()
         FROM alerts
         WHERE id NOT IN (SELECT alert_id FROM soc_alert_reads)"
    );
}

function soc_alert_read_map(array $ids): array
{
    $ids = array_values(array_unique(array_filter(array_map('intval', $ids))));
    if (!$ids) {
        return [];
    }

    soc_ensure_reads_table();
    $placeholders = implode(',', array_fill(0, count($ids), '?'));
    $rows = soc_db_select(
        "SELECT alert_id, read_at FROM soc_alert_reads WHERE alert_id IN ($placeholders)",
        str_repeat('i', count($ids)),
        $ids
    );

    $map = [];
    foreach ($rows as $row) {
        $map[(int)$row['alert_id']] = $row['read_at'];
    }
    return $map;
}

function soc_apply_read_state(array $alerts): array
{
    $map = soc_alert_read_map(array_column($alerts, 'id'));
    foreach ($alerts as &$alert) {
        $readAt = $map[(int)($alert['id'] ?? 0)] ?? null;
        $alert['is_read'] = $readAt !== null;
        $alert['read_at'] = $readAt;
    }
    unset($alert);
    return $alerts;
}

function soc_unread_alert_count(): int
{
    soc_ensure_reads_table();
    $row = soc_db_one(
        "SELECT COUNT(*) AS total
         FROM alerts a
         LEFT JOIN soc_alert_reads r ON r.alert_id = a.id
         WHERE r.alert_id IS NULL
         AND (a.status IS NULL OR a.status NOT IN ('resolu', 'faux_positif'))"
    );
    return (int)($row['total'] ?? 0);
}

function soc_siem_pid_file(): string
{
    return __DIR__ . '/mini_siem.pid';
}

function soc_siem_lock_file(): string
{
    return __DIR__ . '/mini_siem.lock';
}

function soc_powershell_quote(string $value): string
{
    return "'" . str_replace("'", "''", $value) . "'";
}

function soc_siem_process_is_running(int $pid): bool
{
    if ($pid <= 0 || !function_exists('shell_exec')) {
        return false;
    }

    if (PHP_OS_FAMILY === 'Windows') {
        $ps = 'try { $p = Get-CimInstance Win32_Process -Filter "ProcessId=' . $pid . '"; if ($p -and $p.CommandLine -like "*mini_siem.py*") { "1" } } catch { "" }';
        $output = trim((string)shell_exec('powershell -NoProfile -ExecutionPolicy Bypass -Command ' . escapeshellarg($ps)));
        return $output === '1';
    }

    $output = trim((string)shell_exec('ps -p ' . (int)$pid . ' -o command= 2>/dev/null'));
    return $output !== '' && str_contains($output, 'mini_siem.py');
}

function soc_siem_current_pid(): int
{
    $pidFile = soc_siem_pid_file();
    if (!is_file($pidFile)) {
        return 0;
    }

    $pid = (int)trim((string)file_get_contents($pidFile));
    if ($pid <= 0) {
        return 0;
    }

    if (soc_siem_process_is_running($pid)) {
        return $pid;
    }

    // Si shell_exec est indisponible, on evite de relancer plusieurs Mini-SIEM
    // a chaque rafraichissement automatique du dashboard.
    if (!function_exists('shell_exec') && (time() - (int)filemtime($pidFile) < 3600)) {
        return $pid;
    }

    return 0;
}

function soc_launch_siem_process(): array
{
    $script = realpath(__DIR__ . '/../mini_siem/mini_siem.py');
    $workdir = realpath(__DIR__ . '/../mini_siem');

    if (!$script || !$workdir || !is_file($script)) {
        return ['running' => false, 'started' => false, 'pid' => 0, 'message' => 'mini_siem.py introuvable'];
    }

    if (!function_exists('exec')) {
        return ['running' => false, 'started' => false, 'pid' => 0, 'message' => 'exec est désactivé dans PHP'];
    }

    $output = [];
    $code = 1;

    if (PHP_OS_FAMILY === 'Windows') {
        $ps = '$p = Start-Process -FilePath "python" -ArgumentList ' . soc_powershell_quote($script) .
              ' -WorkingDirectory ' . soc_powershell_quote($workdir) .
              ' -WindowStyle Hidden -PassThru; $p.Id';
        exec('powershell -NoProfile -ExecutionPolicy Bypass -Command ' . escapeshellarg($ps), $output, $code);
    } else {
        $command = 'cd ' . escapeshellarg($workdir) . ' && nohup python3 ' . escapeshellarg($script) . ' >/dev/null 2>&1 & echo $!';
        exec($command, $output, $code);
    }

    $pid = isset($output[0]) ? (int)trim((string)$output[0]) : 0;
    if ($code === 0 && $pid > 0) {
        file_put_contents(soc_siem_pid_file(), (string)$pid);
        return ['running' => true, 'started' => true, 'pid' => $pid, 'message' => 'Mini-SIEM lancé'];
    }

    return ['running' => false, 'started' => false, 'pid' => 0, 'message' => 'Impossible de lancer Mini-SIEM'];
}

function soc_ensure_siem_running(): array
{
    $lockHandle = fopen(soc_siem_lock_file(), 'c');
    if ($lockHandle === false) {
        $pid = soc_siem_current_pid();
        if ($pid > 0) {
            return ['running' => true, 'started' => false, 'pid' => $pid, 'message' => 'Mini-SIEM déjà actif'];
        }
        return soc_launch_siem_process();
    }

    if (!flock($lockHandle, LOCK_EX)) {
        fclose($lockHandle);
        return ['running' => false, 'started' => false, 'pid' => 0, 'message' => 'Verrou Mini-SIEM indisponible'];
    }

    try {
        $pid = soc_siem_current_pid();
        if ($pid > 0) {
            return ['running' => true, 'started' => false, 'pid' => $pid, 'message' => 'Mini-SIEM déjà actif'];
        }

        return soc_launch_siem_process();
    } finally {
        flock($lockHandle, LOCK_UN);
        fclose($lockHandle);
    }
}

function soc_default_date_from(): string
{
    return date('Y-m-d', strtotime('-' . (SOC_DEFAULT_RANGE_DAYS - 1) . ' days'));
}

function soc_default_date_to(): string
{
    return date('Y-m-d');
}

function soc_valid_date(?string $value): bool
{
    if (!$value || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)) {
        return false;
    }
    $parts = explode('-', $value);
    return checkdate((int)$parts[1], (int)$parts[2], (int)$parts[0]);
}

function soc_normalize_filters(array $source): array
{
    $attack = $source['attack'] ?? 'all';
    if (!in_array($attack, SOC_ATTACK_FILTERS, true)) {
        $attack = 'all';
    }

    $severity = strtoupper((string)($source['severity'] ?? 'all'));
    if (!in_array($severity, SOC_SEVERITIES, true)) {
        $severity = 'all';
    }

    $status = $source['status'] ?? 'all';
    if (!array_key_exists($status, SOC_STATUSES)) {
        $status = 'all';
    }

    $q = trim((string)($source['q'] ?? ''));
    if (strlen($q) > 120) {
        $q = substr($q, 0, 120);
    }

    $dateFrom = (string)($source['date_from'] ?? soc_default_date_from());
    $dateTo = (string)($source['date_to'] ?? soc_default_date_to());
    if (!soc_valid_date($dateFrom)) {
        $dateFrom = soc_default_date_from();
    }
    if (!soc_valid_date($dateTo)) {
        $dateTo = soc_default_date_to();
    }
    if (strtotime($dateFrom) > strtotime($dateTo)) {
        [$dateFrom, $dateTo] = [$dateTo, $dateFrom];
    }

    return [
        'attack' => $attack,
        'severity' => $severity,
        'status' => $status,
        'q' => $q,
        'date_from' => $dateFrom,
        'date_to' => $dateTo,
    ];
}

function soc_alert_conditions(array $filters, bool $activeOnly = false): array
{
    $where = [];
    $types = '';
    $params = [];
    $display = soc_alert_display_settings();

    if ($filters['attack'] === 'sqli') {
        $where[] = "(attack_type LIKE ? OR attack_type = ?)";
        $types .= 'ss';
        $params[] = '%SQL%';
        $params[] = 'SQLi';
    } elseif ($filters['attack'] === 'xss') {
        $where[] = "(attack_type LIKE ? OR attack_type LIKE ?)";
        $types .= 'ss';
        $params[] = '%XSS%';
        $params[] = '%Cross-Site%';
    } elseif ($filters['attack'] === 'bruteforce') {
        $where[] = "attack_type LIKE ?";
        $types .= 's';
        $params[] = '%Brute%';
    }

    if ($filters['severity'] !== 'all') {
        $where[] = "UPPER(severity) = ?";
        $types .= 's';
        $params[] = $filters['severity'];
    }

    $minSeverityValues = soc_min_severity_values((string)$display['min_severity']);
    if ($minSeverityValues) {
        $where[] = 'UPPER(severity) IN (' . implode(',', array_fill(0, count($minSeverityValues), '?')) . ')';
        $types .= str_repeat('s', count($minSeverityValues));
        array_push($params, ...$minSeverityValues);
    }

    if ($filters['status'] !== 'all') {
        $where[] = "status = ?";
        $types .= 's';
        $params[] = $filters['status'];
    } elseif ($activeOnly) {
        $where[] = "(status IS NULL OR status NOT IN (?, ?))";
        $types .= 'ss';
        array_push($params, ...SOC_INACTIVE_STATUSES);
    }

    if ($filters['status'] === 'all' && $display['hide_resolved']) {
        $where[] = "(status IS NULL OR status <> ?)";
        $types .= 's';
        $params[] = 'resolu';
    }

    if ($filters['status'] === 'all' && !$display['show_false_positive']) {
        $where[] = "(status IS NULL OR status <> ?)";
        $types .= 's';
        $params[] = 'faux_positif';
    }

    if ($filters['q'] !== '') {
        $where[] = "(source_ip LIKE ? OR url LIKE ? OR payload LIKE ? OR mitre_id LIKE ? OR attack_type LIKE ?)";
        $types .= 'sssss';
        $needle = '%' . $filters['q'] . '%';
        array_push($params, $needle, $needle, $needle, $needle, $needle);
    }

    if (!empty($filters['date_from']) && soc_valid_date((string)$filters['date_from'])) {
        $where[] = "timestamp >= ?";
        $types .= 's';
        $params[] = $filters['date_from'] . ' 00:00:00';
    }

    if (!empty($filters['date_to']) && soc_valid_date((string)$filters['date_to'])) {
        $where[] = "timestamp <= ?";
        $types .= 's';
        $params[] = $filters['date_to'] . ' 23:59:59';
    }

    return [
        'sql' => $where ? 'WHERE ' . implode(' AND ', $where) : '',
        'types' => $types,
        'params' => $params,
    ];
}

function soc_fetch_alerts(array $filters, int $limit = 0, bool $activeOnly = false): array
{
    if ($limit <= 0) {
        $limit = soc_alert_display_settings()['alert_page_size'];
    }
    $limit = max(1, min(500, $limit));
    $conditions = soc_alert_conditions($filters, $activeOnly);
    $order = soc_alert_order_sql();
    $sql = "SELECT *
            FROM alerts
            {$conditions['sql']}
            ORDER BY $order
            LIMIT $limit";
    $rows = soc_db_select($sql, $conditions['types'], $conditions['params']);
    return array_map('soc_display_alert', soc_apply_read_state(array_map('soc_enrich_alert', $rows)));
}

function soc_fetch_alert_history(array $filters): array
{
    $conditions = soc_alert_conditions($filters);
    $order = soc_alert_order_sql();
    $rows = soc_db_select(
        "SELECT *
         FROM alerts
         {$conditions['sql']}
         ORDER BY $order",
        $conditions['types'],
        $conditions['params']
    );
    return array_map('soc_display_alert', soc_apply_read_state(array_map('soc_enrich_alert', $rows)));
}

function soc_count_alerts(array $filters, bool $activeOnly = false): int
{
    $conditions = soc_alert_conditions($filters, $activeOnly);
    $row = soc_db_one(
        "SELECT COUNT(*) AS total FROM alerts {$conditions['sql']}",
        $conditions['types'],
        $conditions['params']
    );
    return (int)($row['total'] ?? 0);
}

function soc_fetch_alert_by_id(int $id, bool $markRead = false): ?array
{
    if ($id <= 0) {
        return null;
    }

    if ($markRead) {
        soc_mark_alert_read($id);
    }

    $row = soc_db_one("SELECT * FROM alerts WHERE id = ? LIMIT 1", 'i', [$id]);
    if (!$row) {
        return null;
    }
    $alert = soc_enrich_alert($row);
    return soc_display_alert(soc_apply_read_state([$alert])[0] ?? $alert);
}

function soc_fetch_latest_alert(?array $filters = null, bool $activeOnly = false): ?array
{
    $conditions = $filters ? soc_alert_conditions($filters, $activeOnly) : ['sql' => '', 'types' => '', 'params' => []];
    $row = soc_db_one(
        "SELECT * FROM alerts {$conditions['sql']} ORDER BY timestamp DESC, id DESC LIMIT 1",
        $conditions['types'],
        $conditions['params']
    );
    if (!$row) {
        return null;
    }
    $alert = soc_enrich_alert($row);
    return soc_display_alert(soc_apply_read_state([$alert])[0] ?? $alert);
}

function soc_update_alert_status(int $id, string $status): bool
{
    if ($id <= 0 || !array_key_exists($status, SOC_STATUSES) || $status === 'all') {
        return false;
    }
    $updated = soc_db_execute("UPDATE alerts SET status = ? WHERE id = ?", 'si', [$status, $id]);
    if ($updated) {
        soc_recalculate_threat_score();
    }
    return $updated;
}

function soc_score_level(int $score): string
{
    if ($score <= 20) {
        return 'LOW';
    }
    if ($score <= 50) {
        return 'MEDIUM';
    }
    if ($score <= 80) {
        return 'HIGH';
    }
    return 'CRITICAL';
}

function soc_attack_score_points(string $attackType): int
{
    $label = strtolower($attackType);
    if (str_contains($label, 'sql')) {
        return 15;
    }
    if (str_contains($label, 'xss') || str_contains($label, 'cross-site')) {
        return 10;
    }
    if (str_contains($label, 'brute')) {
        return 8;
    }
    return 5;
}

function soc_current_threat_score(): array
{
    $rows = soc_db_select(
        "SELECT attack_type, source_ip, COUNT(*) AS nb
         FROM alerts
         WHERE timestamp >= NOW() - INTERVAL 10 MINUTE
         AND (status IS NULL OR status NOT IN ('resolu', 'faux_positif'))
         GROUP BY attack_type, source_ip
         ORDER BY source_ip ASC, attack_type ASC"
    );

    $score = 0;
    $ipCounts = [];
    $details = [];
    foreach ($rows as $row) {
        $attackType = (string)($row['attack_type'] ?? '');
        $sourceIp = (string)($row['source_ip'] ?? '');
        $count = (int)($row['nb'] ?? 0);
        $base = soc_attack_score_points($attackType);

        $ipCounts[$sourceIp] = ($ipCounts[$sourceIp] ?? 0) + $count;
        $multiplier = $ipCounts[$sourceIp] >= 3 ? 2 : 1;
        $points = $base * $count * $multiplier;
        $score += $points;
        $details[] = $attackType . ' x' . $count . ' depuis ' . $sourceIp . ' = ' . $points . 'pts';
    }

    return [
        'score' => $score,
        'level' => soc_score_level($score),
        'detail' => $details ? implode(' | ', $details) : 'Aucune alerte active',
    ];
}

function soc_recalculate_threat_score(): void
{
    $current = soc_current_threat_score();
    $previous = soc_db_one("SELECT COALESCE(MAX(score_total), 0) AS total FROM threat_score");
    soc_db_execute(
        "INSERT INTO threat_score (timestamp, score_global, niveau, detail, score_total)
         VALUES (NOW(), ?, ?, ?, ?)",
        'issi',
        [(int)$current['score'], (string)$current['level'], (string)$current['detail'], (int)($previous['total'] ?? 0)]
    );
}

function soc_dashboard_stats(?array $filters = null, bool $activeOnly = false): array
{
    $conditions = $filters ? soc_alert_conditions($filters, $activeOnly) : ['sql' => '', 'types' => '', 'params' => []];
    $totals = soc_db_one(
        "SELECT
            COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN attack_type LIKE '%SQL%' OR attack_type = 'SQLi' THEN 1 ELSE 0 END), 0) AS sqli,
            COALESCE(SUM(CASE WHEN attack_type LIKE '%XSS%' OR attack_type LIKE '%Cross-Site%' THEN 1 ELSE 0 END), 0) AS xss,
            COALESCE(SUM(CASE WHEN attack_type LIKE '%Brute%' THEN 1 ELSE 0 END), 0) AS brute_force
         FROM alerts
         {$conditions['sql']}",
        $conditions['types'],
        $conditions['params']
    ) ?? [];

    $severityRows = soc_db_select(
        "SELECT UPPER(severity) AS severity, COUNT(*) AS total
         FROM alerts
         {$conditions['sql']}
         GROUP BY UPPER(severity)",
        $conditions['types'],
        $conditions['params']
    );

    $severity = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
    foreach ($severityRows as $row) {
        $key = strtoupper((string)($row['severity'] ?? ''));
        if (array_key_exists($key, $severity)) {
            $severity[$key] = (int)$row['total'];
        }
    }

    $sources = soc_db_select(
        "SELECT source_ip, COUNT(*) AS total
         FROM alerts
         {$conditions['sql']}
         GROUP BY source_ip
         ORDER BY total DESC, source_ip ASC
         LIMIT 5",
        $conditions['types'],
        $conditions['params']
    );

    if (soc_alert_display_settings()['mask_ip']) {
        $masked = [];
        foreach ($sources as $source) {
            $label = soc_mask_alert_value('ip', (string)($source['source_ip'] ?? ''));
            $masked[$label] = ($masked[$label] ?? 0) + (int)($source['total'] ?? 0);
        }
        arsort($masked);
        $sources = [];
        foreach (array_slice($masked, 0, 5, true) as $sourceIp => $total) {
            $sources[] = ['source_ip' => $sourceIp, 'total' => $total];
        }
    }

    return [
        'total' => (int)($totals['total'] ?? 0),
        'sqli' => (int)($totals['sqli'] ?? 0),
        'xss' => (int)($totals['xss'] ?? 0),
        'brute_force' => (int)($totals['brute_force'] ?? 0),
        'severity' => $severity,
        'sources' => $sources,
    ];
}

function soc_mitre_map(): array
{
    static $map = null;
    if ($map !== null) {
        return $map;
    }

    $file = __DIR__ . '/../mini_siem/mitre_mapping.json';
    if (!is_file($file)) {
        $map = [];
        return $map;
    }

    $json = json_decode((string)file_get_contents($file), true);
    $map = is_array($json['attacks'] ?? null) ? $json['attacks'] : [];
    return $map;
}

function soc_attack_key(string $attackType): string
{
    $value = strtolower($attackType);
    if (str_contains($value, 'sql')) {
        return 'SQLi';
    }
    if (str_contains($value, 'xss') || str_contains($value, 'cross-site')) {
        return 'XSS';
    }
    if (str_contains($value, 'brute')) {
        return 'BruteForce';
    }
    return '';
}

function soc_attack_label(string $attackType): string
{
    $key = soc_attack_key($attackType);
    if ($key === 'SQLi') {
        return 'SQLi';
    }
    if ($key === 'XSS') {
        return 'XSS';
    }
    if ($key === 'BruteForce') {
        return 'Brute Force';
    }
    return $attackType !== '' ? $attackType : 'Inconnu';
}

function soc_recommended_response_from_mapping(array $info): string
{
    $response = $info['recommended_response'] ?? '';
    if (is_string($response)) {
        return $response;
    }
    if (is_array($response) && !empty($response['immediate_actions'][0])) {
        return (string)$response['immediate_actions'][0];
    }
    return '';
}

function soc_enrich_alert(array $alert): array
{
    $key = soc_attack_key((string)($alert['attack_type'] ?? ''));
    $info = soc_mitre_map()[$key] ?? [];

    if (($alert['mitre_id'] ?? '') === '' && isset($info['mitre_id'])) {
        $alert['mitre_id'] = $info['mitre_id'];
    }
    if (($alert['mitre_tactic'] ?? '') === '' && isset($info['tactic'])) {
        $alert['mitre_tactic'] = $info['tactic'];
    }
    if (($alert['mitre_technique'] ?? '') === '' && isset($info['technique'])) {
        $alert['mitre_technique'] = $info['technique'];
    }
    if (($alert['recommended_response'] ?? '') === '') {
        $alert['recommended_response'] = soc_recommended_response_from_mapping($info);
    }
    if (($alert['severity'] ?? '') === '' && isset($info['severity'])) {
        $alert['severity'] = $info['severity'];
    }

    $alert['attack_label'] = soc_attack_label((string)($alert['attack_type'] ?? ''));
    $alert['attack_key'] = $key;
    $alert['triggered_rule'] = $alert['description'] ?: ($alert['attack_label'] . ' détectée par Mini-SIEM');
    return $alert;
}

function soc_status_label(string $status): string
{
    return [
        'all' => soc_t('status_all'),
        'nouveau' => soc_t('status_new'),
        'en_cours' => soc_t('status_progress'),
        'resolu' => soc_t('status_resolved'),
        'faux_positif' => soc_t('status_false_positive'),
    ][$status] ?? ucfirst(str_replace('_', ' ', $status));
}

function soc_severity_label(string $severity): string
{
    $severity = strtoupper($severity);
    return [
        'CRITICAL' => soc_t('critical'),
        'HIGH' => soc_t('high'),
        'MEDIUM' => soc_t('medium'),
        'LOW' => soc_t('low'),
    ][$severity] ?? ($severity ?: 'Non définie');
}

function soc_token(string $value): string
{
    $value = strtolower($value);
    $value = str_replace([' ', '_'], '-', $value);
    return preg_replace('/[^a-z0-9-]/', '', $value) ?: 'default';
}

function soc_format_datetime($value): string
{
    $timestamp = strtotime((string)$value);
    if (!$timestamp) {
        return '-';
    }
    return date('d/m/Y H:i:s', $timestamp);
}

function soc_index_url(array $filters, array $extra = []): string
{
    $params = array_merge($filters, $extra);
    foreach ($params as $key => $value) {
        if ($value === 'all' || $value === '' || $value === null) {
            unset($params[$key]);
        }
    }
    $query = http_build_query($params);
    return 'index.php' . ($query ? '?' . $query : '');
}

function soc_donut_style(array $severity): string
{
    $total = array_sum($severity);
    if ($total <= 0) {
        return 'background: var(--empty-ring);';
    }

    $colors = [
        'CRITICAL' => 'var(--danger)',
        'HIGH' => 'var(--warning)',
        'MEDIUM' => 'var(--medium)',
        'LOW' => 'var(--success)',
    ];
    $segments = [];
    $start = 0.0;
    foreach ($colors as $key => $color) {
        $value = (int)($severity[$key] ?? 0);
        if ($value <= 0) {
            continue;
        }
        $end = $start + (($value / $total) * 360);
        $segments[] = $color . ' ' . round($start, 2) . 'deg ' . round($end, 2) . 'deg';
        $start = $end;
    }
    return 'background: conic-gradient(' . implode(', ', $segments) . ');';
}

function soc_fetch_trend(array $filters, bool $activeOnly = false): array
{
    $fromTs = strtotime($filters['date_from'] . ' 00:00:00');
    $toTs = strtotime($filters['date_to'] . ' 23:59:59');
    if (!$fromTs || !$toTs || $fromTs > $toTs) {
        $fromTs = strtotime(soc_default_date_from() . ' 00:00:00');
        $toTs = strtotime(soc_default_date_to() . ' 23:59:59');
    }

    $days = (int)floor(($toTs - $fromTs) / 86400) + 1;
    if ($days > 31) {
        $fromTs = strtotime('-30 days', $toTs);
        $filters['date_from'] = date('Y-m-d', $fromTs);
    }

    $conditions = soc_alert_conditions($filters, $activeOnly);
    $rows = soc_db_select(
        "SELECT DATE(timestamp) AS day,
                COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN attack_type LIKE '%SQL%' OR attack_type = 'SQLi' THEN 1 ELSE 0 END), 0) AS sqli,
                COALESCE(SUM(CASE WHEN UPPER(severity) IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END), 0) AS high_critical
         FROM alerts
         {$conditions['sql']}
         GROUP BY DATE(timestamp)
         ORDER BY day ASC",
        $conditions['types'],
        $conditions['params']
    );

    $byDay = [];
    foreach ($rows as $row) {
        $byDay[$row['day']] = [
            'total' => (int)$row['total'],
            'sqli' => (int)$row['sqli'],
            'high_critical' => (int)$row['high_critical'],
        ];
    }

    $trend = [];
    for ($ts = strtotime(date('Y-m-d', $fromTs)); $ts <= $toTs; $ts = strtotime('+1 day', $ts)) {
        $day = date('Y-m-d', $ts);
        $trend[] = [
            'day' => $day,
            'label' => date('d/m', $ts),
            'total' => $byDay[$day]['total'] ?? 0,
            'sqli' => $byDay[$day]['sqli'] ?? 0,
            'high_critical' => $byDay[$day]['high_critical'] ?? 0,
        ];
    }
    return $trend;
}

function soc_render_trend_svg(array $trend): string
{
    $width = 640;
    $height = 250;
    $left = 48;
    $right = 22;
    $top = 24;
    $bottom = 42;
    $max = 1;
    foreach ($trend as $point) {
        $max = max($max, (int)$point['total']);
    }

    $count = max(1, count($trend));
    $plotWidth = $width - $left - $right;
    $plotHeight = $height - $top - $bottom;
    $alertPoints = [];

    foreach ($trend as $index => $point) {
        $x = $left + ($count === 1 ? $plotWidth / 2 : ($index / ($count - 1)) * $plotWidth);
        $alertY = $top + $plotHeight - (((int)$point['total'] / $max) * $plotHeight);
        $alertPoints[] = round($x, 1) . ',' . round($alertY, 1);
    }

    ob_start();
    ?>
    <svg class="trend-svg" viewBox="0 0 <?= $width ?> <?= $height ?>" role="img" aria-label="<?= soc_e(soc_t('trend_aria')) ?>">
        <g class="grid-lines">
            <?php for ($i = 0; $i <= 4; $i++): ?>
                <?php $y = $top + ($plotHeight / 4) * $i; ?>
                <line x1="<?= $left ?>" y1="<?= round($y, 1) ?>" x2="<?= $width - $right ?>" y2="<?= round($y, 1) ?>"></line>
            <?php endfor; ?>
        </g>
        <polyline class="trend-line total" points="<?= soc_e(implode(' ', $alertPoints)) ?>"></polyline>
        <?php foreach ($trend as $index => $point): ?>
            <?php
            $x = $left + ($count === 1 ? $plotWidth / 2 : ($index / ($count - 1)) * $plotWidth);
            $showLabel = $count <= 10 || $index % max(1, (int)ceil($count / 6)) === 0 || $index === $count - 1;
            ?>
            <?php if ($showLabel): ?><text x="<?= round($x, 1) ?>" y="<?= $height - 14 ?>" text-anchor="middle"><?= soc_e($point['label']) ?></text><?php endif; ?>
        <?php endforeach; ?>
    </svg>
    <?php
    return trim((string)ob_get_clean());
}

function soc_detection_status(): array
{
    $currentScore = soc_current_threat_score();
    $latestScore = soc_db_one("SELECT * FROM threat_score ORDER BY timestamp DESC, id DESC LIMIT 1");
    $latestAlert = soc_db_one(
        "SELECT *
         FROM alerts
         WHERE status IS NULL OR status NOT IN ('resolu', 'faux_positif')
         ORDER BY timestamp DESC, id DESC
         LIMIT 1"
    );
    $logs = soc_db_one("SELECT COUNT(*) AS unprocessed, MAX(timestamp) AS latest_log FROM http_logs WHERE processed = 0");

    $latestTs = null;
    foreach ([$latestScore['timestamp'] ?? null, $latestAlert['timestamp'] ?? null, $logs['latest_log'] ?? null] as $candidate) {
        $ts = strtotime((string)$candidate);
        if ($ts && (!$latestTs || $ts > $latestTs)) {
            $latestTs = $ts;
        }
    }

    $age = $latestTs ? max(0, time() - $latestTs) : null;
    $state = 'idle';
    if ($age !== null && $age <= 35) {
        $state = 'active';
    } elseif ($age !== null && $age <= 300) {
        $state = 'recent';
    }

    return [
        'state' => $state,
        'label' => ['active' => soc_t('live_active'), 'recent' => soc_t('live_recent'), 'idle' => soc_t('live_idle')][$state],
        'last_seen' => $latestTs ? date('d/m/Y H:i:s', $latestTs) : '-',
        'unprocessed_logs' => (int)($logs['unprocessed'] ?? 0),
        'score_global' => (int)$currentScore['score'],
        'score_level' => (string)$currentScore['level'],
        'latest_alert' => $latestAlert ? soc_enrich_alert($latestAlert) : null,
    ];
}

function soc_alert_payload(?array $alert): ?array
{
    if (!$alert) {
        return null;
    }
    $display = $alert['_display'] ?? soc_alert_display_settings();
    return [
        'id' => (int)$alert['id'],
        'timestamp' => soc_format_datetime($alert['timestamp']),
        'attack_type' => $alert['attack_type'],
        'attack_label' => $alert['attack_label'],
        'attack_token' => soc_token($alert['attack_label']),
        'severity' => strtoupper((string)$alert['severity']),
        'severity_label' => soc_severity_label($alert['severity']),
        'source_ip' => $alert['source_ip'] ?? '',
        'url' => $alert['url'] ?? '',
        'payload' => $alert['payload'] ?? '',
        'triggered_rule' => $alert['triggered_rule'],
        'mitre_id' => $alert['mitre_id'] ?? '',
        'mitre_tactic' => $alert['mitre_tactic'] ?? '',
        'mitre_technique' => $alert['mitre_technique'] ?? '',
        'recommended_response' => $alert['recommended_response'] ?? '',
        'status' => $alert['status'] ?? '',
        'status_label' => soc_status_label($alert['status'] ?? ''),
        'status_token' => soc_token($alert['status'] ?? ''),
        'is_read' => !empty($alert['is_read']),
        'read_label' => !empty($alert['is_read']) ? 'Lu' : 'Non lu',
        'read_token' => !empty($alert['is_read']) ? 'read' : 'unread',
        'detail_url' => 'detail.php?id=' . urlencode((string)$alert['id']),
        'display' => [
            'show_mitre_id' => !empty($display['show_mitre_id']),
            'show_mitre_tactic' => !empty($display['show_mitre_tactic']),
            'show_mitre_technique' => !empty($display['show_mitre_technique']),
            'show_recommended_response' => !empty($display['show_recommended_response']),
        ],
    ];
}

function soc_dashboard_payload(array $filters, int $selectedId = 0): array
{
    $activeOnly = $filters['status'] === 'all';
    $stats = soc_dashboard_stats($filters, $activeOnly);
    $alerts = soc_fetch_alerts($filters, 0, $activeOnly);
    $selected = $selectedId > 0 ? soc_fetch_alert_by_id($selectedId) : null;
    if (!$selected && $alerts) {
        $selected = $alerts[0];
    } elseif (!$selected) {
        $selected = soc_fetch_latest_alert($filters, $activeOnly);
    }

    return [
        'generated_at' => date('d/m/Y H:i:s'),
        'filters' => $filters,
        'stats' => $stats,
        'filtered_total' => soc_count_alerts($filters, $activeOnly),
        'trend' => soc_fetch_trend($filters, $activeOnly),
        'alerts' => array_map('soc_alert_payload', $alerts),
        'selected_alert' => soc_alert_payload($selected),
        'detection' => soc_detection_status(),
        'donut_style' => soc_donut_style($stats['severity']),
        'unread_count' => soc_unread_alert_count(),
    ];
}

function soc_hidden_filters(array $filters, array $exclude = []): void
{
    foreach ($filters as $key => $value) {
        if (in_array($key, $exclude, true) || $value === '' || $value === null || $value === 'all') {
            continue;
        }
        echo '<input type="hidden" name="' . soc_e($key) . '" value="' . soc_e($value) . '">';
    }
}

function soc_sidebar(string $active, int $alertCount): void
{
    ?>
    <aside class="soc-sidebar">
        <a class="soc-brand" href="index.php">
            <span class="brand-mark"><?= soc_icon('shield', 'brand-icon') ?></span>
            <span>
                <strong>Mini-SOC</strong>
                <small><?= soc_e(soc_t('soc_center')) ?></small>
            </span>
        </a>
        <nav class="soc-nav" aria-label="Navigation SOC">
            <a class="<?= $active === 'overview' ? 'active' : '' ?>" href="index.php">
                <span class="nav-icon"><?= soc_icon('grid') ?></span>
                <span><?= soc_e(soc_t('overview')) ?></span>
            </a>
            <a class="<?= $active === 'alerts' ? 'active' : '' ?>" href="alerts.php">
                <span class="nav-icon"><?= soc_icon('bell') ?></span>
                <span><?= soc_e(soc_t('alerts')) ?></span>
                <b><?= soc_e($alertCount) ?></b>
            </a>
            <a class="<?= $active === 'mitre' ? 'active' : '' ?>" href="mitre.php">
                <span class="nav-icon"><?= soc_icon('crosshair') ?></span>
                <span>MITRE</span>
            </a>
            <a class="<?= $active === 'reports' ? 'active' : '' ?>" href="report.php">
                <span class="nav-icon"><?= soc_icon('file') ?></span>
                <span><?= soc_e(soc_t('reports')) ?></span>
            </a>
            <a class="<?= $active === 'settings' ? 'active' : '' ?>" href="settings.php">
                <span class="nav-icon"><?= soc_icon('settings') ?></span>
                <span><?= soc_e(soc_t('settings')) ?></span>
            </a>
            <a class="<?= $active === 'guide' ? 'active' : '' ?>" href="guide.php">
                <span class="nav-icon"><?= soc_icon('book') ?></span>
                <span><?= soc_e(soc_t('guide')) ?></span>
            </a>
        </nav>
        <a class="logout-link" href="logout.php?csrf=<?= soc_e(soc_csrf_token()) ?>"><?= soc_icon('logout') ?><span><?= soc_e(soc_t('logout')) ?></span></a>
    </aside>
    <?php
}

function soc_shell_start(string $title, string $active = 'overview'): void
{
    $alertCount = soc_unread_alert_count();
    ?>
    <!doctype html>
    <html lang="<?= soc_e(soc_current_language()) ?>" data-theme="light">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title><?= soc_e($title) ?> - Mini-SOC</title>
        <script>
            (function () {
                var saved = localStorage.getItem('soc-theme') || 'light';
                document.documentElement.setAttribute('data-theme', saved);
                window.SOC_CSRF = <?= json_encode(soc_csrf_token(), JSON_UNESCAPED_SLASHES) ?>;
                window.SOC_I18N = <?= json_encode(soc_client_i18n(), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>;
            }());
        </script>
        <link rel="stylesheet" href="assets/soc.css">
    </head>
    <body>
        <div class="soc-shell">
            <?php soc_sidebar($active, $alertCount); ?>
            <main class="soc-main">
                <header class="soc-topbar">
                    <div class="topbar-title">
                        <span class="topbar-kicker"><?= soc_e(soc_t('security_operations')) ?></span>
                        <strong><?= soc_e($title) ?></strong>
                    </div>
                    <div class="topbar-actions">
                        <span class="admin-chip">
                            <span class="brand-mark small"><?= soc_icon('user', 'brand-icon small-icon') ?></span>
                            <?= soc_e(soc_user_name()) ?>
                        </span>
                    </div>
                </header>
    <?php
}

function soc_shell_end(): void
{
    ?>
            </main>
        </div>
        <script src="assets/soc.js"></script>
    </body>
    </html>
    <?php
}
