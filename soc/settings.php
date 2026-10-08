<?php
require_once __DIR__ . '/bootstrap.php';

soc_require_admin();

$settings = soc_app_settings();
$lang = soc_current_language();
$isEn = $lang === 'en';
$message = '';
$error = '';

$copy = $isEn ? [
    'title' => 'Settings',
    'intro' => 'Manage global language, display, alert rules, privacy and SOC password.',
    'saved_preferences' => 'Settings saved.',
    'saved_password' => 'SOC password updated.',
    'save_error' => 'Unable to save settings. Check write permissions for the soc folder.',
    'password_error' => 'Current password is invalid.',
    'password_match_error' => 'The new password confirmation does not match.',
    'password_length_error' => 'Use at least 10 characters for the new password.',
    'appearance' => 'Appearance',
    'theme' => 'Dashboard theme',
    'theme_help' => 'Theme is managed here for the SOC interface.',
    'language' => 'Global language',
    'language_help' => 'Applies to sidebar, dashboard, MITRE, guide, reports and generated PDF labels.',
    'compact' => 'Compact tables',
    'compact_help' => 'Reduce row height in alert tables.',
    'realtime' => 'Real time',
    'refresh' => 'Auto-refresh',
    'refresh_help' => 'Synchronize statistics, trend, table and selected detail from api.php.',
    'interval' => 'Interval',
    'interval_help' => 'Choose how often the dashboard synchronizes with alerts.',
    'alerts_help' => 'Controls how alerts are listed across dashboard, history and report preview.',
    'mitre_help' => 'Choose which ATT&CK fields are visible in alert details and SOC pages.',
    'privacy_help' => 'Hide sensitive data during demonstrations or screenshots.',
    'security' => 'Security',
    'current_password' => 'Current password',
    'new_password' => 'New password',
    'confirm_password' => 'Confirm new password',
    'password_help' => 'Username remains admin. Only the SOC password changes.',
    'save' => 'Save',
    'change_password' => 'Change SOC password',
] : [
    'title' => 'Paramètres',
    'intro' => "Gérer la langue globale, l'affichage, les alertes, la confidentialité et le mot de passe SOC.",
    'saved_preferences' => 'Paramètres enregistrés.',
    'saved_password' => 'Mot de passe SOC modifié.',
    'save_error' => "Impossible d'enregistrer les paramètres. Vérifier les droits d'écriture du dossier soc.",
    'password_error' => 'Mot de passe actuel incorrect.',
    'password_match_error' => 'La confirmation du nouveau mot de passe ne correspond pas.',
    'password_length_error' => 'Utiliser au moins 10 caractères pour le nouveau mot de passe.',
    'appearance' => 'Apparence',
    'theme' => 'Thème du dashboard',
    'theme_help' => "Le thème est géré ici pour l'interface SOC.",
    'language' => 'Langue globale',
    'language_help' => 'Appliquée au slide bar, dashboard, MITRE, guide, rapports et libellés PDF.',
    'compact' => 'Table compacte',
    'compact_help' => 'Réduit la hauteur des lignes dans les tableaux des alertes.',
    'realtime' => 'Temps réel',
    'refresh' => 'Auto-refresh',
    'refresh_help' => 'Synchronise statistiques, graphe, tableau et détail depuis api.php.',
    'interval' => 'Intervalle',
    'interval_help' => 'Choisir la fréquence de synchronisation avec la table alerts.',
    'alerts_help' => 'Contrôle la liste des alertes dans dashboard, historique et aperçu rapport.',
    'mitre_help' => 'Choisir les champs ATT&CK visibles dans les détails et pages SOC.',
    'privacy_help' => 'Masque les données sensibles pour une démonstration ou capture.',
    'security' => 'Sécurité',
    'current_password' => 'Mot de passe actuel',
    'new_password' => 'Nouveau mot de passe',
    'confirm_password' => 'Confirmer le nouveau mot de passe',
    'password_help' => "Le username reste admin. Seul le mot de passe SOC change.",
    'save' => 'Enregistrer',
    'change_password' => 'Modifier le mot de passe SOC',
];

if (($_GET['saved'] ?? '') === 'preferences') {
    $message = $copy['saved_preferences'];
} elseif (($_GET['saved'] ?? '') === 'password') {
    $message = $copy['saved_password'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!soc_verify_post_csrf()) {
        http_response_code(403);
        exit('CSRF token invalid');
    }
    $action = (string)($_POST['action'] ?? '');
    $ok = null;

    if ($action === 'save_language') {
        $ok = soc_save_app_settings([
            'language' => (string)($_POST['language'] ?? 'fr'),
        ]);
    }

    if ($action === 'save_alerts') {
        $ok = soc_save_app_settings([
            'alert_page_size' => (int)($_POST['alert_page_size'] ?? 12),
            'alert_sort' => (string)($_POST['alert_sort'] ?? 'newest'),
            'min_severity' => (string)($_POST['min_severity'] ?? 'all'),
            'hide_resolved' => isset($_POST['hide_resolved']),
            'show_false_positive' => isset($_POST['show_false_positive']),
        ]);
    }

    if ($action === 'save_mitre') {
        $ok = soc_save_app_settings([
            'show_mitre_id' => isset($_POST['show_mitre_id']),
            'show_mitre_tactic' => isset($_POST['show_mitre_tactic']),
            'show_mitre_technique' => isset($_POST['show_mitre_technique']),
            'show_recommended_response' => isset($_POST['show_recommended_response']),
        ]);
    }

    if ($action === 'save_privacy') {
        $ok = soc_save_app_settings([
            'privacy_mode' => isset($_POST['privacy_mode']),
            'mask_ip' => isset($_POST['mask_ip']),
            'mask_payload' => isset($_POST['mask_payload']),
            'mask_url' => isset($_POST['mask_url']),
        ]);
    }

    if ($ok === true) {
        header('Location: settings.php?saved=preferences');
        exit;
    }
    if ($ok === false) {
        $error = $copy['save_error'];
    }

    if ($action === 'change_password') {
        $currentPassword = (string)($_POST['current_password'] ?? '');
        $newPassword = (string)($_POST['new_password'] ?? '');
        $confirmPassword = (string)($_POST['confirm_password'] ?? '');

        if (!soc_verify_admin_password($currentPassword)) {
            $error = $copy['password_error'];
        } elseif (strlen($newPassword) < 10) {
            $error = $copy['password_length_error'];
        } elseif ($newPassword !== $confirmPassword) {
            $error = $copy['password_match_error'];
        } else {
            $ok = soc_save_app_settings([
                'password_hash' => password_hash($newPassword, PASSWORD_DEFAULT),
            ]);
            if ($ok) {
                header('Location: settings.php?saved=password');
                exit;
            }
            $error = $copy['save_error'];
        }
    }

    $settings = soc_app_settings(true);
}

$sortOptions = [
    'newest' => soc_t('sort_newest'),
    'oldest' => soc_t('sort_oldest'),
    'severity' => soc_t('sort_severity'),
    'attack' => soc_t('sort_attack'),
];

soc_shell_start($copy['title'], 'settings');
?>
<section class="hero-row compact">
    <div>
        <h1><?= soc_e($copy['title']) ?></h1>
        <p><?= soc_e($copy['intro']) ?></p>
    </div>
</section>

<?php if ($message || $error): ?>
    <section class="settings-message-wrap">
        <div class="<?= $error ? 'settings-message error' : 'settings-message' ?>">
            <?= soc_e($error ?: $message) ?>
        </div>
    </section>
<?php endif; ?>

<section class="settings-grid">
    <article class="panel-card settings-card">
        <div class="panel-head">
            <h2><?= soc_e($copy['appearance']) ?></h2>
            <?= soc_icon('settings') ?>
        </div>
        <div class="setting-row">
            <div>
                <strong><?= soc_e($copy['theme']) ?></strong>
                <p><?= soc_e($copy['theme_help']) ?></p>
            </div>
            <div class="segmented" data-setting-theme>
                <button type="button" data-theme-value="light"><?= $isEn ? 'Light' : 'Clair' ?></button>
                <button type="button" data-theme-value="dark"><?= $isEn ? 'Dark' : 'Sombre' ?></button>
            </div>
        </div>
        <div class="setting-row">
            <div>
                <strong><?= soc_e($copy['compact']) ?></strong>
                <p><?= soc_e($copy['compact_help']) ?></p>
            </div>
            <label class="switch">
                <input type="checkbox" data-setting-compact>
                <span></span>
            </label>
        </div>
        <form class="settings-form" method="post">
            <?php soc_csrf_field(); ?>
            <input type="hidden" name="action" value="save_language">
            <label class="setting-field">
                <span><?= soc_e($copy['language']) ?></span>
                <small><?= soc_e($copy['language_help']) ?></small>
                <select name="language">
                    <option value="fr" <?= $settings['language'] === 'fr' ? 'selected' : '' ?>>Français</option>
                    <option value="en" <?= $settings['language'] === 'en' ? 'selected' : '' ?>>English</option>
                </select>
            </label>
            <button class="primary-action" type="submit"><?= soc_e($copy['save']) ?></button>
        </form>
    </article>

    <article class="panel-card settings-card">
        <div class="panel-head">
            <h2><?= soc_e($copy['realtime']) ?></h2>
            <?= soc_icon('activity') ?>
        </div>
        <div class="setting-row">
            <div>
                <strong><?= soc_e($copy['refresh']) ?></strong>
                <p><?= soc_e($copy['refresh_help']) ?></p>
            </div>
            <label class="switch">
                <input type="checkbox" data-setting-refresh>
                <span></span>
            </label>
        </div>
        <div class="setting-row">
            <div>
                <strong><?= soc_e($copy['interval']) ?></strong>
                <p><?= soc_e($copy['interval_help']) ?></p>
            </div>
            <select data-setting-interval>
                <option value="5000"><?= $isEn ? '5 seconds' : '5 secondes' ?></option>
                <option value="10000"><?= $isEn ? '10 seconds' : '10 secondes' ?></option>
                <option value="30000"><?= $isEn ? '30 seconds' : '30 secondes' ?></option>
                <option value="60000"><?= $isEn ? '60 seconds' : '60 secondes' ?></option>
            </select>
        </div>
    </article>

    <article class="panel-card settings-card">
        <div class="panel-head">
            <div>
                <h2><?= soc_e(soc_t('alerts_settings')) ?></h2>
                <p><?= soc_e($copy['alerts_help']) ?></p>
            </div>
            <?= soc_icon('bell') ?>
        </div>
        <form class="settings-form" method="post">
            <?php soc_csrf_field(); ?>
            <input type="hidden" name="action" value="save_alerts">
            <label class="setting-field">
                <span><?= soc_e(soc_t('alerts_per_page')) ?></span>
                <select name="alert_page_size">
                    <?php foreach ([5, 10, 12, 20, 50] as $limit): ?>
                        <option value="<?= soc_e($limit) ?>" <?= (int)$settings['alert_page_size'] === $limit ? 'selected' : '' ?>><?= soc_e($limit) ?></option>
                    <?php endforeach; ?>
                </select>
            </label>
            <label class="setting-field">
                <span><?= soc_e(soc_t('default_sort')) ?></span>
                <select name="alert_sort">
                    <?php foreach ($sortOptions as $value => $label): ?>
                        <option value="<?= soc_e($value) ?>" <?= $settings['alert_sort'] === $value ? 'selected' : '' ?>><?= soc_e($label) ?></option>
                    <?php endforeach; ?>
                </select>
            </label>
            <label class="setting-field">
                <span><?= soc_e(soc_t('min_level_displayed')) ?></span>
                <select name="min_severity">
                    <option value="all" <?= $settings['min_severity'] === 'all' ? 'selected' : '' ?>><?= soc_e(soc_t('all_levels')) ?></option>
                    <?php foreach (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as $severity): ?>
                        <option value="<?= soc_e($severity) ?>" <?= $settings['min_severity'] === $severity ? 'selected' : '' ?>><?= soc_e(soc_severity_label($severity)) ?></option>
                    <?php endforeach; ?>
                </select>
            </label>
            <label class="checkbox-line">
                <input type="checkbox" name="hide_resolved" <?= !empty($settings['hide_resolved']) ? 'checked' : '' ?>>
                <span><?= soc_e(soc_t('hide_resolved')) ?></span>
            </label>
            <label class="checkbox-line">
                <input type="checkbox" name="show_false_positive" <?= !empty($settings['show_false_positive']) ? 'checked' : '' ?>>
                <span><?= soc_e(soc_t('show_false_positive')) ?></span>
            </label>
            <button class="primary-action" type="submit"><?= soc_e($copy['save']) ?></button>
        </form>
    </article>

    <article class="panel-card settings-card">
        <div class="panel-head">
            <div>
                <h2><?= soc_e(soc_t('mitre_settings')) ?></h2>
                <p><?= soc_e($copy['mitre_help']) ?></p>
            </div>
            <?= soc_icon('crosshair') ?>
        </div>
        <form class="settings-form" method="post">
            <?php soc_csrf_field(); ?>
            <input type="hidden" name="action" value="save_mitre">
            <label class="checkbox-line">
                <input type="checkbox" name="show_mitre_id" <?= !empty($settings['show_mitre_id']) ? 'checked' : '' ?>>
                <span><?= soc_e(soc_t('show_mitre_id')) ?></span>
            </label>
            <label class="checkbox-line">
                <input type="checkbox" name="show_mitre_tactic" <?= !empty($settings['show_mitre_tactic']) ? 'checked' : '' ?>>
                <span><?= soc_e(soc_t('show_tactic')) ?></span>
            </label>
            <label class="checkbox-line">
                <input type="checkbox" name="show_mitre_technique" <?= !empty($settings['show_mitre_technique']) ? 'checked' : '' ?>>
                <span><?= soc_e(soc_t('show_technique')) ?></span>
            </label>
            <label class="checkbox-line">
                <input type="checkbox" name="show_recommended_response" <?= !empty($settings['show_recommended_response']) ? 'checked' : '' ?>>
                <span><?= soc_e(soc_t('show_recommended_response')) ?></span>
            </label>
            <button class="primary-action" type="submit"><?= soc_e($copy['save']) ?></button>
        </form>
    </article>

    <article class="panel-card settings-card">
        <div class="panel-head">
            <div>
                <h2><?= soc_e(soc_t('privacy')) ?></h2>
                <p><?= soc_e($copy['privacy_help']) ?></p>
            </div>
            <?= soc_icon('shield') ?>
        </div>
        <form class="settings-form" method="post">
            <?php soc_csrf_field(); ?>
            <input type="hidden" name="action" value="save_privacy">
            <label class="checkbox-line">
                <input type="checkbox" name="privacy_mode" <?= !empty($settings['privacy_mode']) ? 'checked' : '' ?>>
                <span><?= soc_e(soc_t('privacy_mode')) ?></span>
            </label>
            <label class="checkbox-line">
                <input type="checkbox" name="mask_ip" <?= !empty($settings['mask_ip']) ? 'checked' : '' ?>>
                <span><?= soc_e(soc_t('mask_ip')) ?></span>
            </label>
            <label class="checkbox-line">
                <input type="checkbox" name="mask_payload" <?= !empty($settings['mask_payload']) ? 'checked' : '' ?>>
                <span><?= soc_e(soc_t('mask_payload')) ?></span>
            </label>
            <label class="checkbox-line">
                <input type="checkbox" name="mask_url" <?= !empty($settings['mask_url']) ? 'checked' : '' ?>>
                <span><?= soc_e(soc_t('mask_full_url')) ?></span>
            </label>
            <button class="primary-action" type="submit"><?= soc_e($copy['save']) ?></button>
        </form>
    </article>

    <article class="panel-card settings-card">
        <div class="panel-head">
            <h2><?= soc_e($copy['security']) ?></h2>
            <?= soc_icon('lock') ?>
        </div>
        <form class="settings-form" method="post" autocomplete="off">
            <?php soc_csrf_field(); ?>
            <input type="hidden" name="action" value="change_password">
            <p class="settings-note"><?= soc_e($copy['password_help']) ?></p>
            <label class="setting-field">
                <span><?= soc_e($copy['current_password']) ?></span>
                <input type="password" name="current_password" required>
            </label>
            <label class="setting-field">
                <span><?= soc_e($copy['new_password']) ?></span>
                <input type="password" name="new_password" minlength="10" required>
            </label>
            <label class="setting-field">
                <span><?= soc_e($copy['confirm_password']) ?></span>
                <input type="password" name="confirm_password" minlength="10" required>
            </label>
            <button class="primary-action" type="submit"><?= soc_e($copy['change_password']) ?></button>
        </form>
    </article>
</section>
<?php soc_shell_end(); ?>
