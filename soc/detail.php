<?php
require_once __DIR__ . '/bootstrap.php';

soc_require_admin();

$id = (int)($_GET['id'] ?? $_POST['id'] ?? 0);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'update_status') {
    if (!soc_verify_post_csrf()) {
        http_response_code(403);
        exit('CSRF token invalid');
    }
    $status = (string)($_POST['status'] ?? '');
    soc_update_alert_status($id, $status);
    header('Location: detail.php?id=' . urlencode((string)$id));
    exit;
}

$alert = soc_fetch_alert_by_id($id);

soc_shell_start(soc_t('detail_title'), 'alerts');
?>
<section class="hero-row compact">
    <div>
        <h1><?= soc_e(soc_t('detail_title')) ?> #<?= soc_e($id) ?></h1>
        <p><?= soc_e(soc_t('detail_intro')) ?></p>
    </div>
    <a class="secondary-action" href="index.php"><?= soc_e(soc_t('back_dashboard')) ?></a>
</section>

<?php if (!$alert): ?>
    <article class="panel-card">
        <h2><?= soc_e(soc_t('alert_not_found')) ?></h2>
        <p class="empty-note"><?= soc_e(soc_t('alert_not_found_text')) ?></p>
    </article>
<?php else: ?>
    <?php
    $display = $alert['_display'] ?? soc_alert_display_settings();
    $showMitrePanel = !empty($display['show_mitre_id'])
        || !empty($display['show_mitre_tactic'])
        || !empty($display['show_mitre_technique'])
        || !empty($display['show_recommended_response']);
    ?>
    <section class="detail-page-grid">
        <article class="panel-card detail-wide">
            <div class="panel-head">
                <h2><?= soc_e($alert['attack_label']) ?></h2>
                <div class="detail-badges">
                    <span class="pill severity-<?= soc_e(strtolower($alert['severity'])) ?>"><?= soc_e(soc_severity_label($alert['severity'])) ?></span>
                    <span class="pill status-<?= soc_e(soc_token($alert['status'])) ?>"><?= soc_e(soc_status_label($alert['status'])) ?></span>
                </div>
            </div>
            <dl class="detail-list columns">
                <div><dt><?= soc_e(soc_t('date')) ?></dt><dd><?= soc_e(soc_format_datetime($alert['timestamp'])) ?></dd></div>
                <div><dt><?= soc_e(soc_t('source_ip')) ?></dt><dd><?= soc_e($alert['source_ip']) ?></dd></div>
                <div><dt><?= soc_e(soc_t('target_url')) ?></dt><dd><?= soc_e($alert['url']) ?></dd></div>
                <div><dt><?= soc_e(soc_t('source_log')) ?></dt><dd>#<?= soc_e($alert['log_id']) ?></dd></div>
                <div class="full"><dt><?= soc_e(soc_t('payload')) ?></dt><dd><code><?= soc_e($alert['payload']) ?></code></dd></div>
                <div class="full"><dt><?= soc_e(soc_t('triggered_rule')) ?></dt><dd><?= soc_e($alert['triggered_rule']) ?></dd></div>
            </dl>
        </article>

        <?php if ($showMitrePanel): ?>
            <article class="panel-card detail-wide">
                <div class="panel-head">
                    <h2><?= soc_e(soc_t('mitre_information')) ?></h2>
                    <?php if (!empty($display['show_mitre_id'])): ?><span class="mitre-chip"><?= soc_e($alert['mitre_id']) ?></span><?php endif; ?>
                </div>
                <dl class="detail-list columns">
                    <?php if (!empty($display['show_mitre_tactic'])): ?>
                        <div><dt><?= soc_e(soc_t('tactic')) ?></dt><dd><?= soc_e($alert['mitre_tactic']) ?></dd></div>
                    <?php endif; ?>
                    <?php if (!empty($display['show_mitre_technique'])): ?>
                        <div><dt><?= soc_e(soc_t('technique')) ?></dt><dd><?= soc_e($alert['mitre_technique']) ?></dd></div>
                    <?php endif; ?>
                    <?php if (!empty($display['show_recommended_response'])): ?>
                        <div class="full"><dt><?= soc_e(soc_t('recommended_response')) ?></dt><dd><?= soc_e($alert['recommended_response']) ?></dd></div>
                    <?php endif; ?>
                </dl>
            </article>
        <?php endif; ?>

        <aside class="panel-card status-panel">
            <h2><?= soc_e(soc_t('status')) ?></h2>
            <form class="status-form stacked" method="post">
                <?php soc_csrf_field(); ?>
                <input type="hidden" name="action" value="update_status">
                <input type="hidden" name="id" value="<?= soc_e($alert['id']) ?>">
                <label for="status"><?= soc_e(soc_t('change_status')) ?></label>
                <select id="status" name="status">
                    <?php foreach (SOC_STATUSES as $value => $label): ?>
                        <?php if ($value === 'all') continue; ?>
                        <option value="<?= soc_e($value) ?>" <?= $alert['status'] === $value ? 'selected' : '' ?>><?= soc_e(soc_status_label($value)) ?></option>
                    <?php endforeach; ?>
                </select>
                <button type="submit"><?= soc_e(soc_t('save')) ?></button>
            </form>
        </aside>
    </section>
<?php endif; ?>
<?php soc_shell_end(); ?>
