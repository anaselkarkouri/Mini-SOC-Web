<?php
require_once __DIR__ . '/bootstrap.php';

soc_require_admin();

$filters = soc_normalize_filters(array_merge([
    'date_from' => '1970-01-01',
    'date_to' => soc_default_date_to(),
], $_GET));
soc_mark_all_alerts_read();
$alerts = soc_fetch_alert_history($filters);
$total = count($alerts);

soc_shell_start(soc_t('history_title'), 'alerts');
?>
<section class="hero-row compact">
    <div>
        <h1><?= soc_e(soc_t('history_h1')) ?></h1>
        <p><?= soc_e(soc_t('history_intro')) ?></p>
    </div>
</section>

<section class="history-grid">
    <article class="table-card">
        <div class="table-head">
            <div>
                <h2><?= soc_e(soc_t('alerts')) ?></h2>
                <p><?= soc_e($total) ?> <?= soc_e(soc_t('history_count')) ?></p>
            </div>
            <form class="filters" method="get">
                <span class="filter-title"><?= soc_icon('filter') ?> <?= soc_e(soc_t('filters')) ?></span>
                <select name="attack" aria-label="<?= soc_e(soc_t('attack_filter')) ?>">
                    <option value="all"><?= soc_e(soc_t('attack_filter')) ?>: <?= soc_e(soc_t('all_feminine')) ?></option>
                    <option value="sqli" <?= $filters['attack'] === 'sqli' ? 'selected' : '' ?>>SQLi</option>
                    <option value="xss" <?= $filters['attack'] === 'xss' ? 'selected' : '' ?>>XSS</option>
                    <option value="bruteforce" <?= $filters['attack'] === 'bruteforce' ? 'selected' : '' ?>>Brute Force</option>
                </select>
                <select name="severity" aria-label="<?= soc_e(soc_t('severity_filter')) ?>">
                    <option value="all"><?= soc_e(soc_t('severity_filter')) ?>: <?= soc_e(soc_t('all_feminine')) ?></option>
                    <?php foreach (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as $severity): ?>
                        <option value="<?= soc_e($severity) ?>" <?= $filters['severity'] === $severity ? 'selected' : '' ?>><?= soc_e(soc_severity_label($severity)) ?></option>
                    <?php endforeach; ?>
                </select>
                <select name="status" aria-label="<?= soc_e(soc_t('status_filter')) ?>">
                    <?php foreach (SOC_STATUSES as $value => $label): ?>
                        <option value="<?= soc_e($value) ?>" <?= $filters['status'] === $value ? 'selected' : '' ?>><?= soc_e(soc_t('status')) ?>: <?= soc_e(soc_status_label($value)) ?></option>
                    <?php endforeach; ?>
                </select>
                <button type="submit"><?= soc_e(soc_t('filter')) ?></button>
                <a href="alerts.php"><?= soc_e(soc_t('reset')) ?></a>
            </form>
        </div>

        <div class="table-scroll">
            <table class="alerts-table history-table">
                <thead>
                    <tr>
                        <th><?= soc_e(soc_t('time')) ?></th>
                        <th><?= soc_e(soc_t('type')) ?></th>
                        <th><?= soc_e(soc_t('severity')) ?></th>
                        <th><?= soc_e(soc_t('source_ip')) ?></th>
                        <th><?= soc_e(soc_t('target_url')) ?></th>
                        <th><?= soc_e(soc_t('status')) ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php if (!$alerts): ?>
                    <tr><td colspan="6" class="empty-cell"><?= soc_e(soc_t('empty_history')) ?></td></tr>
                <?php endif; ?>
                <?php foreach ($alerts as $alert): ?>
                    <tr>
                        <td><?= soc_e(soc_format_datetime($alert['timestamp'])) ?></td>
                        <td><span class="attack-label <?= soc_e(soc_token($alert['attack_label'])) ?>"><?= soc_e($alert['attack_label']) ?></span></td>
                        <td><span class="pill severity-<?= soc_e(strtolower($alert['severity'])) ?>"><?= soc_e(soc_severity_label($alert['severity'])) ?></span></td>
                        <td><?= soc_e($alert['source_ip']) ?></td>
                        <td class="url-cell"><?= soc_e($alert['url']) ?></td>
                        <td><span class="pill status-<?= soc_e(soc_token($alert['status'])) ?>"><?= soc_e(soc_status_label($alert['status'])) ?></span></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </article>
</section>
<?php soc_shell_end(); ?>
