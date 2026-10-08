<?php
require_once __DIR__ . '/bootstrap.php';

soc_require_admin();

$filters = soc_normalize_filters($_GET);
$filters['q'] = '';
$selectedId = (int)($_GET['id'] ?? 0);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'update_status') {
    if (!soc_verify_post_csrf()) {
        http_response_code(403);
        exit('CSRF token invalid');
    }
    $id = (int)($_POST['id'] ?? 0);
    $status = (string)($_POST['status'] ?? '');
    soc_update_alert_status($id, $status);
    header('Location: ' . soc_index_url($filters, ['id' => $id]));
    exit;
}

$payload = soc_dashboard_payload($filters, $selectedId);
$stats = $payload['stats'];
$alerts = $payload['alerts'];
$filteredTotal = $payload['filtered_total'];
$selectedAlert = $payload['selected_alert'];
$trend = $payload['trend'];
$detection = $payload['detection'];
$severityTotal = array_sum($stats['severity']);

soc_shell_start(soc_t('dashboard_title'), 'overview');
?>
<div id="socDashboard" data-live-dashboard>
    <section class="dashboard-tools">
        <div class="dashboard-tool-right">
            <form class="date-bar" method="get">
                <?= soc_icon('calendar') ?>
                <label>
                    <span><?= soc_e(soc_t('from')) ?></span>
                    <input type="date" name="date_from" value="<?= soc_e($filters['date_from']) ?>">
                </label>
                <label>
                    <span><?= soc_e(soc_t('to')) ?></span>
                    <input type="date" name="date_to" value="<?= soc_e($filters['date_to']) ?>">
                </label>
                <?php soc_hidden_filters($filters, ['date_from', 'date_to', 'q']); ?>
                <?php if ($selectedId > 0): ?><input type="hidden" name="id" value="<?= soc_e($selectedId) ?>"><?php endif; ?>
                <button type="submit"><?= soc_e(soc_t('apply')) ?></button>
                <a href="index.php"><?= soc_e(soc_t('reset')) ?></a>
            </form>
            <div class="refresh-chip">
                <?= soc_icon('activity') ?>
                <span><?= soc_e(soc_t('auto_refresh')) ?></span>
                <strong data-updated-at><?= soc_e($payload['generated_at']) ?></strong>
            </div>
        </div>
    </section>

    <section class="hero-row dashboard-hero">
        <div>
            <h1><?= soc_e(soc_t('dashboard_hello')) ?></h1>
            <p><?= soc_e(soc_t('dashboard_intro')) ?></p>
        </div>
    </section>

    <section class="stats-grid" aria-label="<?= soc_e(soc_t('stats_label')) ?>">
        <article class="stat-card primary">
            <span class="stat-icon"><?= soc_icon('shield') ?></span>
            <div>
                <strong data-stat="total"><?= soc_e($stats['total']) ?></strong>
                <span><?= soc_e(soc_t('total_alerts')) ?></span>
            </div>
        </article>
        <article class="stat-card">
            <span class="stat-icon danger"><?= soc_icon('database') ?></span>
            <div>
                <strong data-stat="sqli"><?= soc_e($stats['sqli']) ?></strong>
                <span><?= soc_e(soc_t('sqli_alerts')) ?></span>
            </div>
        </article>
        <article class="stat-card">
            <span class="stat-icon purple"><?= soc_icon('code') ?></span>
            <div>
                <strong data-stat="xss"><?= soc_e($stats['xss']) ?></strong>
                <span><?= soc_e(soc_t('xss_alerts')) ?></span>
            </div>
        </article>
        <article class="stat-card">
            <span class="stat-icon warning"><?= soc_icon('lock') ?></span>
            <div>
                <strong data-stat="brute_force"><?= soc_e($stats['brute_force']) ?></strong>
                <span><?= soc_e(soc_t('brute_force_alerts')) ?></span>
            </div>
        </article>
        <article class="stat-card score-card">
            <span class="stat-icon danger"><?= soc_icon('activity') ?></span>
            <div>
                <strong class="score-value">
                    <span data-stat="score_global"><?= soc_e($detection['score_global']) ?></span>
                    <em>/</em>
                    <span class="score-level-chip" data-stat="score_level"><?= soc_e($detection['score_level']) ?></span>
                </strong>
                <span><?= soc_e(soc_t('score_global')) ?></span>
            </div>
        </article>
    </section>

    <section class="analytics-grid" aria-label="<?= soc_e(soc_t('analytics_label')) ?>">
        <article class="panel-card trend-card">
            <div class="panel-head">
                <div>
                    <h2><?= soc_e(soc_t('alert_trend')) ?></h2>
                    <p><?= soc_e(soc_t('alerts_detected_per_day')) ?></p>
                </div>
                <span><?= soc_e($filters['date_from']) ?> - <?= soc_e($filters['date_to']) ?></span>
            </div>
            <div class="trend-legend">
                <span><i class="dot total"></i><?= soc_e(soc_t('detected_alerts')) ?></span>
            </div>
            <div class="trend-chart" data-trend-chart><?= soc_render_trend_svg($trend) ?></div>
        </article>

        <article class="panel-card">
            <div class="panel-head">
                <h2><?= soc_e(soc_t('severity_distribution')) ?></h2>
                <span data-severity-total><?= soc_e($severityTotal) ?> <?= soc_e(soc_t('alerts_lower')) ?></span>
            </div>
            <div class="severity-layout">
                <div class="donut" data-donut style="<?= soc_e($payload['donut_style']) ?>">
                    <span data-stat="donut_total"><?= soc_e($stats['total']) ?></span>
                </div>
                <div class="legend-list">
                    <?php foreach (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as $severity): ?>
                        <div>
                            <i class="dot <?= soc_e(strtolower($severity)) ?>"></i>
                            <span><?= soc_e(soc_severity_label($severity)) ?></span>
                            <strong data-severity="<?= soc_e($severity) ?>"><?= soc_e($stats['severity'][$severity]) ?></strong>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </article>

        <article class="panel-card">
            <div class="panel-head">
                <h2><?= soc_e(soc_t('alerts_by_source')) ?></h2>
                <span><?= soc_e(soc_t('top_5')) ?></span>
            </div>
            <div class="source-list" data-sources>
                <?php if (!$stats['sources']): ?>
                    <p class="empty-note"><?= soc_e(soc_t('empty_sources')) ?></p>
                <?php endif; ?>
                <?php foreach ($stats['sources'] as $source): ?>
                    <?php $width = $stats['total'] > 0 ? max(8, ((int)$source['total'] / $stats['total']) * 100) : 0; ?>
                    <div class="source-row">
                        <span><?= soc_e($source['source_ip']) ?></span>
                        <b><?= soc_e($source['total']) ?></b>
                        <i><em style="width: <?= soc_e(round($width, 2)) ?>%;"></em></i>
                    </div>
                <?php endforeach; ?>
            </div>
        </article>
    </section>

    <section class="workspace-grid">
        <article class="table-card" id="alerts">
            <div class="table-head">
                <div>
                    <h2><?= soc_e(soc_t('recent_alerts')) ?></h2>
                    <p><span data-alert-count><?= soc_e($filteredTotal) ?></span> <?= soc_e(soc_t('alerts_found')) ?></p>
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
                    <?php soc_hidden_filters($filters, ['attack', 'severity', 'status', 'q']); ?>
                    <button type="submit"><?= soc_e(soc_t('filter')) ?></button>
                    <a href="index.php"><?= soc_e(soc_t('reset')) ?></a>
                </form>
            </div>

            <div class="table-scroll">
                <table class="alerts-table">
                    <thead>
                        <tr>
                            <th><?= soc_e(soc_t('time')) ?></th>
                            <th><?= soc_e(soc_t('type')) ?></th>
                            <th><?= soc_e(soc_t('severity')) ?></th>
                            <th><?= soc_e(soc_t('source_ip')) ?></th>
                            <th><?= soc_e(soc_t('target_url')) ?></th>
                            <th><?= soc_e(soc_t('status')) ?></th>
                            <th><?= soc_e(soc_t('detail')) ?></th>
                        </tr>
                    </thead>
                    <tbody data-alerts-table>
                    <?php if (!$alerts): ?>
                        <tr>
                            <td colspan="7" class="empty-cell"><?= soc_e(soc_t('empty_alerts')) ?></td>
                        </tr>
                    <?php endif; ?>
                    <?php foreach ($alerts as $alert): ?>
                        <?php $isSelected = $selectedAlert && (int)$selectedAlert['id'] === (int)$alert['id']; ?>
                        <tr class="clickable-row <?= $isSelected ? 'selected' : '' ?>" data-alert-row="<?= soc_e($alert['id']) ?>" data-row-url="<?= soc_e(soc_index_url($filters, ['id' => $alert['id']])) ?>">
                            <td><?= soc_e($alert['timestamp']) ?></td>
                            <td><span class="attack-label <?= soc_e($alert['attack_token']) ?>"><?= soc_e($alert['attack_label']) ?></span></td>
                            <td><span class="pill severity-<?= soc_e(strtolower($alert['severity'])) ?>"><?= soc_e($alert['severity_label']) ?></span></td>
                            <td><?= soc_e($alert['source_ip']) ?></td>
                            <td class="url-cell"><?= soc_e($alert['url']) ?></td>
                            <td><span class="pill status-<?= soc_e($alert['status_token']) ?>"><?= soc_e($alert['status_label']) ?></span></td>
                            <td><a class="mini-link" href="<?= soc_e(soc_index_url($filters, ['id' => $alert['id']])) ?>"><?= soc_e(soc_t('view')) ?></a></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </article>

        <aside class="detail-card" id="mitre" data-detail-card>
            <?php if (!$selectedAlert): ?>
                <div class="panel-head"><h2><?= soc_e(soc_t('detail_title')) ?></h2></div>
                <p class="empty-note"><?= soc_e(soc_t('no_alert_selected')) ?></p>
            <?php else: ?>
                <?php $display = $selectedAlert['display'] ?? soc_alert_display_settings(); ?>
                <div class="panel-head">
                    <h2><?= soc_e(soc_t('detail_title')) ?></h2>
                    <a class="mini-link" href="<?= soc_e($selectedAlert['detail_url']) ?>"><?= soc_e(soc_t('detail_page')) ?></a>
                </div>
                <div class="detail-badges">
                    <span class="pill severity-<?= soc_e(strtolower($selectedAlert['severity'])) ?>"><?= soc_e($selectedAlert['severity_label']) ?></span>
                    <span class="pill status-<?= soc_e($selectedAlert['status_token']) ?>"><?= soc_e($selectedAlert['status_label']) ?></span>
                </div>
                <dl class="detail-list">
                    <div><dt><?= soc_e(soc_t('source_ip')) ?></dt><dd><?= soc_e($selectedAlert['source_ip']) ?></dd></div>
                    <div><dt><?= soc_e(soc_t('target_url')) ?></dt><dd><?= soc_e($selectedAlert['url']) ?></dd></div>
                    <div><dt><?= soc_e(soc_t('payload')) ?></dt><dd><code><?= soc_e($selectedAlert['payload']) ?></code></dd></div>
                    <div><dt><?= soc_e(soc_t('triggered_rule')) ?></dt><dd><?= soc_e($selectedAlert['triggered_rule']) ?></dd></div>
                    <?php if (!empty($display['show_mitre_id'])): ?>
                        <div><dt><?= soc_e(soc_t('mitre_id')) ?></dt><dd><span class="mitre-chip"><?= soc_e($selectedAlert['mitre_id']) ?></span></dd></div>
                    <?php endif; ?>
                    <?php if (!empty($display['show_mitre_tactic'])): ?>
                        <div><dt><?= soc_e(soc_t('tactic')) ?></dt><dd><?= soc_e($selectedAlert['mitre_tactic']) ?></dd></div>
                    <?php endif; ?>
                    <?php if (!empty($display['show_mitre_technique'])): ?>
                        <div><dt><?= soc_e(soc_t('technique')) ?></dt><dd><?= soc_e($selectedAlert['mitre_technique']) ?></dd></div>
                    <?php endif; ?>
                    <?php if (!empty($display['show_recommended_response'])): ?>
                        <div><dt><?= soc_e(soc_t('recommended_response')) ?></dt><dd><?= soc_e($selectedAlert['recommended_response']) ?></dd></div>
                    <?php endif; ?>
                </dl>
                <form class="status-form" method="post">
                    <?php soc_csrf_field(); ?>
                    <input type="hidden" name="action" value="update_status">
                    <input type="hidden" name="id" value="<?= soc_e($selectedAlert['id']) ?>">
                    <label for="status"><?= soc_e(soc_t('status')) ?></label>
                    <div>
                        <select id="status" name="status">
                            <?php foreach (SOC_STATUSES as $value => $label): ?>
                                <?php if ($value === 'all') continue; ?>
                                <option value="<?= soc_e($value) ?>" <?= $selectedAlert['status'] === $value ? 'selected' : '' ?>><?= soc_e(soc_status_label($value)) ?></option>
                            <?php endforeach; ?>
                        </select>
                        <button type="submit"><?= soc_e(soc_t('update')) ?></button>
                    </div>
                </form>
            <?php endif; ?>
        </aside>
    </section>
</div>
<?php soc_shell_end(); ?>
