<?php
require_once __DIR__ . '/bootstrap.php';

soc_require_admin();

$mitreMap = soc_mitre_map();
$isEn = soc_current_language() === 'en';
$display = soc_alert_display_settings();
$projectNotes = [
    'SQLi' => [
        'label' => 'SQL Injection',
        'surface' => 'search.php, login.php, product.php, track_order.php',
        'usage' => $isEn
            ? 'Mini-SIEM inspects GET/POST parameters and suspicious User-Agent values to detect SQL keywords, UNION SELECT, SQL comments, boolean payloads and time-based payloads.'
            : 'Le Mini-SIEM inspecte les paramètres GET/POST et les User-Agent suspects pour détecter les mots clés SQL, UNION SELECT, commentaires SQL, payloads booléens et time-based.',
    ],
    'XSS' => [
        'label' => 'Cross-Site Scripting',
        'surface' => 'review.php, search.php, track_order.php',
        'usage' => $isEn
            ? 'The engine looks for script tags, JavaScript handlers, javascript:, SVG/IMG onload/onerror and encoded payloads in user fields.'
            : 'Le moteur recherche les balises script, handlers JavaScript, javascript:, SVG/IMG onload/onerror et payloads encodés dans les champs utilisateur.',
    ],
    'BruteForce' => [
        'label' => 'Brute Force',
        'surface' => 'login.php',
        'usage' => $isEn
            ? 'The engine counts failed login attempts per IP in a short window and enriches the alert with the MITRE Credential Access technique.'
            : 'Le moteur compte les échecs de connexion par IP dans une fenêtre courte et enrichit l’alerte avec la technique MITRE Credential Access.',
    ],
];
$readSteps = $isEn ? [
    ['1. Attack type', 'SQLi, XSS or Brute Force indicates the family detected by Mini-SIEM rules.'],
    ['2. MITRE ID', 'The identifier links the alert to a clear ATT&CK technique for the SOC demonstration.'],
    ['3. Response', 'The recommended response gives the quick action to present: block IP, review logs or fix vulnerable input.'],
] : [
    ['1. Type attaque', 'SQLi, XSS ou Brute Force indique la famille détectée par les règles Mini-SIEM.'],
    ['2. MITRE ID', 'L’identifiant relie l’alerte à une technique ATT&CK claire pour la démonstration SOC.'],
    ['3. Réponse', 'La réponse recommandée donne l’action rapide à présenter: bloquer IP, analyser logs ou corriger l’entrée vulnérable.'],
];

soc_shell_start(soc_t('mitre_title'), 'mitre');
?>
<section class="hero-row compact">
    <div>
        <h1><?= soc_e(soc_t('mitre_h1')) ?></h1>
        <p><?= soc_e(soc_t('mitre_intro')) ?></p>
    </div>
</section>

<section class="mitre-grid">
    <?php foreach ($projectNotes as $key => $note): ?>
        <?php $info = $mitreMap[$key] ?? []; ?>
        <article class="panel-card mitre-card">
            <div class="panel-head">
                <div>
                    <h2><?= soc_e($note['label']) ?></h2>
                    <p><?= soc_e($note['surface']) ?></p>
                </div>
                <?php if (!empty($display['show_mitre_id'])): ?>
                    <span class="mitre-chip"><?= soc_e($info['mitre_id'] ?? '-') ?></span>
                <?php endif; ?>
            </div>
            <dl class="detail-list columns">
                <?php if (!empty($display['show_mitre_tactic'])): ?>
                    <div><dt><?= soc_e(soc_t('tactic')) ?></dt><dd><?= soc_e($info['tactic'] ?? '-') ?></dd></div>
                <?php endif; ?>
                <?php if (!empty($display['show_mitre_technique'])): ?>
                    <div><dt><?= soc_e(soc_t('technique')) ?></dt><dd><?= soc_e($info['technique'] ?? '-') ?></dd></div>
                <?php endif; ?>
                <div><dt><?= soc_e(soc_t('default_severity')) ?></dt><dd><span class="pill severity-<?= soc_e(strtolower($info['severity'] ?? '')) ?>"><?= soc_e(soc_severity_label($info['severity'] ?? '')) ?></span></dd></div>
                <div><dt><?= soc_e(soc_t('project_surface')) ?></dt><dd><?= soc_e($note['surface']) ?></dd></div>
                <div class="full"><dt><?= soc_e(soc_t('mini_siem_usage')) ?></dt><dd><?= soc_e($note['usage']) ?></dd></div>
                <?php if (!empty($display['show_recommended_response'])): ?>
                    <div class="full"><dt><?= soc_e(soc_t('recommended_response')) ?></dt><dd><?= soc_e(soc_recommended_response_from_mapping($info)) ?></dd></div>
                <?php endif; ?>
            </dl>
        </article>
    <?php endforeach; ?>
</section>

<section class="guide-strip">
    <article class="panel-card">
        <div class="panel-head">
            <h2><?= soc_e(soc_t('read_mitre_alert')) ?></h2>
            <?= soc_icon('crosshair') ?>
        </div>
        <div class="steps-grid">
            <?php foreach ($readSteps as $step): ?>
                <div><strong><?= soc_e($step[0]) ?></strong><p><?= soc_e($step[1]) ?></p></div>
            <?php endforeach; ?>
        </div>
    </article>
</section>
<?php soc_shell_end(); ?>
