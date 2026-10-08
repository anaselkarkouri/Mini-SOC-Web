<?php
require_once __DIR__ . '/bootstrap.php';

soc_require_admin();

$isEn = soc_current_language() === 'en';
$sections = $isEn ? [
    [
        'title' => soc_t('guide_prepare'),
        'icon' => 'database',
        'items' => [
            'Import `database/schema.sql` into the `minisoc_shop` database.',
            'Sign in to SOC with `admin` and the configured SOC password.',
            'Open `soc/index.php` from the local XAMPP/WAMP server.',
        ],
    ],
    [
        'title' => soc_t('guide_detect'),
        'icon' => 'activity',
        'items' => [
            'Open the dashboard: `api.php` automatically launches `mini_siem.py` in the background if the engine is not already active.',
            'Generate SQLi, XSS requests or failed login attempts.',
            'The engine reads `http_logs`, creates rows in `alerts`, then the dashboard updates through `api.php`.',
        ],
    ],
    [
        'title' => soc_t('guide_read'),
        'icon' => 'grid',
        'items' => [
            'Use the top search to filter by IP, URL, payload or MITRE ID.',
            'Change the period with the date bar.',
            'Read the cards, Alert Trend, severity distribution and source IP chart.',
            'Click a recent row to show its details without changing the read state.',
            'Open `Alerts` in the sidebar to view the full history without details and mark alerts as read.',
        ],
    ],
    [
        'title' => soc_t('guide_document'),
        'icon' => 'file',
        'items' => [
            'Change status: New, In progress, Resolved or False positive.',
            'Open MITRE to explain the techniques used by the project.',
            'Generate a PDF from `Reports` for the demonstration.',
            'Change dark mode, language and auto-refresh from `Settings`.',
        ],
    ],
] : [
    [
        'title' => soc_t('guide_prepare'),
        'icon' => 'database',
        'items' => [
            'Importer `database/schema.sql` dans la base `minisoc_shop`.',
            'Se connecter au SOC avec `admin` et le mot de passe SOC configuré.',
            'Ouvrir `soc/index.php` depuis le serveur local XAMPP/WAMP.',
        ],
    ],
    [
        'title' => soc_t('guide_detect'),
        'icon' => 'activity',
        'items' => [
            "Ouvrir le dashboard: `api.php` lance automatiquement `mini_siem.py` en arrière-plan si le moteur n'est pas déjà actif.",
            'Générer des requêtes SQLi, XSS ou des échecs de login.',
            'Le moteur lit `http_logs`, crée les lignes dans `alerts`, puis le dashboard se met à jour via `api.php`.',
        ],
    ],
    [
        'title' => soc_t('guide_read'),
        'icon' => 'grid',
        'items' => [
            'Utiliser la recherche en haut pour filtrer par IP, URL, payload ou MITRE ID.',
            'Changer la période avec la barre de dates.',
            'Observer les cartes, la Tendance des alertes, la distribution de gravité et les sources IP.',
            'Cliquer une ligne récente pour afficher son détail sans changer son état de lecture.',
            "Ouvrir `Alertes` dans la barre latérale pour voir tout l'historique sans détail et marquer les alertes comme lues.",
        ],
    ],
    [
        'title' => soc_t('guide_document'),
        'icon' => 'file',
        'items' => [
            'Changer le statut: nouveau, en cours, résolu ou faux positif.',
            'Consulter MITRE pour expliquer les techniques utilisées dans le projet.',
            'Générer un PDF depuis `Rapports` pour la démonstration.',
            'Modifier le mode sombre, la langue et l’auto-refresh depuis `Paramètres`.',
        ],
    ],
];

soc_shell_start(soc_t('guide_title'), 'guide');
?>
<section class="hero-row compact">
    <div>
        <h1><?= soc_e(soc_t('guide_h1')) ?></h1>
        <p><?= soc_e(soc_t('guide_intro')) ?></p>
    </div>
</section>

<section class="guide-grid">
    <?php foreach ($sections as $section): ?>
        <article class="panel-card">
            <div class="panel-head">
                <h2><?= soc_e($section['title']) ?></h2>
                <?= soc_icon($section['icon']) ?>
            </div>
            <ol class="guide-list">
                <?php foreach ($section['items'] as $item): ?>
                    <li><?= soc_e($item) ?></li>
                <?php endforeach; ?>
            </ol>
        </article>
    <?php endforeach; ?>
</section>
<?php soc_shell_end(); ?>
