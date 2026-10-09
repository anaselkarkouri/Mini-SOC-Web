<?php
$pageTitle = 'Catalogue';
require_once __DIR__ . '/includes/header.php';
require_once __DIR__ . '/includes/logger.php';
log_http_request();

$q = is_string($_GET['q'] ?? '') ? ($_GET['q'] ?? '') : '';

if ($q !== '') {
    /* Vulnérabilité volontaire : concaténation directe de q dans SQL. */
    $sql = "SELECT p.id, p.name, p.price, p.image, p.short_description, c.name AS category
            FROM products p
            LEFT JOIN categories c ON c.id = p.category_id
            WHERE p.name LIKE '%$q%'
               OR p.description LIKE '%$q%'
               OR c.name LIKE '%$q%'
            ORDER BY p.created_at DESC";
} else {
    $sql = "SELECT p.id, p.name, p.price, p.image, p.short_description, c.name AS category
            FROM products p
            LEFT JOIN categories c ON c.id = p.category_id
            ORDER BY p.created_at DESC";
}

if (MINISOC_HARDENED && $q !== '') {
    $products = db_prepared_rows("SELECT p.id,p.name,p.price,p.image,p.short_description,c.name AS category
        FROM products p LEFT JOIN categories c ON c.id=p.category_id
        WHERE p.name LIKE ? OR p.description LIKE ? OR c.name LIKE ? ORDER BY p.created_at DESC",
        'sss', ['%'.$q.'%', '%'.$q.'%', '%'.$q.'%']);
} else {
    $products = db_all($sql);
}
?>
<section class="page-title">
    <div class="container">
        <h1>Catalogue</h1>
        <?php if ($q !== ''): ?>
            <!-- Vulnérabilité volontaire : reflected XSS, q est affiché sans encodage. -->
            <p>Résultats pour : <strong><?= MINISOC_HARDENED ? e($q) : $q ?></strong></p>
        <?php else: ?>
            <p>Tous les produits disponibles dans la boutique.</p>
        <?php endif; ?>
    </div>
</section>

<section class="section">
    <div class="container">
        <?php if ($q !== ''): ?>
            <div class="alert alert-warn">Recherche active : <?= MINISOC_HARDENED ? e($q) : $q ?></div>
        <?php endif; ?>
        <?php if (count($products) === 0): ?>
            <div class="panel">Aucun produit trouvé.</div>
        <?php else: ?>
            <div class="grid">
                <?php foreach ($products as $product): ?>
                    <?php product_card($product); ?>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</section>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
