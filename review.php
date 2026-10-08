<?php
require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/includes/logger.php';
log_http_request();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.php');
    exit;
}

$productId = $_POST['product_id'] ?? '1';
$author = $_POST['author_name'] ?? 'Client';
$rating = $_POST['rating'] ?? '5';
$comment = $_POST['comment'] ?? '';

/* Vulnérabilité volontaire : INSERT construit par concaténation directe. */
$sql = "INSERT INTO reviews (product_id, author_name, rating, comment, created_at)
        VALUES ($productId, '$author', $rating, '$comment', NOW())";

$result = db_query($sql);

if ($result) {
    header('Location: product.php?id=' . $productId . '#reviews');
    exit;
}

$pageTitle = 'Erreur avis';
require_once __DIR__ . '/includes/header.php';
?>
<section class="section">
    <div class="container panel">
        <h1>Impossible d’enregistrer l’avis</h1>
        <p>Une erreur SQL s’est produite.</p>
        <a class="btn" href="product.php?id=<?= e($productId) ?>">Retour produit</a>
    </div>
</section>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
