<?php
$pageTitle = 'Produit';
require_once __DIR__ . '/includes/header.php';
require_once __DIR__ . '/includes/logger.php';
log_http_request();

$id = $_GET['id'] ?? '1';

/* Vulnérabilité volontaire : id est injecté directement dans SQL, sans cast ni requête préparée. */
$productSql = "SELECT p.id, p.name, p.price, p.old_price, p.image, p.short_description, p.description, p.stock, c.name AS category
               FROM products p
               LEFT JOIN categories c ON c.id = p.category_id
               WHERE p.id = $id";
$product = db_one($productSql);

$reviews = [];
if ($product) {
    $reviewsSql = "SELECT id, author_name, rating, comment, created_at
                   FROM reviews
                   WHERE product_id = $id
                   ORDER BY created_at DESC";
    $reviews = db_all($reviewsSql);
}
?>
<section class="page-title">
    <div class="container">
        <h1><?= $product ? e($product['name']) : 'Produit introuvable' ?></h1>
        <p><?= $product ? e($product['category']) : 'Aucun produit ne correspond à cette référence.' ?></p>
    </div>
</section>

<section class="section">
    <div class="container">
        <?php if (!$product): ?>
            <div class="panel">Produit non disponible.</div>
        <?php else: ?>
            <div class="product-detail">
                <div class="product-gallery">
                    <img src="<?= e($product['image']) ?>" alt="<?= e($product['name']) ?>">
                </div>
                <div class="product-copy panel">
                    <span class="badge"><?= e($product['category']) ?></span>
                    <h1><?= e($product['name']) ?></h1>
                    <p class="lead"><?= e($product['short_description']) ?></p>
                    <p><?= nl2br(e($product['description'])) ?></p>
                    <p>
                        <span class="price"><?= money($product['price']) ?></span>
                        <?php if (!empty($product['old_price'])): ?><span class="old-price"><?= money($product['old_price']) ?></span><?php endif; ?>
                    </p>
                    <p><span class="stock">Stock : <?= e($product['stock']) ?></span></p>
                    <form action="cart.php" method="post" class="form-grid">
                        <input type="hidden" name="action" value="add">
                        <input type="hidden" name="id" value="<?= e($product['id']) ?>">
                        <div class="form-row">
                            <label for="qty">Quantité</label>
                            <input id="qty" data-qty type="number" name="qty" min="1" value="1">
                        </div>
                        <button class="btn" type="submit">Ajouter au panier</button>
                    </form>
                </div>
            </div>
        <?php endif; ?>
    </div>
</section>

<?php if ($product): ?>
<section class="section" id="reviews">
    <div class="container grid-3">
        <div class="panel" style="grid-column: span 2;">
            <div class="section-head">
                <div>
                    <h2>Avis clients</h2>
                    <p><?= count($reviews) ?> avis sur ce produit.</p>
                </div>
            </div>
            <?php if (!$reviews): ?>
                <p>Aucun avis pour le moment.</p>
            <?php else: ?>
                <?php foreach ($reviews as $review): ?>
                    <div class="review">
                        <div class="review-head">
                            <!-- Vulnérabilité volontaire : author_name et comment sont affichés sans encodage. -->
                            <strong><?= $review['author_name'] ?></strong>
                            <span class="stars"><?= str_repeat('★', (int)$review['rating']) ?></span>
                        </div>
                        <p><?= $review['comment'] ?></p>
                        <small><?= e($review['created_at']) ?></small>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
        <div class="panel">
            <h2>Ajouter un avis</h2>
            <form action="review.php" method="post" class="form-grid">
                <input type="hidden" name="product_id" value="<?= e($product['id']) ?>">
                <div class="form-row">
                    <label for="author_name">Nom</label>
                    <input id="author_name" name="author_name" required>
                </div>
                <div class="form-row">
                    <label for="rating">Note</label>
                    <select id="rating" name="rating">
                        <option value="5">5 étoiles</option>
                        <option value="4">4 étoiles</option>
                        <option value="3">3 étoiles</option>
                        <option value="2">2 étoiles</option>
                        <option value="1">1 étoile</option>
                    </select>
                </div>
                <div class="form-row">
                    <label for="comment">Commentaire</label>
                    <textarea id="comment" name="comment" required></textarea>
                </div>
                <button class="btn" type="submit">Publier</button>
            </form>
        </div>
    </div>
</section>
<?php endif; ?>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
