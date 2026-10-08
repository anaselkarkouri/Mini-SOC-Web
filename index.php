<?php
$pageTitle = 'Accueil';
require_once __DIR__ . '/includes/header.php';

$featured = db_all("SELECT p.id, p.name, p.price, p.image, p.short_description, c.name AS category
                    FROM products p
                    LEFT JOIN categories c ON c.id = p.category_id
                    WHERE p.featured = 1
                    ORDER BY p.created_at DESC
                    LIMIT 8");
$categories = db_all("SELECT id, name, description FROM categories ORDER BY name ASC");
?>
<section class="hero">
    <div class="container hero-grid">
        <div class="hero-card">
            <div class="eyebrow">Livraison locale · Produits fictifs</div>
            <h1>Votre shop tech local pour la maison, le bureau et le quotidien.</h1>
            <p class="lead">Explorez un catalogue de démonstration avec produits, avis clients, panier et suivi de commande. L’interface est volontairement réaliste pour servir de cible M1.</p>
            <div class="hero-actions">
                <a class="btn" href="search.php">Voir le catalogue</a>
                <a class="btn btn-secondary" href="track_order.php">Suivre une commande</a>
            </div>
        </div>
        <div class="hero-side">
            <div class="promo-box">
                Offre du jour
                <span data-promo-message>-20% sur les accessoires connectés</span>
            </div>
            <div class="info-card">
                <strong>Panier rapide</strong>
                <p>Ajoutez des articles et validez une commande fictive avec un code de suivi local.</p>
            </div>
            <div class="info-card">
                <strong>Avis clients</strong>
                <p>Chaque produit dispose d’un espace d’avis pour simuler les interactions utilisateurs.</p>
            </div>
        </div>
    </div>
</section>

<section class="section">
    <div class="container">
        <div class="section-head">
            <div>
                <h2>Catégories</h2>
                <p>Parcourez les univers du catalogue.</p>
            </div>
        </div>
        <div class="grid-3">
            <?php foreach ($categories as $category): ?>
                <a class="info-card" href="search.php?q=<?= e(urlencode($category['name'])) ?>">
                    <strong><?= e($category['name']) ?></strong>
                    <p><?= e($category['description']) ?></p>
                </a>
            <?php endforeach; ?>
        </div>
    </div>
</section>

<section class="section">
    <div class="container">
        <div class="section-head">
            <div>
                <h2>Produits en vedette</h2>
                <p>Une sélection de produits fictifs pour la démonstration.</p>
            </div>
            <a class="btn btn-secondary" href="search.php">Tout voir</a>
        </div>
        <div class="grid">
            <?php foreach ($featured as $product): ?>
                <?php product_card($product); ?>
            <?php endforeach; ?>
        </div>
    </div>
</section>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
