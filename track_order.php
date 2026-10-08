<?php
$pageTitle = 'Suivi commande';
require_once __DIR__ . '/includes/header.php';
require_once __DIR__ . '/includes/logger.php';
log_http_request();

$code = $_GET['code'] ?? ($_POST['code'] ?? '');
$order = null;
$items = [];

if ($code !== '') {
    /* Vulnérabilité volontaire : SQLi sur code de commande. */
    $sql = "SELECT id, order_code, customer_name, email, phone, address, notes, total_amount, status, created_at
            FROM orders
            WHERE order_code = '$code'
            LIMIT 1";
    $order = db_one($sql);
    if ($order) {
        $items = db_all("SELECT oi.quantity, oi.unit_price, p.name
                         FROM order_items oi
                         LEFT JOIN products p ON p.id = oi.product_id
                         WHERE oi.order_id = " . $order['id']);
    }
}
?>
<section class="page-title">
    <div class="container">
        <h1>Suivi de commande</h1>
        <p>Entrez votre code de commande pour afficher son état.</p>
    </div>
</section>
<section class="section">
    <div class="container grid-3">
        <div class="panel">
            <form method="get" class="form-grid">
                <div class="form-row">
                    <label for="code">Code de commande</label>
                    <input id="code" name="code" value="<?= e($code) ?>" placeholder="AMS-20250101-1234">
                </div>
                <button class="btn" type="submit">Rechercher</button>
            </form>
        </div>
        <div class="panel" style="grid-column: span 2;">
            <?php if ($code === ''): ?>
                <p>Aucune recherche lancée.</p>
            <?php elseif (!$order): ?>
                <div class="alert alert-error">Aucune commande trouvée pour ce code.</div>
            <?php else: ?>
                <h2>Commande <?= e($order['order_code']) ?></h2>
                <p><span class="badge badge-ok"><?= e($order['status']) ?></span> · <?= e($order['created_at']) ?></p>
                <table class="table">
                    <thead><tr><th>Produit</th><th>Qté</th><th>Prix</th></tr></thead>
                    <tbody>
                    <?php foreach ($items as $item): ?>
                        <tr><td><?= e($item['name']) ?></td><td><?= e($item['quantity']) ?></td><td><?= money($item['unit_price']) ?></td></tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <p><strong>Total :</strong> <?= money($order['total_amount']) ?></p>
                <p><strong>Adresse :</strong><br><?= nl2br(e($order['address'])) ?></p>
                <!-- Notes affichées brutes dans le back-office ; ici elles restent encodées pour garder le suivi lisible. -->
            <?php endif; ?>
        </div>
    </div>
</section>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
