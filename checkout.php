<?php
$pageTitle = 'Commande';
require_once __DIR__ . '/includes/header.php';
require_once __DIR__ . '/includes/logger.php';
log_http_request();

if (empty($_SESSION['cart'])) {
    header('Location: cart.php');
    exit;
}

$ids = array_keys($_SESSION['cart']);
$idList = implode(',', array_map('intval', $ids));
$products = db_all("SELECT id, name, price FROM products WHERE id IN ($idList)");
$total = 25.0;
foreach ($products as $product) {
    $total += (float)$product['price'] * (int)($_SESSION['cart'][$product['id']] ?? 1);
}

$orderCode = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $customerName = $_POST['customer_name'] ?? '';
    $email = $_POST['email'] ?? '';
    $phone = $_POST['phone'] ?? '';
    $address = $_POST['address'] ?? '';
    $notes = $_POST['notes'] ?? '';
    $userId = is_logged_in() ? (int)current_user()['id'] : 'NULL';
    $orderCode = 'AMS-' . date('Ymd') . '-' . random_int(1000, 9999);

    /* Vulnérabilité volontaire : données de commande insérées sans préparation ni échappement. */
    $sql = "INSERT INTO orders (order_code, user_id, customer_name, email, phone, address, notes, total_amount, status, created_at)
            VALUES ('$orderCode', $userId, '$customerName', '$email', '$phone', '$address', '$notes', $total, 'processing', NOW())";

    $ok = db_query($sql);
    if ($ok) {
        $orderId = mysqli_insert_id($conn);
        foreach ($products as $product) {
            $qty = (int)($_SESSION['cart'][$product['id']] ?? 1);
            $pid = (int)$product['id'];
            $price = (float)$product['price'];
            db_query("INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES ($orderId, $pid, $qty, $price)");
        }
        $_SESSION['cart'] = [];
    } else {
        $error = 'Erreur lors de la création de la commande.';
    }
}
?>
<section class="page-title">
    <div class="container">
        <h1>Finaliser la commande</h1>
        <p>Commande fictive, aucun paiement réel.</p>
    </div>
</section>
<section class="section">
    <div class="container grid-3">
        <div class="panel" style="grid-column: span 2;">
            <?php if ($orderCode && !$error): ?>
                <div class="alert alert-ok">
                    Commande créée. Code de suivi : <strong><?= e($orderCode) ?></strong>
                </div>
                <a class="btn" href="track_order.php?code=<?= e($orderCode) ?>">Suivre la commande</a>
            <?php else: ?>
                <?php if ($error): ?><div class="alert alert-error"><?= e($error) ?></div><?php endif; ?>
                <form method="post" class="form-grid">
                    <div class="form-row"><label>Nom complet</label><input name="customer_name" required></div>
                    <div class="form-row"><label>Email</label><input type="email" name="email" required></div>
                    <div class="form-row"><label>Téléphone</label><input name="phone" required></div>
                    <div class="form-row"><label>Adresse</label><textarea name="address" required></textarea></div>
                    <div class="form-row"><label>Notes de livraison</label><textarea name="notes"></textarea></div>
                    <button class="btn" type="submit">Valider la commande</button>
                </form>
            <?php endif; ?>
        </div>
        <div class="panel summary">
            <h2>Résumé</h2>
            <?php foreach ($products as $product): ?>
                <div class="summary-row">
                    <span><?= e($product['name']) ?> × <?= e($_SESSION['cart'][$product['id']] ?? 1) ?></span>
                    <strong><?= money((float)$product['price'] * (int)($_SESSION['cart'][$product['id']] ?? 1)) ?></strong>
                </div>
            <?php endforeach; ?>
            <div class="summary-row"><span>Livraison</span><strong><?= money(25) ?></strong></div>
            <div class="summary-row summary-total"><span>Total</span><strong><?= money($total) ?></strong></div>
        </div>
    </div>
</section>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
