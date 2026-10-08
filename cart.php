<?php
$pageTitle = 'Panier';
require_once __DIR__ . '/includes/header.php';

if (!isset($_SESSION['cart'])) {
    $_SESSION['cart'] = [];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $id = (int)($_POST['id'] ?? 0);
    $qty = max(1, (int)($_POST['qty'] ?? 1));

    if ($action === 'add' && $id > 0) {
        $_SESSION['cart'][$id] = ($_SESSION['cart'][$id] ?? 0) + $qty;
        set_flash('cart', 'Produit ajouté au panier.');
    }
    if ($action === 'update' && $id > 0) {
        $_SESSION['cart'][$id] = $qty;
        set_flash('cart', 'Panier mis à jour.');
    }
    if ($action === 'remove' && $id > 0) {
        unset($_SESSION['cart'][$id]);
        set_flash('cart', 'Produit retiré du panier.');
    }

    header('Location: cart.php');
    exit;
}

$ids = array_keys($_SESSION['cart']);
$products = [];
$total = 0.0;

if ($ids) {
    $idList = implode(',', array_map('intval', $ids));
    $products = db_all("SELECT id, name, price, image FROM products WHERE id IN ($idList)");
}
?>
<section class="page-title">
    <div class="container">
        <h1>Panier</h1>
        <p>Vérifiez vos produits avant commande.</p>
    </div>
</section>
<section class="section">
    <div class="container grid-3">
        <div class="panel" style="grid-column: span 2;">
            <?php if ($msg = flash('cart')): ?><div class="alert alert-ok"><?= e($msg) ?></div><?php endif; ?>
            <?php if (!$products): ?>
                <p>Votre panier est vide.</p>
                <a class="btn" href="search.php">Voir le catalogue</a>
            <?php else: ?>
                <table class="cart-table">
                    <thead><tr><th>Produit</th><th>Prix</th><th>Qté</th><th>Total</th><th></th></tr></thead>
                    <tbody>
                    <?php foreach ($products as $product): ?>
                        <?php
                        $qty = $_SESSION['cart'][$product['id']] ?? 1;
                        $line = $qty * (float)$product['price'];
                        $total += $line;
                        ?>
                        <tr>
                            <td>
                                <div class="cart-product">
                                    <img src="<?= e($product['image']) ?>" alt="<?= e($product['name']) ?>">
                                    <a href="product.php?id=<?= e($product['id']) ?>"><?= e($product['name']) ?></a>
                                </div>
                            </td>
                            <td><?= money($product['price']) ?></td>
                            <td>
                                <form method="post" style="display:flex; gap:8px; align-items:center;">
                                    <input type="hidden" name="action" value="update">
                                    <input type="hidden" name="id" value="<?= e($product['id']) ?>">
                                    <input data-qty style="width:76px" type="number" name="qty" value="<?= e($qty) ?>" min="1">
                                    <button class="btn btn-small btn-secondary" type="submit">OK</button>
                                </form>
                            </td>
                            <td><?= money($line) ?></td>
                            <td>
                                <form method="post">
                                    <input type="hidden" name="action" value="remove">
                                    <input type="hidden" name="id" value="<?= e($product['id']) ?>">
                                    <button class="btn btn-small btn-danger" type="submit">Retirer</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
        <div class="panel summary">
            <h2>Résumé</h2>
            <div class="summary-row"><span>Sous-total</span><strong><?= money($total) ?></strong></div>
            <div class="summary-row"><span>Livraison</span><strong><?= $total > 0 ? money(25) : money(0) ?></strong></div>
            <div class="summary-row summary-total"><span>Total</span><strong><?= money($total > 0 ? $total + 25 : 0) ?></strong></div>
            <?php if ($products): ?><a class="btn" href="checkout.php">Commander</a><?php endif; ?>
        </div>
    </div>
</section>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
