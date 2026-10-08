<?php
$pageTitle = 'Mon compte';
require_once __DIR__ . '/includes/header.php';
require_login();
$user = current_user();

$orders = db_all("SELECT id, order_code, total_amount, status, created_at
                  FROM orders
                  WHERE user_id = " . $user['id'] . "
                  ORDER BY created_at DESC");
?>
<section class="page-title">
    <div class="container">
        <h1>Mon compte</h1>
        <p>Bonjour <?= e($user['full_name']) ?>.</p>
    </div>
</section>
<section class="section">
    <div class="container grid-3">
        <div class="panel">
            <h2>Profil</h2>
            <p><strong>Utilisateur :</strong> <?= e($user['username']) ?></p>
            <p><strong>Email :</strong> <?= e($user['email']) ?></p>
            <p><strong>Rôle :</strong> <span class="badge"><?= e($user['role']) ?></span></p>
        </div>
        <div class="panel" style="grid-column: span 2;">
            <h2>Mes commandes</h2>
            <?php if (!$orders): ?>
                <p>Aucune commande enregistrée.</p>
            <?php else: ?>
                <table class="table">
                    <thead><tr><th>Code</th><th>Total</th><th>Statut</th><th>Date</th></tr></thead>
                    <tbody>
                    <?php foreach ($orders as $order): ?>
                        <tr>
                            <td><a href="track_order.php?code=<?= e($order['order_code']) ?>"><?= e($order['order_code']) ?></a></td>
                            <td><?= money($order['total_amount']) ?></td>
                            <td><span class="badge badge-ok"><?= e($order['status']) ?></span></td>
                            <td><?= e($order['created_at']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>
</section>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
