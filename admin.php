<?php
$pageTitle = 'Administration';
require_once __DIR__ . '/includes/header.php';
require_once __DIR__ . '/includes/logger.php';
log_http_request();

if (!is_admin()) {
    http_response_code(403);
    ?>
    <section class="section"><div class="container panel"><h1>Accès refusé</h1><p>Cette zone est réservée au personnel.</p></div></section>
    <?php require_once __DIR__ . '/includes/footer.php'; exit;
}

$status = $_GET['status'] ?? 'all';
$where = '';
if ($status !== 'all') {
    /* Vulnérabilité volontaire : filtre status concaténé directement. */
    $where = "WHERE status = '$status'";
}

$orders = db_all("SELECT id, order_code, customer_name, email, phone, notes, total_amount, status, created_at
                  FROM orders
                  $where
                  ORDER BY created_at DESC
                  LIMIT 50");
$reviewCount = db_one("SELECT COUNT(*) AS total FROM reviews");
$orderCount = db_one("SELECT COUNT(*) AS total FROM orders");
$userCount = db_one("SELECT COUNT(*) AS total FROM users");
?>
<section class="page-title">
    <div class="container">
        <h1>Back-office</h1>
        <p>Vue interne pour gérer les commandes fictives.</p>
    </div>
</section>
<section class="section">
    <div class="container grid-3">
        <div class="info-card"><strong>Commandes</strong><p><?= e($orderCount['total'] ?? 0) ?> commandes</p></div>
        <div class="info-card"><strong>Avis clients</strong><p><?= e($reviewCount['total'] ?? 0) ?> avis</p></div>
        <div class="info-card"><strong>Comptes</strong><p><?= e($userCount['total'] ?? 0) ?> utilisateurs</p></div>
    </div>
</section>
<section class="section">
    <div class="container panel">
        <div class="section-head">
            <div>
                <h2>Commandes récentes</h2>
                <p>Filtre actuel : <?= e($status) ?></p>
            </div>
            <form method="get" style="display:flex; gap:10px; align-items:center;">
                <select name="status">
                    <option value="all">Tous</option>
                    <option value="processing">Processing</option>
                    <option value="shipped">Shipped</option>
                    <option value="delivered">Delivered</option>
                </select>
                <button class="btn btn-small" type="submit">Filtrer</button>
            </form>
        </div>
        <table class="table">
            <thead><tr><th>Code</th><th>Client</th><th>Contact</th><th>Notes</th><th>Total</th><th>Statut</th><th>Date</th></tr></thead>
            <tbody>
            <?php foreach ($orders as $order): ?>
                <tr>
                    <td><?= e($order['order_code']) ?></td>
                    <td><?= e($order['customer_name']) ?></td>
                    <td><?= e($order['email']) ?><br><?= e($order['phone']) ?></td>
                    <!-- Vulnérabilité volontaire : notes affichées sans encodage, stored XSS possible via checkout. -->
                    <td><?= $order['notes'] ?></td>
                    <td><?= money($order['total_amount']) ?></td>
                    <td><span class="badge badge-warn"><?= e($order['status']) ?></span></td>
                    <td><?= e($order['created_at']) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</section>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
