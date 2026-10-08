<?php
require_once __DIR__ . '/helpers.php';
$pageTitle = $pageTitle ?? APP_NAME;
$user = current_user();
?>
<!doctype html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= e($pageTitle) ?> — <?= e(APP_NAME) ?></title>
    <link rel="stylesheet" href="<?= e(asset('css/style.css')) ?>">
</head>
<body>
<header class="topbar">
    <div class="container topbar-inner">
        <a class="brand" href="index.php">
            <span class="brand-mark">AM</span>
            <span>
                <strong><?= e(APP_NAME) ?></strong>
                <small>Mini shop local</small>
            </span>
        </a>
        <form class="top-search" action="search.php" method="get">
            <input type="search" name="q" placeholder="Rechercher un produit" value="<?= isset($_GET['q']) ? e($_GET['q']) : '' ?>">
            <button type="submit">Rechercher</button>
        </form>
        <nav class="nav">
            <a href="index.php">Accueil</a>
            <a href="search.php">Catalogue</a>
            <a href="track_order.php">Suivi</a>
            <a href="cart.php">Panier <span class="pill"><?= cart_count() ?></span></a>
            <?php if ($user): ?>
                <a href="account.php">Compte</a>
                <?php if (is_admin()): ?><a href="admin.php">Admin</a><?php endif; ?>
                <a href="logout.php">Sortir</a>
            <?php else: ?>
                <a href="login.php">Connexion</a>
            <?php endif; ?>
        </nav>
    </div>
</header>
<main>
