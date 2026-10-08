<?php
require_once __DIR__ . '/../config/db.php';

function e($value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function asset(string $path): string
{
    return 'assets/' . ltrim($path, '/');
}

function money($value): string
{
    return number_format((float)$value, 2, ',', ' ') . ' MAD';
}

function current_user(): ?array
{
    return $_SESSION['user'] ?? null;
}

function is_logged_in(): bool
{
    return current_user() !== null;
}

function is_admin(): bool
{
    $user = current_user();
    return $user && in_array($user['role'], ['admin', 'manager'], true);
}

function require_login(): void
{
    if (!is_logged_in()) {
        header('Location: login.php?next=' . urlencode($_SERVER['REQUEST_URI'] ?? 'account.php'));
        exit;
    }
}

function cart_count(): int
{
    if (empty($_SESSION['cart']) || !is_array($_SESSION['cart'])) {
        return 0;
    }
    return array_sum($_SESSION['cart']);
}

function product_card(array $product): void
{
    ?>
    <article class="product-card">
        <a class="product-media" href="product.php?id=<?= e($product['id']) ?>">
            <img src="<?= e($product['image']) ?>" alt="<?= e($product['name']) ?>">
        </a>
        <div class="product-body">
            <div class="product-meta"><?= e($product['category'] ?? 'Catalogue') ?></div>
            <h3><a href="product.php?id=<?= e($product['id']) ?>"><?= e($product['name']) ?></a></h3>
            <p><?= e($product['short_description']) ?></p>
            <div class="product-bottom">
                <span class="price"><?= money($product['price']) ?></span>
                <a class="btn btn-small" href="product.php?id=<?= e($product['id']) ?>">Voir</a>
            </div>
        </div>
    </article>
    <?php
}

function flash(string $key): ?string
{
    if (!isset($_SESSION['flash'][$key])) {
        return null;
    }
    $value = $_SESSION['flash'][$key];
    unset($_SESSION['flash'][$key]);
    return $value;
}

function set_flash(string $key, string $value): void
{
    $_SESSION['flash'][$key] = $value;
}
