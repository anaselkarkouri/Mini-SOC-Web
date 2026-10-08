<?php
require_once __DIR__ . '/bootstrap.php';

if (soc_is_admin()) {
    header('Location: index.php');
    exit;
}

$error = '';
$username = '';
$next = $_GET['next'] ?? $_POST['next'] ?? 'index.php';
$isEn = soc_current_language() === 'en';
$copy = $isEn ? [
    'title' => 'SOC Login',
    'intro' => 'Independent login for the SOC dashboard.',
    'error' => 'Invalid SOC credentials.',
    'username' => 'Username',
    'password' => 'Password',
    'submit' => 'Sign in',
    'csrf_error' => 'Session expired. Try again.',
    'lock_error' => 'Too many failed attempts. Try again in %s seconds.',
] : [
    'title' => 'Login SOC',
    'intro' => 'Connexion indépendante du back-office e-commerce.',
    'error' => 'Identifiants SOC incorrects.',
    'username' => 'Username',
    'password' => 'Password',
    'submit' => 'Se connecter',
    'csrf_error' => 'Session expirée. Réessayez.',
    'lock_error' => 'Trop de tentatives échouées. Réessayez dans %s secondes.',
];
$next = is_string($next) ? soc_safe_redirect_path($next) : 'index.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

    $remaining = soc_login_lock_remaining();
    if (!soc_verify_post_csrf()) {
        $error = $copy['csrf_error'];
    } elseif ($remaining > 0) {
        $error = sprintf($copy['lock_error'], $remaining);
    } elseif (soc_login_attempt($username, $password)) {
        header('Location: ' . $next);
        exit;
    } else {
        $remaining = soc_login_lock_remaining();
        $error = $remaining > 0 ? sprintf($copy['lock_error'], $remaining) : $copy['error'];
    }
}
?>
<!doctype html>
<html lang="<?= soc_e(soc_current_language()) ?>" data-theme="light">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= soc_e($copy['title']) ?> - Mini-SOC</title>
    <script>
        (function () {
            var saved = localStorage.getItem('soc-theme') || 'light';
            document.documentElement.setAttribute('data-theme', saved);
        }());
    </script>
    <link rel="stylesheet" href="assets/soc.css">
</head>
<body class="soc-centered">
    <main class="access-card soc-login-card">
        <span class="brand-mark"><?= soc_icon('shield', 'brand-icon') ?></span>
        <h1>Mini-SOC</h1>
        <p><?= soc_e($copy['intro']) ?></p>
        <?php if ($error): ?><div class="login-error"><?= soc_e($error) ?></div><?php endif; ?>
        <form class="soc-login-form" method="post" autocomplete="off">
            <?php soc_csrf_field(); ?>
            <input type="hidden" name="next" value="<?= soc_e($next) ?>">
            <label for="username"><?= soc_e($copy['username']) ?></label>
            <input id="username" name="username" value="<?= soc_e($username) ?>" required autofocus>
            <label for="password"><?= soc_e($copy['password']) ?></label>
            <input id="password" type="password" name="password" required>
            <button type="submit"><?= soc_e($copy['submit']) ?></button>
        </form>
    </main>
    <script src="assets/soc.js"></script>
</body>
</html>
