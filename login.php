<?php
$pageTitle = 'Connexion';
require_once __DIR__ . '/includes/header.php';
require_once __DIR__ . '/includes/logger.php';
log_http_request();

$error = null;
$username = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    /* Vulnérabilité volontaire : SQLi sur username/password + mots de passe faibles en clair. */
    $sql = "SELECT id, username, full_name, email, role
            FROM users
            WHERE username = '$username' AND password = '$password'
            LIMIT 1";

    $userRow = db_one($sql);

    if ($userRow) {
        $_SESSION['user'] = $userRow;
        http_response_code(200);
        $next = $_GET['next'] ?? 'account.php';
        header('Location: ' . $next);
        exit;
    }

    /* Aligné avec les règles BF : échecs de login en HTTP 401. */
    http_response_code(401);
    $error = 'Identifiants incorrects.';
}
?>
<section class="page-title">
    <div class="container">
        <h1>Connexion client</h1>
        <p>Accédez au suivi de vos commandes et à votre espace client.</p>
    </div>
</section>

<section class="section">
    <div class="container grid-3">
        <div class="panel" style="grid-column: span 2;">
            <?php if ($error): ?><div class="alert alert-error"><?= e($error) ?></div><?php endif; ?>
            <form method="post" class="form-grid" autocomplete="off">
                <div class="form-row">
                    <label for="username">Nom d’utilisateur</label>
                    <input id="username" name="username" value="<?= e($username) ?>" required>
                </div>
                <div class="form-row">
                    <label for="password">Mot de passe</label>
                    <input id="password" type="password" name="password" required>
                </div>
                <button class="btn" type="submit">Se connecter</button>
            </form>
        </div>
        <div class="panel">
            <h2>Nouveau client ?</h2>
            <p>La création de compte est temporairement désactivée. Utilisez un compte fictif fourni pour la démonstration.</p>
            <a class="btn btn-secondary" href="search.php">Continuer les achats</a>
        </div>
    </div>
</section>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
