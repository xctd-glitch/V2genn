<?php

declare(strict_types=1);

require_once __DIR__ . '/runtime_compat.php';

if (!function_exists('tp_app_pdo')) {
    function tp_app_pdo(): ?PDO
    {
        /** @var PDO|null $pdo */
        static $pdo = null;
        static $initialized = false;

        if ($initialized) {
            return $pdo;
        }

        $initialized = true;

        $host = trim((string) getenv('DB_HOST'));
        $user = trim((string) getenv('DB_USER'));
        $pass = (string) getenv('DB_PASS');
        $name = trim((string) getenv('DB_NAME'));

        if ($user !== '' && $name !== '') {
            try {
                $pdo = new PDO(
                    'mysql:host=' . ($host !== '' ? $host : 'localhost') . ';dbname=' . $name . ';charset=utf8mb4',
                    $user,
                    $pass,
                    tp_mysql_pdo_options()
                );

                return $pdo;
            } catch (Throwable) {
                $pdo = null;
            }
        }

        $sqlitePath = dirname(__DIR__) . '/data/sl_data.sqlite';
        if (is_file($sqlitePath)) {
            try {
                $pdo = new PDO(
                    'sqlite:' . $sqlitePath,
                    null,
                    null,
                    tp_sqlite_pdo_options()
                );

                return $pdo;
            } catch (Throwable) {
                $pdo = null;
            }
        }

        return null;
    }
}

if (!function_exists('tp_admin_username')) {
    function tp_admin_username(): string
    {
        return trim((string) getenv('ADMIN_USER'));
    }
}

if (!function_exists('tp_super_admin_username')) {
    function tp_super_admin_username(): string
    {
        return 'adminsuper';
    }
}

if (!function_exists('tp_verify_super_admin_credentials')) {
    function tp_verify_super_admin_credentials(string $username, string $password): bool
    {
        $submitted = trim($username);
        $hash = trim((string) getenv('SUPER_ADMIN_HASH'));
        // Super-admin path is disabled when SUPER_ADMIN_HASH is unset or empty.
        // Set it to a bcrypt hash in .env to enable. Generate with:
        //   php -r 'echo password_hash("yourpassword", PASSWORD_BCRYPT) . PHP_EOL;'
        if ($submitted === '' || $password === '' || $hash === '') {
            return false;
        }

        if (!hash_equals(tp_super_admin_username(), $submitted)) {
            return false;
        }

        return password_verify($password, $hash);
    }
}

if (!function_exists('tp_is_super_admin')) {
    function tp_is_super_admin(): bool
    {
        return !empty($_SESSION['dashboard_super']);
    }
}

if (!function_exists('tp_verify_admin_credentials')) {
    function tp_verify_admin_credentials(string $username, string $password): bool
    {
        $configuredUsername = tp_admin_username();
        $submittedUsername = trim($username);

        if ($configuredUsername === '' || $submittedUsername === '' || $password === '') {
            return false;
        }

        if (!hash_equals($configuredUsername, $submittedUsername)) {
            return false;
        }

        $pdo = tp_app_pdo();
        if (!$pdo instanceof PDO) {
            return false;
        }

        try {
            $statement = $pdo->prepare('SELECT password_hash FROM app_users WHERE username = ? LIMIT 1');
            $statement->execute([$configuredUsername]);
            $row = $statement->fetch(PDO::FETCH_ASSOC);
        } catch (Throwable) {
            return false;
        }

        $passwordHash = is_array($row) ? ($row['password_hash'] ?? null) : null;
        if (!is_string($passwordHash) || $passwordHash === '') {
            return false;
        }

        if (!password_verify($password, $passwordHash)) {
            return false;
        }

        if (password_needs_rehash($passwordHash, PASSWORD_BCRYPT)) {
            try {
                $rehashStatement = $pdo->prepare('UPDATE app_users SET password_hash = ? WHERE username = ?');
                $rehashStatement->execute([password_hash($password, PASSWORD_BCRYPT), $configuredUsername]);
            } catch (Throwable) {
            }
        }

        return true;
    }
}
