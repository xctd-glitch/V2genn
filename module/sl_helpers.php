<?php

declare(strict_types=1);

/**
 * sl_helpers.php — Pure utility functions extracted from sl.php.
 *
 * Contains:  slDb, ensureSlTables, generateRandSub, generateSlug,
 *            slUnwrapShimlink, slNormalizeLinkRow, resolveDefaultUrl,
 *            ixgBase64Url, ixgSign, ixgCall, createExternalShortUrl, jsonOut,
 *            fetchAdminAddonDomains, resolveRandomDomain.
 *
 * Why separate?
 * ─────────────
 * sl.php was 3500+ lines mixing DB helpers, IXG integration, short-URL
 * services, schema migrations, and the main request handler+HTML view.
 * Extracting the stateless utility functions makes each part easier to
 * review, test, and grep. The include is idempotent (require_once).
 */

// ── DB helper ──
function slDb(): ?PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }
    // ── Try MySQL first ──
    $host = getenv('DB_HOST') ?: 'localhost';
    $user = getenv('DB_USER') ?: '';
    $pass = getenv('DB_PASS') ?: '';
    $name = getenv('DB_NAME') ?: '';
    if ($user && $name) {
        try {
            $pdo = new PDO(
                "mysql:host={$host};dbname={$name};charset=utf8mb4",
                $user,
                $pass,
                tp_mysql_pdo_options()
            );
            return $pdo;
        } catch (Throwable) {
        }
    }
    // ── Fallback: local SQLite (dev / server without MySQL) ──
    if (extension_loaded('pdo_sqlite')) {
        try {
            $file = __DIR__ . '/../data/sl_data.sqlite';
            $pdo  = new PDO("sqlite:{$file}", null, null, tp_sqlite_pdo_options());
            $pdo->exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;');
            return $pdo;
        } catch (Throwable) {
        }
    }
    return null;
}

// ── Ensure tables exist ──
function ensureSlTables(PDO $db): void
{
    static $ran = false;
    if ($ran) {
        return;
    }
    $ran = true;

    // APCu guard: skip DDL migrations if already confirmed good within the last 24 h.
    // This prevents ALTER TABLE from running on every request under PHP-FPM.
    $apcuKey = 'tp_sl_tables_ensured_v2';
    if (function_exists('apcu_fetch') && apcu_fetch($apcuKey) === true) {
        return;
    }

    $isSqlite = $db->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite';

    if ($isSqlite) {
        $db->exec("CREATE TABLE IF NOT EXISTS app_users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            domain        TEXT DEFAULT '',
            created_at    TEXT DEFAULT (datetime('now'))
        )");
        try {
            $db->exec("ALTER TABLE app_users ADD COLUMN domain TEXT DEFAULT ''");
        } catch (PDOException $e) {
        }
        try {
            $db->exec("ALTER TABLE app_users ADD COLUMN cf_token TEXT DEFAULT ''");
        } catch (PDOException $e) {
        }
        try {
            $db->exec("ALTER TABLE app_users ADD COLUMN cf_account_id TEXT DEFAULT ''");
        } catch (PDOException $e) {
        }
        try {
            $db->exec("ALTER TABLE app_users ADD COLUMN cf_zone_id TEXT DEFAULT ''");
        } catch (PDOException $e) {
        }
        try {
            $db->exec("ALTER TABLE app_users ADD COLUMN cf_proxied TEXT DEFAULT 'true'");
        } catch (PDOException $e) {
        }
        $db->exec("CREATE TABLE IF NOT EXISTS user_domains (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL,
            domain        TEXT NOT NULL,
            created_at    TEXT DEFAULT (datetime('now'))
        )");
        $db->exec("CREATE TABLE IF NOT EXISTS short_links (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            slug          TEXT NOT NULL UNIQUE,
            title         TEXT DEFAULT '',
            description   TEXT DEFAULT '',
            image         TEXT DEFAULT '',
            default_url   TEXT NOT NULL,
            redirect_url  TEXT DEFAULT '',
            country_rules TEXT DEFAULT '{}',
            domain        TEXT DEFAULT '',
            smartlink_id  INTEGER DEFAULT 0,
            smartlink_ids    TEXT DEFAULT '[]',
            smartlink_network TEXT DEFAULT '',
            shimlink          TEXT DEFAULT '',
            short_service     TEXT DEFAULT 'default',
            external_url  TEXT DEFAULT '',
            hits          INTEGER DEFAULT 0,
            active        INTEGER DEFAULT 1,
            created_by    TEXT DEFAULT '',
            created_at    TEXT DEFAULT (datetime('now')),
            updated_at    TEXT DEFAULT (datetime('now'))
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_slug ON short_links (slug)");
        // Migrate new columns if table already exists (SQLite)
        foreach (['domain TEXT DEFAULT \'\'', 'smartlink_id INTEGER DEFAULT 0', 'smartlink_ids TEXT DEFAULT \'[]\'', 'smartlink_network TEXT DEFAULT \'\'', 'shimlink TEXT DEFAULT \'\'', 'short_service TEXT DEFAULT \'default\'', 'external_url TEXT DEFAULT \'\'', 'redirect_url TEXT DEFAULT \'\'', 'user_id INTEGER DEFAULT 0', 'rand_sub TEXT DEFAULT \'\'', 'owner TEXT DEFAULT \'\''] as $col) {
            try {
                $db->exec("ALTER TABLE short_links ADD COLUMN {$col}");
            } catch (PDOException $e) {
            }
        }

        // ── link_hits (SQLite) ──
        $db->exec("CREATE TABLE IF NOT EXISTS link_hits (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            link_id    INTEGER NOT NULL DEFAULT 0,
            slug       TEXT NOT NULL,
            hit_date   TEXT NOT NULL,
            country    TEXT DEFAULT '',
            device     TEXT DEFAULT '',
            network    TEXT DEFAULT '',
            hits       INTEGER DEFAULT 1,
            UNIQUE (slug, hit_date, country, device, network)
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_lh_slug   ON link_hits (slug)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_lh_date   ON link_hits (hit_date)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_lh_linkid ON link_hits (link_id)");

        // ── postbacks (SQLite) ──
        $db->exec("CREATE TABLE IF NOT EXISTS postbacks (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL DEFAULT 0,
            name       TEXT DEFAULT '',
            slug       TEXT DEFAULT '',
            url        TEXT NOT NULL,
            event      TEXT DEFAULT 'click',
            active     INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_pb_user          ON postbacks (user_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_pb_slug          ON postbacks (slug)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_pb_active_event  ON postbacks (active, event, slug)");

        // ── clicks (SQLite) ──
        $db->exec("CREATE TABLE IF NOT EXISTS clicks (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER DEFAULT 0,
            slug       TEXT DEFAULT '',
            clickid    TEXT DEFAULT '',
            subid      TEXT DEFAULT '',
            country    TEXT DEFAULT '',
            device     TEXT DEFAULT '',
            network    TEXT DEFAULT '',
            ip         TEXT DEFAULT '',
            payout     REAL DEFAULT 0.0,
            created_at TEXT DEFAULT (datetime('now'))
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cl_user         ON clicks (user_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cl_slug         ON clicks (slug)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cl_clickid      ON clicks (clickid)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cl_created      ON clicks (created_at)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cl_clickid_slug ON clicks (clickid, slug)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cl_slug_created ON clicks (slug, created_at)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cl_user_created ON clicks (user_id, created_at)");

        // ── conversions (SQLite) — incoming postbacks from affiliate networks ──
        $db->exec("CREATE TABLE IF NOT EXISTS conversions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER DEFAULT 0,
            clickid    TEXT DEFAULT '',
            subid      TEXT DEFAULT '',
            slug       TEXT DEFAULT '',
            country    TEXT DEFAULT '',
            device     TEXT DEFAULT '',
            network    TEXT DEFAULT '',
            payout     REAL DEFAULT 0.0,
            status     TEXT DEFAULT 'approved',
            raw_params TEXT DEFAULT '',
            source_ip  TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cv_user         ON conversions (user_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cv_slug         ON conversions (slug)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cv_clickid      ON conversions (clickid)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cv_status       ON conversions (status)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cv_created      ON conversions (created_at)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cv_slug_created ON conversions (slug, created_at)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cv_user_created ON conversions (user_id, created_at)");
    } else {
        $db->exec("CREATE TABLE IF NOT EXISTS app_users (
            id            INT AUTO_INCREMENT PRIMARY KEY,
            username      VARCHAR(50)  NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            domain        VARCHAR(255) DEFAULT '',
            created_at    TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        try {
            $db->exec("ALTER TABLE app_users ADD COLUMN domain VARCHAR(255) DEFAULT ''");
        } catch (PDOException $e) {
        }
        try {
            $db->exec("ALTER TABLE app_users ADD COLUMN cf_token VARCHAR(255) DEFAULT ''");
        } catch (PDOException $e) {
        }
        try {
            $db->exec("ALTER TABLE app_users ADD COLUMN cf_account_id VARCHAR(100) DEFAULT ''");
        } catch (PDOException $e) {
        }
        try {
            $db->exec("ALTER TABLE app_users ADD COLUMN cf_zone_id VARCHAR(100) DEFAULT ''");
        } catch (PDOException $e) {
        }
        try {
            $db->exec("ALTER TABLE app_users ADD COLUMN cf_proxied VARCHAR(10) DEFAULT 'true'");
        } catch (PDOException $e) {
        }
        $db->exec("CREATE TABLE IF NOT EXISTS user_domains (
            id            INT AUTO_INCREMENT PRIMARY KEY,
            user_id       INT NOT NULL,
            domain        VARCHAR(255) NOT NULL,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $db->exec("CREATE TABLE IF NOT EXISTS short_links (
            id            INT AUTO_INCREMENT PRIMARY KEY,
            slug          VARCHAR(30)  NOT NULL UNIQUE,
            title         VARCHAR(255) DEFAULT '',
            description   TEXT,
            image         VARCHAR(500) DEFAULT '',
            default_url   TEXT         NOT NULL,
            redirect_url  TEXT,
            country_rules TEXT,
            domain        VARCHAR(255) DEFAULT '',
            smartlink_id  INT          DEFAULT 0,
            smartlink_ids     TEXT,
            smartlink_network VARCHAR(50)  DEFAULT '',
            shimlink          VARCHAR(10)  DEFAULT '',
            short_service     VARCHAR(20)  DEFAULT 'default',
            external_url  TEXT,
            hits          INT UNSIGNED DEFAULT 0,
            active        TINYINT(1)   DEFAULT 1,
            created_by    VARCHAR(50)  DEFAULT '',
            created_at    TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
            updated_at    TIMESTAMP    DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            KEY idx_active (active),
            KEY idx_user_id (user_id),
            KEY idx_user_active (user_id, active),
            KEY idx_smartlink_network (smartlink_network)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Migrate new columns if table already exists
        foreach (['domain VARCHAR(255) DEFAULT \'\'', 'smartlink_id INT DEFAULT 0', 'smartlink_ids TEXT', 'smartlink_network VARCHAR(50) DEFAULT \'\'', 'shimlink VARCHAR(10) DEFAULT \'\'', 'short_service VARCHAR(20) DEFAULT \'default\'', 'external_url TEXT', 'redirect_url TEXT', 'user_id INT DEFAULT 0', 'rand_sub VARCHAR(20) DEFAULT \'\'', 'owner VARCHAR(50) DEFAULT \'\''] as $col) {
            try {
                $db->exec("ALTER TABLE short_links ADD COLUMN {$col}");
            } catch (PDOException $e) {
            }
        }

        try {
            $db->exec("ALTER TABLE short_links ADD INDEX idx_slug (slug)");
        } catch (PDOException $e) {
        }
        foreach ([
            'ALTER TABLE short_links ADD INDEX idx_active (active)',
            'ALTER TABLE short_links ADD INDEX idx_user_id (user_id)',
            'ALTER TABLE short_links ADD INDEX idx_user_active (user_id, active)',
            'ALTER TABLE short_links ADD INDEX idx_smartlink_network (smartlink_network)',
        ] as $statement) {
            try {
                $db->exec($statement);
            } catch (PDOException $e) {
            }
        }

        // ── link_hits: per-day analytics ──
        $db->exec("CREATE TABLE IF NOT EXISTS link_hits (
            id       BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            link_id  INT UNSIGNED NOT NULL DEFAULT 0,
            slug     VARCHAR(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
            hit_date DATE NOT NULL,
            country  VARCHAR(5)  DEFAULT '',
            device   VARCHAR(10) DEFAULT '',
            network  VARCHAR(50) DEFAULT '',
            hits     INT UNSIGNED DEFAULT 1,
            UNIQUE KEY uniq_lh (slug, hit_date, country, device, network),
            KEY idx_lh_slug (slug),
            KEY idx_lh_date (hit_date),
            KEY idx_lh_linkid (link_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        // Fix collation if table already exists with wrong collation
        try {
            $db->exec("ALTER TABLE link_hits MODIFY slug VARCHAR(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL");
        } catch (PDOException $e) {
        }
        try {
            $db->exec("ALTER TABLE link_hits ADD INDEX idx_lh_linkid (link_id)");
        } catch (PDOException $e) {
        }

        // ── postbacks ──
        $db->exec("CREATE TABLE IF NOT EXISTS postbacks (
            id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            user_id    INT UNSIGNED NOT NULL DEFAULT 0,
            name       VARCHAR(100) DEFAULT '',
            slug       VARCHAR(30)  DEFAULT '',
            url        TEXT NOT NULL,
            event      VARCHAR(20)  DEFAULT 'click',
            active     TINYINT(1)   DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            KEY idx_pb_user (user_id),
            KEY idx_pb_slug (slug),
            KEY idx_pb_active_event (active, event, slug)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        try {
            $db->exec("ALTER TABLE postbacks ADD INDEX idx_pb_active_event (active, event, slug)");
        } catch (PDOException $e) {
        }

        // ── clicks: individual click events (conversion tracking) ──
        $db->exec("CREATE TABLE IF NOT EXISTS clicks (
            id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            user_id    INT UNSIGNED    DEFAULT 0,
            slug       VARCHAR(30)     DEFAULT '',
            clickid    VARCHAR(255)    DEFAULT '',
            subid      VARCHAR(100)    DEFAULT '',
            country    VARCHAR(5)      DEFAULT '',
            device     VARCHAR(10)     DEFAULT '',
            network    VARCHAR(50)     DEFAULT '',
            ip         VARCHAR(45)     DEFAULT '',
            payout     DECIMAL(10,4)   DEFAULT 0.0000,
            created_at TIMESTAMP       DEFAULT CURRENT_TIMESTAMP,
            KEY idx_cl_user    (user_id),
            KEY idx_cl_slug    (slug),
            KEY idx_cl_clickid (clickid(100)),
            KEY idx_cl_created (created_at),
            KEY idx_cl_clickid_slug (clickid(100), slug),
            KEY idx_cl_slug_created (slug, created_at),
            KEY idx_cl_user_created (user_id, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        foreach ([
            'ALTER TABLE clicks ADD INDEX idx_cl_clickid_slug (clickid(100), slug)',
            'ALTER TABLE clicks ADD INDEX idx_cl_slug_created (slug, created_at)',
            'ALTER TABLE clicks ADD INDEX idx_cl_user_created (user_id, created_at)',
        ] as $statement) {
            try {
                $db->exec($statement);
            } catch (PDOException $e) {
            }
        }

        // ── conversions: incoming postbacks from affiliate networks ──
        $db->exec("CREATE TABLE IF NOT EXISTS conversions (
            id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            user_id    INT UNSIGNED    DEFAULT 0,
            clickid    VARCHAR(255)    DEFAULT '',
            subid      VARCHAR(100)    DEFAULT '',
            slug       VARCHAR(30)     DEFAULT '',
            country    VARCHAR(5)      DEFAULT '',
            device     VARCHAR(10)     DEFAULT '',
            network    VARCHAR(50)     DEFAULT '',
            payout     DECIMAL(10,4)   DEFAULT 0.0000,
            status     VARCHAR(20)     DEFAULT 'approved',
            raw_params TEXT            DEFAULT '',
            source_ip  VARCHAR(45)     DEFAULT '',
            created_at TIMESTAMP       DEFAULT CURRENT_TIMESTAMP,
            KEY idx_cv_user    (user_id),
            KEY idx_cv_slug    (slug),
            KEY idx_cv_clickid (clickid(100)),
            KEY idx_cv_status  (status),
            KEY idx_cv_created (created_at),
            KEY idx_cv_slug_created (slug, created_at),
            KEY idx_cv_user_created (user_id, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        foreach ([
            'ALTER TABLE conversions ADD INDEX idx_cv_slug (slug)',
            'ALTER TABLE conversions ADD INDEX idx_cv_status (status)',
            'ALTER TABLE conversions ADD INDEX idx_cv_slug_created (slug, created_at)',
            'ALTER TABLE conversions ADD INDEX idx_cv_user_created (user_id, created_at)',
        ] as $statement) {
            try {
                $db->exec($statement);
            } catch (PDOException $e) {
            }
        }
    }

    if (function_exists('apcu_store')) {
        apcu_store($apcuKey, true, 86400);
    }
}

// ── Generate random subdomain prefix ──
function generateRandSub(int $len = 8): string
{
    // Letters only — no digits — so the subdomain looks like a real hostname
    // (e.g. "abcde.domain.com") rather than a DGA-style random string.
    $chars = 'abcdefghijklmnopqrstuvwxyz';
    $str   = '';
    for ($i = 0; $i < $len; $i++) {
        $str .= $chars[tp_random_int(0, strlen($chars) - 1)];
    }
    return $str;
}

// ── Generate random slug ──
function generateSlug(int $len = 7): string
{
    // Mixed case a-zA-Z0-9, excluding visually ambiguous chars (0/O, 1/l/I)
    // so slugs look like Bitly/goo.gl style: e.g. "3AbCdEf", "DkF3bN".
    $chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
    $slug  = '';
    for ($i = 0; $i < $len; $i++) {
        $slug .= $chars[tp_random_int(0, strlen($chars) - 1)];
    }
    return $slug;
}

// ── Build shimlink wrapper URL around a local shortlink ──
// Wraps the go.php URL (not the destination) so the cloaked URL is stored
// in `external_url` at create/update time.
// Flow: l.wl.co/l?u={localUrl} → go.php → SmartlinkURL
function slBuildShimlinkWrapperUrl(string $localUrl, string $shimlink): string
{
    return match ($shimlink) {
        'wl'    => 'https://l.wl.co/l?u='            . rawurlencode($localUrl),
        'fb'    => 'https://l.facebook.com/l.php?u=' . rawurlencode($localUrl),
        default => $localUrl,
    };
}

// ── Strip legacy shimlink wrapping (mirror of unwrapShimlink in go.php) ──
// Used by list_links / create_link / update_link response normalisation so
// the admin UI always sees raw destination URLs in the edit form, even for
// rows that were saved before the CREATE-time wrapping was removed.
// Idempotent: a no-op for un-wrapped URLs.
function slUnwrapShimlink(string $url): string
{
    if ($url === '') {
        return $url;
    }
    if (preg_match('#^https?://l\.wl\.co/l\?u=([^&]+)#i', $url, $m)
        || preg_match('#^https?://l\.facebook\.com/l\.php\?u=([^&]+)#i', $url, $m)
    ) {
        $decoded = rawurldecode($m[1]);
        if (filter_var($decoded, FILTER_VALIDATE_URL)) {
            return $decoded;
        }
    }
    return $url;
}

// ── Normalise a link row for API response ──
// Unwraps any legacy shimlink prefix baked into default_url so the UI
// always shows the raw destination in the edit form. The `shimlink` column
// on the row is what actually drives runtime wrapping in go.php.
/**
 * @param array<string, mixed> $row
 * @return array<string, mixed>
 */
function slNormalizeLinkRow(array $row): array
{
    if (isset($row['default_url']) && is_string($row['default_url'])) {
        $row['default_url'] = slUnwrapShimlink($row['default_url']);
    }
    return $row;
}

// ── Resolve default_url from smartlink_network or smartlink_id ──
// Eliminates exact duplication in create_link and update_link
function resolveDefaultUrl(PDO $db, string $smartlinkNetwork, int $smartlinkId, string $currentUrl): string
{
    if ($smartlinkNetwork) {
        try {
            $stmt = $db->prepare('SELECT url FROM smartlinks WHERE network = ? ORDER BY id ASC LIMIT 1');
            $stmt->execute([$smartlinkNetwork]);
            $row = $stmt->fetch();
            if ($row && $row['url']) {
                return $row['url'];
            }
        } catch (PDOException $e) {
        }
    } elseif ($smartlinkId > 0) {
        try {
            $stmt = $db->prepare('SELECT url FROM smartlinks WHERE id = ? LIMIT 1');
            $stmt->execute([$smartlinkId]);
            $row = $stmt->fetch();
            if ($row && $row['url']) {
                return $row['url'];
            }
        } catch (PDOException $e) {
        }
    }
    return $currentUrl;
}

// ── IXG API: base64url encode ──
function ixgBase64Url(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

// ── IXG API: sign params ──
// Canonical: all POST body fields (except sig), without op (op is in the query string).
// Sorted alphabetically, JSON encoded, HMAC-SHA256 raw binary → base64url.
/** @param array<string, mixed> $params */
function ixgSign(array $params, string $secret): string
{
    $canonical = [
        'code'  => (string)($params['code']  ?? ''),
        'desc'  => (string)($params['desc']  ?? ''),
        'img'   => (string)($params['img']   ?? ''),
        'title' => (string)($params['title'] ?? ''),
        'ts'    => (int)   ($params['ts']    ?? 0),
        'url'   => (string)($params['url']   ?? ''),
    ];
    ksort($canonical);
    $json = json_encode($canonical, JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        throw new RuntimeException('IXG: failed to encode JSON signature.');
    }
    return ixgBase64Url(hash_hmac('sha256', $json, $secret, true));
}

// ── IXG API: call ──
// op is sent as a query string (?op=create), not in the POST body.
/**
 * @param array<string, mixed> $payload
 * @return array<string, mixed>
 */
function ixgCall(string $op, array $payload): array
{
    $baseUrl = rtrim(getenv('IXG_API_URL') ?: 'https://me.ixg.llc/api.php', '?&');
    $apiUrl  = $baseUrl . (strpos($baseUrl, '?') === false ? '?' : '&') . 'op=' . urlencode($op);
    $json    = json_encode($payload, JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        throw new RuntimeException('IXG: failed to encode JSON request.');
    }

    $ch = curl_init($apiUrl);
    if ($ch === false) {
        throw new RuntimeException('IXG: failed to initialize cURL.');
    }

    $origin = rtrim(getenv('IXG_API_URL') ?: 'https://me.ixg.llc/api.php', '?&');
    $originBase = preg_replace('#/[^/]*$#', '', $origin) ?: $origin;

    $headers = [
        'Content-Type: application/json',
        'Accept: application/json, text/plain, */*',
        'Accept-Language: en-US,en;q=0.9',
        'Connection: keep-alive',
        'Origin: ' . $originBase,
        'Referer: ' . $originBase . '/',
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    ];

    // X-IXG-Key bypasses the Cloudflare WAF challenge on IXG side via their custom rule:
    //   any(http.request.headers["x-ixg-key"][*] eq "...")
    $ixgKey = trim((string) getenv('IXG_API_KEY'));
    if ($ixgKey !== '') {
        $headers[] = 'X-IXG-Key: ' . $ixgKey;
    }

    curl_setopt_array($ch, [
        CURLOPT_POST            => true,
        CURLOPT_RETURNTRANSFER  => true,
        CURLOPT_HTTPHEADER      => $headers,
        CURLOPT_ENCODING        => 'gzip, deflate', // explicit — exclude br (brotli) to avoid decode errors
        CURLOPT_POSTFIELDS      => $json,
        CURLOPT_TIMEOUT         => 15,
        CURLOPT_CONNECTTIMEOUT  => 10,
        CURLOPT_SSL_VERIFYPEER  => true,
        CURLOPT_SSL_VERIFYHOST  => 2,
    ]);

    $body = curl_exec($ch);
    if ($body === false) {
        $err = curl_error($ch);
        curl_close($ch);
        throw new RuntimeException('IXG cURL error: ' . $err);
    }
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    // Detect WAF / bot-protection block before JSON decode.
    // When blocked, the server returns an HTML page instead of JSON.
    $bodyStr = (string) $body;

    // Cloudflare bot challenge ("Just a moment..." interstitial)
    if (
        stripos($bodyStr, 'Just a moment') !== false
        || stripos($bodyStr, '/cdn-cgi/challenge-platform') !== false
        || stripos($bodyStr, 'cf-chl-') !== false
        || stripos($bodyStr, 'checking your browser') !== false
    ) {
        throw new RuntimeException(
            'IXG: Cloudflare bot challenge blocked the request (HTTP ' . $code . '). ' .
            'IXG API is behind Cloudflare and rejecting server-side requests from this IP. ' .
            'Coba pakai shortener lain (is.gd / tinyurl) atau biarkan "Default" (tanpa 3rd-party shortener).'
        );
    }

    // Imunify360 / generic WAF block
    if (stripos($bodyStr, 'Imunify360') !== false || stripos($bodyStr, 'bot-protection') !== false) {
        throw new RuntimeException(
            'IXG: Request blocked by Imunify360 bot-protection. ' .
            'HTTP ' . $code . '. The outbound request from this server was rejected. ' .
            'Please contact your hosting provider to allow outbound API requests from this server IP.'
        );
    }

    $decoded = json_decode($bodyStr, true);
    if (!is_array($decoded)) {
        // Generic "got HTML when expecting JSON" — likely some other WAF/proxy block.
        $isHtml = stripos(ltrim($bodyStr), '<!doctype') === 0 || stripos(ltrim($bodyStr), '<html') === 0;
        if ($isHtml) {
            throw new RuntimeException(
                "IXG: API returned an HTML page instead of JSON (HTTP {$code}). " .
                'Likely a WAF / Cloudflare challenge is blocking server-side requests. ' .
                'Coba pakai shortener lain (is.gd / tinyurl).'
            );
        }
        throw new RuntimeException("IXG: response is not JSON. HTTP {$code}. Body: " . substr($bodyStr, 0, 200));
    }

    return ['status' => $code, 'body' => $decoded];
}

// ── External short URL services ──
/**
 * @param array<string, mixed> $meta
 * @return array<string, mixed>
 */
function createExternalShortUrl(string $url, string $service, array $meta = []): array
{
    $encoded = rawurlencode($url);

    if ($service === 'ixg') {
        $secret = getenv('IXG_API_SECRET') ?: '';
        if (!$secret) {
            return ['success' => false, 'url' => '', 'error' => 'IXG_API_SECRET is not configured in .env'];
        }

        // Retry up to 3x for transient failures: shared host fork limits cause
        // intermittent getaddrinfo() failures, and the IXG API occasionally
        // returns an incomplete body (status 201 but missing ok/short_url).
        // Successful calls typically come back on the 1st or 2nd attempt.
        $maxAttempts = 3;
        $lastErr     = '';
        $lastBody    = null;
        $lastStatus  = 0;

        for ($attempt = 1; $attempt <= $maxAttempts; $attempt++) {
            try {
                $params = [
                    'url'   => $url,
                    'title' => $meta['title'] ?? '',
                    'desc'  => $meta['desc']  ?? '',
                    'img'   => $meta['img']   ?? '',
                    'code'  => $meta['code']  ?? '',
                    'ts'    => time(),
                ];
                $params['sig'] = ixgSign($params, $secret);
                $res = ixgCall('create', $params);
                $lastStatus = (int) ($res['status'] ?? 0);
                $lastBody   = $res['body'] ?? null;

                // Response: {"ok":true,"code":"abc","short_url":"https://...","target":"..."}
                if (!empty($res['body']['ok']) && !empty($res['body']['short_url'])) {
                    $shortUrl = $res['body']['short_url'];
                    // Replace subdomain: me.ixg.llc → {custom|random}.ixg.llc
                    $rawSub  = preg_replace('/[^a-z0-9]/', '', strtolower($meta['ixg_sub'] ?? ''));
                    $usedSub = $rawSub ?: substr(str_replace(['+','/','='], '', base64_encode(tp_random_bytes(6))), 0, 8);
                    $shortUrl = preg_replace(
                        '#^(https?://)[^.]+\.ixg\.llc/#',
                        '$1' . $usedSub . '.ixg.llc/',
                        $shortUrl
                    );
                    if (filter_var($shortUrl, FILTER_VALIDATE_URL)) {
                        return ['success' => true, 'url' => $shortUrl];
                    }
                    // Reached only if subdomain replacement broke the URL.
                    $lastErr = 'subdomain replacement produced invalid URL: ' . $shortUrl;
                } else {
                    // API replied but response is missing fields. Could be transient.
                    $lastErr = $res['body']['err']
                        ?? $res['body']['error']
                        ?? $res['body']['message']
                        ?? ('HTTP ' . $lastStatus . ' incomplete body');
                }
            } catch (Throwable $e) {
                $lastErr = $e->getMessage();
            }

            // Backoff before retrying. DNS failures (getaddrinfo) on shared
            // hosting need a longer pause so the kernel can reclaim threads.
            if ($attempt < $maxAttempts) {
                $isDnsFail = stripos($lastErr, 'getaddrinfo') !== false
                    || stripos($lastErr, 'could not resolve') !== false;
                usleep($isDnsFail ? 1_500_000 : 250_000); // 1.5s for DNS, 250ms otherwise
            }
        }

        // All attempts failed — surface the last error with attempt count.
        return [
            'success' => false,
            'url'     => '',
            'error'   => 'IXG (after ' . $maxAttempts . ' attempts): ' . $lastErr,
        ];
    }

    // ── TinyURL ──
    // Priority: API v2 (token) if TINYURL_API_KEY is set, fallback to old API (no token)
    if ($service === 'tinyurl') {
        $token = getenv('TINYURL_API_KEY') ?: '';

        if ($token) {
            // v2: POST JSON with a Bearer token -> JSON response
            $ch = curl_init('https://api.tinyurl.com/create');
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST           => true,
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_HTTPHEADER     => ['Authorization: Bearer ' . $token, 'Content-Type: application/json'],
                CURLOPT_POSTFIELDS     => json_encode(['url' => $url, 'domain' => 'tinyurl.com']),
            ]);
            $resp = curl_exec($ch);
            $cerr = curl_error($ch);
            curl_close($ch);
            if (!$cerr) {
                $json = json_decode((string)$resp, true);
                $tiny = $json['data']['tiny_url'] ?? '';
                if ($tiny && filter_var($tiny, FILTER_VALIDATE_URL)) {
                    return ['success' => true, 'url' => $tiny];
                }
            }
            // v2 failed → fallback to old API
        }

        // Legacy API: GET plain-text, no token required
        $ch = curl_init('https://tinyurl.com/api-create.php?url=' . $encoded);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT      => 'Mozilla/5.0',
        ]);
        $resp = trim((string)curl_exec($ch));
        $cerr = curl_error($ch);
        curl_close($ch);
        if ($cerr) {
            return ['success' => false, 'url' => '', 'error' => 'cURL: ' . $cerr];
        }
        if ($resp && filter_var($resp, FILTER_VALIDATE_URL) && strpos($resp, 'tinyurl.com') !== false) {
            return ['success' => true, 'url' => $resp];
        }
        return ['success' => false, 'url' => '', 'error' => $resp ?: 'No response from TinyURL'];
    }

    // ── is.gd (GET, plain-text response) ──
    if ($service === 'isgd') {
        $api = "https://is.gd/create.php?format=simple&url={$encoded}";
        $ch = curl_init($api);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT      => 'Mozilla/5.0 (compatible; ShortlinkManager/1.0)',
        ]);
        $resp = trim((string)curl_exec($ch));
        $err  = curl_error($ch);
        curl_close($ch);
        if ($err) {
            return ['success' => false, 'url' => '', 'error' => 'cURL: ' . $err];
        }
        if ($resp && filter_var($resp, FILTER_VALIDATE_URL)) {
            return ['success' => true, 'url' => $resp];
        }
        return ['success' => false, 'url' => '', 'error' => $resp ? substr($resp, 0, 120) : 'No response'];
    }

    return ['success' => false, 'url' => '', 'error' => 'Unknown service'];
}

// ── JSON response helper ──
/** @param array<string, mixed> $data */
function jsonOut(array $data, int $code = 200): void
{
    ob_end_clean();
    http_response_code($code);
    header('Content-Type: application/json');
    exit(json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
}

// ── Random domain helpers ──────────────────────────────────────

/**
 * Fetch admin addon domains from addondomain table.
 * These are the domains available for random rotation
 * (domain_id = '' or 'admin').
 */
/** @return array<int, string> */
function fetchAdminAddonDomains(\PDO $db): array
{
    try {
        $stmt = $db->query(
            "SELECT domain FROM addondomain
             WHERE domain_id = '' OR domain_id = 'admin'
             ORDER BY id"
        );
        return $stmt->fetchAll(\PDO::FETCH_COLUMN) ?: [];
    } catch (\PDOException $e) {
        return [];
    }
}

/**
 * Resolve domain when the input may be '__random__'.
 * Picks randomly from addondomain where domain_id = 'admin'.
 * Returns [string $domain, bool $isRandom, array $pool].
 * - If random and ≥2 domains: $domain='', $isRandom=true, $pool=domains list.
 * - If random but <2 domains: falls back to the single domain (or '').
 * - Otherwise: returns the literal domain.
 */
/** @return array{0: string, 1: bool, 2: array<int, string>} */
function resolveRandomDomain(\PDO $db, int $userId, string $domainRaw): array
{
    if ($domainRaw !== '__random__') {
        return [$domainRaw, false, []];
    }
    $pool = fetchAdminAddonDomains($db);
    if (count($pool) < 2) {
        return [$pool[0] ?? '', false, []];
    }
    return ['', true, $pool];
}

// ── Facebook URL Linter / Sharing Debugger scrape ──────────────
// POST https://graph.facebook.com/v21.0/
//      ?id={url}&scrape=true&access_token={app_id}|{app_secret}
// Forces Facebook to re-fetch OG tags so preview image shows immediately.
// Requires FB_APP_ID + FB_APP_SECRET in .env for reliable scraping.
// Returns: ['ok'=>bool, 'title'=>string, 'image'=>string, 'error'=>string]
/** @return array<string, mixed> */
function fbScrape(string $url): array
{
    if (!$url || !filter_var($url, FILTER_VALIDATE_URL)) {
        return ['ok' => false, 'error' => 'Invalid URL'];
    }

    // Build app access token from env (required by Graph API)
    $appId     = trim((string) getenv('FB_APP_ID'));
    $appSecret = trim((string) getenv('FB_APP_SECRET'));
    if (!$appId || !$appSecret) {
        return ['ok' => false, 'error' => 'FB_APP_ID / FB_APP_SECRET not configured in .env'];
    }
    $accessToken = $appId . '|' . $appSecret;

    $endpoint = 'https://graph.facebook.com/v21.0/'
              . '?id=' . urlencode($url)
              . '&scrape=true'
              . '&access_token=' . urlencode($accessToken);

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL             => $endpoint,
        CURLOPT_POST            => true,
        CURLOPT_POSTFIELDS      => '',
        CURLOPT_RETURNTRANSFER  => true,
        CURLOPT_TIMEOUT         => 15,
        CURLOPT_CONNECTTIMEOUT  => 5,
        CURLOPT_SSL_VERIFYPEER  => true,
        CURLOPT_SSL_VERIFYHOST  => 2,
        CURLOPT_USERAGENT       => 'NoTracking/2.0 OG-Scraper',
        CURLOPT_HTTPHEADER      => ['Content-Type: application/x-www-form-urlencoded'],
    ]);

    $resp    = curl_exec($ch);
    $code    = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);

    if ($curlErr) {
        return ['ok' => false, 'error' => 'cURL: ' . $curlErr];
    }

    $data = json_decode($resp, true) ?: [];

    // Facebook returns 200 with OG data on success
    if ($code === 200 && !empty($data['id'])) {
        return [
            'ok'    => true,
            'title' => $data['title'] ?? '',
            'image' => $data['image'][0]['url'] ?? ($data['image'] ?? ''),
            'url'   => $data['url'] ?? $url,
        ];
    }

    // Error response
    $errMsg = $data['error']['message'] ?? ($data['error'] ?? "HTTP {$code}");
    if (is_array($errMsg)) {
        $errMsg = json_encode($errMsg);
    }
    return ['ok' => false, 'error' => $errMsg];
}
