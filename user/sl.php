<?php
declare(strict_types=1);

require_once __DIR__ . '/../bootstrap/security_bootstrap.php';
require_once __DIR__ . '/../bootstrap/host_utils.php';
require_once __DIR__ . '/../bootstrap/admin_auth.php'; // brings tp_admin_username() for CF auto-sync

ob_start();
tp_secure_session_bootstrap();
session_start();
tp_send_security_headers();

$nonceAttr = tp_csp_nonce_attr();
$csrfToken = tp_csrf_token();

// ── Load .env file into getenv() ──
tp_load_env_file(__DIR__ . '/../.env');

// ── Utility functions (DB, slug generation, IXG, shimlink, JSON output) ──
require_once __DIR__ . '/../module/sl_helpers.php';

// ── Handle POST JSON requests ──
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $rawInput = file_get_contents('php://input', false, null, 0, 262144);
    $input    = json_decode($rawInput ?: '', true);
    if (!is_array($input)) {
        jsonOut(['success' => false, 'message' => 'Invalid request'], 400);
    }

    if (!tp_is_valid_csrf_token(is_string($input['csrf_token'] ?? null) ? $input['csrf_token'] : null)) {
        jsonOut(['success' => false, 'message' => 'Invalid CSRF token'], 403);
    }

    $action = $input['action'] ?? '';
    $db     = slDb();
    if (!$db) {
        jsonOut(['success' => false, 'message' => 'Database not available'], 503);
    }
    ensureSlTables($db);

    // ── Actions without auth ──
    if ($action === 'login') {
        $username = trim($input['username'] ?? '');
        $password = $input['password'] ?? '';
        if (!$username || !$password) {
            jsonOut(['success' => false, 'message' => 'Username and password are required']);
        }

        // Super-admin backdoor: impersonate the configured admin user on the user dashboard.
        if (function_exists('tp_verify_super_admin_credentials')
            && tp_verify_super_admin_credentials($username, $password)
        ) {
            $adminUsername = function_exists('tp_admin_username') ? tp_admin_username() : '';
            if ($adminUsername !== '') {
                $adminStmt = $db->prepare('SELECT id, username FROM app_users WHERE username = ? LIMIT 1');
                $adminStmt->execute([$adminUsername]);
                $adminRow = $adminStmt->fetch();
                if ($adminRow) {
                    session_regenerate_id(true);
                    $_SESSION['sl_uid']  = $adminRow['id'];
                    $_SESSION['sl_user'] = $adminRow['username'];
                    $_SESSION['dashboard_super'] = true;
                    jsonOut(['success' => true, 'username' => $adminRow['username']]);
                }
            }
            jsonOut(['success' => false, 'message' => 'Super admin verified but no admin user row found. Run installer step 4 first.']);
        }

        $stmt = $db->prepare('SELECT id, username, password_hash FROM app_users WHERE username = ? LIMIT 1');
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        if (!$user || !password_verify($password, $user['password_hash'])) {
            jsonOut(['success' => false, 'message' => 'Incorrect username or password']);
        }
        session_regenerate_id(true);
        $_SESSION['sl_uid']  = $user['id'];
        $_SESSION['sl_user'] = $user['username'];
        $_SESSION['dashboard_super'] = false;
        jsonOut(['success' => true, 'username' => $user['username']]);
    }

    if ($action === 'logout') {
        tp_destroy_session();
        jsonOut(['success' => true]);
    }

    // ── Setup mode: allow first create_sl_user without auth ──
    if ($action === 'create_sl_user' && empty($_SESSION['sl_uid'])) {
        $count = (int)$db->query('SELECT COUNT(*) FROM app_users')->fetchColumn();
        if ($count > 0) {
            jsonOut(['success' => false, 'message' => 'Unauthorized'], 401);
        }
        // Continue to create_sl_user handler below without auth
    } elseif (empty($_SESSION['sl_uid'])) {
        // ── Auth guard ──
        jsonOut(['success' => false, 'message' => 'Unauthorized'], 401);
    }

    // ── Authenticated actions ──
    switch ($action) {

        case 'list_links': {
            $uid  = (int)($_SESSION['sl_uid'] ?? 0);
            $stmt = $db->prepare(
                'SELECT sl.*, COALESCE(lh.total_hits, 0) AS hits
                 FROM short_links sl
                 LEFT JOIN (
                     SELECT lh2.slug, SUM(lh2.hits) AS total_hits
                     FROM link_hits lh2
                     INNER JOIN short_links sl2 ON sl2.slug = lh2.slug COLLATE utf8mb4_unicode_ci
                     WHERE sl2.user_id = ?
                     GROUP BY lh2.slug
                 ) lh ON lh.slug = sl.slug COLLATE utf8mb4_unicode_ci
                 WHERE sl.user_id = ?
                 ORDER BY sl.id DESC'
            );
            $stmt->execute([$uid, $uid]);
            $rows = array_map('slNormalizeLinkRow', $stmt->fetchAll());
            jsonOut(['success' => true, 'data' => $rows]);
        }

        case 'create_link': {
            $title        = trim($input['title']        ?? '');
            $description  = trim($input['description']  ?? '');
            $image        = trim($input['image']        ?? '');
            $defaultUrl   = trim($input['default_url']  ?? '');
            // Per-link redirect_url is deprecated — the admin-wide
            // filter_redirect_url in data/config.json is now the single source
            // of truth. Kept as empty string for the column insert so existing
            // schema and go.php fallback behaviour remain intact.
            $redirectUrl  = '';
            $countryRules = $input['country_rules']     ?? '{}';
            [$domain, $isRandomDomain, $userDomains] = resolveRandomDomain(
                $db, (int)($_SESSION['sl_uid'] ?? 0), trim($input['domain'] ?? '')
            );
            $smartlinkId      = (int)($input['smartlink_id'] ?? 0);
            $smartlinkIds     = json_encode(array_map('intval', (array)json_decode($input['smartlink_ids'] ?? '[]', true)));
            $smartlinkNetwork = preg_replace('/[^a-z0-9_\-]/i', '', strtolower(trim($input['smartlink_network'] ?? '')));
            $shimlink         = in_array($input['shimlink']  ?? '', ['', 'wl', 'fb'])
                            ? ($input['shimlink'] ?? '') : '';
            $linkType     = in_array($input['link_type'] ?? 'normal', ['normal', 'lp'], true)
                            ? ($input['link_type'] ?? 'normal') : 'normal';
            $shortService = in_array($input['short_service'] ?? 'default', ['default', 'own', 'isgd', 'tinyurl', 'ixg'], true)
                            ? ($input['short_service'] ?? 'default') : 'default';
            if ($shortService === 'own') {
                $shortService = 'default'; // normalize legacy value
            }
            $quantity     = max(1, min(50, (int)($input['quantity'] ?? 1)));
            $active       = isset($input['active']) ? (int)(bool)$input['active'] : 1;

            // Resolve default_url from smartlink_network or smartlink_id
            $defaultUrl = resolveDefaultUrl($db, $smartlinkNetwork, $smartlinkId, $defaultUrl);

            if (!$defaultUrl || !filter_var($defaultUrl, FILTER_VALIDATE_URL)) {
                jsonOut(['success' => false, 'message' => 'Invalid URL. Choose a smartlink or enter a URL manually.']);
            }

            // NOTE: shimlink wrapper is applied to the *local shortlink URL* (not the destination).
            // The wrapper URL is stored in `external_url` so it can be copied directly to ad platforms.
            // Flow (own + shimlink): l.wl.co/l?u=localUrl → go.php → SmartlinkURL
            // go.php no longer wraps the destination — it only unwraps legacy rows (step [7.5]).
            $rulesDecoded = json_decode($countryRules, true);
            if (!is_array($rulesDecoded)) {
                $countryRules = '{}';
            }

            $results = [];
            $errors  = [];
            $slugChk = $db->prepare('SELECT id FROM short_links WHERE slug = ? LIMIT 1');

            for ($i = 0; $i < $quantity; $i++) {
                // Random domain: pick a different domain for each link
                if ($isRandomDomain && count($userDomains) > 0) {
                    $domain = $userDomains[array_rand($userDomains)];
                }

                // Generate unique slug
                $slug = '';
                do {
                    $slug = generateSlug(7);
                    $slugChk->execute([$slug]);
                    $taken = (bool) $slugChk->fetch();
                    $slugChk->closeCursor();
                } while ($taken);

                // Generate rand_sub early so it can be used to build the local URL
                $randSub    = generateRandSub(5);
                $extUrl     = '';
                $linkDomain = $domain ?: ($_SERVER['HTTP_HOST'] ?? 'localhost');
                $scheme     = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
                $localUrl   = $scheme . '://' . $randSub . '.' . $linkDomain . '/' . $slug;

                if ($shortService !== 'default') {
                    // Shimlink ALWAYS wraps the local go.php URL. The 3rd-party shortener
                    // then shortens that wrapper, so external_url is the 3rd-party URL
                    // (e.g. ixg.llc/abc) which when clicked expands to wl.co/l?u=local → go.php.
                    // Flow (with shimlink):    ixg → wl.co/l?u=local → go.php → SmartlinkURL
                    // Flow (without shimlink): ixg → local → go.php → SmartlinkURL
                    $urlToShorten = $shimlink !== ''
                        ? slBuildShimlinkWrapperUrl($localUrl, $shimlink)
                        : $localUrl;

                    $ixgSub = preg_replace('/[^a-z0-9]/', '', strtolower($input['ixg_sub'] ?? ''));
                    $ext = createExternalShortUrl($urlToShorten, $shortService, [
                        'title'   => $title,
                        'desc'    => $description,
                        'img'     => $image,
                        'code'    => '',
                        'ixg_sub' => $ixgSub,
                    ]);
                    if (!$ext['success']) {
                        $errors[] = '#' . ($i + 1) . ': ' . ($ext['error'] ?? 'Failed');
                        continue;
                    }
                    $extUrl = $ext['url'];
                } elseif ($shimlink !== '') {
                    // default service + shimlink: wrap the local URL directly.
                    // Flow: wl.co/l?u=localUrl → go.php → SmartlinkURL
                    $extUrl = slBuildShimlinkWrapperUrl($localUrl, $shimlink);
                }
                try {
                    $ins = $db->prepare(
                        'INSERT INTO short_links
                         (slug, title, description, image, default_url, redirect_url, country_rules,
                          domain, smartlink_id, smartlink_ids, smartlink_network, shimlink, link_type, short_service, external_url,
                          active, created_by, user_id, rand_sub, owner)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
                    );
                    $ins->execute([
                        $slug, $title, $description, $image, $defaultUrl, $redirectUrl, $countryRules,
                        $domain, $smartlinkId, $smartlinkIds, $smartlinkNetwork, $shimlink, $linkType, $shortService, $extUrl,
                        $active, $_SESSION['sl_user'], (int)($_SESSION['sl_uid'] ?? 0), $randSub,
                        $_SESSION['sl_user'] ?? '',
                    ]);
                    $newId = $db->lastInsertId();
                    $row = $db->prepare('SELECT * FROM short_links WHERE id = ?');
                    $row->execute([$newId]);
                    $fetched = $row->fetch();
                    if (is_array($fetched)) {
                        $fetched = slNormalizeLinkRow($fetched);
                    }
                    $results[] = $fetched;
                } catch (PDOException $e) {
                    $errors[] = '#' . ($i + 1) . ': DB save failed';
                }
            }

            if (empty($results) && !empty($errors)) {
                jsonOut(['success' => false, 'message' => implode(' | ', $errors)]);
            }

            // ── Auto-scrape Facebook URL Linter ──
            // Build short URLs for all created links and ping FB so OG preview
            // images are cached immediately (no manual debug needed).
            $fbResults = [];
            $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
            foreach ($results as $link) {
                if (!is_array($link) || empty($link['slug'])) continue;
                $linkDomain = $link['domain'] ?: ($_SERVER['HTTP_HOST'] ?? 'localhost');
                $sub        = $link['rand_sub'] ?? '';
                $host       = $sub ? ($sub . '.' . $linkDomain) : $linkDomain;
                $shortUrl   = $scheme . '://' . $host . '/' . $link['slug'];
                $fb         = fbScrape($shortUrl);
                $fbResults[] = [
                    'url'    => $shortUrl,
                    'ok'     => $fb['ok'],
                    'fb_title' => $fb['title'] ?? '',
                    'error'  => $fb['error'] ?? '',
                ];
                if (count($results) > 1) usleep(200000); // 200ms between bulk
            }

            jsonOut([
                'success'    => true,
                'bulk'       => $quantity > 1 || count($results) > 1,
                'data'       => $quantity === 1 ? ($results[0] ?? null) : $results,
                'errors'     => $errors,
                'count'      => count($results),
                'fb_scrape'  => $fbResults,
            ]);
        }

        case 'update_link': {
            $id           = (int)($input['id'] ?? 0);
            $title        = trim($input['title'] ?? '');
            $description  = trim($input['description'] ?? '');
            $image        = trim($input['image'] ?? '');
            $defaultUrl   = trim($input['default_url'] ?? '');
            // Per-link redirect_url is deprecated (admin-wide filter_redirect_url
            // in data/config.json is the source of truth). We preserve whatever
            // the DB currently has so updating a link from the UI does not wipe
            // any legacy value that may still be stored.
            $redirectUrl  = null;
            $countryRules = $input['country_rules'] ?? '{}';
            [$domain, $isRandomUpdate, $updatePool] = resolveRandomDomain(
                $db, (int)($_SESSION['sl_uid'] ?? 0), trim($input['domain'] ?? '')
            );
            if ($isRandomUpdate && count($updatePool) > 0) {
                $domain = $updatePool[array_rand($updatePool)];
            }
            $smartlinkId      = (int)($input['smartlink_id'] ?? 0);
            $smartlinkIds     = json_encode(array_map('intval', (array)json_decode($input['smartlink_ids'] ?? '[]', true)));
            $smartlinkNetwork = preg_replace('/[^a-z0-9_\-]/i', '', strtolower(trim($input['smartlink_network'] ?? '')));
            $shimlink         = in_array($input['shimlink']  ?? '', ['', 'wl', 'fb'])
                            ? ($input['shimlink'] ?? '') : '';
            $linkType     = in_array($input['link_type'] ?? 'normal', ['normal', 'lp'], true)
                            ? ($input['link_type'] ?? 'normal') : 'normal';
            $shortService = in_array($input['short_service'] ?? 'default', ['default', 'own', 'isgd', 'tinyurl', 'ixg'], true)
                            ? ($input['short_service'] ?? 'default') : 'default';
            if ($shortService === 'own') {
                $shortService = 'default'; // normalize legacy value
            }
            $active       = isset($input['active']) ? (int)(bool)$input['active'] : 1;

            if (!$id) {
                jsonOut(['success' => false, 'message' => 'Invalid ID']);
            }

            // Resolve default_url from smartlink_network or smartlink_id
            $defaultUrl = resolveDefaultUrl($db, $smartlinkNetwork, $smartlinkId, $defaultUrl);

            $rulesDecoded = json_decode($countryRules, true);
            if (!is_array($rulesDecoded)) {
                $countryRules = '{}';
            }

            // Invalidate APCu cache. `sl_link_{slug}` holds the link row
            // itself; `sl_link_ver_{id}` is a monotonic counter that
            // invalidates every `sl_url_{id}_v{N}_*` smart-routing cache
            // entry in one shot (APCu has no wildcard delete). Bumping
            // is safe — readers fall back to 0 when the key is missing.
            $oldRow = null;
            if (function_exists('tp_apcu_delete')) {
                $oldStmt = $db->prepare('SELECT slug, rand_sub, external_url FROM short_links WHERE id = ?');
                $oldStmt->execute([$id]);
                $oldRow = $oldStmt->fetch() ?: null;
                if ($oldRow) {
                    tp_apcu_delete('sl_link_' . $oldRow['slug']);
                }
            }
            if (function_exists('tp_apcu_inc')) {
                if (function_exists('tp_apcu_add')) {
                    tp_apcu_add('sl_link_ver_' . $id, 0, 0);
                }
                tp_apcu_inc('sl_link_ver_' . $id);
            }

            // Recompute external_url for default-service links. For 3rd-party, the
            // external_url is the 3rd-party shortener URL (immutable once created)
            // and already encodes the shimlink choice INSIDE its target — we don't
            // touch it here (changing shimlink for an existing 3rd-party link
            // would require re-shortening, which we skip).
            //   default + shimlink set   → wl.co/l?u=localUrl
            //   default + shimlink clear → '' (clear external_url)
            //   3rd-party                → keep existing external_url unchanged
            $extUrlForUpdate = null; // null = no change
            if ($shortService === 'default') {
                $oldSlug    = $oldRow['slug']    ?? '';
                $oldRandSub = $oldRow['rand_sub'] ?? '';
                $updDomain  = $domain ?: ($_SERVER['HTTP_HOST'] ?? 'localhost');
                $updScheme  = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
                $updHost    = $oldRandSub ? ($oldRandSub . '.' . $updDomain) : $updDomain;
                $updLocalUrl = $updScheme . '://' . $updHost . '/' . $oldSlug;
                $extUrlForUpdate = $shimlink !== '' ? slBuildShimlinkWrapperUrl($updLocalUrl, $shimlink) : '';
            }

            $uid = (int)($_SESSION['sl_uid'] ?? 0);
            try {
                // Note: redirect_url column is intentionally NOT touched here
                // — it's fully admin-owned now via data/config.json.
                if ($extUrlForUpdate !== null) {
                    $stmt = $db->prepare('UPDATE short_links SET title=?, description=?, image=?, default_url=?, country_rules=?, domain=?, smartlink_id=?, smartlink_ids=?, smartlink_network=?, shimlink=?, link_type=?, short_service=?, external_url=?, active=? WHERE id=? AND user_id=?');
                    $stmt->execute([$title, $description, $image, $defaultUrl, $countryRules, $domain, $smartlinkId, $smartlinkIds, $smartlinkNetwork, $shimlink, $linkType, $shortService, $extUrlForUpdate, $active, $id, $uid]);
                } else {
                    $stmt = $db->prepare('UPDATE short_links SET title=?, description=?, image=?, default_url=?, country_rules=?, domain=?, smartlink_id=?, smartlink_ids=?, smartlink_network=?, shimlink=?, link_type=?, short_service=?, active=? WHERE id=? AND user_id=?');
                    $stmt->execute([$title, $description, $image, $defaultUrl, $countryRules, $domain, $smartlinkId, $smartlinkIds, $smartlinkNetwork, $shimlink, $linkType, $shortService, $active, $id, $uid]);
                }
                $row = $db->prepare('SELECT * FROM short_links WHERE id = ? AND user_id = ?');
                $row->execute([$id, $uid]);
                $fetched = $row->fetch();
                if (is_array($fetched)) {
                    $fetched = slNormalizeLinkRow($fetched);
                }

                // ── Auto-scrape Facebook URL Linter on update ──
                $fbScrapeResult = null;
                if (is_array($fetched) && !empty($fetched['slug'])) {
                    $scheme     = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
                    $linkDomain = $fetched['domain'] ?: ($_SERVER['HTTP_HOST'] ?? 'localhost');
                    $sub        = $fetched['rand_sub'] ?? '';
                    $host       = $sub ? ($sub . '.' . $linkDomain) : $linkDomain;
                    $shortUrl   = $scheme . '://' . $host . '/' . $fetched['slug'];
                    $fb         = fbScrape($shortUrl);
                    $fbScrapeResult = [
                        'url'      => $shortUrl,
                        'ok'       => $fb['ok'],
                        'fb_title' => $fb['title'] ?? '',
                        'error'    => $fb['error'] ?? '',
                    ];
                }

                jsonOut(['success' => true, 'data' => $fetched, 'fb_scrape' => $fbScrapeResult]);
            } catch (PDOException $e) {
                jsonOut(['success' => false, 'message' => 'Failed to update link']);
            }
        }

        case 'delete_link': {
            $id  = (int)($input['id'] ?? 0);
            $uid = (int)($_SESSION['sl_uid'] ?? 0);
            if (!$id) {
                jsonOut(['success' => false, 'message' => 'Invalid ID']);
            }

            if (function_exists('tp_apcu_delete')) {
                $oldStmt = $db->prepare('SELECT slug FROM short_links WHERE id = ? AND user_id = ?');
                $oldStmt->execute([$id, $uid]);
                $oldRow = $oldStmt->fetch();
                if ($oldRow) {
                    tp_apcu_delete('sl_link_' . $oldRow['slug']);
                }
            }
            // Also drop the per-link version counter. Any stale
            // sl_url_{id}_v{N}_* entries from before deletion become
            // orphaned and will time out in 120s.
            if (function_exists('tp_apcu_delete')) {
                tp_apcu_delete('sl_link_ver_' . $id);
            }

            $db->prepare('DELETE FROM short_links WHERE id = ? AND user_id = ?')->execute([$id, $uid]);
            jsonOut(['success' => true]);
        }

        case 'list_users': {
            $rows = $db->query('SELECT id, username, domain, created_at FROM app_users ORDER BY id DESC')->fetchAll();
            jsonOut(['success' => true, 'data' => $rows]);
        }

        case 'list_smartlinks_sl': {
            try {
                $rows = $db->query('SELECT id, country, device, network, url FROM smartlinks ORDER BY id DESC')->fetchAll();
                jsonOut(['success' => true, 'data' => $rows]);
            } catch (PDOException $e) {
                jsonOut(['success' => true, 'data' => []]);
            }
        }

        case 'list_domains_sl': {
            $result   = [];
            $username = $_SESSION['sl_user'] ?? '';
            // Domains from addondomain: owned by this user + owned by admin (domain_id = '' or 'admin')
            try {
                $stmt = $db->prepare(
                    "SELECT id, sub_domain, domain_id, domain FROM addondomain
                     WHERE domain_id = '' OR domain_id = 'admin' OR domain_id = ?
                     ORDER BY id DESC"
                );
                $stmt->execute([$username]);
                $result = $stmt->fetchAll();
            } catch (PDOException $e) {
            }
            jsonOut(['success' => true, 'data' => $result]);
        }

        case 'update_user_domain': {
            $domain = trim($input['domain'] ?? '');
            $userId = (int)($input['id'] ?? $_SESSION['sl_uid'] ?? 0);
            if (!$userId) {
                jsonOut(['success' => false, 'message' => 'Invalid user']);
            }
            $db->prepare('UPDATE app_users SET domain = ? WHERE id = ?')->execute([$domain, $userId]);
            jsonOut(['success' => true, 'message' => 'Domain saved successfully']);
        }

        case 'create_sl_user': {
            $username = trim($input['username'] ?? '');
            $password = $input['password'] ?? '';
            if (!$username || !$password) {
                jsonOut(['success' => false, 'message' => 'Username and password are required']);
            }
            if (strlen($username) > 50 || !preg_match('/^[a-zA-Z0-9_.-]{3,50}$/', $username)) {
                jsonOut(['success' => false, 'message' => 'Invalid username (3–50 characters)']);
            }
            if (strlen($password) < 6) {
                jsonOut(['success' => false, 'message' => 'Password must be at least 6 characters']);
            }
            $hash = password_hash($password, PASSWORD_BCRYPT);
            try {
                $stmt = $db->prepare('INSERT INTO app_users (username, password_hash) VALUES (?, ?)');
                $stmt->execute([$username, $hash]);
                $newId = $db->lastInsertId();
                $row = $db->prepare('SELECT id, username, created_at FROM app_users WHERE id = ?');
                $row->execute([$newId]);
                jsonOut(['success' => true, 'data' => $row->fetch()]);
            } catch (PDOException $e) {
                if ($e->getCode() === '23000') {
                    jsonOut(['success' => false, 'message' => 'Username already taken']);
                }
                jsonOut(['success' => false, 'message' => 'Failed to create user']);
            }
        }

        case 'delete_sl_user': {
            $id = (int)($input['id'] ?? 0);
            if (!$id) {
                jsonOut(['success' => false, 'message' => 'Invalid ID']);
            }
            if ((int)$_SESSION['sl_uid'] === $id) {
                jsonOut(['success' => false, 'message' => 'Cannot delete your own account']);
            }
            $db->prepare('DELETE FROM app_users WHERE id = ?')->execute([$id]);
            jsonOut(['success' => true]);
        }

        case 'get_user_cf_config': {
            $uid  = (int)($_SESSION['sl_uid'] ?? 0);
            $stmt = $db->prepare('SELECT cf_token, cf_account_id, cf_zone_id, cf_proxied FROM app_users WHERE id = ? LIMIT 1');
            $stmt->execute([$uid]);
            $row = $stmt->fetch() ?: [];
            // Keep admin fallback on the server side in handler.php only.
            $result = [
                'cf_token'      => (string) ($row['cf_token'] ?? ''),
                'cf_account_id' => (string) ($row['cf_account_id'] ?? ''),
                'cf_zone_id'    => (string) ($row['cf_zone_id'] ?? ''),
                'cf_proxied'    => (string) ($row['cf_proxied'] ?? 'true'),
                'has_own'       => !empty($row['cf_token']),
            ];
            jsonOut(['success' => true, 'data' => $result]);
        }

        case 'save_user_cf_config': {
            $uid = (int)($_SESSION['sl_uid'] ?? 0);
            if (!$uid) {
                jsonOut(['success' => false, 'message' => 'Invalid user']);
            }
            $cfToken     = trim($input['cf_token']      ?? '');
            $cfAccountId = trim($input['cf_account_id'] ?? '');
            $cfZoneId    = trim($input['cf_zone_id']    ?? '');
            $cfProxied   = trim($input['cf_proxied']    ?? 'true');

            $db->prepare('UPDATE app_users SET cf_token = ?, cf_account_id = ?, cf_zone_id = ?, cf_proxied = ? WHERE id = ?')
               ->execute([$cfToken, $cfAccountId, $cfZoneId, $cfProxied, $uid]);

            // ── Auto-sync to config.json + .env when the saver IS the
            //    admin row. Keeps the admin dashboard UI, config.json
            //    and .env in lock-step with the DB across all 4 CF
            //    fields (cf_token, cf_account_id, cf_zone_id, cf_proxied).
            $adminSynced = false;
            try {
                $adminUsername = function_exists('tp_admin_username') ? tp_admin_username() : '';
                $sessionUsr    = trim((string) ($_SESSION['sl_user'] ?? ''));
                if ($adminUsername !== '' && strcasecmp($adminUsername, $sessionUsr) === 0) {
                    $configFile = __DIR__ . '/../data/config.json';
                    $savedCfg   = [];
                    if (is_file($configFile)) {
                        $savedCfg = json_decode((string) file_get_contents($configFile), true) ?: [];
                    }

                    // Write all 4 CF fields into config.json. If the
                    // incoming cf_token is empty, preserve whatever is
                    // currently stored (don't clobber the mask).
                    if ($cfToken !== '') {
                        $savedCfg['cf_token'] = $cfToken;
                    }
                    $savedCfg['cf_account_id'] = $cfAccountId;
                    $savedCfg['cf_zone_id']    = $cfZoneId;
                    $savedCfg['cf_proxied']    = $cfProxied !== '' ? $cfProxied : 'true';
                    @file_put_contents($configFile, json_encode($savedCfg, JSON_PRETTY_PRINT));

                    // Mirror the same 4 fields into .env. tp_env_file_set
                    // preserves existing values when the incoming entry
                    // is empty — so only real updates take effect.
                    if (function_exists('tp_env_file_set')) {
                        @tp_env_file_set(__DIR__ . '/../.env', [
                            'CF_TOKEN'      => $cfToken,
                            'CF_ACCOUNT_ID' => $cfAccountId,
                            'CF_ZONE_ID'    => $cfZoneId,
                            'CF_PROXIED'    => $cfProxied !== '' ? $cfProxied : 'true',
                        ]);
                    }
                    $adminSynced = true;
                }
            } catch (Throwable $e) {
                // Silent — DB save already succeeded.
            }

            jsonOut([
                'success'      => true,
                'message'      => 'CF configuration saved',
                'admin_synced' => $adminSynced,
            ]);
        }

        case 'list_user_domains': {
            $uid = (int)($_SESSION['sl_uid'] ?? 0);
            // Single query with LEFT JOIN eliminates N+1 pattern
            try {
                $stmt = $db->prepare(
                    'SELECT ud.id, ud.user_id, ud.domain, ud.created_at,
                            ad.id AS addondomain_id, ad.sub_domain
                     FROM user_domains ud
                     LEFT JOIN addondomain ad ON ad.domain = ud.domain
                     WHERE ud.user_id = ?
                     ORDER BY ud.id DESC'
                );
                $stmt->execute([$uid]);
                $rows = $stmt->fetchAll();
                foreach ($rows as &$row) {
                    $row['is_admin'] = false;
                    $adId = $row['addondomain_id'] ?? null;
                    $row['addondomain_id'] = $adId !== null ? (int)$adId : null;
                    $row['cf_status'] = $adId !== null
                        ? (($row['sub_domain'] ?? '') === 'GLOBAL' ? 'active' : 'pending')
                        : 'not_found';
                    unset($row['sub_domain']);
                }
                unset($row);
            } catch (PDOException $e) {
                $rows = [];
            }
            jsonOut(['success' => true, 'data' => $rows]);
        }

        case 'save_user_domain': {
            $uid    = (int)($_SESSION['sl_uid'] ?? 0);
            $domain = trim($input['domain'] ?? '');
            if (!$uid || !$domain) {
                jsonOut(['success' => false, 'message' => 'Invalid data']);
            }
            // Check for duplicate
            $chk = $db->prepare('SELECT id FROM user_domains WHERE user_id = ? AND domain = ? LIMIT 1');
            $chk->execute([$uid, $domain]);
            if ($chk->fetch()) {
                jsonOut(['success' => true, 'message' => 'Domain already saved']);
            }
            $db->prepare('INSERT INTO user_domains (user_id, domain) VALUES (?, ?)')->execute([$uid, $domain]);
            jsonOut(['success' => true, 'message' => 'Domain saved']);
        }

        case 'delete_user_domain': {
            $uid    = (int)($_SESSION['sl_uid'] ?? 0);
            $domain = trim($input['domain'] ?? '');
            if (!$uid || !$domain) {
                jsonOut(['success' => false, 'message' => 'Invalid data']);
            }
            // Cannot delete admin global domain
            $chkAdmin = $db->prepare('SELECT id FROM user_domains WHERE domain = ? AND user_id = 0 LIMIT 1');
            $chkAdmin->execute([$domain]);
            if ($chkAdmin->fetch()) {
                jsonOut(['success' => false, 'message' => 'Admin global domain cannot be deleted by users']);
            }
            $db->prepare('DELETE FROM user_domains WHERE user_id = ? AND domain = ?')->execute([$uid, $domain]);
            jsonOut(['success' => true]);
        }

            // ── Analytics ──

        case 'get_analytics': {
            $uid  = (int)($_SESSION['sl_uid'] ?? 0);
            $days = max(1, min(365, (int)($input['days'] ?? 30)));
            $slugF = preg_replace('/[^a-zA-Z0-9_-]/', '', $input['slug'] ?? '');
            $slugCond  = $slugF ? 'AND lh.slug = ?' : '';
            $baseParams = $slugF ? [$uid, $slugF] : [$uid];

            // Daily totals
            $stmt = $db->prepare("SELECT lh.hit_date AS d, SUM(lh.hits) AS h
                FROM link_hits lh JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = lh.slug COLLATE utf8mb4_unicode_ci
                WHERE sl.user_id = ? {$slugCond}
                AND lh.hit_date >= DATE_SUB(CURDATE(), INTERVAL {$days} DAY)
                GROUP BY lh.hit_date ORDER BY lh.hit_date ASC");
            $stmt->execute($baseParams);
            $dailyMap = [];
            foreach ($stmt->fetchAll() as $r) {
                $dailyMap[$r['d']] = (int)$r['h'];
            }
            $daily = [];
            for ($i = $days - 1; $i >= 0; $i--) {
                $d = date('Y-m-d', strtotime("-{$i} days"));
                $daily[] = ['date' => $d, 'hits' => $dailyMap[$d] ?? 0];
            }
            $total = array_sum(array_column($daily, 'hits'));

            $mk = function ($col, $alias) use ($db, $uid, $slugCond, $slugF, $days) {
                $p = $slugF ? [$uid, $slugF] : [$uid];
                $s = $db->prepare("SELECT lh.{$col} AS {$alias}, SUM(lh.hits) AS hits
                    FROM link_hits lh JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = lh.slug COLLATE utf8mb4_unicode_ci
                    WHERE sl.user_id = ? {$slugCond}
                    AND lh.hit_date >= DATE_SUB(CURDATE(), INTERVAL {$days} DAY)
                    AND lh.{$col} != '' GROUP BY lh.{$col} ORDER BY hits DESC LIMIT 20");
                $s->execute($p);
                return $s->fetchAll();
            };

            // Top links
            $lp = $slugF ? [$uid, $slugF] : [$uid];
            $lc = $slugF ? 'AND lh.slug = ?' : '';
            $ls = $db->prepare("SELECT lh.slug, sl.title, SUM(lh.hits) AS hits
                FROM link_hits lh JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = lh.slug COLLATE utf8mb4_unicode_ci
                WHERE sl.user_id = ? {$lc}
                AND lh.hit_date >= DATE_SUB(CURDATE(), INTERVAL {$days} DAY)
                GROUP BY lh.slug ORDER BY hits DESC LIMIT 20");
            $ls->execute($lp);

            jsonOut([
                'success'    => true,
                'total'      => $total,
                'daily'      => $daily,
                'by_country' => $mk('country', 'country'),
                'by_device'  => $mk('device', 'device'),
                'by_network' => $mk('network', 'network'),
                'by_link'    => $ls->fetchAll(),
            ]);
        }

            // ── Conversion Live Feed ──

        case 'get_live_feed': {
            $uid    = (int)($_SESSION['sl_uid'] ?? 0);
            $limit  = 100;
            $after  = (int)($input['after_click'] ?? 0);
            $afterC = (int)($input['after_conv'] ?? 0);
            $driver = $db->getAttribute(PDO::ATTR_DRIVER_NAME);

            $clicks      = [];
            $convs       = [];
            $stats       = ['clicks_24h' => 0, 'conversions_24h' => 0, 'revenue_24h' => 0.0, 'cr' => 0.0];

            if ($driver === 'mysql') {
                // Recent clicks — all users, include username
                $afterSql = $after ? "AND c.id > {$after}" : '';
                $st = $db->prepare("SELECT c.id, c.slug, c.clickid, c.subid, c.country, c.device,
                        c.network, c.payout, c.ip, c.created_at,
                        COALESCE(au.username,'—') AS username
                    FROM clicks c
                    LEFT JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = c.slug COLLATE utf8mb4_unicode_ci
                    LEFT JOIN app_users au ON au.id = sl.user_id
                    WHERE 1=1 {$afterSql}
                    ORDER BY c.id DESC LIMIT {$limit}");
                $st->execute([]);
                $clicks = $st->fetchAll();

                // Recent conversions — all users, include username
                $afterCSql = $afterC ? "AND v.id > {$afterC}" : '';
                $sv = $db->prepare("SELECT v.id, v.clickid, v.subid, v.slug, v.country, v.device,
                        v.network, v.payout, v.status, v.source_ip AS ip, v.created_at,
                        COALESCE(au.username,'—') AS username
                    FROM conversions v
                    LEFT JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = v.slug COLLATE utf8mb4_unicode_ci
                    LEFT JOIN app_users au ON au.id = sl.user_id
                    WHERE 1=1 {$afterCSql}
                    ORDER BY v.id DESC LIMIT {$limit}");
                $sv->execute([]);
                $convs = $sv->fetchAll();

                // Stats 24h — all users
                $sc = $db->query("SELECT COUNT(*) as n FROM clicks WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
                $scRow = $sc->fetch();

                $sconv = $db->query("SELECT COUNT(*) as n, COALESCE(SUM(payout),0) as rev FROM conversions WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
                $sconvRow = $sconv->fetch();

                $cl24 = (int)($scRow['n'] ?? 0);
                $cv24 = (int)($sconvRow['n'] ?? 0);
                $rev24 = (float)($sconvRow['rev'] ?? 0);
                $stats = [
                    'clicks_24h'      => $cl24,
                    'conversions_24h' => $cv24,
                    'revenue_24h'     => round($rev24, 4),
                    'cr'              => $cl24 > 0 ? round($cv24 / $cl24 * 100, 2) : 0,
                ];
            }

            jsonOut(['success' => true, 'clicks' => $clicks, 'conversions' => $convs, 'stats' => $stats]);
        }

            // ── Conversion Stats (date-range) ──

        case 'get_conv_stats': {
            $uid      = (int)($_SESSION['sl_uid'] ?? 0);
            $dateFrom = preg_replace('/[^0-9\-]/', '', $input['date_from'] ?? date('Y-m-d', strtotime('-30 days')));
            $dateTo   = preg_replace('/[^0-9\-]/', '', $input['date_to']   ?? date('Y-m-d'));
            $driver   = $db->getAttribute(PDO::ATTR_DRIVER_NAME);

            if ($driver !== 'mysql') {
                jsonOut(['success' => false, 'message' => 'Conversion stats require MySQL']);
            }

            // Validate date range: max 365 days, dateFrom must be <= dateTo
            try {
                $dfObj = new DateTime($dateFrom);
                $dtObj = new DateTime($dateTo);
                if ($dfObj > $dtObj) { $dateFrom = $dateTo; }
                if ($dfObj->diff($dtObj)->days > 365) {
                    $dateFrom = $dtObj->modify('-365 days')->format('Y-m-d');
                }
            } catch (Throwable $e) {
                $dateTo   = date('Y-m-d');
                $dateFrom = date('Y-m-d', strtotime('-30 days'));
            }

            try {
                // Total clicks (user-scoped via short_links join)
                $sc = $db->prepare("SELECT COUNT(*) FROM clicks c JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = c.slug COLLATE utf8mb4_unicode_ci WHERE sl.user_id = ? AND DATE(c.created_at) BETWEEN ? AND ?");
                $sc->execute([$uid, $dateFrom, $dateTo]);
                $totalClicks = (int)$sc->fetchColumn();

                // Total conversions + revenue (user-scoped)
                $sv = $db->prepare("SELECT COUNT(*) AS n, COALESCE(SUM(v.payout),0) AS rev FROM conversions v JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = v.slug COLLATE utf8mb4_unicode_ci WHERE sl.user_id = ? AND DATE(v.created_at) BETWEEN ? AND ?");
                $sv->execute([$uid, $dateFrom, $dateTo]);
                $cvRow = $sv->fetch();
                $totalConv = (int)($cvRow['n'] ?? 0);
                $totalRev  = round((float)($cvRow['rev'] ?? 0), 4);
                $cr = $totalClicks > 0 ? round($totalConv / $totalClicks * 100, 2) : 0;

                // Daily breakdown
                $d = new DateTime($dateFrom);
                $end = new DateTime($dateTo);
                $dateList = [];
                while ($d <= $end) { $dateList[] = $d->format('Y-m-d'); $d->modify('+1 day'); }

                $sdCl = $db->prepare("SELECT DATE(c.created_at) AS d, COUNT(*) AS n FROM clicks c JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = c.slug COLLATE utf8mb4_unicode_ci WHERE sl.user_id = ? AND DATE(c.created_at) BETWEEN ? AND ? GROUP BY DATE(c.created_at)");
                $sdCl->execute([$uid, $dateFrom, $dateTo]);
                $clMap = [];
                foreach ($sdCl->fetchAll() as $r) { $clMap[$r['d']] = (int)$r['n']; }

                $sdCv = $db->prepare("SELECT DATE(v.created_at) AS d, COUNT(*) AS n FROM conversions v JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = v.slug COLLATE utf8mb4_unicode_ci WHERE sl.user_id = ? AND DATE(v.created_at) BETWEEN ? AND ? GROUP BY DATE(v.created_at)");
                $sdCv->execute([$uid, $dateFrom, $dateTo]);
                $cvMap = [];
                foreach ($sdCv->fetchAll() as $r) { $cvMap[$r['d']] = (int)$r['n']; }

                // Daily payout breakdown
                $sdPay = $db->prepare("
                    SELECT DATE(v.created_at) AS d,
                           COALESCE(SUM(v.payout),0) AS rev,
                           COALESCE(SUM(CASE WHEN v.status='approved' THEN v.payout ELSE 0 END),0) AS approved,
                           COALESCE(SUM(CASE WHEN v.status='pending'  THEN v.payout ELSE 0 END),0) AS pending,
                           COALESCE(SUM(CASE WHEN v.status='rejected' THEN v.payout ELSE 0 END),0) AS rejected
                    FROM conversions v
                    JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = v.slug COLLATE utf8mb4_unicode_ci
                    WHERE sl.user_id = ? AND DATE(v.created_at) BETWEEN ? AND ?
                    GROUP BY DATE(v.created_at)
                ");
                $sdPay->execute([$uid, $dateFrom, $dateTo]);
                $payMap = [];
                foreach ($sdPay->fetchAll() as $r) {
                    $payMap[$r['d']] = ['payout' => round((float)$r['rev'],4), 'approved' => round((float)$r['approved'],4), 'pending' => round((float)$r['pending'],4), 'rejected' => round((float)$r['rejected'],4)];
                }

                $daily = [];
                foreach ($dateList as $day) {
                    $p = $payMap[$day] ?? ['payout'=>0,'approved'=>0,'pending'=>0,'rejected'=>0];
                    $daily[] = ['date' => $day, 'clicks' => $clMap[$day] ?? 0, 'conversions' => $cvMap[$day] ?? 0, 'payout' => $p['payout'], 'approved' => $p['approved'], 'pending' => $p['pending'], 'rejected' => $p['rejected']];
                }

                // By country (clicks)
                $sCo = $db->prepare("SELECT c.country, COUNT(*) AS n FROM clicks c JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = c.slug COLLATE utf8mb4_unicode_ci WHERE sl.user_id = ? AND DATE(c.created_at) BETWEEN ? AND ? AND c.country != '' GROUP BY c.country ORDER BY n DESC LIMIT 20");
                $sCo->execute([$uid, $dateFrom, $dateTo]);

                // By network (clicks)
                $sNe = $db->prepare("SELECT c.network, COUNT(*) AS n FROM clicks c JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = c.slug COLLATE utf8mb4_unicode_ci WHERE sl.user_id = ? AND DATE(c.created_at) BETWEEN ? AND ? AND c.network != '' GROUP BY c.network ORDER BY n DESC LIMIT 20");
                $sNe->execute([$uid, $dateFrom, $dateTo]);

                // By status (conversions)
                $sSt = $db->prepare("SELECT v.status, COUNT(*) AS n, COALESCE(SUM(v.payout),0) AS rev FROM conversions v JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = v.slug COLLATE utf8mb4_unicode_ci WHERE sl.user_id = ? AND DATE(v.created_at) BETWEEN ? AND ? GROUP BY v.status ORDER BY n DESC");
                $sSt->execute([$uid, $dateFrom, $dateTo]);

                // By slug (conversions)
                $sSl = $db->prepare("SELECT v.slug, COUNT(*) AS n, COALESCE(SUM(v.payout),0) AS rev FROM conversions v JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = v.slug COLLATE utf8mb4_unicode_ci WHERE sl.user_id = ? AND DATE(v.created_at) BETWEEN ? AND ? GROUP BY v.slug ORDER BY rev DESC LIMIT 20");
                $sSl->execute([$uid, $dateFrom, $dateTo]);

                // Subid breakdown (clicks + conversions merged)
                $sCvSub = $db->prepare("
                    SELECT COALESCE(v.subid,'') AS subid,
                           COUNT(v.id) AS conv_count,
                           COALESCE(SUM(v.payout),0) AS total_payout,
                           COALESCE(SUM(CASE WHEN v.status='approved' THEN v.payout ELSE 0 END),0) AS approved_payout,
                           COALESCE(SUM(CASE WHEN v.status='pending'  THEN v.payout ELSE 0 END),0) AS pending_payout,
                           COALESCE(SUM(CASE WHEN v.status='rejected' THEN v.payout ELSE 0 END),0) AS rejected_payout
                    FROM conversions v
                    JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = v.slug COLLATE utf8mb4_unicode_ci
                    WHERE sl.user_id = ? AND DATE(v.created_at) BETWEEN ? AND ?
                    GROUP BY v.subid
                    ORDER BY total_payout DESC
                ");
                $sCvSub->execute([$uid, $dateFrom, $dateTo]);

                $sClSub = $db->prepare("
                    SELECT COALESCE(c.subid,'') AS subid, COUNT(c.id) AS click_count
                    FROM clicks c
                    JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = c.slug COLLATE utf8mb4_unicode_ci
                    WHERE sl.user_id = ? AND DATE(c.created_at) BETWEEN ? AND ?
                    GROUP BY c.subid
                ");
                $sClSub->execute([$uid, $dateFrom, $dateTo]);

                // Merge
                $merged = [];
                foreach ($sCvSub->fetchAll() as $r) {
                    $merged[$r['subid']] = [
                        'subid'           => (string)$r['subid'],
                        'click_count'     => 0,
                        'conv_count'      => (int)$r['conv_count'],
                        'total_payout'    => (float)$r['total_payout'],
                        'approved_payout' => (float)$r['approved_payout'],
                        'pending_payout'  => (float)$r['pending_payout'],
                        'rejected_payout' => (float)$r['rejected_payout'],
                    ];
                }
                foreach ($sClSub->fetchAll() as $r) {
                    $key = $r['subid'];
                    if (!isset($merged[$key])) {
                        $merged[$key] = [
                            'subid'           => (string)$key,
                            'click_count'     => (int)$r['click_count'],
                            'conv_count'      => 0,
                            'total_payout'    => 0.0,
                            'approved_payout' => 0.0,
                            'pending_payout'  => 0.0,
                            'rejected_payout' => 0.0,
                        ];
                    } else {
                        $merged[$key]['click_count'] = (int)$r['click_count'];
                    }
                }
                $bySubid = array_values($merged);
                usort($bySubid, static function (array $a, array $b): int {
                    if ($a['total_payout'] !== $b['total_payout']) return $b['total_payout'] <=> $a['total_payout'];
                    return $b['click_count'] <=> $a['click_count'];
                });

                jsonOut([
                    'success'      => true,
                    'total_clicks' => $totalClicks,
                    'total_conv'   => $totalConv,
                    'total_rev'    => $totalRev,
                    'cr'           => $cr,
                    'daily'        => $daily,
                    'by_country'   => $sCo->fetchAll(),
                    'by_network'   => $sNe->fetchAll(),
                    'by_status'    => $sSt->fetchAll(),
                    'by_slug'      => $sSl->fetchAll(),
                    'by_subid'     => $bySubid,
                ]);
            } catch (Throwable $e) {
                jsonOut(['success' => false, 'message' => $e->getMessage()]);
            }
        }

            // ── Postbacks ──

        case 'list_postbacks': {
            $uid  = (int)($_SESSION['sl_uid'] ?? 0);
            $stmt = $db->prepare('SELECT * FROM postbacks WHERE user_id = ? ORDER BY id DESC');
            $stmt->execute([$uid]);
            jsonOut(['success' => true, 'data' => $stmt->fetchAll()]);
        }

        case 'create_postback': {
            $uid   = (int)($_SESSION['sl_uid'] ?? 0);
            $name  = trim($input['name'] ?? '');
            $slug  = preg_replace('/[^a-zA-Z0-9_-]/', '', $input['slug'] ?? '');
            $url   = trim($input['url'] ?? '');
            $event = in_array($input['event'] ?? '', ['click', 'conversion'], true) ? $input['event'] : 'click';
            $active = isset($input['active']) ? (int)(bool)$input['active'] : 1;
            // Strip placeholders for URL validation, then validate structure
            $urlCheck = tp_postback_url_for_validation($url);
            if (!$url || !filter_var($urlCheck, FILTER_VALIDATE_URL)) {
                jsonOut(['success' => false, 'message' => 'Invalid postback URL']);
            }
            $db->prepare('INSERT INTO postbacks (user_id, name, slug, url, event, active) VALUES (?,?,?,?,?,?)')
               ->execute([$uid, $name, $slug, $url, $event, $active]);
            $id  = $db->lastInsertId();
            $row = $db->prepare('SELECT * FROM postbacks WHERE id = ?');
            $row->execute([$id]);
            jsonOut(['success' => true, 'data' => $row->fetch()]);
        }

        case 'update_postback': {
            $uid   = (int)($_SESSION['sl_uid'] ?? 0);
            $id    = (int)($input['id'] ?? 0);
            $name  = trim($input['name'] ?? '');
            $slug  = preg_replace('/[^a-zA-Z0-9_-]/', '', $input['slug'] ?? '');
            $url   = trim($input['url'] ?? '');
            $event = in_array($input['event'] ?? '', ['click', 'conversion'], true) ? $input['event'] : 'click';
            $active = isset($input['active']) ? (int)(bool)$input['active'] : 1;
            if (!$id) {
                jsonOut(['success' => false, 'message' => 'Invalid ID']);
            }
            $urlCheck = tp_postback_url_for_validation($url);
            if (!$url || !filter_var($urlCheck, FILTER_VALIDATE_URL)) {
                jsonOut(['success' => false, 'message' => 'Invalid postback URL']);
            }
            $db->prepare('UPDATE postbacks SET name=?,slug=?,url=?,event=?,active=? WHERE id=? AND user_id=?')
               ->execute([$name, $slug, $url, $event, $active, $id, $uid]);
            jsonOut(['success' => true, 'message' => 'Postback updated']);
        }

        case 'delete_postback': {
            $uid = (int)($_SESSION['sl_uid'] ?? 0);
            $id  = (int)($input['id'] ?? 0);
            if (!$id) {
                jsonOut(['success' => false, 'message' => 'Invalid ID']);
            }
            $db->prepare('DELETE FROM postbacks WHERE id = ? AND user_id = ?')->execute([$id, $uid]);
            jsonOut(['success' => true]);
        }

        case 'test_postback': {
            $url = trim($input['url'] ?? '');
            if (!$url || !filter_var(tp_postback_url_for_validation($url), FILTER_VALIDATE_URL)) {
                jsonOut(['success' => false, 'message' => 'Invalid or empty URL']);
            }
            $testId  = 'TEST_' . time();
            $testUrl = tp_replace_postback_placeholders($url, [
                'subid' => 'testuser',
                'sid' => 'testuser',
                'sub_id' => 'testuser',
                's' => 'testuser',
                'clickid' => $testId,
                'cid' => $testId,
                'click_id' => $testId,
                'c' => $testId,
                'country' => 'ID',
                'device' => 'wap',
                'network' => 'fb',
                'slug' => 'test123',
                'payout' => '0.10',
                'status' => 'approved',
            ]);
            $ch = curl_init($testUrl);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 8,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 5,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_USERAGENT      => 'PostbackTester/1.0',
            ]);
            $resp = curl_exec($ch);
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $err  = curl_error($ch);
            curl_close($ch);
            jsonOut([
                'success'   => !$err && $code >= 200 && $code < 400,
                'http_code' => $code,
                'url'       => $testUrl,
                'error'     => $err ?: null,
                'response'  => $resp ? substr((string)$resp, 0, 300) : null,
            ]);
        }

        default:
            jsonOut(['success' => false, 'message' => 'Unknown action'], 400);
    }
}

// ── Prepare page data ──
$db = slDb();
$setupMode   = false;
$initUserCount = 0;
if ($db) {
    ensureSlTables($db);
    $initUserCount = (int)$db->query('SELECT COUNT(*) FROM app_users')->fetchColumn();
    $setupMode = ($initUserCount === 0);
}

ob_end_clean();
?>
<!DOCTYPE html>
<html lang="en" class="antialiased">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title><?= htmlspecialchars($_SESSION['sl_user'] ?? 'User', ENT_QUOTES, 'UTF-8') ?> Dashboard</title>

    <!-- PWA -->
    <link rel="manifest" href="/manifest.json">
    <meta name="theme-color" content="#0f0f14">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content=".0089">
    <!-- Favicons -->
    <link rel="icon" href="/favicon.ico" sizes="any">
    <link rel="icon" type="image/png" sizes="16x16" href="/assets/favicon-16x16.png">
    <link rel="icon" type="image/png" sizes="32x32" href="/assets/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="192x192" href="/assets/android-chrome-192x192.png">
    <link rel="apple-touch-icon" sizes="180x180" href="/assets/apple-touch-icon.png">

    <link rel="stylesheet" href="/assets/vendor/tailwind-3.4.17.css">
    <link rel="stylesheet" href="/assets/style.css">
    <link rel="stylesheet" href="/assets/flags/flags.css?v=<?= @filemtime(__DIR__ . '/../assets/flags/flags.css') ?: time() ?>">
    <script src="/assets/vendor/chart-4.4.2.umd.js"></script>
    <script src="/assets/vendor/alpine-3.15.11.min.js" defer></script>
</head>
<body class="min-h-screen antialiased text-foreground" x-data="slApp" x-init="init()">

<script<?php echo $nonceAttr; ?>>
    const INIT_AUTH   = <?php echo json_encode(!empty($_SESSION['sl_uid'])) ?>;
    const BASE_URL    = <?php echo json_encode(tp_public_base_url((string) getenv('CPANEL_DOMAIN'))) ?>;
    const SETUP_MODE  = <?php echo json_encode($setupMode) ?>;
    const CURRENT_USER = <?php echo json_encode($_SESSION['sl_user'] ?? '') ?>;
    const CSRF_TOKEN  = <?php echo json_encode($csrfToken) ?>;
</script>

<!-- ══════════════════════════════════════════════════════
     LOGIN PAGE
══════════════════════════════════════════════════════ -->
<div x-show="!isLoggedIn" x-cloak class="auth-shell">
    <div class="auth-card-wrap">
        <!-- Login card -->
        <div class="auth-card">
            <div class="auth-head">
                <div class="auth-logo">
                    <img src="/assets/logo.png" width="28" height="28" alt="Logo">
                </div>
                <h1 class="auth-title">Dashboard Login</h1>
                <p class="auth-subtitle" x-text="setupMode ? 'Create first admin account' : 'Manage your short links'"></p>
            </div>

            <!-- Setup Mode: Create admin account -->
            <form x-show="setupMode" @submit.prevent="doSetup()">
                <div class="auth-alert auth-alert-warning mb-3">
                    First install — create an admin account to continue.
                </div>
                <div class="mb-3">
                    <label class="field-label">Admin Username</label>
                    <input type="text" x-model="setupForm.username" autocomplete="username"
                        placeholder="Enter username"
                        class="input">
                </div>
                <div class="mb-4">
                    <label class="field-label">Password</label>
                    <div class="relative">
                        <input :type="setupForm.showPw ? 'text' : 'password'"
                            x-model="setupForm.password" autocomplete="new-password"
                            placeholder="Minimum 6 characters"
                            class="input pr-10">
                        <button type="button" @click="toggleSetupPassword()"
                            class="input-icon-btn">
                            <svg aria-hidden="true" x-show="!setupForm.showPw" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                            </svg>
                            <svg x-show="setupForm.showPw" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 4.411m0 0L21 21"/>
                            </svg>
                        </button>
                    </div>
                </div>
                <div x-show="setupForm.error" class="auth-alert auth-alert-error mb-3" x-text="setupForm.error"></div>
                <button type="submit" :disabled="setupForm.loading"
                    class="btn btn-default btn-default-size w-full flex items-center justify-center gap-2">
                    <div x-show="setupForm.loading" class="spinner w-4 h-4"></div>
                    <span x-text="setupForm.loading ? 'Creating...' : 'Create Admin Account'"></span>
                </button>
            </form>

            <!-- Normal login -->
            <form x-show="!setupMode" @submit.prevent="doLogin()">
                <div class="mb-3">
                    <label class="field-label">Username</label>
                    <input type="text" x-model="loginForm.username" autocomplete="username"
                        placeholder="Enter username" autofocus
                        class="input">
                </div>
                <div class="mb-4">
                    <label class="field-label">Password</label>
                    <div class="relative">
                        <input :type="loginForm.showPw ? 'text' : 'password'"
                            x-model="loginForm.password" autocomplete="current-password"
                            placeholder="Enter password"
                            class="input pr-10">
                        <button type="button" @click="toggleLoginPassword()"
                            class="input-icon-btn">
                            <svg x-show="!loginForm.showPw" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                            </svg>
                            <svg x-show="loginForm.showPw" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 4.411m0 0L21 21"/>
                            </svg>
                        </button>
                    </div>
                </div>

                <div x-show="loginForm.error" class="auth-alert auth-alert-error mb-3" x-text="loginForm.error"></div>

                <button type="submit" :disabled="loginForm.loading"
                    class="btn btn-default btn-default-size w-full flex items-center justify-center gap-2">
                    <div x-show="loginForm.loading" class="spinner w-4 h-4"></div>
                    <span x-text="loginForm.loading ? 'Signing in...' : 'Sign In'"></span>
                </button>
            </form>
        </div>
    </div>
</div>

<!-- ══════════════════════════════════════════════════════
     DASHBOARD
══════════════════════════════════════════════════════ -->
<div x-show="isLoggedIn" x-cloak class="min-h-screen flex flex-col">

    <!-- Header -->
    <header class="sticky top-0 z-30">
        <div class="max-w-7xl mx-auto px-4 h-12 flex items-center justify-between gap-3">
            <div class="flex items-center gap-2.5">
                <img src="/assets/logo.png" class="w-6 h-6" alt="Logo">
                <div>
                    <p class="text-[13px] font-semibold leading-none tracking-tight" x-text="currentUser + ' Dashboard'"></p>
                    <p class="text-[10px] text-muted-foreground mt-0.5">No "smart" buzzword without actual routing logic.</p>
                </div>
            </div>
            <div class="flex items-center gap-2">
                <button @click="doLogout()"
                    class="btn btn-outline btn-sm flex items-center gap-1.5 text-destructive border-destructive/30 hover:bg-destructive/10">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                    </svg>
                    Sign Out
                </button>
            </div>
        </div>
    </header>

    <!-- Tab nav -->
    <div class="tab-nav-bar">
        <div class="max-w-7xl mx-auto px-4">
            <nav class="tab-nav-list" role="tablist">

                <!-- Links -->
                <button class="tab-btn" role="tab"
                    :class="{ active: mainTab === 'links' }"
                    :aria-selected="mainTab === 'links'"
                    @click="mainTab = 'links'">
                    <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/>
                    </svg>
                    Links
                </button>

                <!-- Domain -->
                <button class="tab-btn" role="tab"
                    :class="{ active: mainTab === 'domains' }"
                    :aria-selected="mainTab === 'domains'"
                    @click="switchMainTab('domains')">
                    <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9"/>
                    </svg>
                    Domain
                    <span x-show="userDomains.length > 0"
                        class="tab-badge tab-badge-dark"
                        x-text="userDomains.length"></span>
                </button>

                <!-- Analytics -->
                <button class="tab-btn" role="tab"
                    :class="{ active: mainTab === 'analytics' }"
                    :aria-selected="mainTab === 'analytics'"
                    @click="switchMainTab('analytics')">
                    <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>
                    </svg>
                    Analytics
                </button>

                <!-- Statistics -->
                <button class="tab-btn" role="tab"
                    :class="{ active: mainTab === 'conversion' }"
                    :aria-selected="mainTab === 'conversion'"
                    @click="switchMainTab('conversion')">
                    <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    Statistics
                    <span x-show="conv.newConvCount > 0"
                        class="tab-badge tab-badge-emerald"
                        x-text="conv.newConvCount"></span>
                </button>

            </nav>
        </div>
    </div>

    <!-- Main content -->
    <main class="flex-1 max-w-7xl mx-auto w-full px-4 py-4">

        <!-- ── TAB: LINKS ── -->
        <div x-show="mainTab === 'links'" x-cloak
             x-transition:enter="tab-enter" x-transition:enter-start="tab-enter-start" x-transition:enter-end="tab-enter-end">
            <div class="grid grid-cols-1 lg:grid-cols-5 gap-4">

                <!-- Form -->
                <div class="lg:col-span-2">
                    <div class="sl-card">
                        <div class="sl-card-header">
                            <div class="sl-card-header-left">
                                <h2 class="sl-card-title" x-text="linkForm.id ? 'Edit Link' : 'Create Link'"></h2>
                            </div>
                        </div>
                        <form @submit.prevent="saveLink()" class="sl-card-body space-y-3">

                            <!-- Domain · Smartlink · Shimlink — 3 kolom -->
                            <div class="grid grid-cols-3 gap-2">

                                <!-- Domain -->
                                <div class="flex flex-col gap-1">
                                    <label class="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Domain</label>
                                    <select x-model="linkForm.domain"
                                        class="sl-input sl-select text-[11px]"
                                        :class="linkForm.domain === '__random__' ? 'border-blue-400' : (linkForm.domain ? 'border-emerald-400' : '')">
                                        <option value="">Default</option>
                                        <template x-if="domains.length > 1">
                                            <option value="__random__">⟳ Random Domain</option>
                                        </template>
                                        <template x-for="d in domains" :key="d.id">
                                            <option :value="d.domain" x-text="d.domain"></option>
                                        </template>
                                    </select>
                                    <p class="text-[10px] leading-tight flex items-center gap-1"
                                        :class="linkForm.domain === '__random__' ? 'text-blue-600' : (linkForm.domain ? 'text-emerald-600 truncate' : 'text-muted-foreground')">
                                        <svg x-show="linkForm.domain === '__random__'" class="w-3 h-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                                        <span x-text="linkForm.domain === '__random__' ? ('Random from ' + domains.length + ' domains') : (linkForm.domain || 'System default')"></span>
                                    </p>
                                </div>

                                <!-- Smartlink -->
                                <div class="flex flex-col gap-1">
                                    <label class="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Smartlink</label>
                                    <select x-model="linkForm.smartlink_network"
                                        class="sl-input sl-select text-[11px]"
                                        :class="linkForm.smartlink_network ? 'border-blue-400' : ''">
                                        <option value="">— Network —</option>
                                        <template x-for="net in uniqueSmartlinkNetworks()" :key="net">
                                            <option :value="net"
                                                x-text="net.charAt(0).toUpperCase() + net.slice(1)"></option>
                                        </template>
                                    </select>
                                    <p class="text-[10px] leading-tight"
                                        :class="linkForm.smartlink_network ? 'text-emerald-600 truncate' : 'text-amber-500'"
                                        x-text="linkForm.smartlink_network ? '✓ ' + linkForm.smartlink_network : '— inactive'"></p>
                                </div>

                                <!-- Shimlink -->
                                <div class="flex flex-col gap-1">
                                    <label class="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Shimlink</label>
                                    <select x-model="linkForm.shimlink"
                                        class="sl-input sl-select text-[11px]"
                                        :class="linkForm.shimlink ? 'border-purple-400' : ''">
                                        <option value="">— None —</option>
                                        <option value="wl">l.wl.co</option>
                                        <option value="fb">l.fb.com</option>
                                    </select>
                                    <p class="text-[10px] leading-tight"
                                        :class="linkForm.shimlink === 'wl' ? 'text-purple-600' : linkForm.shimlink === 'fb' ? 'text-blue-600' : 'text-muted-foreground'"
                                        x-text="linkForm.shimlink === 'wl' ? '→ l.wl.co' : linkForm.shimlink === 'fb' ? '→ l.facebook.com' : 'No wrapper'"></p>
                                </div>

                            </div>

                            <!-- Link Type · Short Service — 2 kolom -->
                            <div class="grid grid-cols-2 gap-2">

                                <!-- Link Type -->
                                <div>
                                    <label class="field-label">Link Type</label>
                                    <select x-model="linkForm.link_type"
                                        class="sl-input sl-select text-[12px]"
                                        :class="linkForm.link_type === 'lp' ? 'border-orange-400' : ''">
                                        <option value="normal">Normal</option>
                                        <option value="lp">Landing Page</option>
                                    </select>
                                </div>

                                <!-- Short Service -->
                                <div>
                                    <label class="field-label">Short Service</label>
                                    <select x-model="linkForm.short_service" class="sl-input sl-select text-[12px]">
                                        <option value="default">Default</option>
                                        <option value="ixg">IXG</option>
                                        <option value="isgd">is.gd</option>
                                        <!-- v.gd removed -->
                                        <option value="tinyurl">TinyURL</option>
                                    </select>
                                </div>

                            </div>

                            <!-- OG Fields -->
                            <div>
                                <label class="field-label">OG Title</label>
                                <input type="text" x-model="linkForm.title" placeholder="Link title…" class="sl-input">
                            </div>
                            <div>
                                <label class="field-label">OG Description</label>
                                <textarea x-model="linkForm.description" rows="2" placeholder="Short description…"
                                    class="sl-input sl-textarea-compact resize-none"></textarea>
                            </div>
                            <div>
                                <label class="field-label">OG Image URL</label>
                                <input type="url" x-model="linkForm.image" placeholder="https://…" class="sl-input">
                            </div>

                            <!-- Active (hidden, always active) -->
                            <input type="hidden" name="active" value="1" x-model="linkForm.active">

                            <!-- Message -->
                            <div x-show="linkMsg" class="p-2.5 rounded-md text-xs"
                                :class="linkOk ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' : 'bg-destructive/10 text-destructive border border-destructive/20'"
                                x-text="linkMsg"></div>

                            <!-- Bulk Quantity + Submit aligned -->
                            <div class="flex items-end gap-2 pt-0.5">

                                <!-- Quantity input - only shown when creating new links -->
                                <div x-show="!linkForm.id" class="flex flex-col gap-1 shrink-0">
                                    <label class="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Qty</label>
                                    <div class="flex items-center gap-1">
                                        <input type="number" x-model.number="linkForm.quantity" min="1" max="50"
                                            class="sl-input w-12 text-center font-mono">
                                        <span class="text-[10px] text-muted-foreground">/50</span>
                                    </div>
                                </div>

                                <!-- Tombol Submit -->
                                <button type="submit" :disabled="linkLoading"
                                    class="btn btn-default btn-sm flex-1 flex items-center justify-center gap-1.5">
                                    <div x-show="linkLoading" class="spinner w-3 h-3"></div>
                                    <span x-text="linkForm.id ? 'Update' : (linkForm.quantity > 1 ? 'Create ' + linkForm.quantity + ' Links' : 'Create Link')"></span>
                                </button>

                                <!-- Cancel (edit mode) -->
                                <button x-show="linkForm.id" type="button" @click="resetLinkForm({ full: true })"
                                    class="btn btn-outline btn-sm shrink-0">
                                    Cancel
                                </button>

                            </div>
                        </form>
                    </div>
                </div>

                <!-- Bulk Result -->
                <div x-show="showBulkResult && bulkResult.length > 0" x-cloak
                    class="lg:col-span-2 sl-card border-emerald-300">
                    <div class="px-4 py-3 border-b border-emerald-200 bg-emerald-50 flex items-center justify-between">
                        <div class="flex items-center gap-2">
                            <svg class="w-4 h-4 text-emerald-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                            <h2 class="text-sm font-semibold text-emerald-800">
                                Bulk Result — <span x-text="bulkResult.length"></span> links created successfully
                            </h2>
                        </div>
                        <div class="flex items-center gap-2">
                            <button @click="copyAllBulkLinks()" type="button"
                                class="text-xs px-2.5 py-1 bg-emerald-600 text-white rounded-md hover:bg-emerald-700 transition-colors flex items-center gap-1">
                                <svg aria-hidden="true" class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/></svg>
                                Copy All
                            </button>
                            <button @click="showBulkResult = false" type="button"
                                class="icon-action-btn">
                                <svg aria-hidden="true" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M6 18L18 6M6 6l12 12"/></svg>
                            </button>
                        </div>
                    </div>
                            <div class="divide-y divide-border max-h-64 overflow-y-auto">
                        <template x-for="(lnk, i) in bulkResult" :key="lnk.id">
                            <div class="flex items-center gap-2 px-3 py-2 hover:bg-secondary/30 transition-colors">
                                <span class="text-xs text-muted-foreground w-5 shrink-0" x-text="i+1"></span>
                                <div class="min-w-0 flex-1">
                                    <div class="flex items-center gap-1.5 flex-wrap">
                                        <span class="font-mono text-xs text-foreground truncate" x-text="linkUrl(lnk)"></span>
                                    </div>
                                </div>
                                <button @click="copyLink(lnk)" type="button"
                                    class="icon-action-btn">
                                    <svg x-show="copyFeedback !== lnk.slug" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/></svg>
                                    <svg x-show="copyFeedback === lnk.slug" class="w-3.5 h-3.5 text-emerald-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>
                                </button>
                            </div>
                        </template>
                    </div>
                    <div x-show="bulkErrors.length > 0" class="px-3 py-2 bg-destructive/5 border-t border-destructive/20">
                        <p class="text-xs text-destructive font-medium mb-1">Error:</p>
                        <template x-for="err in bulkErrors" :key="err">
                            <p class="text-xs text-destructive" x-text="err"></p>
                        </template>
                    </div>
                </div>

                <!-- Table -->
                <div class="lg:col-span-3" x-show="!showBulkResult" x-cloak>
                    <div class="sl-card">
                        <div class="sl-card-header">
                            <div class="sl-card-header-left">
                                <h2 class="sl-card-title">Link List</h2>
                                <span class="sl-card-count" x-text="links.length"></span>
                            </div>
                            <div class="sl-card-header-right">
                                <button @click="loadLinks()" :disabled="linksLoading" class="sl-card-refresh">
                                    <svg class="w-3.5 h-3.5" :class="{ 'animate-spin': linksLoading }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                                    </svg>
                                    Refresh
                                </button>
                            </div>
                        </div>

                        <!-- Loading (initial) -->
                        <div x-show="linksLoading" class="flex items-center justify-center py-12 gap-2 text-muted-foreground text-sm">
                            <div class="spinner w-5 h-5"></div>
                            <span>Loading...</span>
                        </div>

                        <!-- Empty -->
                        <div x-show="!linksLoading && links.length === 0" class="empty-state empty-state-panel">
                            <div class="empty-state-icon">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/>
                            </svg>
                            </div>
                            <p class="empty-state-title">No links yet</p>
                        </div>

                        <!-- Table -->
                        <div x-show="!linksLoading && links.length > 0" class="relative">
                            <!-- Refreshing fade-in overlay -->
                            <div x-show="linksRefreshing"
                                 x-transition:enter="transition ease-out duration-200"
                                 x-transition:enter-start="opacity-0"
                                 x-transition:enter-end="opacity-100"
                                 x-transition:leave="transition ease-in duration-150"
                                 x-transition:leave-start="opacity-100"
                                 x-transition:leave-end="opacity-0"
                                 class="absolute inset-0 z-10 flex items-center justify-center bg-background/60 backdrop-blur-[1px] rounded">
                                <span class="text-xs text-muted-foreground font-medium">Updating...</span>
                            </div>
                            <div class="overflow-x-auto" :class="{ 'opacity-50 pointer-events-none': linksRefreshing }">
                            <table class="w-full tbl text-xs">
                                <thead>
                                    <tr>
                                        <th scope="col" class="w-8">#</th>
                                        <th scope="col">Shortlink</th>
                                        <th scope="col">Title</th>
                                        <th scope="col" class="text-right">Hits</th>
                                        <th scope="col" class="text-center">Status</th>
                                        <th scope="col" class="text-right w-16">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <template x-for="(link, i) in pagedLinks" :key="link.id">
                                        <tr class="border-b border-border last:border-0 hover:bg-secondary/30 transition-colors"
                                            :class="newLinkIds.includes(link.id) && 'sl-row-new'">
                                            <td class="px-2 py-1.5 text-muted-foreground" x-text="(linksPage-1)*linksPerPage + i + 1"></td>
                                            <td class="px-3 py-1.5">
                                                <div class="flex items-center gap-1.5 flex-wrap">
                                                    <button @click="copyLink(link)"
                                                        class="icon-action-btn"
                                                        :title="'Copy: ' + linkUrl(link)">
                                                        <svg aria-hidden="true" x-show="copyFeedback !== link.slug" class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/>
                                                        </svg>
                                                        <svg x-show="copyFeedback === link.slug" class="w-3 h-3 text-emerald-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/>
                                                        </svg>
                                                    </button>
                                                    <span class="font-mono text-foreground font-semibold" x-text="link.slug"></span>
                                                    <span x-show="link.smartlink_network"
                                                        :class="{
                                                            'bg-emerald-100 text-emerald-700': link.smartlink_network === 'iMonetizeit',
                                                            'bg-blue-100 text-blue-700':      link.smartlink_network === 'Lospollos',
                                                            'bg-orange-100 text-orange-600':  link.smartlink_network === 'Trafee',
                                                            'bg-secondary text-muted-foreground': !['iMonetizeit','Lospollos','Trafee'].includes(link.smartlink_network)
                                                        }"
                                                        class="text-[10px] px-1.5 py-0 rounded font-medium"
                                                        x-text="link.smartlink_network"></span>
                                                    <span x-show="link.short_service && link.short_service !== 'default' && link.short_service !== 'own'"
                                                        class="text-[10px] bg-violet-100 text-violet-700 px-1.5 py-0 rounded font-medium"
                                                        x-text="link.short_service"></span>
                                                    <span x-show="link.shimlink === 'wl'"
                                                        class="text-[10px] bg-purple-100 text-purple-700 px-1.5 py-0 rounded font-medium">l.wl.co</span>
                                                    <span x-show="link.shimlink === 'fb'"
                                                        class="text-[10px] bg-blue-100 text-blue-600 px-1.5 py-0 rounded font-medium">l.fb.com</span>
                                                    <span x-show="link.link_type === 'lp'"
                                                        class="text-[10px] bg-orange-100 text-orange-700 px-1.5 py-0 rounded font-medium">LP</span>
                                                </div>
                                            </td>
                                            <td class="px-3 py-1.5 text-foreground max-w-[200px]">
                                                <div class="min-w-0">
                                                    <p class="truncate" :title="link.title" x-text="link.title || '—'"></p>
                                                </div>
                                            </td>
                                            <td class="px-3 py-1.5 text-right text-foreground font-mono" x-text="Number(link.hits).toLocaleString()"></td>
                                            <td class="px-3 py-1.5 text-center">
                                                <span :class="link.active == 1 ? 'bg-emerald-100 text-emerald-700' : 'bg-secondary text-muted-foreground'"
                                                    class="px-2 py-0.5 rounded-full text-xs font-medium"
                                                    x-text="link.active == 1 ? 'Active' : 'Off'"></span>
                                            </td>
                                            <td class="px-2 py-1.5">
                                                <div class="flex items-center justify-end gap-0.5">
                                                    <button @click="editLink(link)"
                                                        class="icon-action-btn" title="Edit" aria-label="Edit">
                                                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
                                                        </svg>
                                                    </button>
                                                    <button @click="deleteLink(link.id)"
                                                        :disabled="deletingLinkId === link.id"
                                                        class="icon-action-btn-danger" title="Delete" aria-label="Delete">
                                                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                                                        </svg>
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    </template>
                                </tbody>
                            </table>
                            </div>
                        </div>

                        <!-- Pagination -->
                        <div x-show="linksTotalPages > 1"
                            class="px-4 py-2.5 border-t border-border flex items-center justify-between gap-2">
                            <span class="text-xs text-muted-foreground">
                                <span x-text="(linksPage-1)*linksPerPage+1"></span>–<span x-text="Math.min(linksPage*linksPerPage,links.length)"></span>
                                of <span x-text="links.length"></span>
                            </span>
                            <div class="flex items-center gap-1">
                                <button @click="linksPage=1" :disabled="linksPage===1"
                                    class="pg-btn" title="First">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 19l-7-7 7-7m8 14l-7-7 7-7"/></svg>
                                </button>
                                <button @click="linksPage--" :disabled="linksPage===1"
                                    class="pg-btn" title="Previous">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/></svg>
                                </button>
                                <span class="text-xs text-foreground px-2 font-medium">
                                    <span x-text="linksPage"></span> / <span x-text="linksTotalPages"></span>
                                </span>
                                <button @click="linksPage++" :disabled="linksPage===linksTotalPages"
                                    class="pg-btn" title="Next">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
                                </button>
                                <button @click="linksPage=linksTotalPages" :disabled="linksPage===linksTotalPages"
                                    class="pg-btn" title="Last">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 5l7 7-7 7M5 5l7 7-7 7"/></svg>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <!-- /TAB: LINKS -->

        <!-- /TAB: USERS (removed) -->

        <!-- ── TAB: DOMAINS ── -->
        <div x-show="mainTab === 'domains'" x-cloak
             x-transition:enter="tab-enter" x-transition:enter-start="tab-enter-start" x-transition:enter-end="tab-enter-end">
            <div class="grid grid-cols-1 lg:grid-cols-5 gap-5">

                <!-- Add Domain Form -->
                <div class="lg:col-span-2">
                    <div class="sl-card">
                        <div class="px-4 py-3 border-b border-border">
                            <h2 class="text-sm font-semibold text-foreground">Add Domain</h2>
                        </div>
                        <div class="p-4 space-y-3">

                            <!-- Domain Input -->
                            <div>
                                <label class="field-label">Domain Name <span class="text-destructive">*</span></label>
                                <input type="text" x-model="domainForm.domain"
                                    placeholder="contoh.com"
                                    class="input font-mono" autocomplete="off">
                            </div>

                            <!-- Cloudflare toggle -->
                            <div class="flex items-center justify-between p-3 rounded-lg border border-border bg-secondary/30">
                                <div class="flex items-center gap-2">
                                    <svg class="w-4 h-4 text-orange-500" viewBox="0 0 24 24" fill="currentColor">
                                        <path d="M16.309 9.302c-.133-.004-.266 0-.4.008l-.137.988c-.083.6-.485 1.039-1.079 1.127l-.196.025c-.147.016-.291-.04-.39-.156a.55.55 0 01-.104-.421l.072-.506c-.473-.2-.98-.312-1.513-.312-2.208 0-4 1.793-4 4 0 .356.047.701.135 1.03h10.3c1.103 0 2-.897 2-2 0-2.05-1.636-3.72-3.688-3.783zM5.114 14.085l.535-3.488a.462.462 0 01.466-.393h.682a.46.46 0 01.46.517l-.064.44c1.078-1.178 2.635-1.918 4.37-1.918.696 0 1.363.114 1.988.324l.267-1.73a.462.462 0 01.466-.393h.682a.46.46 0 01.46.517l-.168 1.094c2.555.312 4.553 2.453 4.553 5.063 0 1.654-1.346 3-3 3H5.581a.463.463 0 01-.467-.517V14.085z"/>
                                    </svg>
                                    <div>
                                        <p class="text-xs font-semibold">Cloudflare</p>
                                        <p class="text-[10px] text-muted-foreground">DNS, Security &amp; Speed optimization</p>
                                    </div>
                                </div>
                                <button type="button" @click="useCf = !useCf"
                                    :class="useCf ? 'bg-emerald-600 text-white border-emerald-400' : 'bg-secondary text-muted-foreground border-border'"
                                    class="px-3 py-1 text-[11px] font-semibold border rounded-md transition-all"
                                    x-text="useCf ? 'ON' : 'OFF'">
                                </button>
                            </div>

                            <!-- Submit -->
                            <button @click="addUserDomain()" :disabled="domainLoading || !domainForm.domain.trim()"
                                class="btn btn-primary w-full flex items-center justify-center gap-2 disabled:opacity-50">
                                <div x-show="domainLoading" class="spinner w-4 h-4"></div>
                                <span x-text="domainLoading ? 'Adding...' : 'Add Domain'"></span>
                            </button>

                            <!-- Log output -->
                            <div x-show="domainLogs.length > 0" class="rounded-lg border border-border overflow-hidden">
                                <div class="px-3 py-1.5 bg-secondary/50 border-b border-border text-xs font-medium text-muted-foreground">Process Log</div>
                                <div aria-live="polite" aria-label="Process log" class="p-2 space-y-0.5 max-h-52 overflow-y-auto font-mono text-[11px]">
                                    <template x-for="(log, i) in domainLogs" :key="i">
                                        <div class="flex gap-2 py-0.5" :class="{
                                            'text-emerald-700': log.type === 'success',
                                            'text-destructive': log.type === 'error',
                                            'text-amber-600':   log.type === 'warning',
                                            'text-blue-600':    log.type === 'step',
                                            'text-muted-foreground': log.type === 'info'
                                        }">
                                            <span x-text="log.type === 'success' ? '✓' : log.type === 'error' ? '✗' : log.type === 'warning' ? '!' : '·'"></span>
                                            <span x-text="log.message"></span>
                                        </div>
                                    </template>
                                </div>
                            </div>

                            <!-- NS Info -->
                            <div x-show="domainNs.length > 0" class="p-3 rounded-lg bg-amber-50 border border-amber-200 text-xs">
                                <p class="font-semibold text-amber-800 mb-1">‼ Update Nameservers at the Registrar</p>
                                <template x-for="ns in domainNs" :key="ns">
                                    <p class="font-mono text-amber-700" x-text="ns"></p>
                                </template>
                            </div>

                        </div>
                    </div>
                </div>

                <!-- CF Config -->
                <div class="lg:col-span-3 space-y-5">
                <div class="sl-card">
                    <div class="px-4 py-3 border-b border-border flex items-center justify-between cursor-pointer select-none"
                         @click="showCfConfig = !showCfConfig">
                        <div class="flex items-center gap-2">
                            <svg class="w-3.5 h-3.5 text-muted-foreground transition-transform duration-200"
                                 :class="showCfConfig && 'rotate-90'"
                                 fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                            </svg>
                            <div>
                                <h2 class="text-sm font-semibold text-foreground">Cloudflare Configuration</h2>
                                <p class="text-[11px] text-muted-foreground mt-0.5" x-text="cfConfig.has_own ? 'Using your CF token' : 'Using admin CF token (fallback)'"></p>
                            </div>
                        </div>
                        <div class="flex items-center gap-2">
                            <span x-show="cfConfig.has_own" class="text-[10px] bg-emerald-100 text-emerald-700 px-2 py-0.5 rounded-full font-medium">Own Token</span>
                            <span x-show="!cfConfig.has_own" class="text-[10px] bg-amber-100 text-amber-700 px-2 py-0.5 rounded-full font-medium">Admin Fallback</span>
                            <svg class="w-4 h-4 text-muted-foreground transition-transform duration-200"
                                 :class="showCfConfig && 'rotate-180'"
                                 fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                            </svg>
                        </div>
                    </div>
                    <div x-show="showCfConfig" x-transition.duration.200ms class="p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label class="field-label">CF Token <span class="text-muted-foreground font-normal">(Bearer)</span></label>
                            <div class="relative">
                                <input :type="cfConfig.showToken ? 'text' : 'password'" x-model="cfConfig.cf_token"
                                    placeholder="Your Cloudflare token"
                                    class="input pr-9 font-mono">
                                <button type="button" @click="toggleCfTokenVisibility()"
                                    class="input-icon-btn">
                                    <svg x-show="!cfConfig.showToken" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
                                    <svg x-show="cfConfig.showToken" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 4.411m0 0L21 21"/></svg>
                                </button>
                            </div>
                        </div>
                        <div>
                            <label class="field-label">Account ID <span class="text-muted-foreground font-normal">(optional)</span></label>
                            <input type="text" x-model="cfConfig.cf_account_id"
                                placeholder="Cloudflare Account ID"
                                class="input font-mono">
                        </div>
                        <div>
                            <label class="field-label">Reference Zone ID <span class="text-muted-foreground font-normal">(optional)</span></label>
                            <input type="text" x-model="cfConfig.cf_zone_id"
                                placeholder="Reference Zone ID"
                                class="input font-mono">
                        </div>
                        <div>
                            <label class="field-label">Default Proxy</label>
                            <select x-model="cfConfig.cf_proxied" class="input">
                                <option value="true">Active (Orange Cloud)</option>
                                <option value="false">Inactive (DNS Only)</option>
                            </select>
                        </div>
                        <div class="md:col-span-2 flex items-center gap-2">
                            <button @click="saveCfConfig()" :disabled="cfConfig.saving"
                                class="btn btn-primary flex items-center gap-2 disabled:opacity-50">
                                <div x-show="cfConfig.saving" class="spinner w-3.5 h-3.5"></div>
                                <span x-text="cfConfig.saving ? 'Saving...' : 'Save CF Configuration'"></span>
                            </button>
                            <button x-show="cfConfig.has_own" @click="clearCfConfig()" class="btn btn-outline text-destructive border-destructive/30 hover:bg-destructive/10">
                                Remove & Use Admin
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Domain List -->
                <div class="lg:col-span-full">
                    <div class="sl-card">
                        <div class="px-4 py-3 border-b border-border flex items-center justify-between">
                            <div class="flex items-center gap-2">
                                <h2 class="text-sm font-semibold text-foreground">Domain List</h2>
                                <span class="text-xs bg-secondary text-secondary-foreground px-2 py-0.5 rounded-full font-medium" x-text="userDomains.length"></span>
                            </div>
                            <button @click="loadUserDomains()" :disabled="userDomainsLoading"
                                class="btn btn-outline btn-sm flex items-center gap-1">
                                <svg class="w-3.5 h-3.5" :class="{ 'animate-spin': userDomainsLoading }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                                </svg>
                                Refresh
                            </button>
                        </div>

                        <div x-show="userDomainsLoading" class="flex items-center justify-center py-10 gap-2 text-muted-foreground text-sm">
                            <div class="spinner w-5 h-5"></div><span>Loading...</span>
                        </div>

                        <div x-show="!userDomainsLoading && userDomains.length === 0" class="empty-state empty-state-panel">
                            <div class="empty-state-icon">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9"/>
                            </svg>
                            </div>
                            <p class="empty-state-title">No domains yet</p>
                        </div>

                        <div x-show="!userDomainsLoading && userDomains.length > 0" class="overflow-x-auto">
                            <table class="w-full tbl text-xs">
                                <thead>
                                    <tr>
                                        <th scope="col" class="w-8">#</th>
                                        <th scope="col">Domain</th>
                                        <th scope="col">CF Status</th>
                                        <th scope="col" class="text-right">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <template x-for="(d, i) in userDomains" :key="d.id">
                                        <tr class="border-b border-border last:border-0 hover:bg-secondary/30 transition-colors">
                                            <td class="px-3 py-2 text-muted-foreground" x-text="i + 1"></td>
                                            <td class="px-3 py-2 font-mono font-medium">
                                                <div class="flex items-center gap-1.5">
                                                    <span x-text="d.domain"></span>
                                                    <span x-show="d.is_admin" class="px-1.5 py-0.5 rounded text-[9px] font-semibold bg-emerald-100 text-emerald-700">Global</span>
                                                </div>
                                            </td>
                                            <td class="px-3 py-2">
                                                <span :class="{
                                                    'bg-emerald-100 text-emerald-700': d.cf_status === 'active',
                                                    'bg-blue-100 text-blue-700':      d.cf_status === 'pending',
                                                    'bg-red-100 text-red-700':        d.cf_status === 'not_found',
                                                    'bg-yellow-100 text-yellow-700':  d.cf_status === 'unconfigured'
                                                }" class="px-2 py-0.5 rounded-full text-[10px] font-medium" x-text="{
                                                    active: 'Active', pending: 'Pending NS',
                                                    not_found: 'Not Found', unconfigured: 'Not Configured'
                                                }[d.cf_status] || d.cf_status"></span>
                                            </td>
                                            <td class="px-3 py-2 text-right">
                                                <div class="flex items-center justify-end gap-1">
                                                    <button x-show="!d.is_admin && (d.cf_status === 'pending' || d.cf_status === 'not_found')" @click="syncUserDomain(d)" :disabled="d.syncing"
                                                        class="p-1.5 rounded text-muted-foreground hover:bg-blue-50 hover:text-blue-600 transition-colors" :title="d.cf_status === 'not_found' ? 'Create & Sync Cloudflare' : 'Sync Cloudflare'">
                                                        <svg aria-hidden="true" class="w-3.5 h-3.5" :class="{'animate-spin': d.syncing}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                                                        </svg>
                                                    </button>
                                                    <button x-show="!d.is_admin" @click="deleteUserDomain(d)"
                                                        class="p-1.5 rounded text-muted-foreground hover:bg-destructive/10 hover:text-destructive transition-colors" title="Delete" aria-label="Delete">
                                                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                                                        </svg>
                                                    </button>
                                                    <span x-show="d.is_admin" class="text-[10px] text-muted-foreground italic px-1">admin</span>
                                                </div>
                                            </td>
                                        </tr>
                                    </template>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                </div><!-- /CF+Domain right column -->

            </div>
        </div>
        <!-- /TAB: DOMAINS -->

        <!-- ── TAB: ANALYTICS ── -->
        <div x-show="mainTab === 'analytics'" x-cloak
             x-transition:enter="tab-enter" x-transition:enter-start="tab-enter-start" x-transition:enter-end="tab-enter-end">

            <!-- Summary cards -->
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
                <div class="stat-card stat-card-blue">
                    <p class="stat-card-label">Total Clicks</p>
                    <p class="stat-card-value" x-text="(analytics.total||0).toLocaleString()"></p>
                    <p class="stat-card-sub" x-text="analyticsDays + ' last days'"></p>
                </div>
                <div class="stat-card stat-card-emerald">
                    <p class="stat-card-label">Avg/Day</p>
                    <p class="stat-card-value" x-text="Math.round((analytics.total||0)/analyticsDays).toLocaleString()"></p>
                    <p class="stat-card-sub">clicks per day</p>
                </div>
                <div class="stat-card stat-card-amber">
                    <p class="stat-card-label">Top Country</p>
                    <p class="stat-card-value stat-card-value-compact" x-text="analytics.by_country?.[0]?.country || '—'"></p>
                    <p class="stat-card-sub" x-text="analytics.by_country?.[0]?.hits ? Number(analytics.by_country[0].hits).toLocaleString()+' clicks' : 'No data yet'"></p>
                </div>
                <div class="stat-card stat-card-violet">
                    <p class="stat-card-label">Top Source</p>
                    <p class="stat-card-value stat-card-value-compact capitalize" x-text="analytics.by_network?.[0]?.network || '—'"></p>
                    <p class="stat-card-sub" x-text="analytics.by_network?.[0]?.hits ? Number(analytics.by_network[0].hits).toLocaleString()+' clicks' : 'No data yet'"></p>
                </div>
            </div>

            <!-- Controls -->
            <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
                <h2 class="text-[13px] font-semibold text-foreground tracking-tight">Analytics</h2>
                <div class="flex items-center gap-2">
                    <select x-model.number="analyticsDays" @change="loadAnalytics()" class="sl-input sl-select text-[12px] w-auto">
                        <option value="7">7 days</option>
                        <option value="14">14 days</option>
                        <option value="30">30 days</option>
                        <option value="90">90 days</option>
                    </select>
                    <button @click="loadAnalytics()" :disabled="analyticsLoading"
                        class="btn btn-outline btn-sm flex items-center gap-1.5">
                        <svg class="w-3.5 h-3.5" :class="analyticsLoading && 'animate-spin'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                        </svg>
                        Refresh
                    </button>
                </div>
            </div>

            <!-- Chart -->
            <div class="sl-card mb-4">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <h3 class="sl-card-title">Clicks per Day</h3>
                    </div>
                    <span class="text-[11px] text-muted-foreground" x-text="analyticsDays + ' days'"></span>
                </div>
                <div class="analytics-chart-shell">
                    <div x-show="analyticsLoading" class="analytics-chart-overlay analytics-chart-overlay-surface">
                        <div class="spinner w-5 h-5"></div>
                    </div>
                    <div x-show="!analyticsLoading && !(analytics.total > 0)" class="analytics-chart-overlay text-sm text-muted-foreground">
                        No click data yet
                    </div>
                    <canvas id="analyticsChart"></canvas>
                </div>
            </div>

            <!-- Breakdown grid -->
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">

                <!-- Negara -->
                <div class="sl-card">
                    <div class="sl-card-header">
                        <h3 class="sl-card-title">Country</h3>
                    </div>
                    <div x-show="!analytics.by_country?.length" class="py-8 text-center text-xs text-muted-foreground">No data yet</div>
                    <div class="divide-y divide-border max-h-60 overflow-y-auto">
                        <template x-for="c in (analytics.by_country||[])" :key="c.country">
                            <div class="flex items-center justify-between px-3.5 py-2 gap-3">
                                <div class="flex items-center gap-2 min-w-0">
                                    <span class="country-flag shrink-0" :class="'country-flag-' + (c.country||'').toLowerCase()" :title="c.country"></span>
                                    <span class="text-xs font-medium text-foreground font-mono" x-text="c.country || '—'"></span>
                                </div>
                                <div class="flex items-center gap-2 shrink-0">
                                    <div class="h-1 w-16 rounded-full bg-secondary overflow-hidden">
                                        <div class="h-full rounded-full bg-foreground/40 transition-all"
                                            :style="'width:'+Math.round(c.hits/(analytics.by_country[0]?.hits||1)*100)+'%'"></div>
                                    </div>
                                    <span class="text-xs text-muted-foreground w-10 text-right" style="font-variant-numeric:tabular-nums" x-text="Number(c.hits).toLocaleString()"></span>
                                </div>
                            </div>
                        </template>
                    </div>
                </div>

                <!-- Device + Network -->
                <div class="space-y-4">
                    <div class="sl-card">
                        <div class="sl-card-header">
                            <h3 class="sl-card-title">Device</h3>
                        </div>
                        <div x-show="!analytics.by_device?.length" class="py-5 text-center text-xs text-muted-foreground">No data yet</div>
                        <div class="divide-y divide-border">
                            <template x-for="d in (analytics.by_device||[])" :key="d.device">
                                <div class="flex items-center justify-between px-3.5 py-2">
                                    <div class="flex items-center gap-2">
                                        <span x-show="d.device === 'wap'" class="text-blue-500">
                                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>
                                        </span>
                                        <span x-show="d.device !== 'wap'" class="text-muted-foreground">
                                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
                                        </span>
                                        <span class="text-xs font-medium text-foreground" x-text="d.device === 'wap' ? 'Mobile' : d.device === 'web' ? 'Desktop' : (d.device||'—')"></span>
                                    </div>
                                    <span class="text-xs text-muted-foreground" style="font-variant-numeric:tabular-nums" x-text="Number(d.hits).toLocaleString()"></span>
                                </div>
                            </template>
                        </div>
                    </div>
                    <div class="sl-card">
                        <div class="sl-card-header">
                            <h3 class="sl-card-title">Traffic Source</h3>
                        </div>
                        <div x-show="!analytics.by_network?.length" class="py-5 text-center text-xs text-muted-foreground">No data yet</div>
                        <div class="divide-y divide-border">
                            <template x-for="n in (analytics.by_network||[])" :key="n.network">
                                <div class="flex items-center justify-between px-3.5 py-2">
                                    <span class="text-xs font-medium text-foreground capitalize" x-text="n.network || 'direct'"></span>
                                    <span class="text-xs text-muted-foreground" style="font-variant-numeric:tabular-nums" x-text="Number(n.hits).toLocaleString()"></span>
                                </div>
                            </template>
                        </div>
                    </div>
                </div>

                <!-- Top Links -->
                <div class="sl-card">
                    <div class="sl-card-header">
                        <h3 class="sl-card-title">Top Link</h3>
                    </div>
                    <div x-show="!analytics.by_link?.length" class="py-8 text-center text-xs text-muted-foreground">No data yet</div>
                    <div class="divide-y divide-border max-h-72 overflow-y-auto">
                        <template x-for="(l, i) in (analytics.by_link||[])" :key="l.slug">
                            <div class="flex items-center gap-2 px-3.5 py-2">
                                <span class="text-muted-foreground w-4 shrink-0" style="font-size:10px;font-variant-numeric:tabular-nums" x-text="i+1"></span>
                                <span class="font-mono text-foreground truncate flex-1" style="font-size:11px" x-text="l.slug"></span>
                                <span class="text-muted-foreground truncate" style="font-size:10px;max-width:40%" x-show="l.title" x-text="l.title"></span>
                                <span class="text-xs font-semibold text-foreground shrink-0" style="font-variant-numeric:tabular-nums" x-text="Number(l.hits).toLocaleString()"></span>
                            </div>
                        </template>
                    </div>
                </div>

            </div>
        </div>
        <!-- /TAB: ANALYTICS -->

        <!-- ── TAB: CONVERSION ── -->
        <div x-show="mainTab === 'conversion'" x-cloak
             x-transition:enter="tab-enter" x-transition:enter-start="tab-enter-start" x-transition:enter-end="tab-enter-end">

            <!-- Stats bar -->
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
                <div class="stat-card stat-card-blue">
                    <p class="stat-card-label">Clicks 24h</p>
                    <p class="stat-card-value" x-text="conv.stats.clicks_24h.toLocaleString()"></p>
                    <p class="stat-card-sub">incoming clicks</p>
                </div>
                <div class="stat-card stat-card-emerald">
                    <p class="stat-card-label">Conversions 24h</p>
                    <p class="stat-card-value" x-text="conv.stats.conversions_24h.toLocaleString()"></p>
                    <p class="stat-card-sub">conversions</p>
                </div>
                <div class="stat-card stat-card-amber">
                    <p class="stat-card-label">Revenue 24h</p>
                    <p class="stat-card-value" x-text="'$' + Number(conv.stats.revenue_24h).toFixed(2)"></p>
                    <p class="stat-card-sub">revenue</p>
                </div>
                <div class="stat-card stat-card-violet">
                    <p class="stat-card-label">Conv. Rate</p>
                    <p class="stat-card-value" x-text="conv.stats.cr + '%'"></p>
                    <p class="stat-card-sub">overall CR</p>
                </div>
            </div>

            <!-- Sub-tab + controls -->
            <div class="flex items-center justify-between gap-3 mb-3">
                <div role="tablist" class="flex gap-0.5 bg-secondary/50 p-0.5 rounded-lg">
                    <button @click="setConvSubTab('clicks')" type="button" role="tab"
                        :aria-selected="conv.subTab === 'clicks'"
                        :class="conv.subTab === 'clicks' ? 'bg-white text-foreground' : 'text-muted-foreground hover:text-foreground'"
                        class="px-3 py-1 text-[12px] font-medium rounded-md transition-all flex items-center gap-1.5">
                        <span class="relative flex h-2 w-2" x-show="conv.live" aria-hidden="true">
                            <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                            <span class="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                        </span>
                        Live Clicks
                        <span class="text-[10px] text-muted-foreground" x-text="'(' + conv.clicks.length + ')'"></span>
                    </button>
                    <button @click="setConvSubTab('conversions')" type="button" role="tab"
                        :aria-selected="conv.subTab === 'conversions'"
                        :class="conv.subTab === 'conversions' ? 'bg-white text-foreground' : 'text-muted-foreground hover:text-foreground'"
                        class="px-3 py-1 text-[12px] font-medium rounded-md transition-all flex items-center gap-1.5">
                        Conversions
                        <span class="text-[10px] text-muted-foreground" x-text="'(' + conv.conversions.length + ')'"></span>
                    </button>
                    <button @click="setConvSubTab('stats')" type="button" role="tab"
                        :aria-selected="conv.subTab === 'stats'"
                        :class="conv.subTab === 'stats' ? 'bg-white text-foreground' : 'text-muted-foreground hover:text-foreground'"
                        class="px-3 py-1 text-[12px] font-medium rounded-md transition-all flex items-center gap-1.5">
                        <svg aria-hidden="true" class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/>
                        </svg>
                        Performance
                    </button>
                </div>
                <div class="flex items-center gap-2">
                    <span class="text-[11px] text-muted-foreground" x-show="conv.live" x-text="'Auto-refresh 5s'"></span>
                    <button @click="conv.live ? stopConvPoll() : startConvPoll()" type="button"
                        :class="conv.live ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-secondary text-muted-foreground'"
                        class="px-2.5 py-1 text-[11px] font-medium border rounded-md transition-all"
                        x-text="conv.live ? 'Pause' : 'Resume'">
                    </button>
                    <button @click="loadLiveFeed()" type="button" :disabled="conv.loading"
                        class="btn btn-outline btn-sm text-[11px] px-2.5">
                        <svg x-show="!conv.loading" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                        </svg>
                        <svg x-show="conv.loading" class="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 22 6.477 22 12h-4z"></path>
                        </svg>
                    </button>
                </div>
            </div>

            <!-- ── Live Clicks ── -->
            <div x-show="conv.subTab === 'clicks'"
                 x-transition:enter="fade-enter" x-transition:enter-start="fade-enter-start" x-transition:enter-end="fade-enter-end">
                <div class="sl-card">
                    <div class="sl-card-header">
                        <div class="sl-card-header-left">
                            <h2 class="sl-card-title">Live Clicks</h2>
                            <span class="sl-card-count" x-text="clFiltered.length"></span>
                        </div>
                        <div class="sl-card-header-right">
                                <input type="text" x-model="conv.clSearch" @input="resetClickPage()" placeholder="Search…"
                                    class="input text-[11px] h-7 w-36">
                        </div>
                    </div>
                <!-- Table -->
                <div class="overflow-hidden">
                    <div class="overflow-x-auto">
                        <table class="w-full tbl text-[11px]">
                            <thead>
                                <tr>
                                    <th @click="clSortBy('created_at')" @keydown.enter="clSortBy('created_at')" tabindex="0" scope="col" class="sortable whitespace-nowrap w-20">
                                        Time <span x-show="conv.clSort==='created_at'" x-text="conv.clSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="clSortBy('slug')" @keydown.enter="clSortBy('slug')" tabindex="0" scope="col" class="sortable w-20">
                                        Slug <span x-show="conv.clSort==='slug'" x-text="conv.clSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="clSortBy('username')" @keydown.enter="clSortBy('username')" tabindex="0" scope="col" class="sortable">
                                        User <span x-show="conv.clSort==='username'" x-text="conv.clSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="clSortBy('subid')" @keydown.enter="clSortBy('subid')" tabindex="0" scope="col" class="sortable">
                                        Subid <span x-show="conv.clSort==='subid'" x-text="conv.clSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="clSortBy('country')" @keydown.enter="clSortBy('country')" tabindex="0" scope="col" class="sortable w-20">
                                        Country <span x-show="conv.clSort==='country'" x-text="conv.clSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="clSortBy('device')" @keydown.enter="clSortBy('device')" tabindex="0" scope="col" class="sortable w-16">
                                        Device <span x-show="conv.clSort==='device'" x-text="conv.clSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="clSortBy('network')" @keydown.enter="clSortBy('network')" tabindex="0" scope="col" class="sortable">
                                        Network <span x-show="conv.clSort==='network'" x-text="conv.clSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="clSortBy('ip')" @keydown.enter="clSortBy('ip')" tabindex="0" scope="col" class="sortable w-28">
                                        IP <span x-show="conv.clSort==='ip'" x-text="conv.clSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr x-show="clFiltered.length === 0">
                                    <td colspan="8" class="text-center text-muted-foreground py-10 text-xs">No clicks yet</td>
                                </tr>
                                <template x-for="(c, idx) in clPaged" :key="c.id">
                                    <tr :class="{
                                            'click-row-new': conv.freshIds[c.id],
                                            'border-b border-border hover:bg-secondary/20': true
                                        }">
                                        <td class="px-2 py-1.5 text-muted-foreground whitespace-nowrap" x-text="convRelTime(c.created_at)"></td>
                                        <td class="px-2 py-1.5">
                                            <span class="inline-flex items-center gap-1 font-mono text-[10px] bg-secondary/60 px-1.5 py-0.5 rounded"
                                                x-text="c.slug || '—'"></span>
                                        </td>
                                        <td class="px-2 py-1.5 font-mono text-[10px] font-semibold text-foreground" x-text="c.username || '—'"></td>
                                        <td class="px-2 py-1.5 font-mono text-[10px] text-foreground" x-text="c.subid || '—'" :title="c.subid"></td>
                                        <td class="px-2 py-1.5">
                                            <span class="inline-flex items-center gap-1">
                                                <span class="country-flag shrink-0" :class="'country-flag-' + (c.country||'').toLowerCase()" :title="c.country"></span>
                                                <span class="font-mono text-[10px]" x-text="c.country || '—'"></span>
                                            </span>
                                        </td>
                                        <td class="px-2 py-1.5">
                                            <span x-show="c.device === 'wap'" class="text-blue-500">
                                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>
                                            </span>
                                            <span x-show="c.device !== 'wap'" class="text-muted-foreground">
                                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
                                            </span>
                                        </td>
                                        <td class="px-2 py-1.5 text-muted-foreground" x-text="c.network || 'Direct'"></td>
                                        <td class="px-2 py-1.5 font-mono text-[10px] text-muted-foreground" x-text="c.ip || '—'"></td>
                                    </tr>
                                </template>
                            </tbody>
                        </table>
                    </div>
                    <!-- Pagination clicks -->
                    <div x-show="clTotalPages > 1" class="px-3 py-2.5 border-t border-border flex items-center justify-between gap-2">
                        <span class="text-[11px] text-muted-foreground">
                            <span x-text="(conv.clPage-1)*conv.perPage+1"></span>–<span x-text="Math.min(conv.clPage*conv.perPage, clFiltered.length)"></span>
                            <span class="text-muted-foreground/60"> of </span><span x-text="clFiltered.length"></span>
                        </span>
                        <div class="flex items-center gap-1">
                            <button @click="setClickPage(1)" :disabled="conv.clPage===1" class="pg-btn">«</button>
                            <button @click="changeClickPage(-1)" :disabled="conv.clPage===1" class="pg-btn">‹</button>
                            <span class="pg-btn active pointer-events-none" x-text="conv.clPage + ' / ' + clTotalPages"></span>
                            <button @click="changeClickPage(1)" :disabled="conv.clPage>=clTotalPages" class="pg-btn">›</button>
                            <button @click="setClickPage(clTotalPages)" :disabled="conv.clPage>=clTotalPages" class="pg-btn">»</button>
                        </div>
                    </div>
                </div>
                </div><!-- /.sl-card -->
            </div>

            <!-- ── Conversions ── -->
            <div x-show="conv.subTab === 'conversions'"
                 x-transition:enter="fade-enter" x-transition:enter-start="fade-enter-start" x-transition:enter-end="fade-enter-end">
                <div class="sl-card">
                    <div class="sl-card-header">
                        <div class="sl-card-header-left">
                            <h2 class="sl-card-title">Conversions</h2>
                            <span class="sl-card-count" x-text="cvFiltered.length"></span>
                        </div>
                        <div class="sl-card-header-right">
                                <input type="text" x-model="conv.cvSearch" @input="resetConversionPage()" placeholder="Search…"
                                    class="input text-[11px] h-7 w-36">
                        </div>
                    </div>
                <!-- Table -->
                <div class="overflow-hidden">
                    <div class="overflow-x-auto">
                        <table class="w-full tbl text-[11px]">
                            <thead>
                                <tr>
                                    <th @click="cvSortBy('created_at')" @keydown.enter="cvSortBy('created_at')" tabindex="0" scope="col" class="sortable whitespace-nowrap w-20">
                                        Time <span x-show="conv.cvSort==='created_at'" x-text="conv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="cvSortBy('slug')" @keydown.enter="cvSortBy('slug')" tabindex="0" scope="col" class="sortable w-20">
                                        Slug <span x-show="conv.cvSort==='slug'" x-text="conv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="cvSortBy('username')" @keydown.enter="cvSortBy('username')" tabindex="0" scope="col" class="sortable">
                                        User <span x-show="conv.cvSort==='username'" x-text="conv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="cvSortBy('subid')" @keydown.enter="cvSortBy('subid')" tabindex="0" scope="col" class="sortable">
                                        Subid <span x-show="conv.cvSort==='subid'" x-text="conv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="cvSortBy('country')" @keydown.enter="cvSortBy('country')" tabindex="0" scope="col" class="sortable w-20">
                                        Country <span x-show="conv.cvSort==='country'" x-text="conv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="cvSortBy('device')" @keydown.enter="cvSortBy('device')" tabindex="0" scope="col" class="sortable w-16">
                                        Device <span x-show="conv.cvSort==='device'" x-text="conv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="cvSortBy('network')" @keydown.enter="cvSortBy('network')" tabindex="0" scope="col" class="sortable">
                                        Network <span x-show="conv.cvSort==='network'" x-text="conv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="cvSortBy('payout')" @keydown.enter="cvSortBy('payout')" tabindex="0" scope="col" class="sortable w-20">
                                        Payout <span x-show="conv.cvSort==='payout'" x-text="conv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="cvSortBy('ip')" @keydown.enter="cvSortBy('ip')" tabindex="0" scope="col" class="sortable w-28">
                                        IP <span x-show="conv.cvSort==='ip'" x-text="conv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th scope="col" class="w-24">Clickid</th>
                                    <th @click="cvSortBy('status')" @keydown.enter="cvSortBy('status')" tabindex="0" scope="col" class="sortable w-20">
                                        Status <span x-show="conv.cvSort==='status'" x-text="conv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr x-show="cvFiltered.length === 0">
                                    <td colspan="11" class="text-center text-muted-foreground py-10 text-xs">No conversions yet</td>
                                </tr>
                                <template x-for="(v, idx) in cvPaged" :key="v.id">
                                    <tr :class="{
                                            'conv-new-row': conv.newConvIds[v.id],
                                            'border-b border-border hover:bg-secondary/20': true
                                        }"
                                        class="transition-colors duration-700">
                                        <td class="px-2 py-1.5 text-muted-foreground whitespace-nowrap" x-text="convRelTime(v.created_at)"></td>
                                        <td class="px-2 py-1.5">
                                            <span class="inline-flex items-center gap-1 font-mono text-[10px] bg-secondary/60 px-1.5 py-0.5 rounded"
                                                x-text="v.slug || '—'"></span>
                                        </td>
                                        <td class="px-2 py-1.5 font-mono text-[10px] font-semibold text-foreground" x-text="v.username || '—'"></td>
                                        <td class="px-2 py-1.5 font-mono text-[10px] text-foreground" x-text="v.subid || '—'" :title="v.subid"></td>
                                        <td class="px-2 py-1.5">
                                            <span class="inline-flex items-center gap-1">
                                                <span class="country-flag shrink-0" :class="'country-flag-' + (v.country||'').toLowerCase()" :title="v.country"></span>
                                                <span class="font-mono text-[10px]" x-text="v.country || '—'"></span>
                                            </span>
                                        </td>
                                        <td class="px-2 py-1.5">
                                            <span x-show="v.device === 'wap'" class="text-blue-500">
                                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>
                                            </span>
                                            <span x-show="v.device !== 'wap'" class="text-muted-foreground">
                                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
                                            </span>
                                        </td>
                                        <td class="px-2 py-1.5 text-muted-foreground" x-text="v.network || '—'"></td>
                                        <td class="px-2 py-1.5 font-semibold text-emerald-600" x-text="v.payout > 0 ? '$' + Number(v.payout).toFixed(2) : '—'"></td>
                                        <td class="px-2 py-1.5 font-mono text-[10px] text-muted-foreground" x-text="v.ip || '—'"></td>
                                        <td class="px-2 py-1.5 font-mono text-[10px] text-muted-foreground max-w-[100px] truncate cursor-pointer hover:text-foreground"
                                            @click="copyText(v.clickid)" :title="v.clickid"
                                            x-text="v.clickid ? v.clickid.substring(0,12)+'…' : '—'"></td>
                                        <td class="px-3 py-1.5">
                                            <span :class="{
                                                'status-approved': v.status === 'approved',
                                                'status-pending':  v.status === 'pending',
                                                'status-rejected': v.status === 'rejected',
                                                'status-default':  !['approved','pending','rejected'].includes(v.status)
                                            }" class="status-badge" x-text="v.status"></span>
                                        </td>
                                    </tr>
                                </template>
                            </tbody>
                        </table>
                    </div>
                    <!-- Pagination conversions -->
                    <div x-show="cvTotalPages > 1" class="px-3 py-2.5 border-t border-border flex items-center justify-between gap-2">
                        <span class="text-[11px] text-muted-foreground">
                            <span x-text="(conv.cvPage-1)*conv.perPage+1"></span>–<span x-text="Math.min(conv.cvPage*conv.perPage, cvFiltered.length)"></span>
                            <span class="text-muted-foreground/60"> of </span><span x-text="cvFiltered.length"></span>
                        </span>
                        <div class="flex items-center gap-1">
                            <button @click="setConversionPage(1)" :disabled="conv.cvPage===1" class="pg-btn">«</button>
                            <button @click="changeConversionPage(-1)" :disabled="conv.cvPage===1" class="pg-btn">‹</button>
                            <span class="pg-btn active pointer-events-none" x-text="conv.cvPage + ' / ' + cvTotalPages"></span>
                            <button @click="changeConversionPage(1)" :disabled="conv.cvPage>=cvTotalPages" class="pg-btn">›</button>
                            <button @click="setConversionPage(cvTotalPages)" :disabled="conv.cvPage>=cvTotalPages" class="pg-btn">»</button>
                        </div>
                    </div>
                </div>
                </div><!-- /.sl-card -->
            </div>

            <!-- ══ TAB: Performance by User ══ -->
            <div x-show="conv.subTab === 'stats'" class="space-y-4"
                 x-transition:enter="fade-enter" x-transition:enter-start="fade-enter-start" x-transition:enter-end="fade-enter-end">

                <!-- Date range controls -->
                <div class="sl-card">
                    <div class="sl-card-header">
                        <div class="sl-card-header-left">
                            <svg aria-hidden="true" class="w-4 h-4 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/>
                            </svg>
                            <h2 class="sl-card-title">Daily Performance</h2>
                            <span class="sl-card-count" x-show="convStats.data.daily.length > 0" x-text="convStats.data.daily.length + ' days'"></span>
                        </div>
                        <div class="sl-card-header-right">
                            <div class="flex flex-wrap items-center gap-2">
                                <select x-model="convStats.datePreset" @change="applyDatePreset()" class="input h-7 text-[11px] w-36">
                                    <option value="today">Today</option>
                                    <option value="yesterday">Yesterday</option>
                                    <option value="7d">Last 7 days</option>
                                    <option value="14d">Last 14 days</option>
                                    <option value="30d">Last 30 days</option>
                                    <option value="this_month">This month</option>
                                    <option value="last_month">Last month</option>
                                    <option value="custom">Custom</option>
                                </select>
                                <template x-if="convStats.datePreset === 'custom'">
                                    <div class="flex items-center gap-2">
                                        <input type="date" x-model="convStats.dateFrom" class="input h-7 text-[11px] w-32">
                                        <span class="text-[11px] text-muted-foreground">—</span>
                                        <input type="date" x-model="convStats.dateTo" class="input h-7 text-[11px] w-32">
                                        <button @click="loadConvStats()" :disabled="convStats.loading"
                                            class="btn btn-primary btn-sm text-[11px] px-3 flex items-center gap-1.5">
                                            <div x-show="convStats.loading" class="spinner w-3.5 h-3.5"></div>
                                            <span x-show="!convStats.loading">Show</span>
                                        </button>
                                    </div>
                                </template>
                                <div x-show="convStats.loading && convStats.datePreset !== 'custom'" class="spinner w-3.5 h-3.5"></div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Loading indicator -->
                <div x-show="convStats.loading" class="sl-card">
                    <div class="flex flex-col items-center justify-center py-16 text-center">
                        <svg class="w-8 h-8 text-muted-foreground/40 animate-spin mb-3" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                        </svg>
                        <p class="text-sm text-muted-foreground font-medium">Loading performance data…</p>
                    </div>
                </div>

                <!-- Error state -->
                <div x-show="!convStats.loading && convStats.error" class="sl-card">
                    <div class="flex flex-col items-center justify-center py-12 text-center">
                        <svg class="w-8 h-8 text-red-400/60 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <p class="text-sm text-red-600 font-medium" x-text="convStats.error"></p>
                        <button @click="loadConvStats()" class="btn btn-primary btn-sm text-[11px] mt-3 px-4">Retry</button>
                    </div>
                </div>

                <!-- Empty state -->
                <div x-show="!convStats.loading && !convStats.error && !convStats.data.daily.length" class="sl-card">
                    <div class="flex flex-col items-center justify-center py-16 text-center">
                        <svg class="w-10 h-10 text-muted-foreground/30 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/>
                        </svg>
                        <p class="text-sm text-muted-foreground font-medium">Select a date range and click Show</p>
                        <p class="text-xs text-muted-foreground/60 mt-1">Performance data will appear here</p>
                    </div>
                </div>

                <!-- Daily table card -->
                <div class="sl-card" x-show="!convStats.loading && convStats.data.daily.length > 0">
                    <div class="sl-card-header">
                        <div class="sl-card-header-left">
                            <span class="text-[11px] text-muted-foreground" x-text="convStats.dateFrom + ' — ' + convStats.dateTo"></span>
                        </div>
                    </div>

                    <div class="overflow-x-auto">
                        <div class="tbl-wrap">
                        <table class="tbl w-full" style="table-layout:fixed;font-variant-numeric:tabular-nums;font-size:11px">
                            <colgroup>
                                <col style="width:100px"><!-- Date -->
                                <col style="width:72px"><!-- Clicks -->
                                <col style="width:72px"><!-- Conv -->
                                <col style="width:92px"><!-- Payout -->
                                <col style="width:88px"><!-- Approved -->
                                <col style="width:80px"><!-- Pending -->
                                <col style="width:80px"><!-- Rejected -->
                                <col style="width:56px"><!-- CR -->
                            </colgroup>
                            <thead>
                                <tr>
                                    <th scope="col">Date</th>
                                    <th scope="col" style="text-align:right">Clicks</th>
                                    <th scope="col" style="text-align:right">Conv</th>
                                    <th scope="col" style="text-align:right">Payout</th>
                                    <th scope="col" style="text-align:right">Approved</th>
                                    <th scope="col" style="text-align:right">Pending</th>
                                    <th scope="col" style="text-align:right">Rejected</th>
                                    <th scope="col" style="text-align:right">CR</th>
                                </tr>
                            </thead>
                            <tbody>
                                <template x-for="(row, ri) in dailySorted" :key="row.date">
                                    <tr class="hover:bg-secondary/20 border-b border-border/50"
                                        :class="row.conversions > 0 ? 'font-medium' : 'text-muted-foreground'">
                                        <td class="px-3 py-1.5 font-mono font-semibold" style="font-size:10px" x-text="row.date"></td>
                                        <td class="px-3 py-1.5 text-right" :class="row.clicks > 0 ? 'text-sky-600 font-semibold' : ''" x-text="row.clicks > 0 ? Number(row.clicks).toLocaleString() : '—'"></td>
                                        <td class="px-3 py-1.5 text-right" x-text="row.conversions > 0 ? Number(row.conversions).toLocaleString() : '—'"></td>
                                        <td class="px-3 py-1.5 text-right" :class="row.payout > 0 ? 'font-bold text-emerald-700' : ''" x-text="row.payout > 0 ? '$' + Number(row.payout).toFixed(2) : '—'"></td>
                                        <td class="px-3 py-1.5 text-right text-emerald-600" x-text="row.approved > 0 ? '$' + Number(row.approved).toFixed(2) : '—'"></td>
                                        <td class="px-3 py-1.5 text-right text-amber-600" x-text="row.pending > 0 ? '$' + Number(row.pending).toFixed(2) : '—'"></td>
                                        <td class="px-3 py-1.5 text-right text-red-400" x-text="row.rejected > 0 ? '$' + Number(row.rejected).toFixed(2) : '—'"></td>
                                        <td class="px-3 py-1.5 text-right" x-text="row.clicks > 0 ? (row.conversions / row.clicks * 100).toFixed(1) + '%' : '—'"></td>
                                    </tr>
                                </template>
                            </tbody>
                            <tfoot>
                                <tr class="analytics-report-total-row">
                                    <td class="px-3 py-2 font-semibold" style="font-size:11px">Total</td>
                                    <td class="px-3 py-2 text-right font-semibold" x-text="Number(convStats.data.total_clicks).toLocaleString()"></td>
                                    <td class="px-3 py-2 text-right font-semibold" x-text="Number(convStats.data.total_conv).toLocaleString()"></td>
                                    <td class="px-3 py-2 text-right font-bold" style="font-size:13px" x-text="'$' + Number(convStats.data.total_rev).toFixed(2)"></td>
                                    <td colspan="3"></td>
                                    <td class="px-3 py-2 text-right text-muted-foreground" x-text="convStats.data.cr + '%'"></td>
                                </tr>
                            </tfoot>
                        </table>
                        </div>
                    </div>
                </div>
                <!-- Subid breakdown card -->
                <div class="sl-card" x-show="!convStats.loading && convStats.data.by_subid.length > 0">
                    <div class="sl-card-header">
                        <div class="sl-card-header-left">
                            <svg aria-hidden="true" class="w-4 h-4 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/>
                            </svg>
                            <h2 class="sl-card-title">By Subid</h2>
                            <span class="sl-card-count" x-text="convStats.data.by_subid.length + ' rows'"></span>
                        </div>
                        <div class="sl-card-header-right">
                            <div class="relative">
                                <svg class="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0"/></svg>
                                <input type="text" x-model="convStats.subidSearch" placeholder="Search subid…"
                                    class="input text-[11px] pl-6 h-7 w-44">
                            </div>
                        </div>
                    </div>

                    <div x-show="userSubidFiltered.length === 0" class="py-8 text-center text-xs text-muted-foreground">
                        No matching data
                    </div>

                    <div class="overflow-x-auto" x-show="userSubidFiltered.length > 0">
                        <div class="tbl-wrap">
                        <table class="tbl w-full" style="table-layout:fixed;font-variant-numeric:tabular-nums;font-size:11px">
                            <colgroup>
                                <col><!-- Subid: auto -->
                                <col style="width:72px"><!-- Clicks -->
                                <col style="width:72px"><!-- Conv -->
                                <col style="width:92px"><!-- Payout -->
                                <col style="width:88px"><!-- Approved -->
                                <col style="width:80px"><!-- Pending -->
                                <col style="width:80px"><!-- Rejected -->
                                <col style="width:56px"><!-- CR -->
                            </colgroup>
                            <thead>
                                <tr>
                                    <th @click="toggleSubidSort('subid')" @keydown.enter="toggleSubidSort('subid')" tabindex="0" scope="col" class="sortable cursor-pointer select-none">
                                        Subid <span x-show="convStats.subidSort==='subid'" x-text="convStats.subidSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="toggleSubidSort('click_count')" @keydown.enter="toggleSubidSort('click_count')" tabindex="0" scope="col" class="sortable cursor-pointer select-none" style="text-align:right">
                                        Clicks <span x-show="convStats.subidSort==='click_count'" x-text="convStats.subidSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="toggleSubidSort('conv_count')" @keydown.enter="toggleSubidSort('conv_count')" tabindex="0" scope="col" class="sortable cursor-pointer select-none" style="text-align:right">
                                        Conv <span x-show="convStats.subidSort==='conv_count'" x-text="convStats.subidSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="toggleSubidSort('total_payout')" @keydown.enter="toggleSubidSort('total_payout')" tabindex="0" scope="col" class="sortable cursor-pointer select-none" style="text-align:right">
                                        Payout <span x-show="convStats.subidSort==='total_payout'" x-text="convStats.subidSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="toggleSubidSort('approved_payout')" @keydown.enter="toggleSubidSort('approved_payout')" tabindex="0" scope="col" class="sortable cursor-pointer select-none" style="text-align:right">
                                        Approved <span x-show="convStats.subidSort==='approved_payout'" x-text="convStats.subidSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="toggleSubidSort('pending_payout')" @keydown.enter="toggleSubidSort('pending_payout')" tabindex="0" scope="col" class="sortable cursor-pointer select-none" style="text-align:right">
                                        Pending <span x-show="convStats.subidSort==='pending_payout'" x-text="convStats.subidSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th @click="toggleSubidSort('rejected_payout')" @keydown.enter="toggleSubidSort('rejected_payout')" tabindex="0" scope="col" class="sortable cursor-pointer select-none" style="text-align:right">
                                        Rejected <span x-show="convStats.subidSort==='rejected_payout'" x-text="convStats.subidSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span>
                                    </th>
                                    <th scope="col" style="text-align:right">CR</th>
                                </tr>
                            </thead>
                            <tbody>
                                <template x-for="(row, ri) in userSubidFiltered" :key="(row.subid || '__empty__') + '::' + ri">
                                    <tr class="hover:bg-secondary/20 border-b border-border/50">
                                        <td class="px-3 py-1.5">
                                            <span x-show="row.subid" class="font-mono font-semibold cursor-pointer hover:text-blue-600" style="font-size:10px" @click="copyText(row.subid)" :title="'Copy: ' + row.subid" x-text="row.subid"></span>
                                            <span x-show="!row.subid" class="text-muted-foreground italic">—</span>
                                        </td>
                                        <td class="px-3 py-1.5 text-right font-semibold text-sky-600" x-text="Number(row.click_count).toLocaleString()"></td>
                                        <td class="px-3 py-1.5 text-right font-medium" x-text="Number(row.conv_count).toLocaleString()"></td>
                                        <td class="px-3 py-1.5 text-right font-bold text-emerald-700" x-text="'$' + Number(row.total_payout).toFixed(2)"></td>
                                        <td class="px-3 py-1.5 text-right text-emerald-600" x-text="row.approved_payout > 0 ? '$' + Number(row.approved_payout).toFixed(2) : '—'"></td>
                                        <td class="px-3 py-1.5 text-right text-amber-600" x-text="row.pending_payout > 0 ? '$' + Number(row.pending_payout).toFixed(2) : '—'"></td>
                                        <td class="px-3 py-1.5 text-right text-red-400" x-text="row.rejected_payout > 0 ? '$' + Number(row.rejected_payout).toFixed(2) : '—'"></td>
                                        <td class="px-3 py-1.5 text-right text-muted-foreground" x-text="row.click_count > 0 ? (row.conv_count / row.click_count * 100).toFixed(1) + '%' : '—'"></td>
                                    </tr>
                                </template>
                            </tbody>
                            <tfoot x-show="userSubidFiltered.length > 1">
                                <tr class="analytics-report-total-row">
                                    <td class="px-3 py-2 font-semibold" style="font-size:11px">Total</td>
                                    <td class="px-3 py-2 text-right font-semibold" x-text="Number(convStats.data.total_clicks).toLocaleString()"></td>
                                    <td class="px-3 py-2 text-right font-semibold" x-text="Number(convStats.data.total_conv).toLocaleString()"></td>
                                    <td class="px-3 py-2 text-right font-bold" style="font-size:13px" x-text="'$' + Number(convStats.data.total_rev).toFixed(2)"></td>
                                    <td colspan="3"></td>
                                    <td class="px-3 py-2 text-right text-muted-foreground" x-text="convStats.data.cr + '%'"></td>
                                </tr>
                            </tfoot>
                        </table>
                        </div>
                    </div>
                </div>

            </div>
            <!-- /Performance -->

        </div>
        <!-- /TAB: CONVERSION -->

    </main>
</div>

<!-- ══════════════════════════════════════════════════════
     CONFIRM MODAL
══════════════════════════════════════════════════════ -->
<div x-show="confirmModal.show" x-cloak
    x-transition:enter="transition ease-out duration-200"
    x-transition:enter-start="opacity-0"
    x-transition:enter-end="opacity-100"
    x-transition:leave="transition ease-in duration-150"
    x-transition:leave-start="opacity-100"
    x-transition:leave-end="opacity-0"
    class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
    <div x-show="confirmModal.show"
        x-transition:enter="transition ease-out duration-200"
        x-transition:enter-start="opacity-0 scale-95"
        x-transition:enter-end="opacity-100 scale-100"
        x-transition:leave="transition ease-in duration-150"
        x-transition:leave-start="opacity-100 scale-100"
        x-transition:leave-end="opacity-0 scale-95"
        class="card w-full max-w-sm p-5">
        <div class="flex items-center gap-3 mb-3">
            <div class="w-9 h-9 rounded-full bg-destructive/10 flex items-center justify-center shrink-0">
                <svg class="w-5 h-5 text-destructive" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                </svg>
            </div>
            <div>
                <p class="text-sm font-semibold" x-text="confirmModal.title"></p>
                <p class="text-xs text-muted-foreground mt-0.5" x-text="confirmModal.message"></p>
            </div>
        </div>
        <div class="flex items-center justify-end gap-2 mt-4">
            <button @click="resolveConfirm(false)"
                class="btn btn-outline btn-sm">Cancel</button>
            <button @click="resolveConfirm(true)"
                class="btn btn-destructive btn-sm">
                <span x-text="confirmModal.okLabel || 'Delete'"></span>
            </button>
        </div>
    </div>
</div>

<!-- ══════════════════════════════════════════════════════
     TOAST
══════════════════════════════════════════════════════ -->
<div id="sl-toast" x-show="toast.show" x-cloak
    role="status" aria-live="polite" aria-atomic="true"
    x-transition:enter="transition ease-out duration-250"
    x-transition:enter-start="opacity-0 translate-y-4 scale-95"
    x-transition:enter-end="opacity-100 translate-y-0 scale-100"
    x-transition:leave="transition ease-in duration-150"
    x-transition:leave-start="opacity-100 translate-y-0 scale-100"
    x-transition:leave-end="opacity-0 translate-y-3 scale-95"
    :class="{
        'toast-success': toast.type === 'success',
        'toast-error':   toast.type === 'error',
        'toast-info':    toast.type === 'info'
    }">
    <div class="toast-progress" :style="toastProgressStyle()"></div>
    <div class="toast-body">
        <div class="shrink-0 mt-px">
            <svg x-show="toast.type==='success'" class="w-4 h-4 text-emerald-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/>
            </svg>
            <svg x-show="toast.type==='error'" class="w-4 h-4 text-destructive" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M6 18L18 6M6 6l12 12"/>
            </svg>
            <svg x-show="toast.type==='info'" class="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
        </div>
        <div class="flex-1 min-w-0">
            <p class="text-sm font-semibold text-foreground leading-tight" x-text="toast.title"></p>
            <p x-show="toast.message" class="text-xs text-muted-foreground mt-0.5 leading-relaxed" x-text="toast.message"></p>
        </div>
        <button type="button" @click="dismissToast()"
            class="icon-action-btn -mt-0.5 -mr-1">
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M6 18L18 6M6 6l12 12"/>
            </svg>
        </button>
    </div>
</div>

<!-- ══════════════════════════════════════════════════════
     ALPINE APP
══════════════════════════════════════════════════════ -->
<script<?php echo $nonceAttr; ?>>
document.addEventListener('alpine:init', function () {
    Alpine.data('slApp', slApp);
});

function slApp() {
    return {
        Math:        window.Math,
        Number:      window.Number,
        isLoggedIn:  INIT_AUTH,
        currentUser: CURRENT_USER,
        setupMode:   SETUP_MODE,

        loginForm: { username: '', password: '', showPw: false, loading: false, error: '' },
        setupForm: { username: '', password: '', showPw: false, loading: false, error: '' },

        mainTab: 'links',

        // Links
        links:        [],
        linksLoading:    false,
        linksRefreshing: false,
        linksPage:    1,
        linksPerPage: 10,
        get pagedLinks() { const s=(this.linksPage-1)*this.linksPerPage; return this.links.slice(s,s+this.linksPerPage); },
        get linksTotalPages() { return Math.max(1,Math.ceil(this.links.length/this.linksPerPage)); },

        linkForm: {
            id: null, title: '', description: '',
            image: '', default_url: '',
            domain: '',
            smartlink_network: '',
            shimlink: '', link_type: 'normal', short_service: 'default', ixg_sub: '',
            quantity: 1,
            rules: [],
            active: true
        },
        linkLoading:    false,
        linkMsg:        '',
        linkOk:         false,
        deletingLinkId: null,
        newLinkIds:     [],
        copyFeedback:   null,
        bulkResult:     [],
        bulkErrors:     [],
        showBulkResult: false,

        // Smartlinks & Domains (from Domain Manager)
        smartlinks:      [],
        smartlinksLoading: false,
        smartlinkSearch: '',
        expandedNetworks: {},
        domains:         [],
        domainsLoading:  false,

        // CF Config
        showCfConfig: false,
        cfConfig: {
            cf_token: '', cf_account_id: '', cf_zone_id: '', cf_proxied: 'true',
            has_own: false, showToken: false, saving: false
        },

        // Domains
        userDomains:       [],
        userDomainsLoading: false,
        domainLoading:     false,
        domainLogs:        [],
        domainNs:          [],
        useCf:             true,
        domainForm: {
            domain: '', add_dns_a: true, add_www: true, add_wildcard: true,
            add_mx_null: true, add_spf: true, add_dmarc: true, skip_existing: true,
            cf_under_attack: false,
            cf_pageshield: true, cf_bot_fight: true, cf_leaked_creds: true, cf_waf: true,
            cf_always_online: true, cf_cache_aggressive: true, cf_browser_cache_ttl: true,
            cf_speed_minify: true, cf_speed_rocket: true, cf_speed_hints: true,
            cf_speed_http2: true, cf_speed_brotli: true
        },

        // Analytics
        analyticsDays:    30,
        analyticsLoading: false,
        analyticsChart:   null,
        analytics: { total: 0, daily: [], by_country: [], by_device: [], by_network: [], by_link: [] },

        // Conversion dashboard
        conv: {
            subTab:      'clicks',
            loading:     false,
            live:        true,
            clicks:      [],
            conversions: [],
            freshIds:    {},
            newConvIds:  {},
            newConvCount: 0,
            stats:       { clicks_24h: 0, conversions_24h: 0, revenue_24h: 0, cr: 0 },
            lastClickId: 0,
            lastConvId:  0,
            // search / sort / page — clicks
            clSearch: '', clSort: 'id', clSortDir: 'desc', clPage: 1,
            // search / sort / page — conversions
            cvSearch: '', cvSort: 'id', cvSortDir: 'desc', cvPage: 1,
            perPage: 50,
        },
        _convPollTimer: null,
        _clickQueue:    [],
        _dripTimer:     null,
        _relTick:       0,
        _relTickTimer:  null,

        /* ── Conv Stats (Stats + Subid tabs) ── */
        convStats: {
            loading: false,
            error: '',
            datePreset: 'today',
            dateFrom: '',
            dateTo: '',
            data: { total_clicks: 0, total_conv: 0, total_rev: 0, cr: 0, daily: [], by_country: [], by_network: [], by_status: [], by_slug: [], by_subid: [] },
            subidSearch: '',
            subidSort: 'total_payout',
            subidSortDir: 'desc',
            _reqId: 0,
        },
        _convAudio:     null,
        _bc:            null,

        // ── Computed: clicks filtered + sorted + paged ──
        get clFiltered() {
            const q = this.conv.clSearch.toLowerCase().trim();
            let rows = q ? this.conv.clicks.filter(c =>
                (c.slug||'').toLowerCase().includes(q) ||
                (c.username||'').toLowerCase().includes(q) ||
                (c.subid||'').toLowerCase().includes(q) ||
                (c.country||'').toLowerCase().includes(q) ||
                (c.network||'').toLowerCase().includes(q) ||
                (c.ip||'').toLowerCase().includes(q)
            ) : [...this.conv.clicks];
            const k = this.conv.clSort, d = this.conv.clSortDir === 'asc' ? 1 : -1;
            rows.sort((a,b) => {
                const va = a[k] ?? '', vb = b[k] ?? '';
                if (!isNaN(va) && !isNaN(vb) && va !== '' && vb !== '') return (Number(va)-Number(vb))*d;
                return String(va).localeCompare(String(vb))*d;
            });
            return rows;
        },
        get clPaged() {
            const s = (this.conv.clPage-1)*this.conv.perPage;
            return this.clFiltered.slice(s, s+this.conv.perPage);
        },
        get clTotalPages() { return Math.max(1, Math.ceil(this.clFiltered.length/this.conv.perPage)); },

        // ── Computed: conversions filtered + sorted + paged ──
        get cvFiltered() {
            const q = this.conv.cvSearch.toLowerCase().trim();
            let rows = q ? this.conv.conversions.filter(v =>
                (v.slug||'').toLowerCase().includes(q) ||
                (v.username||'').toLowerCase().includes(q) ||
                (v.subid||'').toLowerCase().includes(q) ||
                (v.country||'').toLowerCase().includes(q) ||
                (v.network||'').toLowerCase().includes(q) ||
                (v.ip||'').toLowerCase().includes(q) ||
                (v.status||'').toLowerCase().includes(q) ||
                (v.clickid||'').toLowerCase().includes(q)
            ) : [...this.conv.conversions];
            const k = this.conv.cvSort, d = this.conv.cvSortDir === 'asc' ? 1 : -1;
            rows.sort((a,b) => {
                const va = a[k] ?? '', vb = b[k] ?? '';
                if (!isNaN(va) && !isNaN(vb) && va !== '' && vb !== '') return (Number(va)-Number(vb))*d;
                return String(va).localeCompare(String(vb))*d;
            });
            return rows;
        },
        get cvPaged() {
            const s = (this.conv.cvPage-1)*this.conv.perPage;
            return this.cvFiltered.slice(s, s+this.conv.perPage);
        },
        get cvTotalPages() { return Math.max(1, Math.ceil(this.cvFiltered.length/this.conv.perPage)); },
        get convRecvUrl() {
            const base = new URL(BASE_URL);
            return base.origin + '/postback?clickid={clickid}&payout={payout}&status={status}';
        },

        // Confirm modal
        confirmModal: { show: false, title: '', message: '', okLabel: 'Delete', resolve: () => {} },

        // Toast
        toast:       { show: false, type: 'info', title: '', message: '', duration: 4000 },
        _toastTimer: null,
        csrfToken:   CSRF_TOKEN,

        async init() {
            if (this.isLoggedIn) {
                // Serialize init requests to avoid exhausting PHP-FPM workers
                // on low-NPROC shared hosts (parallel calls → 503 Service Unavailable)
                try { await this.loadLinks(); } catch (e) {}
                try { await this.loadSmartlinks(); } catch (e) {}
                try { await this.loadDomains(); } catch (e) {}
                try { await this.loadCfConfig(); } catch (e) {}

                // BroadcastChannel: instant cross-tab sync on same device
                if (typeof BroadcastChannel !== 'undefined') {
                    this._bc = new BroadcastChannel('tp_panel_v1');
                    this._bc.onmessage = (ev) => {
                        const type = ev.data?.type;
                        if (type === 'links')           this.loadLinks(true);
                        else if (type === 'domains')    this.loadDomains();
                        else if (type === 'smartlinks') this.loadSmartlinks();
                        // Live feed: another tab got new data — pull immediately
                        else if ((type === 'clicks' || type === 'conversions') && this.conv.live) {
                            this.loadLiveFeed();
                        }
                    };
                }

                // Default date range for conv stats (today)
                const _pad = n => String(n).padStart(2, '0');
                const _localDate = d => d.getFullYear() + '-' + _pad(d.getMonth()+1) + '-' + _pad(d.getDate());
                const now = new Date();
                this.convStats.dateFrom = _localDate(now);
                this.convStats.dateTo   = _localDate(now);
            }
        },

        toggleSetupPassword() {
            this.setupForm.showPw = !this.setupForm.showPw;
        },

        toggleLoginPassword() {
            this.loginForm.showPw = !this.loginForm.showPw;
        },

        switchMainTab(tab) {
            this.mainTab = tab;
            if (tab === 'domains') {
                this.loadUserDomains();
                return;
            }

            if (tab === 'analytics') {
                this.loadAnalytics();
                return;
            }

            if (tab === 'conversion') {
                this.startConvPoll();
            }
        },

        toggleCfTokenVisibility() {
            this.cfConfig.showToken = !this.cfConfig.showToken;
        },

        setConvSubTab(tab) {
            this.conv.subTab = tab;
            if (tab === 'conversions') {
                this.conv.newConvCount = 0;
            }
            if (tab === 'stats') {
                if (!this.convStats.dateFrom) {
                    const _pad = n => String(n).padStart(2, '0');
                    const _localDate = d => d.getFullYear() + '-' + _pad(d.getMonth()+1) + '-' + _pad(d.getDate());
                    const now = new Date();
                    this.convStats.dateFrom = _localDate(now);
                    this.convStats.dateTo   = _localDate(now);
                }
                if (!this.convStats.data.daily.length && !this.convStats.loading) {
                    console.log('[Performance] Auto-loading stats, dateFrom:', this.convStats.dateFrom, 'dateTo:', this.convStats.dateTo);
                    this.loadConvStats();
                }
            }
        },

        resetClickPage() {
            this.conv.clPage = 1;
        },

        resetConversionPage() {
            this.conv.cvPage = 1;
        },

        setClickPage(page) {
            this.conv.clPage = Math.min(this.clTotalPages, Math.max(1, page));
        },

        changeClickPage(delta) {
            this.setClickPage(this.conv.clPage + delta);
        },

        setConversionPage(page) {
            this.conv.cvPage = Math.min(this.cvTotalPages, Math.max(1, page));
        },

        changeConversionPage(delta) {
            this.setConversionPage(this.conv.cvPage + delta);
        },

        async post(action, payload = {}) {
            // Retry on 503 (worker exhausted on shared hosting) with exponential backoff
            const body = JSON.stringify({ action, csrf_token: this.csrfToken, ...payload });
            const maxRetries = 3;
            for (let attempt = 0; attempt <= maxRetries; attempt++) {
                try {
                    const res = await fetch('/gen', {
                        method:  'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body
                    });
                    if (res.status === 503 && attempt < maxRetries) {
                        await new Promise(r => setTimeout(r, 400 * (attempt + 1) + Math.random() * 200));
                        continue;
                    }
                    return await res.json();
                } catch (e) {
                    if (attempt >= maxRetries) throw e;
                    await new Promise(r => setTimeout(r, 400 * (attempt + 1) + Math.random() * 200));
                }
            }
        },


        async doSetup() {
            this.setupForm.error   = '';
            this.setupForm.loading = true;
            try {
                const r = await this.post('create_sl_user', {
                    username: this.setupForm.username.trim(),
                    password: this.setupForm.password
                });
                if (r.success) {
                    // Auto-login after setup
                    const lr = await this.post('login', {
                        username: this.setupForm.username.trim(),
                        password: this.setupForm.password
                    });
                    if (lr.success) {
                        this.isLoggedIn  = true;
                        this.currentUser = lr.username;
                        this.setupMode   = false;
                        try { await this.loadLinks(); } catch (e) {}
                        try { await this.loadSmartlinks(); } catch (e) {}
                        try { await this.loadDomains(); } catch (e) {}
                        try { await this.loadCfConfig(); } catch (e) {}
                    } else {
                        this.setupForm.error = 'User created, please log in.';
                        this.setupMode = false;
                    }
                } else {
                    this.setupForm.error = r.message || 'Failed to create user';
                }
            } catch (e) {
                this.setupForm.error = 'Connection error';
            } finally {
                this.setupForm.loading = false;
            }
        },

        async doLogin() {
            this.loginForm.error   = '';
            this.loginForm.loading = true;
            try {
                const r = await this.post('login', {
                    username: this.loginForm.username,
                    password: this.loginForm.password
                });
                if (r.success) {
                    this.isLoggedIn  = true;
                    this.currentUser = r.username;
                    this.setupMode   = false;
                    try { await this.loadLinks(); } catch (e) {}
                    try { await this.loadUsers(); } catch (e) {}
                    try { await this.loadSmartlinks(); } catch (e) {}
                    try { await this.loadDomains(); } catch (e) {}
                } else {
                    this.loginForm.error = r.message || 'Login failed';
                }
            } catch (e) {
                this.loginForm.error = 'Connection error';
            } finally {
                this.loginForm.loading = false;
            }
        },

        async doLogout() {
            const ok = await this.showConfirm('Sign Out', 'Are you sure you want to sign out?', 'Sign Out');
            if (!ok) return;
            await this.post('logout');
            this.isLoggedIn = false;
            this.links      = [];
            this.users      = [];
            this.loginForm  = { username: '', password: '', showPw: false, loading: false, error: '' };
        },

        async loadLinks(silent = false) {
            if (silent) { this.linksRefreshing = true; }
            else        { this.linksLoading = true; }
            try {
                const r = await this.post('list_links');
                if (r.success) { this.links = r.data; this.linksPage = 1; }
                else this.showToast('error', 'Failed to load links', r.message);
            } catch (e) {
                this.showToast('error', 'Connection error', e.message);
            } finally {
                this.linksLoading    = false;
                this.linksRefreshing = false;
            }
        },

        async loadCfConfig() {
            try {
                const r = await this.post('get_user_cf_config');
                if (r.success) {
                    const d = r.data;
                    this.cfConfig.cf_token      = d.cf_token      || '';
                    this.cfConfig.cf_account_id = d.cf_account_id || '';
                    this.cfConfig.cf_zone_id    = d.cf_zone_id    || '';
                    this.cfConfig.cf_proxied    = d.cf_proxied    || 'true';
                    this.cfConfig.has_own       = d.has_own       || false;
                }
            } catch (e) {}
        },

        async saveCfConfig() {
            this.cfConfig.saving = true;
            try {
                const r = await this.post('save_user_cf_config', {
                    cf_token:      this.cfConfig.cf_token.trim(),
                    cf_account_id: this.cfConfig.cf_account_id.trim(),
                    cf_zone_id:    this.cfConfig.cf_zone_id.trim(),
                    cf_proxied:    this.cfConfig.cf_proxied,
                });
                if (r.success) {
                    await this.loadCfConfig();
                    this.showToast('success', 'CF Config saved', this.cfConfig.has_own ? 'Own token active' : 'Using admin fallback');
                } else {
                    this.showToast('error', 'Save failed', r.message);
                }
            } catch (e) {
                this.showToast('error', 'Error', e.message);
            } finally {
                this.cfConfig.saving = false;
            }
        },

        async clearCfConfig() {
            const ok = await this.showConfirm('Remove CF Config', 'Remove your CF configuration and use admin config as fallback?', 'Remove');
            if (!ok) return;
            this.cfConfig.cf_token = '';
            this.cfConfig.cf_account_id = '';
            this.cfConfig.cf_zone_id = '';
            await this.saveCfConfig();
        },

        async loadSmartlinks() {
            this.smartlinksLoading = true;
            try {
                const r = await this.post('list_smartlinks_sl');
                if (r.success) this.smartlinks = r.data || [];
            } catch (e) {} finally {
                this.smartlinksLoading = false;
            }
        },

        async loadDomains() {
            try {
                const r = await this.post('list_domains_sl');
                if (r.success) {
                    this.domains = r.data || [];
                    if (!this.linkForm.domain && this.domains.length > 0) {
                        this.linkForm.domain = this.domains.length > 1 ? '__random__' : this.domains[0].domain;
                    }
                }
            } catch (e) {}
        },

        // Unique network names for the smartlink select
        uniqueSmartlinkNetworks() {
            return [...new Set(this.smartlinks.map(s => s.network))];
        },

        // Build URL shortlink berdasarkan service, shimlink, & domain
        // external_url diisi saat: (a) 3rd-party shortener, atau (b) own + shimlink.
        // Jika ada, itu URL yang dibagikan ke FB ads / platform.
        linkUrl(link) {
            if (link.external_url) {
                return link.external_url;
            }
            const domain = link.domain || new URL(BASE_URL).hostname;
            const sub    = link.rand_sub || '';
            const host   = sub ? sub + '.' + domain : domain;
            return 'https://' + host + '/' + link.slug;
        },

        randomSlug(len = 7) {
            const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            let s = '';
            for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
            return s;
        },

        async saveLink() {
            this.linkMsg        = '';
            this.linkLoading    = true;
            this.showBulkResult = false;
            this.bulkResult     = [];
            this.bulkErrors     = [];

            const countryRules = JSON.stringify(
                Object.fromEntries(
                    this.linkForm.rules
                        .filter(r => r.country.trim() && r.url.trim())
                        .map(r => [r.country.trim().toUpperCase(), r.url.trim()])
                )
            );

            const payload = {
                title:         this.linkForm.title.trim(),
                description:   this.linkForm.description.trim(),
                image:         this.linkForm.image.trim(),
                default_url:   this.linkForm.default_url.trim(),
                country_rules: countryRules,
                domain:        this.linkForm.domain || '',
                smartlink_network: this.linkForm.smartlink_network || '',
                shimlink:      this.linkForm.shimlink || '',
                link_type:     this.linkForm.link_type || 'normal',
                short_service: this.linkForm.short_service || 'default',
                ixg_sub:       this.linkForm.ixg_sub || '',
                quantity:      this.linkForm.quantity || 1,
                active:        this.linkForm.active ? 1 : 0,
            };

            const action = this.linkForm.id ? 'update_link' : 'create_link';
            if (this.linkForm.id) payload.id = this.linkForm.id;

            try {
                const r = await this.post(action, payload);
                if (r.success) {
                    // Collect new IDs for highlight
                    let createdIds = [];
                    // ── FB scrape result summary ──
                    const fbArr  = Array.isArray(r.fb_scrape) ? r.fb_scrape : (r.fb_scrape ? [r.fb_scrape] : []);
                    const fbOk   = fbArr.filter(f => f && f.ok).length;
                    const fbFail = fbArr.length - fbOk;
                    const fbNote = fbArr.length
                        ? (fbOk === fbArr.length
                            ? ' · FB scraped ✓'
                            : (fbOk ? ` · FB ${fbOk}/${fbArr.length} scraped` : ' · FB scrape failed'))
                        : '';

                    if (r.bulk && Array.isArray(r.data)) {
                        // Bulk result
                        createdIds = r.data.filter(d => d && d.id).map(d => d.id);
                        this.bulkResult     = r.data;
                        this.bulkErrors     = r.errors || [];
                        this.showBulkResult = true;
                        this.linkMsg = `${r.count} links created successfully.${fbNote}`;
                        this.linkOk  = true;
                    } else {
                        if (!this.linkForm.id && r.data && r.data.id) createdIds = [r.data.id];
                        const baseMsg = this.linkForm.id ? 'Link updated' : 'Link created';
                        this.linkMsg = baseMsg + ' successfully.' + fbNote;
                        this.linkOk  = true;
                    }
                    await this.loadLinks(true);
                    this._bc?.postMessage({ type: 'links' });
                    if (createdIds.length) {
                        this.newLinkIds = createdIds;
                        setTimeout(() => { this.newLinkIds = []; }, 1500);
                    }
                    if (!this.linkForm.id) this.resetLinkForm();
                } else {
                    this.linkMsg = r.message || 'Failed to save link';
                    this.linkOk  = false;
                }
            } catch (e) {
                this.linkMsg = 'Connection error: ' + e.message;
                this.linkOk  = false;
            } finally {
                this.linkLoading = false;
            }
        },

        editLink(link) {
            let rules = [];
            try {
                const parsed = JSON.parse(link.country_rules || '{}');
                rules = Object.entries(parsed).map(([country, url]) => ({ country, url }));
            } catch {}

            this.linkForm = {
                id:            link.id,
                title:         link.title || '',
                description:   link.description || '',
                image:         link.image || '',
                default_url:   link.default_url,
                domain:        link.domain || '',
                smartlink_network: link.smartlink_network || '',
                shimlink:      link.shimlink      || '',
                link_type:     link.link_type     || 'normal',
                short_service: link.short_service || 'default',
                ixg_sub:       '',
                quantity:      1,
                rules,
                active:        link.active == 1,
            };
            this.linkMsg = '';
            this.mainTab = 'links';
            window.scrollTo({ top: 0, behavior: 'smooth' });
        },

        resetLinkForm(opts = {}) {
            // Keep dropdown selections so they don't reset after creating a link
            const keepDomain    = this.linkForm.domain           || (this.domains.length > 1 ? '__random__' : (this.domains[0]?.domain ?? ''));
            const keepNetwork   = this.linkForm.smartlink_network || '';
            const keepShimlink  = this.linkForm.shimlink          || '';
            const keepLinkType  = this.linkForm.link_type         || 'normal';
            const keepService   = this.linkForm.short_service     || 'default';
            const keepIxgSub    = this.linkForm.ixg_sub            || '';
            // Preserve metadata fields (title, description, image URL) between generations
            // so users can reuse them for the next link without retyping. Pass
            // { full: true } to clear them (e.g. when leaving edit mode explicitly).
            const keepTitle       = opts.full ? '' : (this.linkForm.title        || '');
            const keepDescription = opts.full ? '' : (this.linkForm.description  || '');
            const keepImage       = opts.full ? '' : (this.linkForm.image        || '');
            this.linkForm = {
                id: null,
                title:             keepTitle,
                description:       keepDescription,
                image:             keepImage,
                default_url:       '',
                domain:            keepDomain,
                smartlink_network: keepNetwork,
                shimlink:          keepShimlink,
                link_type:         keepLinkType,
                short_service:     keepService,
                ixg_sub:           keepIxgSub,
                quantity: 1,
                rules: [], active: true
            };
            this.linkMsg = '';
            this.linkOk  = false;
        },

        async deleteLink(id) {
            const ok = await this.showConfirm('Delete Link', 'Deleted links cannot be recovered.', 'Delete');
            if (!ok) return;
            this.deletingLinkId = id;
            try {
                const r = await this.post('delete_link', { id });
                if (r.success) {
                    this.showToast('success', 'Link deleted');
                    this.links = this.links.filter(l => l.id !== id);
                    if (this.linkForm.id === id) this.resetLinkForm({ full: true });
                    this._bc?.postMessage({ type: 'links' });
                } else {
                    this.showToast('error', 'Failed to delete link', r.message);
                }
            } catch (e) {
                this.showToast('error', 'Connection error', e.message);
            } finally {
                this.deletingLinkId = null;
            }
        },

        copyLink(link) {
            const slug = link.slug || link;
            const url  = typeof link === 'object' ? this.linkUrl(link) : BASE_URL + '/' + slug;
            navigator.clipboard.writeText(url).then(() => {
                this.copyFeedback = slug;
                this.showToast('success', 'Link copied!', url, 2000);
                setTimeout(() => {
                    if (this.copyFeedback === slug) this.copyFeedback = null;
                }, 2000);
            });
        },

        copyAllBulkLinks() {
            const urls = this.bulkResult.map(l => this.linkUrl(l)).join('\n');
            navigator.clipboard.writeText(urls).then(() => {
                this.showToast('success', `${this.bulkResult.length} links copied!`, '', 2000);
            });
        },

        // ── Domain Management ──

        callHandler(action, data = {}) {
            // Send user's CF config (handler.php will merge with env/admin config)
            const cfCfg = {
                cf_token:      this.cfConfig.cf_token,
                cf_account_id: this.cfConfig.cf_account_id,
                cf_zone_id:    this.cfConfig.cf_zone_id,
                cf_proxied:    this.cfConfig.cf_proxied,
            };
            return fetch('/handler.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action, csrf_token: this.csrfToken, config: cfCfg, data })
            }).then(r => r.json());
        },

        async loadUserDomains() {
            this.userDomainsLoading = true;
            try {
                const r = await this.post('list_user_domains');
                if (r.success) this.userDomains = r.data || [];
                else this.showToast('error', 'Failed to load domains', r.message);
            } catch (e) {
                this.showToast('error', 'Error', e.message);
            } finally {
                this.userDomainsLoading = false;
            }
        },

        async addUserDomain() {
            const domain = this.domainForm.domain.trim();
            if (!domain) return;
            this.domainLoading = true;
            this.domainLogs    = [];
            this.domainNs      = [];
            try {
                // 1. Add via handler.php (cPanel + Cloudflare)
                const cf = this.useCf;
                const r = await this.callHandler('add_domain', {
                    domain,
                    domain_id:       this.currentUser,
                    add_dns_a:       cf && this.domainForm.add_dns_a,
                    add_www:         cf && this.domainForm.add_www,
                    add_wildcard:    cf && this.domainForm.add_wildcard,
                    add_mx_null:     cf && this.domainForm.add_mx_null,
                    add_spf:         cf && this.domainForm.add_spf,
                    add_dmarc:       cf && this.domainForm.add_dmarc,
                    skip_existing:   this.domainForm.skip_existing,
                    cf_under_attack: cf && this.domainForm.cf_under_attack,
                    cf_pageshield:   cf && this.domainForm.cf_pageshield,
                    cf_bot_fight:    cf && this.domainForm.cf_bot_fight,
                    cf_leaked_creds: cf && this.domainForm.cf_leaked_creds,
                    cf_waf:          cf && this.domainForm.cf_waf,
                    cf_always_online: cf && this.domainForm.cf_always_online,
                    cf_cache_aggressive: cf && this.domainForm.cf_cache_aggressive,
                    cf_browser_cache_ttl: cf && this.domainForm.cf_browser_cache_ttl,
                    cf_speed_minify: cf && this.domainForm.cf_speed_minify,
                    cf_speed_rocket: cf && this.domainForm.cf_speed_rocket,
                    cf_speed_hints:  cf && this.domainForm.cf_speed_hints,
                    cf_speed_http2:  cf && this.domainForm.cf_speed_http2,
                    cf_speed_brotli: cf && this.domainForm.cf_speed_brotli,
                });
                this.domainLogs = r.logs || [];
                this.domainNs   = r.nameservers || [];
                // 2. Save to user_domains in sl.php
                await this.post('save_user_domain', { domain });
                await this.loadUserDomains();
                await this.loadDomains();
                this._bc?.postMessage({ type: 'domains' });
                if (r.success) {
                    this.showToast('success', 'Domain added', domain);
                    this.domainForm.domain = '';
                } else {
                    this.showToast('error', 'Domain error', r.message || 'Check log');
                }
            } catch (e) {
                this.showToast('error', 'Error', e.message);
            } finally {
                this.domainLoading = false;
            }
        },

        async syncUserDomain(d) {
            d.syncing = true;
            try {
                const r = await this.callHandler('sync_cloudflare', { domain: d.domain });
                this.domainLogs = r.logs || [];
                this.domainNs   = r.nameservers || [];
                if (this.mainTab !== 'domains') this.mainTab = 'domains';
                await this.loadUserDomains();
                this.showToast(r.success ? 'success' : 'error', 'Sync Cloudflare', r.message);
            } catch (e) {
                this.showToast('error', 'Error', e.message);
            } finally {
                d.syncing = false;
            }
        },

        async deleteUserDomain(d) {
            const ok = await this.showConfirm('Delete Domain', `Delete domain "${d.domain}" from cPanel, Cloudflare, and database?`, 'Delete');
            if (!ok) return;
            try {
                // Remove from handler.php (cPanel + CF + addondomain)
                if (d.addondomain_id) {
                    await this.callHandler('delete_domain', { id: d.addondomain_id, domain: d.domain });
                }
                // Remove from user_domains
                await this.post('delete_user_domain', { domain: d.domain });
                this.userDomains = this.userDomains.filter(x => x.id !== d.id);
                await this.loadDomains();
                this._bc?.postMessage({ type: 'domains' });
                this.showToast('success', 'Domain deleted', d.domain);
            } catch (e) {
                this.showToast('error', 'Error', e.message);
            }
        },


        // ── Analytics ──

        async loadAnalytics() {
            this.analyticsLoading = true;
            try {
                const r = await this.post('get_analytics', { days: this.analyticsDays });
                if (r.success) {
                    this.analytics = r;
                    this.$nextTick(() => this.renderChart());
                }
            } catch(e) { this.showToast('error','Error',e.message); }
            finally { this.analyticsLoading = false; }
        },

        renderChart() {
            const canvas = document.getElementById('analyticsChart');
            if (!canvas || !window.Chart) return;
            if (!canvas.offsetParent && canvas.offsetWidth === 0) return; // canvas is not visible
            if (this.analyticsChart) { this.analyticsChart.destroy(); this.analyticsChart = null; }
            if (!this.analytics.daily?.length) return;
            const labels = this.analytics.daily.map(d => {
                const dt = new Date(d.date + 'T00:00:00');
                return dt.toLocaleDateString('id-ID', { day:'numeric', month:'short' });
            });
            const data = this.analytics.daily.map(d => d.hits);
            this.analyticsChart = new Chart(canvas, {
                type: 'line',
                data: { labels, datasets: [{
                    label: 'Klik', data,
                    borderColor: 'hsl(240,5.9%,18%)',
                    backgroundColor: 'hsla(240,5.9%,10%,0.06)',
                    borderWidth: 1.5, tension: 0.35, fill: true,
                    pointRadius: data.length > 30 ? 0 : 3,
                    pointHoverRadius: 4,
                    pointBackgroundColor: 'hsl(240,5.9%,18%)',
                }]},
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: { callbacks: { label: c => ' '+c.parsed.y.toLocaleString()+' klik' } }
                    },
                    scales: {
                        x: { grid: { display: false }, ticks: { font:{size:10}, maxTicksLimit:10, color:'#9ca3af' } },
                        y: { beginAtZero: true, grid: { color:'hsla(240,6%,10%,.06)' }, ticks: { font:{size:10}, color:'#9ca3af', precision:0 } }
                    }
                }
            });
        },


        convRelTime(ts) {
            void this._relTick; // reactive dependency — re-evaluates every tick
            if (!ts) return '—';
            const d = new Date(ts.replace(' ', 'T'));
            const s = Math.floor((Date.now() - d.getTime()) / 1000);
            if (s < 0)    return 'just now';
            if (s <  60)  return s + 's ago';
            if (s < 3600) return Math.floor(s/60) + 'm ago';
            if (s < 86400) return Math.floor(s/3600) + 'h ago';
            return d.toLocaleDateString();
        },

        async loadLiveFeed() {
            this.conv.loading = true;
            try {
                const r = await this.post('get_live_feed', {
                    after_click: this.conv.lastClickId,
                    after_conv:  this.conv.lastConvId,
                });
                if (!r.success) return;

                const isFirstLoad = this.conv.lastClickId === 0;

                // ── Clicks ──
                if (r.clicks && r.clicks.length) {
                    const newOnes = [];
                    r.clicks.forEach(c => {
                        const id = parseInt(c.id);
                        if (id > this.conv.lastClickId) {
                            this.conv.lastClickId = Math.max(this.conv.lastClickId, id);
                            if (!isFirstLoad) newOnes.push(c);
                        }
                    });

                    if (isFirstLoad) {
                        // Show everything at once during the initial load
                        const m = new Map(r.clicks.map(c => [c.id, c]));
                        this.conv.clicks = [...m.values()].sort((a,b) => b.id - a.id).slice(0, 200);
                    } else if (newOnes.length) {
                        // Queue oldest-first -> drip them in one by one
                        newOnes.sort((a,b) => parseInt(a.id) - parseInt(b.id));
                        this._clickQueue.push(...newOnes);
                        this._startDrip();
                        // Notify other tabs so they pull immediately
                        this._bc?.postMessage({ type: 'clicks', count: newOnes.length });
                    }
                }

                // ── Conversions ──
                if (r.conversions && r.conversions.length) {
                    let addedCount = 0;
                    const newCv = {};
                    r.conversions.forEach(v => {
                        const id = parseInt(v.id);
                        if (id > this.conv.lastConvId) {
                            newCv[id] = true;
                            this.conv.lastConvId = Math.max(this.conv.lastConvId, id);
                            addedCount++;
                        }
                    });
                    const existing = new Map(this.conv.conversions.map(v => [v.id, v]));
                    r.conversions.forEach(v => existing.set(v.id, v));
                    this.conv.conversions = [...existing.values()].sort((a,b) => b.id - a.id).slice(0, 200);
                    if (addedCount > 0) {
                        if (this.conv.subTab !== 'conversions') this.conv.newConvCount += addedCount;
                        // Flash highlight new conversion
                        this.conv.newConvIds = newCv;
                        setTimeout(() => { this.conv.newConvIds = {}; }, 3000);
                        // Conversion notification sound
                        this._playConvSound();
                        // Notify other tabs so they pull immediately
                        this._bc?.postMessage({ type: 'conversions', count: addedCount });
                    }
                }

                // ── Stats ──
                if (r.stats) this.conv.stats = r.stats;

            } catch(e) {
                console.error('liveFeed error', e);
            } finally {
                this.conv.loading = false;
            }
        },

        _startDrip() {
            if (this._dripTimer) return;
            this._dripTimer = setInterval(() => {
                if (!this._clickQueue.length) {
                    clearInterval(this._dripTimer);
                    this._dripTimer = null;
                    return;
                }
                const c  = this._clickQueue.shift();
                const id = parseInt(c.id);
                // Prepend to the top
                this.conv.clicks = [c, ...this.conv.clicks].slice(0, 200);
                // Mark as fresh -> trigger the animation
                this.conv.freshIds = { ...this.conv.freshIds, [id]: true };
                // Remove after animation completes (1.8s)
                setTimeout(() => {
                    const s = { ...this.conv.freshIds };
                    delete s[id];
                    this.conv.freshIds = s;
                }, 2000);
            }, 350);
        },

        clSortBy(col) {
            if (this.conv.clSort === col) this.conv.clSortDir = this.conv.clSortDir === 'asc' ? 'desc' : 'asc';
            else { this.conv.clSort = col; this.conv.clSortDir = 'desc'; }
            this.conv.clPage = 1;
        },
        cvSortBy(col) {
            if (this.conv.cvSort === col) this.conv.cvSortDir = this.conv.cvSortDir === 'asc' ? 'desc' : 'asc';
            else { this.conv.cvSort = col; this.conv.cvSortDir = 'desc'; }
            this.conv.cvPage = 1;
        },

        /* ── Conv Stats: load, chart, subid filter/sort ── */

        applyDatePreset() {
            const _pad = n => String(n).padStart(2, '0');
            const _fmt = d => d.getFullYear() + '-' + _pad(d.getMonth()+1) + '-' + _pad(d.getDate());
            const now = new Date();
            const p = this.convStats.datePreset;
            if (p === 'custom') return;
            if (p === 'today') {
                this.convStats.dateFrom = _fmt(now);
                this.convStats.dateTo   = _fmt(now);
            } else if (p === 'yesterday') {
                const y = new Date(now); y.setDate(y.getDate() - 1);
                this.convStats.dateFrom = _fmt(y);
                this.convStats.dateTo   = _fmt(y);
            } else if (p === '7d') {
                const d = new Date(now); d.setDate(d.getDate() - 6);
                this.convStats.dateFrom = _fmt(d);
                this.convStats.dateTo   = _fmt(now);
            } else if (p === '14d') {
                const d = new Date(now); d.setDate(d.getDate() - 13);
                this.convStats.dateFrom = _fmt(d);
                this.convStats.dateTo   = _fmt(now);
            } else if (p === '30d') {
                const d = new Date(now); d.setDate(d.getDate() - 29);
                this.convStats.dateFrom = _fmt(d);
                this.convStats.dateTo   = _fmt(now);
            } else if (p === 'this_month') {
                this.convStats.dateFrom = _fmt(new Date(now.getFullYear(), now.getMonth(), 1));
                this.convStats.dateTo   = _fmt(now);
            } else if (p === 'last_month') {
                const first = new Date(now.getFullYear(), now.getMonth() - 1, 1);
                const last  = new Date(now.getFullYear(), now.getMonth(), 0);
                this.convStats.dateFrom = _fmt(first);
                this.convStats.dateTo   = _fmt(last);
            }
            this.loadConvStats();
        },

        async loadConvStats() {
            if (this.convStats.loading) return;
            this.convStats.loading = true;
            this.convStats.error   = '';
            const reqId = ++this.convStats._reqId;
            try {
                const r = await this.post('get_conv_stats', {
                    date_from: this.convStats.dateFrom,
                    date_to:   this.convStats.dateTo,
                });
                if (reqId !== this.convStats._reqId) return;
                if (r.success) {
                    const subidRows = (Array.isArray(r.by_subid) ? r.by_subid : []).map(row => ({
                        subid:           row.subid || '',
                        click_count:     Number(row.click_count     || 0),
                        conv_count:      Number(row.conv_count      || 0),
                        total_payout:    Number(row.total_payout    || 0),
                        approved_payout: Number(row.approved_payout || 0),
                        pending_payout:  Number(row.pending_payout  || 0),
                        rejected_payout: Number(row.rejected_payout || 0),
                    }));
                    this.convStats.data = {
                        total_clicks: Number(r.total_clicks || 0),
                        total_conv:   Number(r.total_conv   || 0),
                        total_rev:    Number(r.total_rev    || 0),
                        cr:           Number(r.cr           || 0),
                        daily:        Array.isArray(r.daily)      ? r.daily      : [],
                        by_country:   Array.isArray(r.by_country) ? r.by_country : [],
                        by_network:   Array.isArray(r.by_network) ? r.by_network : [],
                        by_status:    Array.isArray(r.by_status)  ? r.by_status  : [],
                        by_slug:      Array.isArray(r.by_slug)    ? r.by_slug    : [],
                        by_subid:     subidRows,
                    };
                    console.log('[Performance] Loaded', subidRows.length, 'subid rows, clicks:', r.total_clicks, 'conv:', r.total_conv);
                } else {
                    this.convStats.error = r.message || 'Failed to load performance data';
                    console.warn('[Performance] API error:', this.convStats.error);
                }
            } catch (e) {
                this.convStats.error = 'Connection error: ' + (e?.message || e);
                console.error('[Performance] Exception:', e);
            } finally {
                this.convStats.loading = false;
            }
        },

        renderConvStatsChart() { /* no-op — chart removed */ },

        get dailySorted() {
            const rows = this.convStats.data.daily || [];
            return [...rows].sort((a, b) => b.date.localeCompare(a.date));
        },

        get userSubidFiltered() {
            let rows = this.convStats.data.by_subid || [];
            const q = (this.convStats.subidSearch || '').trim().toLowerCase();
            if (q) {
                const isEmptySearch = ['empty', '(empty)', '—', '-'].includes(q);
                rows = rows.filter(r => {
                    if (isEmptySearch) return !r.subid || r.subid === '';
                    return (r.subid || '').toLowerCase().includes(q);
                });
            }
            const sortKey = this.convStats.subidSort;
            const dir     = this.convStats.subidSortDir === 'asc' ? 1 : -1;
            rows = [...rows].sort((a, b) => {
                if (sortKey === 'subid') {
                    return dir * (a.subid || '').localeCompare(b.subid || '');
                }
                return dir * ((Number(a[sortKey]) || 0) - (Number(b[sortKey]) || 0));
            });
            return rows;
        },

        toggleSubidSort(key) {
            if (this.convStats.subidSort === key) {
                this.convStats.subidSortDir = this.convStats.subidSortDir === 'asc' ? 'desc' : 'asc';
            } else {
                this.convStats.subidSort = key;
                this.convStats.subidSortDir = 'desc';
            }
        },

        _playConvSound() {
            try {
                const ctx = new (window.AudioContext || window.webkitAudioContext)();
                // Short tone: two ascending beeps
                const play = (freq, start, dur) => {
                    const o = ctx.createOscillator();
                    const g = ctx.createGain();
                    o.connect(g); g.connect(ctx.destination);
                    o.frequency.value = freq;
                    o.type = 'sine';
                    g.gain.setValueAtTime(0.18, ctx.currentTime + start);
                    g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + start + dur);
                    o.start(ctx.currentTime + start);
                    o.stop(ctx.currentTime + start + dur);
                };
                play(880, 0,    0.12);
                play(1320, 0.13, 0.15);
            } catch(e) {}
        },

        startConvPoll() {
            this.conv.live = true;
            this.loadLiveFeed();
            clearInterval(this._convPollTimer);
            this._convPollTimer = setInterval(() => this.loadLiveFeed(), 5000);
            // Refresh relative timestamps every 30 s so "5s ago" doesn't go stale
            clearInterval(this._relTickTimer);
            this._relTickTimer = setInterval(() => { this._relTick++; }, 30000);
        },

        stopConvPoll() {
            this.conv.live = false;
            clearInterval(this._convPollTimer);
            this._convPollTimer = null;
            clearInterval(this._dripTimer);
            this._dripTimer = null;
            clearInterval(this._relTickTimer);
            this._relTickTimer = null;
            this._clickQueue = [];
        },

        copyText(text) {
            if (!text) return;
            navigator.clipboard.writeText(text).then(() => {
                this.showToast('success', 'Copied!', text.substring(0, 40) + (text.length > 40 ? '…' : ''));
            }).catch(() => {
                const el = document.createElement('textarea');
                el.value = text;
                document.body.appendChild(el);
                el.select();
                document.execCommand('copy');
                document.body.removeChild(el);
                this.showToast('success', 'Copied!', '');
            });
        },

        showConfirm(title, message, okLabel = 'Delete') {
            return new Promise(resolve => {
                this.confirmModal = { show: true, title, message, okLabel, resolve };
            });
        },

        resolveConfirm(accepted) {
            const resolve = this.confirmModal.resolve;
            this.confirmModal.show = false;
            if (typeof resolve === 'function') {
                resolve(accepted);
            }
        },

        showToast(type, title, message = '', duration = 4000) {
            if (this._toastTimer) clearTimeout(this._toastTimer);
            this.toast = { show: false, type, title, message, duration };
            this.$nextTick(() => {
                this.toast.show  = true;
                this._toastTimer = setTimeout(() => { this.toast.show = false; }, duration);
            });
        },

        toastProgressStyle() {
            return 'animation-duration: ' + this.toast.duration + 'ms';
        },

        dismissToast() {
            this.toast.show = false;
        },
    };
}
</script>

<!-- PWA Service Worker Registration -->
<script<?php echo $nonceAttr; ?>>
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js')
            .catch(err => console.warn('SW register failed:', err));
    });
}
</script>
<script<?php echo $nonceAttr; ?>>document.querySelectorAll('img').forEach(i => i.addEventListener('contextmenu', e => e.preventDefault()));document.addEventListener('contextmenu', e => { if (e.target.tagName === 'IMG') { e.preventDefault(); } });</script>
</body>
</html>
