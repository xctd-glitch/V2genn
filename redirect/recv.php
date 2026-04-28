<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap/runtime_compat.php';
require_once __DIR__ . '/../bootstrap/host_utils.php';
require_once __DIR__ . '/../module/security.php';

/**
 * recv.php — Postback / Conversion Receiver
 * Accessible via clean URL: /postback (via .htaccess rewrite)
 *
 * URL format:
 *   https://domain.com/postback?clickid={clickid}&payout={payout}&status={status}
 *
 * Parameters:
 *   clickid / cid / click_id  — required, base64url encoded: subid,country,device,network,ip
 *                               (also accepts legacy pipe-separated format for backwards compat)
 *   payout                    — optional, conversion value in USD (default 0)
 *   status                    — optional: approved / pending / rejected (default approved)
 *   subid                     — optional, sent directly by the network
 */

// ── Load .env ──
tp_load_env_file(__DIR__ . '/../.env');


function recvFormatPayout(float $payout): string
{
    $formatted = number_format($payout, 4, '.', '');
    $trimmed = rtrim(rtrim($formatted, '0'), '.');

    return $trimmed === '' ? '0' : $trimmed;
}

function recvFinishResponse(string $body): void
{
    http_response_code(200);

    if (function_exists('fastcgi_finish_request')) {
        echo $body;
        fastcgi_finish_request();

        return;
    }

    ignore_user_abort(true);
    header('Connection: close');
    header('Content-Length: ' . strlen($body));
    echo $body;
    while (ob_get_level() > 0) {
        @ob_end_flush();
    }
    flush();
}

// ── DB ──
function recvDb(): ?PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $pdo = tp_pdo_connect(true);
    return $pdo;
}

// ── Rate limiting — stricter than go.php (60/min) to slow down fake-conversion floods ──
rateLimitByIp(60);

// ── Parse params (GET + POST) ──
// clickid accepted as: clickid, cid, click_id (all base64url-decoded internally)
$params   = array_merge($_GET, $_POST);
$clickid  = trim($params['clickid'] ?? $params['cid'] ?? $params['click_id'] ?? '');
$payout   = max(0.0, (float)($params['payout']  ?? 0));
$rawStatus = strtolower(trim($params['status']   ?? 'approved'));
$status   = in_array($rawStatus, ['approved','pending','rejected','declined'], true) ? $rawStatus : 'approved';
$subid    = trim($params['subid'] ?? '');

// Respond immediately (affiliate networks just need 200 OK)
header('Content-Type: text/plain');
header('Cache-Control: no-store');

if (!$clickid) {
    http_response_code(400);
    exit('missing clickid');
}

// ── Optional HMAC signature verification ─────────────────────────────
// When POSTBACK_SECRET is set in .env, every incoming postback must carry
// a valid HMAC-SHA256 signature over the canonical payload. This stops an
// attacker from injecting fake conversions just by knowing the clickid
// format. Networks that support signed postbacks should send:
//
//   &ts=<unix seconds> — request timestamp (replay window check)
//   &sig=<hex>         — lowercase HMAC-SHA256(secret, canonical)
//
// Where `canonical` = "clickid|payout|status|subid|ts" (string concat, no
// encoding). We accept the raw numeric payout as provided by the network
// (before our float cast) to keep signatures byte-stable.
//
// Replay protection
// ─────────────────
// A valid signature alone is not enough: without a timestamp, a leaked
// postback URL could be replayed forever. We therefore:
//   1. Require `ts` within ±POSTBACK_REPLAY_WINDOW seconds of now (default 300).
//   2. Include `ts` in the canonical string so any tamper invalidates the sig.
// Legacy integrations that send no `ts` still work when
// POSTBACK_STRICT_TS=0 (default — fail-open on missing ts but still require
// a valid signature over the canonical with empty ts).
//
// Key rotation
// ────────────
// During secret rotation, set POSTBACK_SECRET_OLD to the previous value and
// postbacks signed with either secret will verify. After all networks have
// updated, remove POSTBACK_SECRET_OLD from .env.
//
// If POSTBACK_SECRET is empty, verification is disabled (fail-open) so
// existing integrations keep working. Set `POSTBACK_SECRET=...` in .env
// to enforce verification.
$postbackSecret = trim((string) getenv('POSTBACK_SECRET'));
if ($postbackSecret !== '') {
    $providedSig = strtolower(trim((string) ($params['sig'] ?? '')));
    if ($providedSig === '' || !preg_match('/^[0-9a-f]{64}$/', $providedSig)) {
        http_response_code(401);
        exit('missing or malformed signature');
    }

    // Replay window check — skippable in legacy mode via POSTBACK_STRICT_TS=0.
    $replayWindow = max(30, (int) (getenv('POSTBACK_REPLAY_WINDOW') ?: 300));
    $strictTs     = trim((string) getenv('POSTBACK_STRICT_TS')) !== '0';
    $providedTs   = trim((string) ($params['ts'] ?? ''));
    if ($providedTs !== '') {
        if (!preg_match('/^\d{10,13}$/', $providedTs)) {
            http_response_code(400);
            exit('malformed ts');
        }
        $tsInt = (int) $providedTs;
        // Accept both seconds and milliseconds.
        if ($tsInt > 9_999_999_999) {
            $tsInt = (int) floor($tsInt / 1000);
        }
        $drift = abs(time() - $tsInt);
        if ($drift > $replayWindow) {
            http_response_code(401);
            exit('ts outside replay window');
        }
    } elseif ($strictTs) {
        http_response_code(401);
        exit('missing ts');
    }

    // Canonical payload — keep stable and byte-identical on both sides.
    $canonical = implode('|', [
        $clickid,
        (string) ($params['payout'] ?? '0'),
        $rawStatus,
        $subid,
        $providedTs,
    ]);

    $secrets = [$postbackSecret];
    $oldSecret = trim((string) getenv('POSTBACK_SECRET_OLD'));
    if ($oldSecret !== '' && $oldSecret !== $postbackSecret) {
        $secrets[] = $oldSecret;
    }

    $sigOk = false;
    foreach ($secrets as $candidate) {
        $expectedSig = hash_hmac('sha256', $canonical, $candidate);
        if (hash_equals($expectedSig, $providedSig)) {
            $sigOk = true;
            break;
        }
    }

    if (!$sigOk) {
        http_response_code(403);
        exit('invalid signature');
    }
}

// ── Decode clickid ──
// Current canonical format: "subid,country,device,network,ip" (comma-separated)
// Legacy format (pre-2026-04): "owner|country|device|ip|network" (pipe-separated)
// We auto-detect the separator and fall back to legacy field order on pipe.
$pad     = str_repeat('=', (4 - strlen($clickid) % 4) % 4);
$decoded = base64_decode(strtr($clickid, '-_', '+/') . $pad, true);

$owner   = '';
$country = '';
$device  = '';
$network = '';
if ($decoded !== false && $decoded !== '') {
    if (strpos($decoded, ',') !== false) {
        // New format: subid, country, device, network, ip
        $parts   = explode(',', $decoded);
        $owner   = $parts[0] ?? '';
        $country = strtoupper($parts[1] ?? '');
        $device  = $parts[2] ?? '';
        $network = $parts[3] ?? '';
    } else {
        // Legacy pipe format: owner, country, device, ip, network
        $parts   = explode('|', $decoded);
        $owner   = $parts[0] ?? '';
        $country = strtoupper($parts[1] ?? '');
        $device  = $parts[2] ?? '';
        $network = $parts[4] ?? '';
    }
}

// ── Source IP ── (validated; same logic as go.php::getVisitorIp)
$sourceIp = '';
foreach ([
    trim((string) ($_SERVER['HTTP_CF_CONNECTING_IP'] ?? '')),
    trim(explode(',', (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''))[0]),
    trim((string) ($_SERVER['REMOTE_ADDR'] ?? '')),
] as $_ip) {
    if ($_ip !== '' && filter_var($_ip, FILTER_VALIDATE_IP) !== false) {
        $sourceIp = $_ip;
        break;
    }
}
unset($_ip);

// ── Raw params for debug ──
$rawParams = json_encode($params, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

$db = recvDb();
if (!$db) {
    http_response_code(503);
    exit('db unavailable');
}

// ── Lookup user_id from owner ──
$userId = 0;
if ($owner) {
    try {
        $u = $db->prepare('SELECT id FROM app_users WHERE username = ? LIMIT 1');
        $u->execute([$owner]);
        $row = $u->fetch();
        if ($row) {
            $userId = (int)$row['id'];
        }
    } catch (PDOException $e) {
    }
}

// ── Lookup slug from latest click with this clickid ──
$slug = '';
try {
    $s = $db->prepare(
        'SELECT slug FROM clicks WHERE clickid = ? ORDER BY id DESC LIMIT 1'
    );
    $s->execute([$clickid]);
    $row = $s->fetch();
    if ($row) {
        $slug = $row['slug'];
    }
} catch (PDOException $e) {
}

// ── Skip conversion if subid, network, or payout is empty/zero ──
$resolvedSubid = $subid ?: $owner;
if ($resolvedSubid === '' || $network === '' || $payout <= 0) {
    error_log(sprintf(
        'recv.php: skipped conversion clickid=%s subid=%s network=%s payout=%s ip=%s',
        $clickid,
        $resolvedSubid,
        $network,
        (string) $payout,
        $sourceIp
    ));
    recvFinishResponse('ok');
    exit;
}

// ── Insert conversion + update click payout (atomic transaction) ──
try {
    $db->beginTransaction();

    $db->prepare(
        'INSERT INTO conversions
         (user_id, clickid, subid, slug, country, device, network, payout, status, raw_params, source_ip)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    )->execute([
        $userId,
        $clickid,
        $resolvedSubid,
        $slug,
        $country,
        $device,
        $network,
        $payout,
        $status,
        $rawParams,
        $sourceIp,
    ]);

    if ($payout > 0 && $slug) {
        try {
            $db->prepare(
                'UPDATE clicks SET payout = payout + ?
                 WHERE id = (
                     SELECT id FROM (
                         SELECT id FROM clicks WHERE clickid = ? AND slug = ? ORDER BY id DESC LIMIT 1
                     ) AS t
                 )'
            )->execute([$payout, $clickid, $slug]);
        } catch (PDOException $eUpdate) {
            // Fallback: direct UPDATE (works on MySQL 8+ with ORDER BY)
            try {
                $db->prepare('UPDATE clicks SET payout = payout + ? WHERE clickid = ? AND slug = ? LIMIT 1')
                   ->execute([$payout, $clickid, $slug]);
            } catch (PDOException $eUpdate2) {
                // Best-effort: conversion is still recorded even if payout update fails
            }
        }
    }

    $db->commit();
} catch (PDOException $e) {
    if ($db->inTransaction()) {
        $db->rollBack();
    }
    http_response_code(500);
    error_log('recv.php: db error: ' . $e->getMessage());
    exit('internal error');
}

$_recvPbLimit = max(1, (int) (getenv('POSTBACK_QUERY_LIMIT') ?: 50));
$conversionPostbackUrls = [];
if ($slug !== '') {
    try {
        $postbackStatement = $db->prepare(
            "SELECT url FROM postbacks
             WHERE active = 1 AND event = 'conversion' AND (slug = ? OR slug = '')
             LIMIT ?"
        );
        $postbackStatement->execute([$slug, $_recvPbLimit]);
        $conversionPostbackUrls = $postbackStatement->fetchAll(PDO::FETCH_COLUMN);
    } catch (Throwable $e) {
        $conversionPostbackUrls = [];
    }
}

$resolvedPostbackUrls = [];
if ($conversionPostbackUrls !== []) {
    $safeSubid   = $subid !== '' ? $subid : $owner;
    $safePayout  = recvFormatPayout($payout);
    $subidEnc    = rawurlencode($safeSubid);
    $clickidEnc  = rawurlencode($clickid);
    foreach ($conversionPostbackUrls as $postbackUrl) {
        // Accept all subid/clickid aliases (case-insensitive) plus auxiliary tokens.
        // Supports both {param} and <param> placeholder formats.
        $postbackUrl = tp_replace_postback_placeholders((string) $postbackUrl, [
            'subid' => $subidEnc,
            'sid' => $subidEnc,
            'sub_id' => $subidEnc,
            's' => $subidEnc,
            'clickid' => $clickidEnc,
            'cid' => $clickidEnc,
            'click_id' => $clickidEnc,
            'c' => $clickidEnc,
            'country' => rawurlencode($country),
            'device' => rawurlencode($device),
            'network' => rawurlencode($network),
            'slug' => rawurlencode($slug),
            'payout' => rawurlencode($safePayout),
            'status' => rawurlencode($status),
        ]);
        if (!filter_var($postbackUrl, FILTER_VALIDATE_URL)) {
            continue;
        }

        $resolvedPostbackUrls[] = $postbackUrl;
    }
}

if ($resolvedPostbackUrls !== []) {
    recvFinishResponse('OK');
    tp_enqueue_postbacks($resolvedPostbackUrls);
    exit;
}

http_response_code(200);
exit('OK');
