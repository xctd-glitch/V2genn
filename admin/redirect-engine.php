<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap/security_bootstrap.php';
require_once __DIR__ . '/../bootstrap/admin_auth.php';

tp_runtime_harden();
tp_secure_session_bootstrap();
session_start();
tp_send_security_headers();
tp_load_env_file(__DIR__ . '/../.env');

$requestMethod = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
$nonceAttr = tp_csp_nonce_attr();
$csrfToken = tp_csrf_token();

if ($requestMethod === 'POST' && isset($_POST['_logout'])) {
    if (!tp_is_valid_csrf_token((string) ($_POST['csrf_token'] ?? ''))) {
        http_response_code(403);
        exit('Invalid CSRF token.');
    }

    tp_destroy_session();
    header('Location: /');
    exit;
}

if (empty($_SESSION['dashboard_auth']) || !tp_is_super_admin()) {
    header('Location: /');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redirect Engine</title>
    <link rel="icon" href="/favicon.ico" sizes="any">
    <link rel="stylesheet" href="/assets/vendor/tailwind-3.4.17.css">
    <link rel="stylesheet" href="/assets/style.css?v=<?= @filemtime(__DIR__ . '/../assets/style.css') ?: time() ?>">
    <script src="/assets/vendor/alpine-3.15.11.min.js" defer></script>
    <style<?php echo $nonceAttr; ?>>
        .redirect-engine-layout {
            display: grid;
            grid-template-columns: minmax(0, 2fr) minmax(20rem, 1fr);
            gap: 1rem;
        }

        .redirect-engine-sidebar {
            position: sticky;
            top: 4rem;
            align-self: start;
        }

        .redirect-engine-stat-grid,
        .redirect-engine-audit-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: .75rem;
        }

        .redirect-engine-empty {
            padding: 2.25rem 1rem;
            text-align: center;
            color: var(--muted-foreground);
        }

        .redirect-engine-cell-main {
            font-weight: 600;
            color: var(--foreground);
        }

        .redirect-engine-cell-sub {
            margin-top: .18rem;
            font-size: var(--text-2xs);
            color: var(--muted-foreground);
        }

        @media (max-width: 1279px) {
            .redirect-engine-layout {
                grid-template-columns: minmax(0, 1fr);
            }

            .redirect-engine-sidebar {
                position: static;
            }

            .redirect-engine-stat-grid,
            .redirect-engine-audit-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }

        @media (max-width: 767px) {
            .redirect-engine-stat-grid,
            .redirect-engine-audit-grid {
                grid-template-columns: minmax(0, 1fr);
            }
        }
    </style>
</head>
<body class="min-h-screen text-foreground" x-data="redirectEngineApp()" x-init="init()">
<form method="POST" id="logoutForm" class="hidden">
    <input type="hidden" name="_logout" value="1">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8') ?>">
</form>

<div class="min-h-screen bg-background">
    <header class="sticky top-0 z-30">
        <div class="max-w-7xl mx-auto px-4 h-12 flex items-center justify-between gap-3">
            <div class="flex items-center gap-2.5">
                <img src="/assets/logo.png" class="w-6 h-6" alt="Logo">
                <div>
                    <p class="text-[13px] font-semibold leading-none tracking-tight">Redirect Engine</p>
                    <p class="text-[10px] text-muted-foreground leading-none mt-0.5">Standalone control panel synced to the live decision engine</p>
                </div>
            </div>

            <div class="flex items-center gap-2">
                <a href="/"
                    class="btn btn-outline btn-sm flex items-center gap-1.5">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
                    </svg>
                    Dashboard
                </a>

                <button type="button" @click="logout()"
                    class="btn btn-outline btn-sm flex items-center gap-1.5 text-destructive border-destructive/30 hover:bg-destructive/10">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                    </svg>
                    Logout
                </button>
            </div>
        </div>
    </header>

    <main class="flex-1 max-w-7xl mx-auto w-full px-4 py-4 space-y-4">
        <div x-show="flash.message" x-transition
            class="notice-box"
            :class="flash.ok ? 'notice-box-blue' : 'notice-box-amber'">
            <div class="flex items-start justify-between gap-3">
                <p class="text-sm font-medium" x-text="flash.message"></p>
                <button type="button" class="text-muted-foreground hover:text-foreground" @click="flash.message = ''">×</button>
            </div>
        </div>

        <section class="redirect-engine-layout">
            <article class="sl-card">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <svg class="w-4 h-4 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7h16M4 12h10m-10 5h16"/>
                        </svg>
                        <h2 class="sl-card-title">Engine Status</h2>
                        <span class="sl-card-count" x-text="window.mode === 'filter' ? 'FILTER' : 'NORMAL'"></span>
                    </div>
                    <div class="sl-card-header-right">
                        <button type="button" class="sl-card-refresh" @click="loadAll()" :disabled="loading">
                            <div x-show="loading" class="spinner w-3 h-3"></div>
                            <svg x-show="!loading" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                            </svg>
                            Refresh
                        </button>
                    </div>
                </div>
                <div class="sl-card-body space-y-4">
                    <div class="redirect-engine-stat-grid">
                        <div class="stat-card stat-card-amber">
                            <div class="stat-card-label">Current Mode</div>
                            <div class="stat-card-value" x-text="window.mode === 'filter' ? 'Filter' : 'Normal'"></div>
                            <div class="stat-card-sub">Active branch for the live redirect cycle</div>
                        </div>
                        <div class="stat-card stat-card-blue">
                            <div class="stat-card-label">Seconds Left</div>
                            <div class="stat-card-value tabular-nums" x-text="Number(window.seconds_until_switch || 0)"></div>
                            <div class="stat-card-sub">Countdown until the next cycle switch</div>
                        </div>
                        <div class="stat-card stat-card-emerald">
                            <div class="stat-card-label">Next Switch</div>
                            <div class="stat-card-value stat-card-value-compact" x-text="formatUnix(window.next_switch_at_unix)"></div>
                            <div class="stat-card-sub">Cycle anchor: <span x-text="formatUnix(config.cycle_anchor_unix)"></span></div>
                        </div>
                        <div class="stat-card stat-card-violet">
                            <div class="stat-card-label">Health</div>
                            <div class="stat-card-value" x-text="health.healthy ? 'OK' : 'Warn'"></div>
                            <div class="stat-card-sub">Alerts: <span x-text="Array.isArray(health.alerts) ? health.alerts.length : 0"></span></div>
                        </div>
                    </div>

                    <div class="panel-box p-4">
                        <div class="flex flex-col gap-2 text-sm">
                            <div class="flex items-center gap-2">
                                <span class="text-xs font-bold uppercase tracking-wider text-muted-foreground">Current Hour</span>
                                <span class="font-semibold tabular-nums" x-text="health.current_hour_count"></span>
                            </div>
                            <div class="flex items-center gap-2">
                                <span class="text-xs font-bold uppercase tracking-wider text-muted-foreground">Previous Hour</span>
                                <span class="font-semibold tabular-nums" x-text="health.previous_hour_count"></span>
                            </div>
                            <div class="flex items-center gap-2">
                                <span class="text-xs font-bold uppercase tracking-wider text-muted-foreground">Audit Errors</span>
                                <span class="font-semibold tabular-nums" x-text="health.redirect_decision_errors"></span>
                            </div>
                        </div>
                    </div>

                    <template x-if="Array.isArray(health.alerts) && health.alerts.length > 0">
                        <div class="space-y-2">
                            <template x-for="alert in health.alerts" :key="alert.code">
                                <div class="notice-box" :class="alert.severity === 'critical' ? 'notice-box-amber' : 'notice-box-blue'">
                                    <div class="font-semibold" x-text="alert.code"></div>
                                    <div class="mt-1 text-xs" x-text="alert.message"></div>
                                </div>
                            </template>
                        </div>
                    </template>
                </div>
            </article>

            <article class="sl-card redirect-engine-sidebar">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <svg class="w-4 h-4 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/>
                        </svg>
                        <h2 class="sl-card-title">Actions</h2>
                    </div>
                </div>
                <div class="sl-card-body space-y-3">
                    <button type="button" class="btn btn-primary w-full justify-center"
                        @click="saveConfig()" :disabled="saving">
                        <span x-text="saving ? 'Saving...' : 'Save Engine Config'"></span>
                    </button>

                    <button type="button" class="btn btn-outline w-full justify-center"
                        @click="resetCycle()" :disabled="resetting">
                        <span x-text="resetting ? 'Resetting...' : 'Reset Cycle Anchor'"></span>
                    </button>

                    <button type="button" class="btn btn-outline w-full justify-center"
                        @click="resetAuditErrors()">
                        Reset Audit Error Counter
                    </button>

                    <div class="panel-box p-4 text-sm">
                        <p class="font-semibold">Saved Config Snapshot</p>
                        <dl class="mt-3 space-y-2 text-muted-foreground">
                        <div class="flex justify-between gap-3">
                            <dt>Enabled</dt>
                            <dd class="font-medium text-foreground" x-text="config.enabled ? 'Yes' : 'No'"></dd>
                        </div>
                        <div class="flex justify-between gap-3">
                            <dt>Require WAP</dt>
                            <dd class="font-medium text-foreground" x-text="config.require_wap ? 'Yes' : 'No'"></dd>
                        </div>
                        <div class="flex justify-between gap-3">
                            <dt>No VPN only</dt>
                            <dd class="font-medium text-foreground" x-text="config.require_no_vpn ? 'Yes' : 'No'"></dd>
                        </div>
                        <div class="flex justify-between gap-3">
                            <dt>Updated</dt>
                            <dd class="font-medium text-foreground text-right" x-text="formatIso(config.updated_at)"></dd>
                        </div>
                        </dl>
                    </div>
                </div>
            </article>
        </section>

        <section>
            <article class="sl-card">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <svg class="w-4 h-4 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.341A8 8 0 108.659 4.572m10.769 10.769L21 17m-5.572-1.659A8 8 0 116.34 4.572"/>
                        </svg>
                        <h2 class="sl-card-title">Configuration</h2>
                    </div>
                </div>
                <div class="sl-card-body">
                    <p class="text-sm text-muted-foreground mb-4">This writes directly to the live redirect decision JSON config.</p>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <label class="panel-box p-4 flex items-start gap-3">
                        <input type="checkbox" class="mt-1" x-model="config.enabled">
                        <span>
                            <span class="block font-medium">Engine enabled</span>
                            <span class="block text-sm text-muted-foreground mt-1">Filter routing can switch between normal and redirect windows.</span>
                        </span>
                    </label>

                    <label class="panel-box p-4 flex items-start gap-3">
                        <input type="checkbox" class="mt-1" x-model="config.require_wap">
                        <span>
                            <span class="block font-medium">Require WAP device</span>
                            <span class="block text-sm text-muted-foreground mt-1">Non-WAP traffic stays on the normal route during filter windows.</span>
                        </span>
                    </label>

                    <label class="panel-box p-4 flex items-start gap-3 md:col-span-2">
                        <input type="checkbox" class="mt-1" x-model="config.require_no_vpn">
                        <span>
                            <span class="block font-medium">Block VPN-like traffic from redirect path</span>
                            <span class="block text-sm text-muted-foreground mt-1">When enabled, VPN or proxy-like traffic remains on the normal route.</span>
                        </span>
                    </label>

                    <div class="md:col-span-2">
                        <label class="field-label">Redirect URL</label>
                        <input type="url" x-model="config.redirect_url"
                            class="input font-mono"
                            :class="globalFilterRedirectUrl ? 'opacity-50' : ''"
                            placeholder="https://example.com/offer">
                        <template x-if="globalFilterRedirectUrl">
                            <p class="hint mt-1 text-amber-600 font-medium">
                                ⚠ Overridden by System Config <code>filter_redirect_url</code>:
                                <span class="font-mono break-all" x-text="globalFilterRedirectUrl"></span>.
                                This field is inactive until that setting is cleared.
                            </p>
                        </template>
                        <template x-if="!globalFilterRedirectUrl">
                            <p class="hint mt-1">Used only when the decision engine returns <code>redirect_url</code>.</p>
                        </template>
                    </div>

                    <div>
                        <label class="field-label">Filter Window (seconds)</label>
                        <input type="number" min="10" max="86400" step="1" x-model="config.filter_duration_seconds" class="input">
                    </div>

                    <div>
                        <label class="field-label">Normal Window (seconds)</label>
                        <input type="number" min="10" max="86400" step="1" x-model="config.normal_duration_seconds" class="input">
                    </div>

                    <div class="md:col-span-2">
                        <label class="field-label">Allowed Countries</label>
                        <textarea x-model="allowedCountriesInput"
                            rows="4"
                            class="textarea font-mono"
                            placeholder="US, CA, GB"></textarea>
                        <p class="hint mt-1">Comma, space, or newline separated ISO country codes. Empty means all countries.</p>
                    </div>
                </div>
                </div>
            </article>
        </section>

        <section class="sl-card">
            <div class="sl-card-header">
                <div class="sl-card-header-left">
                    <svg class="w-4 h-4 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-6m3 6V7m3 10v-4m3 8H3a2 2 0 01-2-2V5a2 2 0 012-2h18a2 2 0 012 2v14a2 2 0 01-2 2z"/>
                    </svg>
                    <h2 class="sl-card-title">Decision Audit</h2>
                    <span class="sl-card-count" x-text="auditRows.length + ' rows'"></span>
                </div>
                <div class="sl-card-header-right">
                    <button type="button" class="sl-card-refresh" @click="loadAudit()" :disabled="auditLoading">
                        <div x-show="auditLoading" class="spinner w-3 h-3"></div>
                        <svg x-show="!auditLoading" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                        </svg>
                        Reload Audit
                    </button>
                </div>
            </div>
            <div class="sl-card-body space-y-4">
            <p class="text-sm text-muted-foreground">Latest recorded redirect decisions from the live audit table.</p>

            <div class="redirect-engine-audit-grid">
                <div class="stat-card stat-card-blue">
                    <div class="stat-card-label">Rows Loaded</div>
                    <div class="stat-card-value" x-text="auditRows.length"></div>
                    <div class="stat-card-sub">Most recent decisions from the audit table</div>
                </div>
                <div class="stat-card stat-card-amber">
                    <div class="stat-card-label">Redirect Branch</div>
                    <div class="stat-card-value" x-text="auditDecisionCount('redirect_url')"></div>
                    <div class="stat-card-sub">Rows resolved to redirect_url</div>
                </div>
                <div class="stat-card stat-card-violet">
                    <div class="stat-card-label">Meta Tag Branch</div>
                    <div class="stat-card-value" x-text="auditDecisionCount('meta_tag')"></div>
                    <div class="stat-card-sub">Crawler-facing snapshot rows</div>
                </div>
                <div class="stat-card stat-card-emerald">
                    <div class="stat-card-label">Latest Slug</div>
                    <div class="stat-card-value stat-card-value-compact font-mono" x-text="latestAuditSlug()"></div>
                    <div class="stat-card-sub" x-text="latestAuditTimeLabel()"></div>
                </div>
            </div>

            <div class="tbl-wrap overflow-x-auto">
                <table class="tbl w-full">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Slug</th>
                            <th>Decision</th>
                            <th>Reason</th>
                            <th>Window</th>
                            <th>Country</th>
                            <th>Device</th>
                            <th>Network</th>
                        </tr>
                    </thead>
                    <tbody>
                        <template x-if="auditRows.length === 0">
                            <tr>
                                <td colspan="8" class="redirect-engine-empty">No audit rows available.</td>
                            </tr>
                        </template>
                        <template x-for="row in auditRows" :key="row.id">
                            <tr>
                                <td class="whitespace-nowrap">
                                    <div class="redirect-engine-cell-main" x-text="formatUnix(row.created_at_unix)"></div>
                                    <div class="redirect-engine-cell-sub">audit row #<span x-text="row.id || '-'"></span></div>
                                </td>
                                <td class="font-mono">
                                    <div class="redirect-engine-cell-main" x-text="row.slug || '-'"></div>
                                    <div class="redirect-engine-cell-sub">country <span x-text="row.country_code || '-'"></span></div>
                                </td>
                                <td>
                                    <span class="badge" :class="decisionBadgeClass(row.decision, row.window_mode)" x-text="row.decision"></span>
                                </td>
                                <td class="font-mono text-xs">
                                    <div class="redirect-engine-cell-main text-xs" x-text="row.primary_reason || '-'"></div>
                                </td>
                                <td>
                                    <div class="redirect-engine-cell-main"
                                        :class="row.window_mode === 'error' ? 'text-red-600 font-semibold' : ''"
                                        x-text="row.window_mode || '-'"></div>
                                </td>
                                <td>
                                    <div class="redirect-engine-cell-main" x-text="row.country_code || '-'"></div>
                                </td>
                                <td>
                                    <div class="redirect-engine-cell-main" x-text="row.device || '-'"></div>
                                </td>
                                <td>
                                    <div class="redirect-engine-cell-main" x-text="row.visitor_network || '-'"></div>
                                    <div class="redirect-engine-cell-sub" x-text="row.redirect_url ? 'target set' : 'normal route'"></div>
                                </td>
                            </tr>
                        </template>
                    </tbody>
                </table>
            </div>
            </div>
        </section>
    </main>
</div>

<script<?php echo $nonceAttr; ?>>
document.addEventListener('alpine:init', function () {
    Alpine.data('redirectEngineApp', redirectEngineApp);
});

function redirectEngineApp()
{
    return {
        csrfToken: <?= json_encode($csrfToken, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?>,
        _bc: null,
        loading: false,
        saving: false,
        resetting: false,
        auditLoading: false,
        allowedCountriesInput: '',
        flash: {
            ok: true,
            message: '',
        },
        config: {
            enabled: false,
            redirect_url: '',
            allowed_countries: [],
            cycle_anchor_unix: 0,
            filter_duration_seconds: 120,
            normal_duration_seconds: 180,
            require_wap: true,
            require_no_vpn: true,
            updated_at: '',
        },
        globalFilterRedirectUrl: '',
        window: {
            mode: 'normal',
            seconds_until_switch: 0,
            next_switch_at_unix: 0,
        },
        health: {
            current_hour_count: 0,
            previous_hour_count: 0,
            healthy: true,
            alerts: [],
            redirect_decision_errors: 0,
        },
        auditRows: [],

        init: function () {
            var self = this;
            this.loadAll();
            window.setInterval(function () {
                self.tickWindow();
            }, 1000);
            if (typeof BroadcastChannel !== 'undefined') {
                this._bc = new BroadcastChannel('tp_panel_v1');
                this._bc.onmessage = function (ev) {
                    if (ev.data?.type === 'engine') { self.loadAll(); }
                };
            }
        },

        logout: function () {
            document.getElementById('logoutForm').submit();
        },

        tickWindow: function () {
            var remaining = Number(this.window.seconds_until_switch || 0);
            if (remaining > 1) {
                this.window.seconds_until_switch = remaining - 1;
                this.window.next_switch_at_unix = Number(this.window.next_switch_at_unix || 0) - 1;
                return;
            }

            if (!this.loading && !this.saving && !this.resetting) {
                this.loadConfig(false);
            }
        },

        showFlash: function (ok, message) {
            this.flash.ok = !!ok;
            this.flash.message = message;
        },

        request: async function (action, data) {
            var response = await fetch('handler.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'fetch',
                },
                credentials: 'same-origin',
                body: JSON.stringify({
                    action: action,
                    csrf_token: this.csrfToken,
                    data: data || {},
                }),
            });

            var payload = await response.json();
            if (response.status === 401 || response.status === 403) {
                window.location.href = '/';
                throw new Error(payload.message || 'Unauthorized');
            }

            return payload;
        },

        buildConfigPayload: function () {
            return {
                enabled: !!this.config.enabled,
                redirect_url: String(this.config.redirect_url || '').trim(),
                allowed_countries: this.parseAllowedCountries(),
                cycle_anchor_unix: Number(this.config.cycle_anchor_unix || 0),
                filter_duration_seconds: Number(this.config.filter_duration_seconds || 120),
                normal_duration_seconds: Number(this.config.normal_duration_seconds || 180),
                require_wap: !!this.config.require_wap,
                require_no_vpn: !!this.config.require_no_vpn,
            };
        },

        parseAllowedCountries: function () {
            var raw = String(this.allowedCountriesInput || '').toUpperCase();
            var tokens = raw.split(/[\s,]+/);
            var seen = {};
            var result = [];
            var i = 0;

            for (i = 0; i < tokens.length; i += 1) {
                var token = String(tokens[i] || '').replace(/[^A-Z]/g, '').trim();
                if (token.length !== 2 || seen[token]) {
                    continue;
                }

                seen[token] = true;
                result.push(token);
            }

            return result;
        },

        applyConfigResponse: function (payload) {
            this.config = Object.assign({}, this.config, payload.config || {});
            this.allowedCountriesInput = Array.isArray(this.config.allowed_countries)
                ? this.config.allowed_countries.join(', ')
                : '';
            this.window = Object.assign({}, this.window, payload.window || {});
            this.health = Object.assign({}, this.health, payload.health || {});
            this.globalFilterRedirectUrl = String(payload.global_filter_redirect_url || '');
        },

        loadAll: async function () {
            await this.loadConfig(true);
            await this.loadAudit();
        },

        loadConfig: async function (showError) {
            this.loading = true;
            try {
                var payload = await this.request('get_redirect_engine_config', {});
                if (payload.success) {
                    this.applyConfigResponse(payload);
                } else if (showError !== false) {
                    this.showFlash(false, payload.message || 'Failed to load redirect engine config.');
                }
            } catch (error) {
                if (showError !== false) {
                    this.showFlash(false, error.message || 'Failed to load redirect engine config.');
                }
            } finally {
                this.loading = false;
            }
        },

        saveConfig: async function () {
            this.saving = true;
            try {
                var payload = await this.request('save_redirect_engine_config', {
                    config: this.buildConfigPayload(),
                });
                if (payload.success) {
                    this.applyConfigResponse(payload);
                    this.showFlash(true, payload.message || 'Redirect engine configuration saved.');
                    this._bc?.postMessage({ type: 'engine' });
                } else {
                    this.showFlash(false, payload.message || 'Failed to save redirect engine configuration.');
                }
            } catch (error) {
                this.showFlash(false, error.message || 'Failed to save redirect engine configuration.');
            } finally {
                this.saving = false;
            }
        },

        resetCycle: async function () {
            this.resetting = true;
            try {
                var payload = await this.request('reset_redirect_engine_cycle', {
                    config: this.buildConfigPayload(),
                });
                if (payload.success) {
                    this.applyConfigResponse(payload);
                    this.showFlash(true, payload.message || 'Redirect engine cycle reset.');
                    this._bc?.postMessage({ type: 'engine' });
                } else {
                    this.showFlash(false, payload.message || 'Failed to reset redirect engine cycle.');
                }
            } catch (error) {
                this.showFlash(false, error.message || 'Failed to reset redirect engine cycle.');
            } finally {
                this.resetting = false;
            }
        },

        loadAudit: async function () {
            this.auditLoading = true;
            try {
                var payload = await this.request('list_decision_audit', { limit: 50 });
                if (payload.success) {
                    this.auditRows = Array.isArray(payload.rows) ? payload.rows : [];
                    this.health.redirect_decision_errors = Number(payload.redirect_decision_errors || 0);
                } else {
                    this.showFlash(false, payload.message || 'Failed to load decision audit.');
                }
            } catch (error) {
                this.showFlash(false, error.message || 'Failed to load decision audit.');
            } finally {
                this.auditLoading = false;
            }
        },

        resetAuditErrors: async function () {
            try {
                var payload = await this.request('reset_decision_audit_errors', {});
                this.showFlash(!!payload.success, payload.message || 'Audit error counter updated.');
                await this.loadConfig(false);
            } catch (error) {
                this.showFlash(false, error.message || 'Failed to reset audit error counter.');
            }
        },

        formatUnix: function (value) {
            var unixValue = Number(value || 0);
            if (unixValue <= 0) {
                return '-';
            }

            return new Date(unixValue * 1000).toLocaleString();
        },

        formatIso: function (value) {
            if (!value) {
                return '-';
            }

            return new Date(value).toLocaleString();
        },

        auditDecisionCount: function (decision) {
            var count = 0;
            var i = 0;

            for (i = 0; i < this.auditRows.length; i += 1) {
                if (String(this.auditRows[i].decision || '') === decision) {
                    count += 1;
                }
            }

            return count;
        },

        latestAuditSlug: function () {
            if (!Array.isArray(this.auditRows) || this.auditRows.length === 0) {
                return '-';
            }

            return String(this.auditRows[0].slug || '-');
        },

        latestAuditTimeLabel: function () {
            if (!Array.isArray(this.auditRows) || this.auditRows.length === 0) {
                return 'No audit activity loaded';
            }

            return this.formatUnix(this.auditRows[0].created_at_unix);
        },

        decisionBadgeClass: function (decision, windowMode) {
            if (decision === 'redirect_url') {
                return 'bg-amber-100 text-amber-800 border border-amber-200';
            }

            if (decision === 'meta_tag') {
                return 'bg-sky-100 text-sky-800 border border-sky-200';
            }

            // decision='normal' with window_mode='error' = engine threw an exception
            if (windowMode === 'error') {
                return 'bg-red-100 text-red-800 border border-red-200';
            }

            return 'bg-emerald-100 text-emerald-800 border border-emerald-200';
        },
    };
}
</script>
</body>
</html>
