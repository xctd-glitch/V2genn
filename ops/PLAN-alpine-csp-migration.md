# Initiative — Alpine.js CSP Build Migration

**Status**: Scheduled (deferred from `security/hardening-2026-05-01`)
**Origin**: Patch 5 of the 2026-05-01 security review
**Estimated effort**: 1 sprint (1–2 dev days + 0.5 day manual UI QA)
**Owner**: TBD
**Related**: `bootstrap/security_bootstrap.php` CSP builder

---

## 1. Goal

Remove `'unsafe-eval'` from the admin/installer/user CSP `script-src` directive
in `tp_send_security_headers()` (`bootstrap/security_bootstrap.php`).

`'unsafe-eval'` is currently required because Alpine.js's standard build uses
`new Function(expr)` to evaluate the JS expressions inside `x-text`,
`x-show`, `x-bind`, etc. Removing it without replacing Alpine breaks the
entire UI.

The supported alternative is the official Alpine **CSP build**
(`@alpinejs/csp` / `alpine.csp.min.js`), which ships its own evaluator that
does **not** use `eval`/`Function()`. Its trade-off: the evaluator only
understands a constrained subset of JS — property access, ternary,
comparison, logical, arithmetic, string concat, array/object index. It
**does not** support function or method calls inline.

## 2. Scope (measured 2026-05-01)

- 4 UI files: `install.php`, `admin/index.php`, `admin/redirect-engine.php`, `user/sl.php`
- ~893 total `x-*` directive occurrences
- **225 inline expressions that contain JS function/method calls** and must
  be moved into Alpine `data()` component getters/methods before the CSP
  build can evaluate them.

Breakdown of incompatible patterns (sample):
- `x-text="Number(window.seconds_until_switch || 0)"`
- `x-text="Array.isArray(health.alerts) ? health.alerts.length : 0"`
- `x-text="task.status.charAt(0).toUpperCase() + task.status.slice(1)"`
- `x-bind:class="{'opened': $store.foo.split(',').length}"`
- `new Date(...)`, `.map()`, `.filter()`, `.split()`, `.toLocaleString()` etc.

## 3. Strategy

For each incompatible expression:

1. Identify the surrounding `Alpine.data('name', () => ({ … }))` factory.
2. Add a **getter** (`get foo() { return … }`) or **method** that returns the
   computed value using normal JS.
3. Replace the inline expression with `x-text="foo"` or `x-text="formatted(row)"`.

Example refactor:

```html
<!-- BEFORE (CSP-incompatible) -->
<span x-text="Number(window.seconds_until_switch || 0)"></span>
```

```js
// In Alpine.data('redirectEngineApp', () => ({ … get safeSeconds() { return Number(this.window.seconds_until_switch || 0); } … }))
```

```html
<!-- AFTER -->
<span x-text="safeSeconds"></span>
```

For repeated patterns in `<template x-for>` rows, define a `formatRow(row)`
method on the component and pass `row` in: `x-text="formatRow(row)"`.

## 4. CSP change (the actual security win)

After all 225 expressions are migrated and a CSP-build copy of Alpine
(`assets/vendor/alpine-3.15.11.csp.min.js` — or current 3.x release) is
shipped:

```diff
--- a/bootstrap/security_bootstrap.php
+++ b/bootstrap/security_bootstrap.php
-            "script-src 'self' 'nonce-{$nonce}' 'unsafe-eval'",
+            "script-src 'self' 'nonce-{$nonce}'",
```

And in each HTML page, swap the script tag:

```diff
-<script src="/assets/vendor/alpine-3.15.11.min.js" defer></script>
+<script src="/assets/vendor/alpine-3.15.11.csp.min.js" defer></script>
```

## 5. Risk + QA

- **Blast radius**: every interactive page in `/admin`, `/redirect-engine`,
  `/gen` user dashboard, and the installer.
- **No automated UI tests in repo** → all verification is manual.
- **Verification matrix** (must run before merge):
  - Login (admin) + login (super-admin via env hash)
  - Add Domain wizard end-to-end (cPanel + CF flow)
  - Smartlink CRUD (`/gen` user dashboard)
  - Redirect Engine config save + cycle reset
  - Conversion list filters (`admin/index.php` analytics modal)
  - Installer steps 1 → 5 (fresh DB)
  - Logout + CSRF rotation
- **Browser matrix**: latest Chrome, latest Firefox, Safari iOS (PWA
  manifest is wired). Check the browser console for `[Alpine] expression error`
  on each page.
- **Rollback plan**: revert the CSP `script-src` change to keep
  `'unsafe-eval'`, and revert the script-tag swap. The component getters
  can stay (no harm — they just become unused in the standard build).

## 6. Acceptance criteria

- [ ] CSP `script-src` directive no longer contains `'unsafe-eval'` on any
  page served by `tp_send_security_headers()`.
- [ ] All 4 UI files load without `[Alpine] expression error` in DevTools.
- [ ] Manual verification matrix in §5 passes on Chrome + Firefox + iOS Safari.
- [ ] PHPStan + PHPUnit + `php -l` still green.
- [ ] CSP can be observed via:
  ```bash
  curl -sI https://example.com/ | grep -i content-security
  ```
  and contains `script-src 'self' 'nonce-…'` with **no** `'unsafe-eval'`.

## 7. Out of scope for this initiative

- Replacing Alpine with a different framework.
- Removing `'unsafe-inline'` from `style-src` (separate analysis required —
  Tailwind utilities + dynamic inline styles in heredocs).
- The hot-path redirect loader CSP in `goSendTrackerPageHeaders()` —
  that one is already strict (no `'unsafe-eval'`) and unrelated.
- Changing the blocked-page CSP in `module/security.php:499` (low-impact,
  static page only — can be tightened in a separate small patch).

## 8. References

- Audit observation: 2026-05-01 02:05 GMT+7 — 225 incompatible expressions
  detected via grep across 4 files.
- Security review report: commit `94de7fe` on `security/hardening-2026-05-01`.
- Alpine.js CSP build docs: https://alpinejs.dev/advanced/csp
