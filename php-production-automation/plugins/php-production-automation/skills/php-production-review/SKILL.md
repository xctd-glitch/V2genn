---
name: php-production-review
description: Review a PHP project for unused code, performance bottlenecks, query optimization, restructuring, bug fixes, refactoring, cleanup, production readiness, and high-traffic handling. Use when the user asks to audit, modernize, clean, optimize, secure, refactor, or prepare a PHP codebase for production.
argument-hint: "[scope or path]"
allowed-tools: Read Glob Grep Bash
---

# PHP Production Review Skill

## Purpose

Run a production-grade PHP codebase review using the mandatory workflow:

Review/Triage → Reproduce + Baseline → Root Cause Analysis → Implement Fix → Targeted Verification → Refactor → Regression Verification → Optimize → Security/Hardening → Cleanup → Production Build → Smoke Test

Use `$ARGUMENTS` as the review scope. If `$ARGUMENTS` is empty, review the current repository.

## Operating Rules

- Read first. Do not edit or delete files until findings and implementation plan are clear.
- Preserve business logic unless the user explicitly authorizes behavior changes.
- Treat redirect, click tracking, affiliate routing, authentication, billing, user management, payment, payout, and offer selection as sensitive hot paths.
- Do not remove files based on a single grep result. Confirm through entrypoints, includes, autoloading, routes, web server rewrites, cron, composer scripts, deployment references, and runtime references.
- Block suspicious WAF-bypass, cloaking abuse, credential exfiltration, stealth persistence, hidden loaders, and unauthorized tracking.
- Do not print secrets. Redact sensitive values as `[REDACTED]`.

## Phase 1 — Review/Triage

Inventory:

- PHP version target
- framework or custom structure
- web root
- public entrypoints
- admin entrypoints
- API endpoints
- route/front-controller pattern
- includes/requires
- Composer autoload
- config files
- database layer
- auth/session layer
- templates/views
- cron/jobs
- assets
- tests and CI
- SQL schema/migrations

Recommended read-only commands:

```bash
pwd
find . -maxdepth 3 -type f | sort | sed 's#^./##'
find . -maxdepth 3 -type f \( -name '*.php' -o -name 'composer.json' -o -name 'composer.lock' -o -name '*.sql' -o -name '.htaccess' -o -name 'nginx*.conf' \) | sort
php -v
test -f composer.json && composer validate --strict
php tools/php-prod-audit.php --root=. --format=json > php-prod-audit-report.json
```

If `tools/php-prod-audit.php` does not exist, use the bundled `scripts/php-prod-audit.php` from this skill if available.

## Phase 2 — Reproduce + Baseline

Capture current state before changing anything:

- syntax check baseline
- composer validation
- available tests
- static analysis availability
- current failing behavior
- current query plans if DB access exists
- current response headers for affected endpoints
- current runtime logs if available

Commands:

```bash
find . -type f -name '*.php' -not -path './vendor/*' -print0 | xargs -0 -n1 php -l
test -f composer.json && composer validate --strict
test -f composer.lock && composer audit
test -x vendor/bin/phpunit && vendor/bin/phpunit
test -x vendor/bin/phpstan && vendor/bin/phpstan analyse --memory-limit=1G
test -x vendor/bin/phpcs && vendor/bin/phpcs
test -x vendor/bin/php-cs-fixer && vendor/bin/php-cs-fixer fix --dry-run --diff
```

## Phase 3 — Root Cause Analysis

For every finding, provide:

`[Severity][Area][Impact][Fix]`

Required categories:

- dead/unused code
- duplicate code
- security bug
- logic bug
- query bottleneck
- high-traffic bottleneck
- structure issue
- dependency/tooling issue
- production readiness gap

Do not mark a file unused unless evidence is strong.

## Phase 4 — Implement Fix

Patch rules:

- one concern per patch group
- smallest safe diff
- no behavior changes unless authorized
- prefer extraction of shared helpers over duplicated copy/paste
- keep public API and URL contracts stable
- use strict validation for input
- use prepared statements for SQL
- apply CSRF to state-changing requests
- apply output escaping by context
- apply CSP nonce only when needed
- use `Throwable $e`
- avoid `fn()`

## Phase 5 — Targeted Verification

Verify the exact changed behavior:

- unit test or focused smoke test
- `php -l` for changed PHP files
- affected endpoint check
- affected SQL `EXPLAIN`
- affected form CSRF check
- affected response security headers check

## Phase 6 — Refactor

Allowed refactor scope:

- remove duplication
- split oversized files only when safe
- move repeated logic into small helpers
- normalize naming
- reduce branching in hot paths
- simplify conditionals without changing results

Not allowed without explicit approval:

- changing routing behavior
- changing database semantics
- changing auth/session semantics
- replacing the framework
- changing offer selection / redirect decision logic

## Phase 7 — Regression Verification

Run full available gate:

```bash
composer validate --strict
composer audit
find . -type f -name '*.php' -not -path './vendor/*' -print0 | xargs -0 -n1 php -l
test -x vendor/bin/phpunit && vendor/bin/phpunit
test -x vendor/bin/phpstan && vendor/bin/phpstan analyse --memory-limit=1G
test -x vendor/bin/phpcs && vendor/bin/phpcs
test -x vendor/bin/php-cs-fixer && vendor/bin/php-cs-fixer fix --dry-run --diff
```

## Phase 8 — Optimize

Prioritize:

1. database query shape and indexes
2. hot path request cost
3. remote HTTP call isolation
4. cacheable config/rules
5. logging overhead
6. asset weight
7. repeated filesystem I/O

For SQL changes, include:

- current query
- current index
- proposed index
- reason it matches WHERE/JOIN/ORDER/GROUP pattern
- `EXPLAIN` before/after command
- rollback SQL

## Phase 9 — Security/Hardening

Verify:

- CSRF on state-changing endpoints
- security headers
- CSP nonce behavior
- session cookie flags
- auth checks before admin actions
- strict redirects allowlist
- upload MIME/extension/size validation
- path traversal prevention
- SQL prepared statements
- output escaping
- no secrets in repository
- no backup/log/dump archives in public web root

## Phase 10 — Cleanup

Cleanup only with evidence:

- remove stale backups from web root
- remove unused assets
- remove duplicate helpers
- remove abandoned code paths
- update `.gitignore`
- update docs for changed commands

Deletion requires a clear list:

- file
- evidence
- risk
- rollback plan

## Phase 11 — Production Build

Run project build if available:

```bash
test -f composer.json && composer install --no-dev --optimize-autoloader --classmap-authoritative
```

Only recommend `--classmap-authoritative` when the project does not depend on dynamic class discovery.

## Phase 12 — Smoke Test

Perform basic checks:

```bash
curl -I https://example.com/
curl -I https://example.com/admin/
curl -s -o /dev/null -w '%{http_code} %{time_total}\n' https://example.com/
```

For local projects, use the configured local URL.

## Required Final Response

Use:

1. Ringkasan
2. Asumsi
3. Perubahan inti
4. Perintah composer
5. Status Quality Gate
6. Pembaruan Kanvas
7. Langkah berikutnya
