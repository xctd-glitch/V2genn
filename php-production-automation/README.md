# Claude PHP Production Automation

Paket ini berisi konfigurasi Claude Code untuk audit dan modernisasi codebase PHP berbasis workflow:

`Review/Triage → Reproduce + Baseline → Root Cause Analysis → Implement Fix → Targeted Verification → Refactor → Regression Verification → Optimize → Security/Hardening → Cleanup → Production Build → Smoke Test`

## Isi Paket

### Standalone Project Mode

Copy folder/file berikut ke root project PHP:

```text
CLAUDE.md
.claude/skills/php-production-review/SKILL.md
.claude/agents/php-production-auditor.md
.claude/commands/php-prod-review.md
.claude/rules/php-production-baseline.md
tools/php-prod-audit.php
custom-instructions.md
```

Skill standalone bisa dipanggil:

```text
/php-production-review .
```

Command compatibility bisa dipanggil:

```text
/php-prod-review .
```

Agent bisa dipakai:

```text
Use the php-production-auditor agent to review this PHP project for unused code, performance bottlenecks, query optimization, restructuring, bug fixes, refactor, cleanup, production readiness, and high-traffic handling.
```

### Plugin Mode

Plugin reusable ada di:

```text
plugins/php-production-automation/
```

Test lokal:

```bash
claude --plugin-dir ./plugins/php-production-automation
```

Lalu panggil:

```text
/php-production-automation:php-production-review .
```

## PHP CLI Inventory Script

Script read-only:

```bash
php tools/php-prod-audit.php --root=. --format=json > php-prod-audit-report.json
```

Output membantu Claude melihat:

- entrypoint PHP
- Composer files
- SQL files
- `.htaccess`
- risky backup/archive/dump/log files
- raw SQL pattern
- `mysqli_*`
- `eval`
- shell execution
- unsafe request access
- potential unescaped echo
- largest files
- basic extension statistics

Script ini tidak menghapus dan tidak mengubah file.

## Composer Dev Tooling yang Disarankan

Tambahkan bila project belum punya tooling:

```bash
composer require --dev phpunit/phpunit phpstan/phpstan squizlabs/php_codesniffer friendsofphp/php-cs-fixer
```

Quality gate:

```bash
composer validate --strict
composer audit
find . -type f -name '*.php' -not -path './vendor/*' -print0 | xargs -0 -n1 php -l
vendor/bin/phpunit
vendor/bin/phpstan analyse --memory-limit=1G
vendor/bin/phpcs
vendor/bin/php-cs-fixer fix --dry-run --diff
```

## Catatan

- Skill sengaja read-first.
- Deletion harus berbasis bukti.
- Flow bisnis tidak boleh diubah otomatis.
- Suspicious WAF-bypass/exfiltration/stealth loader harus diblok, bukan diperbaiki agar makin tersembunyi.
