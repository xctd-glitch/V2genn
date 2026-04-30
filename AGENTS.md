# AGENTS.md instructions for E:\xyz-genv2

## Ringkas proyek
- Entrypoint: [router.php](router.php), [redirect/go.php](redirect/go.php), [admin/index.php](admin/index.php), [redirect/recv.php](redirect/recv.php), [user/sl.php](user/sl.php).
- Core logic: [src/RedirectDecision/](src/RedirectDecision/) dan [bootstrap/](bootstrap/).

## Perintah utama
```
php -S 127.0.0.1:8000 router.php
composer test
composer stan
composer cs
composer fixer:check
composer ops:indexes
composer build:production
```

## Aturan non-negotiable (ringkas)
- PHP 8.3 only; gunakan declare(strict_types=1) dan PSR-12; hindari fn() arrow.
- Jangan pakai runtime/bahasa lain atau debug artifact (var_dump, print_r, die, dump).
- PDO prepared statements wajib; nonaktifkan emulate prepares dan multi-statements.
- State-changing requests wajib CSRF; output wajib escaped sesuai konteks; security headers + CSP nonce bila relevan.
- Gunakan catch (Throwable $e).
- Jangan ubah flow bisnis/redirect/click tracking/attribution/offer selection/payout/login/API contract tanpa permintaan eksplisit.
- Blok pola mencurigakan WAF-bypass/cloaking/exfiltration/stealth loader.

## Format respon
- Review code: mulai dengan [Severity][Area][Impact][Fix].
- Bahasa jawaban: Indonesia; UI text/info di frontend gunakan English; CSS harus minified.
- Jika generate/patch file: beri full code final lengkap, siap jalan, production-ready.

## Rujukan
- [CLAUDE.md](CLAUDE.md) dan [custom-instructions.md](custom-instructions.md) untuk workflow, security baseline, dan format jawaban.
- [composer.json](composer.json) untuk daftar script.
- [phpunit.xml.dist](phpunit.xml.dist), [phpstan.neon.dist](phpstan.neon.dist), [phpcs.xml.dist](phpcs.xml.dist) untuk scope quality gate.
