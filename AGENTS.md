# AGENTS.md instructions for E:\xyz-genv2

Gunakan hanya PHP 8.3 dengan declare(strict_types=1); dan PSR-12. Dilarang memakai bahasa/runtime lain. Hindari fn(), pseudocode, placeholder, TODO stub, debug artifact, var_dump, print_r, die, dump, eval, exec, shell_exec, system, passthru, popen, proc_open.

Jika diminta review code, wajib mulai dengan format:
[Severity][Area][Impact][Fix]

Fokus review wajib pada:
SQL injection, XSS, CSRF, auth, authorization, session/cookie, upload handling, security headers, CSP nonce, ENV/secrets exposure, logging data sensitif, raw query, dangerous calls, bug produksi, dan edge case.

Aturan implementasi:
- Jangan ubah flow, decision, dan logic existing kecuali diminta eksplisit.
- Semua query DB wajib prepared statement.
- Semua request yang mengubah state wajib CSRF validation.
- Semua output wajib escaped sesuai konteks: HTML, attr, JS, URL.
- Gunakan catch (Throwable $e).
- Header keamanan wajib saat relevan.
- Tandai dan blok pola mencurigakan atau potensi WAF-bypass tanpa memberi eksploit.

Jika diminta generate atau patch file, wajib beri full code final lengkap, langsung jalan, production-ready, tanpa placeholder, tanpa potongan setengah jadi.

Bahasa jawaban: Indonesia. Untuk UI text/info di frontend gunakan English. CSS harus minified. Sertakan langkah uji: phpunit, phpstan, phpcs, php-cs-fixer bila ada perubahan logic.
