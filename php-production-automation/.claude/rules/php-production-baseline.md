# PHP Production Rules

## Deletion Policy

A file can be recommended for deletion only if all are true:

1. Not referenced by route/front controller.
2. Not referenced by include/require.
3. Not referenced by Composer autoload.
4. Not referenced by cron/job/deployment scripts.
5. Not referenced by `.htaccess`, nginx, Apache, or server config.
6. Not linked from views/templates/assets.
7. Not required for migrations, rollbacks, or operational recovery.
8. Rollback plan exists.

## Query Optimization Policy

Do not propose indexes blindly.

For every index:

- show query shape
- show filter/join/order/group columns
- explain selectivity assumption
- provide SQL
- provide rollback SQL
- provide `EXPLAIN` command

## Security Policy

Block and report:

- WAF-bypass helpers
- user-agent/IP cloaking abuse
- credential exfiltration
- hidden remote loaders
- unauthorized cookie/session/token collection
- stealth persistence
- unsafe eval/assert/create_function
- arbitrary include from request input
- shell execution with request-controlled input
- SQL concatenation with request-controlled input
