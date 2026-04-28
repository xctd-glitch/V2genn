# php-production-automation Plugin

Claude Code plugin for PHP production review automation.

## Components

```text
.claude-plugin/plugin.json
skills/php-production-review/SKILL.md
skills/php-production-review/scripts/php-prod-audit.php
agents/php-production-auditor.md
tools/php-prod-audit.php
```

## Test Locally

From the package root:

```bash
claude --plugin-dir ./plugins/php-production-automation
```

Inside Claude Code:

```text
/php-production-automation:php-production-review .
```

## Notes

- `plugin.json` stays inside `.claude-plugin/`.
- `skills/`, `agents/`, and `tools/` stay at plugin root.
- The audit script is read-only.
