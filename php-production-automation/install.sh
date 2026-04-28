#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-.}"

mkdir -p "$TARGET/.claude/skills/php-production-review/scripts"
mkdir -p "$TARGET/.claude/agents"
mkdir -p "$TARGET/.claude/commands"
mkdir -p "$TARGET/.claude/rules"
mkdir -p "$TARGET/tools"

cp CLAUDE.md "$TARGET/CLAUDE.md"
cp custom-instructions.md "$TARGET/custom-instructions.md"
cp .claude/skills/php-production-review/SKILL.md "$TARGET/.claude/skills/php-production-review/SKILL.md"
cp .claude/skills/php-production-review/scripts/php-prod-audit.php "$TARGET/.claude/skills/php-production-review/scripts/php-prod-audit.php"
cp .claude/agents/php-production-auditor.md "$TARGET/.claude/agents/php-production-auditor.md"
cp .claude/commands/php-prod-review.md "$TARGET/.claude/commands/php-prod-review.md"
cp .claude/rules/php-production-baseline.md "$TARGET/.claude/rules/php-production-baseline.md"
cp tools/php-prod-audit.php "$TARGET/tools/php-prod-audit.php"

echo "Installed Claude PHP production automation into: $TARGET"
