#!/bin/bash
# recall-recent.sh - Display recent memories for SessionStart hook
# Shows a summary of recent decisions without requiring a search query

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

MEMORY_GROUP_ID="fb21fc12"
MEMORY_FILE="$HOME/.termdock/memory/groups/$MEMORY_GROUP_ID/index.md"
WORKSPACE=$(git rev-parse --show-toplevel 2>/dev/null || pwd)

if ! ensure_not_stale_recall_skill "$WORKSPACE" "$SCRIPT_DIR"; then
    exit 1
fi

# Check if memory file exists
if [ ! -f "$MEMORY_FILE" ]; then
    echo "No memories found for this project."
    exit 0
fi

# Count total memories
total_count=$(grep -c "^- \[" "$MEMORY_FILE" 2>/dev/null || echo "0")

if [ "$total_count" -eq 0 ]; then
    echo "No memories found for this project."
    exit 0
fi

echo "=== Project Memory Loaded ==="
echo ""
echo "Recent decisions ($total_count total):"
echo ""

# Show last 5 memories
grep "^- \[" "$MEMORY_FILE" | tail -5 | while read -r line; do
    echo "$line"
done

echo ""
echo "Use './recall.sh <keyword>' to search specific topics"
echo "Use './remember.sh <category> \"<content>\"' to save new memories"
