#!/bin/bash
# Usage: ./forget.sh <query>
# Remove memories matching query (interactive)

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

MEMORY_GROUP_ID="fb21fc12"
MEMORY_FILE="$HOME/.termdock/memory/groups/$MEMORY_GROUP_ID/index.md"

QUERY="$1"
WORKSPACE=$(git rev-parse --show-toplevel 2>/dev/null || pwd)

if [ -z "$QUERY" ]; then
    echo "Usage: forget <query>"
    echo "Example: forget \"old auth pattern\""
    exit 1
fi

if ! ensure_not_stale_recall_skill "$WORKSPACE" "$SCRIPT_DIR"; then
    exit 1
fi

if [ ! -f "$MEMORY_FILE" ]; then
    echo "Memory file not found: $MEMORY_FILE"
    exit 1
fi

echo "=== Memories matching: $QUERY ==="
echo ""

# Use -- to prevent query from being interpreted as grep flags
MATCHES=$(grep -n -i -- "$QUERY" "$MEMORY_FILE")

if [ -z "$MATCHES" ]; then
    echo "No memories found matching: $QUERY"
    exit 0
fi

echo "$MATCHES"
echo ""
echo "---"
echo "Review these candidates before removing or archiving anything."
echo "Use Memory Library settings to inspect the matched entries and run maintenance actions."
echo "If UI access is unavailable, prefer the maintenance-aware memory workflow rather than editing raw markdown by hand."
