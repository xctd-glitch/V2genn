---
name: recall
description: Retrieves cross-session memories about past decisions, lessons, and patterns. Use when user asks about prior work, past decisions, or mentions a feature. Triggers include check memory, what did we decide, how did we solve.
context: fork
allowed-tools:
  - Bash
---

## Proactive Usage Guidelines

**You should proactively use this skill when:**

1. **Session Start**: When user mentions a feature/module, search for related memories first
   - User says "let's work on authentication" → `"E:\.genv2\.gemini\skills\recall-phpworkspace-083c/recall.sh" authentication`
   - User mentions a specific service → search for prior decisions about it

2. **Before Decisions**: Before making architectural or technical choices
   - About to choose a library → check if there's a prior decision
   - Designing a new feature → search for related patterns

3. **After Problem Solving**: When you've solved a tricky issue
   - Found a non-obvious bug → `"E:\.genv2\.gemini\skills\recall-phpworkspace-083c/remember.sh" lesson "description"`
   - Made an important decision → `"E:\.genv2\.gemini\skills\recall-phpworkspace-083c/remember.sh" architecture "description"`

4. **Encountering Familiar Issues**: When something seems like a recurring problem
   - Error looks familiar → search lessons learned

5. **When memory looks stale or misleading**
   - Use `"E:\.genv2\.gemini\skills\recall-phpworkspace-083c/forget.sh" "<keywords>"` to review candidate entries
   - Prefer the maintenance-aware workflow over editing raw memory files by hand
   - Use Memory Library settings for review-first maintenance when available

## Commands

| Action | Command |
|--------|---------|
| Search memories | `"E:\.genv2\.gemini\skills\recall-phpworkspace-083c/recall.sh" <keywords>` |
| Save memory | `"E:\.genv2\.gemini\skills\recall-phpworkspace-083c/remember.sh" <category> "<content>"` |
| Review stale/outdated candidates | `"E:\.genv2\.gemini\skills\recall-phpworkspace-083c/forget.sh" "<keywords>"` |

## Maintenance workflow

- Use `recall.sh` to search for relevant memories before making decisions
- Use `remember.sh` to save new lessons, patterns, or architecture decisions
- Use `forget.sh` to review candidates when a memory looks stale, duplicated, or misleading
- When available, prefer Memory Library settings for archive / restore / delete / merge / prune actions
- Do not treat raw markdown editing as the default maintenance path

## Categories

`architecture` - Design decisions, technology choices
`lesson` - Gotchas, debugging discoveries, edge cases
`pattern` - Reusable solutions, conventions
`style` - Naming, code organization
`preference` - Tooling, workflow choices

## Examples

```bash
"E:\.genv2\.gemini\skills\recall-phpworkspace-083c/recall.sh" terminal session
"E:\.genv2\.gemini\skills\recall-phpworkspace-083c/recall.sh" "error handling"
"E:\.genv2\.gemini\skills\recall-phpworkspace-083c/remember.sh" lesson "node-pty requires explicit shell path on macOS"
"E:\.genv2\.gemini\skills\recall-phpworkspace-083c/remember.sh" architecture "Use EventBus for cross-service communication"
"E:\.genv2\.gemini\skills\recall-phpworkspace-083c/forget.sh" "old auth pattern"
```
