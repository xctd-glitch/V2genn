---
description: Run PHP production review workflow for the current project or provided path.
argument-hint: "[scope or path]"
allowed-tools: Read Glob Grep Bash
---

Run the PHP production review workflow on `$ARGUMENTS`.

Use the exact sequence:

Review/Triage → Reproduce + Baseline → Root Cause Analysis → Implement Fix → Targeted Verification → Refactor → Regression Verification → Optimize → Security/Hardening → Cleanup → Production Build → Smoke Test

If no argument is provided, use the current repository.

Read first. Produce evidence-backed findings before editing. Do not delete unused code without strong evidence and rollback plan.

Required finding format:

`[Severity][Area][Impact][Fix]`

Required response format:

1. Ringkasan
2. Asumsi
3. Perubahan inti
4. Perintah composer
5. Status Quality Gate
6. Pembaruan Kanvas
7. Langkah berikutnya
