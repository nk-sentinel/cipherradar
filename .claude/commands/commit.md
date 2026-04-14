---
description: Stage named files, run gates, and commit (no co-author, no --no-verify)
argument-hint: "<commit message subject>"
---

Create a git commit for the in-progress CLI work. This is a wrapper that
enforces the project's commit conventions — it does NOT override Claude's
git-safety rules (never updates git config, never pushes without an
explicit user ask).

Steps:

1. Run gates in parallel from inside `cli/`:
   - `go build ./...`
   - `go vet ./...`
   - `go test -count=1 ./... 2>&1 | grep -E "^--- FAIL" | sort -u`
   Compare the failure list against the baseline in
   `.claude/commands/test-coverage.md`. If there are any new failures,
   STOP and report them to the user — do not commit.

2. Run `git status --short` from the repo root. Show the list of changed
   files and ask the user whether the set is correct (skip this step if
   they pre-approved by supplying arguments).

3. Stage ONLY files the user approved. Never `git add -A` / `git add .`.
   Skip `cli/cradar` (the compiled binary) unless the user explicitly
   asks to include it.

4. Build a commit message:
   - Subject: imperative mood, lowercase after the first word, ≤ 70
     chars. Use the argument text if supplied, otherwise infer from the
     diff.
   - Body: why, not what. Reference ADRs / plan items if relevant.
   - NEVER include a `Co-Authored-By:` trailer. The project forbids
     co-author tags (see CLAUDE.md).

5. `git commit -m "$(cat <<'EOF' ... EOF)"` with the HEREDOC pattern.
   NEVER use `--no-verify`, `--amend`, or `--no-gpg-sign` unless the
   user asks for it explicitly. If a pre-commit hook fails, fix the
   underlying issue and create a NEW commit.

6. After committing, print the short log (`git log -1 --oneline`) and
   ask whether to `git push`. Do NOT push without explicit confirmation.

Reject the commit if:
- `.env`, credential files, or PEM keys are in the staged set.
- The staged diff touches `.git/config` or hooks directory.
- Any gate in step 1 added a new failure.
