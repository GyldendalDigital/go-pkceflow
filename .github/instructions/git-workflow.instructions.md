---
applyTo: "**"
---

# Git Workflow

Follow these conventions for all git operations in this project.

## Branch Model (trunk-based)

- `master` - main branch, always the latest working code. PRs target here. Tagged for releases.
- `feature/*` - new functionality, branches off master
- `fix/*` - bug fixes, branches off master
- `chore/*` - maintenance (deps, CI, tooling), branches off master
- Releases are created by tagging master (e.g., `v1.0.0`)

## Branch Discipline

- One branch per work package. Never combine unrelated changes.
- Always rebase onto latest base branch before pushing (resolve conflicts if needed).
- If a feature depends on or touches the same code as another in-flight feature, branch off that feature branch instead of development.

## Commit Messages

Format: `type(scope): description`

Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `ci`

Body (optional): explain WHY, not what. What is visible in the diff.

Examples:
```
feat(auth): implement PKCE S256 login flow
fix(tokenstore): use persistent random key instead of hostname fallback
chore: bump go-oidc v3.18.0 → v3.19.0
docs: add Keycloak IdP setup guide
```

## Push Protocol

- Before push: pull base branch, rebase, resolve conflicts
- Force-push with `--force-with-lease` after rebase (safe, fails if remote diverged)
- Agent does commits and pushes; user handles PRs and merges on GitHub

## After a PR is Merged

- Wait for user to confirm the merge
- Rebase any in-flight branches that are now stale
- Delete local branches whose remote is gone (`git fetch --prune` + delete [gone] branches)
- Do not preemptively rebase without being asked

## Tag Convention

- `v1.0.0-beta.1` / `v1.0.0-rc.1` → pre-release
- `v1.0.0` → production release (clean semver)
- Tags on master only

## Git Config (expected)

```
push.autoSetupRemote = true
push.default = current
```

These allow plain `git push` on new branches without `-u origin <branch>`.
