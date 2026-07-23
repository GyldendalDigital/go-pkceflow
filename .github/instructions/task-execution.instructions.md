---
applyTo: "**"
---

# Task Execution Protocol

When executing tasks from the work breakdown (docs/work-breakdown.md or equivalent):

## Before Starting a Task

1. Read the task specification (ID, files, acceptance criteria, dependencies)
2. Verify all dependency tasks are complete (merged to development)
3. Create a branch with the suggested name from the task spec
4. If the task references the reference implementation, read those files first

## During Execution

1. Follow the acceptance criteria exactly. Do not add scope.
2. Write tests BEFORE or alongside implementation (never after as an afterthought)
3. Run tests after implementation: `go test ./...`
4. If a task is classified AGENT, proceed to completion without stopping for approval
5. If a task is classified REVIEW, complete it but flag it for human review before merge
6. If blocked by something outside the task spec, stop and explain the blocker
7. Always update relevant documentation (README, CONTRIBUTING, architecture docs, etc.) if the task changes public API or developer experience

## After Completing a Task

1. Run full test suite to verify no regressions
2. Commit with message: `feat(package): M{X}.{YY} description` matching the task
3. Push the branch
4. If AGENT: note completion and move to next task (if instructed to continue)
5. If REVIEW: stop and wait for human to review and merge
6. Do NOT start the next task until the current one's branch is pushed
7. Keep the roadmap up to date with task status (in progress, blocked, completed, etc.)

## Task Boundaries

- One branch per task. Never combine tasks.
- If a task turns out to need splitting, stop and propose the split rather than exceeding scope.
- Do not refactor, optimize, or "improve" code outside the task's listed files unless the acceptance criteria require it.
- Do not add documentation beyond what the task specifies.

## Parallelization

- Tasks with no dependency relationship can be worked on in parallel (separate branches)
- When resuming after a merge, rebase any in-flight branches onto development
- The dependency graph in the work breakdown is authoritative
