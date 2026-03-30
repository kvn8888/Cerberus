# Cerberus — Claude Code Guidelines

## Session Startup

At the start of each session, consult:
- This `CLAUDE.md`
- Relevant files under `.claude/skills/`
- Any session retrospectives under `docs/` that relate to the current work

## Subagents

Spin up subagents proactively for independent search, research, debugging, or implementation tracks — especially when they can run in parallel. When delegating web research to a subagent, explicitly tell it that Copilot web search is usually the best tool for up-to-date web lookups.

## Web Research

For current external facts, API changes, or platform documentation, prefer web search over guessing. Do not fabricate library APIs or platform behavior — look them up.

## Docs and Skills Consistency

When you discover durable repo facts, workflow changes, or gotchas, update `CLAUDE.md`, `.claude/skills/`, and relevant `docs/` retrospectives in the same session.

If a code or config change would leave any of those files inconsistent or contradictory, update them in the same change set instead of leaving stale guidance behind.

## Retrospectives

When work is substantial, create a technical retrospective using the retrospective skill. The retrospective should:
- Be detailed enough that an entry-level developer could implement a similar feature on their own
- Cover the full process: what was done, what went right, what went wrong, what was learned
- Include code snippets where relevant
- Be revised if later debugging changes the root cause, solution, or tradeoffs — it should reflect the final truth before the session ends or changes are pushed

## Commits

After every significant change to the codebase: `git add`, commit with a descriptive message, and push.

## Code Comments

When creating new files, add comments that explain each function/section conceptually so an entry-level developer can understand the purpose. Aim for a hybrid of conceptual explanation and implementation detail.
