# Oracle Skills — Agent Instructions

A collection of source-backed, installable skills for Oracle technologies (Oracle Database,
OCI, GraalVM, Oracle Fusion, Oracle APEX). This is a pure Markdown content library — no build,
test, or compile step.

> **Agent-instructions standard.** This file (`AGENTS.md`) is the canonical agent guidance.
> `CLAUDE.md` is a symlink to it for tools that still look for that name. Edit `AGENTS.md`
> only. Where a tool/OS cannot follow symlinks, regenerate `CLAUDE.md` as a copy.

## How to use this collection

1. Pick the **domain** closest to the task and read its `SKILL.md` first — that file is the
   table of contents and routing index for the domain.
2. Within a domain, follow `## Category Routing` to the right category directory, then the
   specific skill file.
3. Add other domains only when the task needs them.

## Domains

| Domain | Entry point | Scope |
| --- | --- | --- |
| `db/` | `db/SKILL.md` | Active: SQL, PL/SQL, SQLcl, ORDS, admin, architecture, performance, security, migrations, design, devops, frameworks, containers, agent-safe workflows |
| `graal/` | `graal/SKILL.md` | GraalVM, starting with Native Image |
| `oci/` | `oci/SKILL.md` | Oracle Cloud Infrastructure (stub) |
| `fusion/` | `fusion/SKILL.md` | Oracle Fusion (stub) |
| `apex/` | `apex/SKILL.md` | Oracle APEX (stub) |

The `db/` domain is the largest; its `db/SKILL.md` holds the category routing table and key
starting points. Do not duplicate that routing here — defer to it.

## Conventions

1. **Skill files** follow `SKILL_AUTHORING_GUIDE.md`: one topic per file, with explanations,
   practical examples, best practices, and common mistakes. Organize by category directory;
   `SKILL.md` is the domain table of contents.
2. **Version coverage:** skills with version-specific behavior include a
   `## Oracle Version Notes (19c vs 26ai)` section. Oracle Database **19c is the baseline**;
   call out features needing newer releases and give 19c-compatible alternatives where practical.
3. **SQL safety:** prefer bind variables; never concatenate untrusted input into SQL. Example
   queries against the data dictionary should stay scoped (owner/table) to avoid false matches.
4. **Source-backed:** cite the Oracle documentation or source skill a rule derives from.
5. **Contributions** follow `CONTRIBUTING.md`; report security issues per `SECURITY.md`.

## Do not

- Edit `CLAUDE.md` directly (edit `AGENTS.md`).
- Duplicate a domain's category routing here — keep it in the domain `SKILL.md`.
- Add version-specific guidance without an Oracle Version Notes section.
