---
project: ../../agentic-brain-spevnik
---
# Project rules

The agent loads this file in every session. It applies to everything you do in this repo.
All agent data is in one visible folder, `agentic-brain/`.

## Where things are

- `agentic-brain/skills/<name>/`: a skill, with `SKILL.md` and `scripts/`. Claude Code reads it through the symlink `.claude/skills/<name>`, which `agentic-brain/bin/check.sh` creates.
- `agentic-brain/artifacts/<name>/`: an approved pattern of work, with `PLAYBOOK.md` and `reference/`.
- `agentic-brain/errors/REGISTER.md`: the error register. The script `skills/error/scripts/error.sh` adds a row.
- `agentic-brain/decisions/`: decisions, one file `D0001-<slug>.md` per decision. `decide.sh [<repo>] "<title>"` creates new ones.
- `agentic-brain/memory/MEMORY.md`: the memory index. The content is in `memory/<file>.md`.
- `agentic-brain/scratch/`: working files of a task. Git ignores them, and the folder is empty at the end of a task.
- `agentic-brain/bin/`: only in a standalone copy (`adopt.sh --standalone`): the check `check.sh`, the installer `install.sh`, the rollout `adopt.sh`, `decide.sh` and the hook `repeat_guard.mjs`. Otherwise these scripts stay in the agent-runtime repo (`brain/bin/`) and serve the repo without a copy: `check.sh <repo>`.

The `.claude/` folder holds only symlinks to skills and `settings.json`. It holds no data.

## Mandatory automation

You decide the goal and check the result. A script does the mechanical step.

A mechanical step is an upload, a download, a search, a comparison, a move or a conversion. Do not run such a step by hand with terminal commands. Write a script in `agentic-brain/skills/<name>/scripts/` and run it.

- A manual run of a mechanical step is an error. Record it in the register with the skill `error`.
- Each skill has `scripts/`. `SKILL.md` says what the agent decides and what the script does.
- A script you can reuse belongs in a skill, not in `scratch/`.
- The hook `repeat_guard.mjs` of a standalone copy (optional, Claude Code only) rejects the third manual run of the same program with different arguments in one session. The rule applies without the hook too.

## End of task

Before you report the end of a task, run the skill `task-end`. It verifies these points.

- `check.sh` passed without errors (the skill `task-end` runs it for the repo).
- `agentic-brain/scratch/` is empty.
- A repeated procedure is a skill with a script.
- An error from the run is in the error register.
- New knowledge is in `memory/` or in `decisions/`.
- A skill or artifact that reaches beyond the project has `scope: shared` in its frontmatter and appears in the report to the operator.

## Layers

The brain has three layers with the same structure: `RULES.md`, `skills/`, `artifacts/`, `errors/`, `decisions/`, `memory/`, `scratch/` and `bin/`. One `check.sh`, `install.sh` and `adopt.sh` serve all of them.

- Global layer: the repo `~/agentic-brain` on the agent's machine. Rules and skills for all projects on that machine. The user installs it with `install.sh --global`.
- Project layer: the folder `agentic-brain/` in the repo of a project that stands above several code repos. It holds the knowledge of the project: artifacts, source material and domain memory. It is optional, a project with one repo has no project layer.
- Repo layer: the folder `agentic-brain/` in each code repo, with its own content. It is not a clone or a submodule of the project layer. This folder is the repo layer.

The header of this file may hold a frontmatter, a block between two lines `---` at the start of the file, with these optional lines.

```
---
upstream: <url>
project: <path>
---
```

- `upstream: <url>` in the global repo points to the repo it comes from.
- `project: <path>` in the repo layer points to the project layer. The path is relative to the repo root, for example `../project/agentic-brain`. `adopt.sh --project <path>` writes it.

When `project:` is set, read `RULES.md` of the project layer and the lists in its `artifacts/` and `memory/MEMORY.md` at the start of a task. Claude Code reads skills only from `.claude/skills`, so `check.sh` creates a symlink `.claude/skills/<name>` for each skill of the project layer that the repo layer does not have.

The same skill name in two layers is an error when the `SKILL.md` differs, and `check.sh` reports it. The same skill of the template (identical `SKILL.md`) may exist in every layer, for example `error` and `task-end`. Its symlink in `.claude/skills` points to the nearest layer, the repo layer before the project layer.

The operator promotes an item with `scope: shared` to the global or the project layer. The agent only marks it in the end-of-task report.

`CLAUDE.md` and `AGENTS.md` of a repo stay a single line, `@agentic-brain/RULES.md`. State, decisions and source material go to `decisions/`, `memory/` and `artifacts/`, not to `CLAUDE.md`.

## Artifact

An artifact is an approved pattern for repeated work. Before you design or implement something an artifact may cover, look at the list in `agentic-brain/artifacts/`.

1. If one fits, read the whole `PLAYBOOK.md` and open the files in `reference/`.
2. Take values (colors, sizes, fonts, structure) from the reference. Do not write them from memory. If text and reference disagree, the reference wins.
3. Deviate from an artifact only with a reason. Tell the operator the deviation in one sentence and do not rewrite the rule.
4. Do the verification steps from the playbook before you hand over, and report the result.
5. The agent that did the work creates a new artifact, and the operator approves it. Without approval, nothing is created.
