# Artifacts

An artifact is an approved pattern for repeated work. The operator approved a concrete result, and its rules are written down so every agent applies them the same way.

## Structure

```
artifacts/<name>/
  PLAYBOOK.md
  reference/
```

- `<name>`: short and named after the thing, not after the agent or project.
- `PLAYBOOK.md`: what the artifact covers, the rules as short sentences with concrete values and reasons, what not to do, and how to verify the result.
- `reference/`: the approved result as a template you can copy, not a description. It is the source of truth for values. The folder must not be empty.

If text and reference disagree, the reference wins. When you change the reference, change `PLAYBOOK.md` too, and the other way round.

## Scope

An artifact that reaches beyond the project carries the line `scope: shared` in the frontmatter of `PLAYBOOK.md`. The operator promotes it to the central repo.

## Creation

The agent that did the work creates the artifact, and the operator approves it. Without approval, nothing is created. This repo has no sample artifact. The first one comes from the first approved piece of work.
