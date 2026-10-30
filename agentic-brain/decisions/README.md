# Decisions

One decision is one file `D0001-<slug>.md`. The number grows by one. The slug is a short name in lowercase ASCII.

`bin/decide.sh "<title>"` creates a new decision. The script finds the highest number and creates the next file with a header.

## File format

The file starts with a header between two `---` lines.

- `id`: the decision number, for example `D0001`.
- `date`: the date of the entry, in the form `2026-01-31`.
- `status`: `proposed`, `valid`, `canceled` or `replaced`.
- `decided-by`: who approved the decision (a role or a name).

After the header come a title and two sections.

- `Decision`: what applies, in one to three sentences.
- `Reason`: why, including the path we did not choose.

## Changing a decision

Do not delete an old decision. Change its `status` to `replaced` and name the one it replaces in the new file. Fix every place that still states the old decision in the same step.

A decision is not a remark from a discussion. Write it only after the operator has confirmed it.
