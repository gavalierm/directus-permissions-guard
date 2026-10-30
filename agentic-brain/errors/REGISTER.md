# Error register

One row is one occurrence of an error. The script `skills/error/scripts/error.sh` adds the row. Do not write it by hand.

- Class: a short name for the kind of error. The same kind gets the same name.
- Fix: the file change that blocks the error (a tool, a rule, a check). You fill it in after the fix.
- Test: a command that fails on the error and passes after the fix.

Two or more rows of the same class without a fix fail in `bin/check.sh`. One row without a fix is a warning.

| date | class | description | fix | test |
|---|---|---|---|---|
