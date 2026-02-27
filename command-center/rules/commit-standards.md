# Commit Standards

## Format
All commits MUST use Conventional Commits format:

```
<type>(<optional-scope>): <description>

[optional body]
[optional footer]
```

## Types
- `feat`: New feature or capability
- `fix`: Bug fix
- `security`: Security-related fix (from slopless scan)
- `refactor`: Code restructuring without behavior change
- `test`: Adding or updating tests
- `docs`: Documentation changes only
- `chore`: Maintenance, dependency updates, CI changes
- `perf`: Performance improvement

## Rules
- Subject line: max 72 characters, imperative mood ("add" not "added")
- Body: explain WHY, not WHAT (the diff shows what)
- All commits MUST be GPG-signed (`git commit -S`)
- Reference issue/ticket when applicable: `Closes #42` or `Refs JIRA-123`
- One logical change per commit -- do not mix features with fixes

## Examples

Good:
```
feat(scan): add cross-validation for HIGH severity findings

Reduces false positive rate by ~30% by running a secondary
analysis pass on findings rated HIGH or above.

Closes #87
```

Bad:
```
updated stuff and fixed some things
```
