# PR Quality Standards

## Structure
Every PR MUST include:
- **Title**: Conventional commit format (e.g., `feat(scan): add cross-validation`)
- **Summary**: 1-3 sentences explaining what and why
- **Changes**: List of files changed with brief descriptions
- **Test Plan**: How to verify the changes work
- **Slopless Scan Status**: Results of security scan

## Size Limits
- Target: under 400 lines changed per PR
- If larger: suggest splitting into smaller PRs with clear dependencies
- Exception: generated files, migrations, or bulk renames

## Quality Gates
- Zero CRITICAL findings in slopless scan
- Zero HIGH findings (or explicit justification in PR body)
- All existing tests pass
- New functionality includes tests
- No hardcoded secrets, tokens, or credentials
- Dependencies pinned to exact versions

## Branch Naming
- Format: `slopless/<description-slug>`
- Examples: `slopless/add-health-check`, `slopless/fix-sql-injection`
- Max 60 characters

## Review Protocol
- PRs created by the command center are tagged with `slopless-bot`
- Include open questions for human reviewers
- Flag any design decisions that need team input
- Auto-request review from CODEOWNERS if configured
