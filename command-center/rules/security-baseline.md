# Security Baseline

## Absolute Rules (never allow)
- No hardcoded secrets, API keys, tokens, or passwords in source code
- No `eval()`, `exec()`, `Function()`, or equivalent dynamic code execution
- No SQL string concatenation -- use parameterized queries only
- No `dangerouslySetInnerHTML` or equivalent without sanitization
- No disabled CSRF/XSS protections
- No wildcard CORS (`Access-Control-Allow-Origin: *`) in production configs

## Input Handling
- All user input MUST be validated and sanitized before use
- File paths MUST be canonicalized and checked for traversal (`../`)
- URL inputs MUST be validated against allowlists for SSRF prevention
- Integer inputs MUST be bounds-checked

## Dependencies
- All dependencies pinned to exact versions (no `^` or `~` ranges)
- No dependencies with known CVEs (check with `npm audit` / `pip audit` / `cargo audit`)
- Minimize dependency count -- prefer standard library when reasonable

## Authentication & Authorization
- Passwords hashed with bcrypt/argon2 (never MD5/SHA1)
- Session tokens: minimum 128 bits of entropy
- API keys transmitted only over HTTPS
- Rate limiting on authentication endpoints

## Logging
- Never log secrets, tokens, passwords, or PII
- Log security-relevant events: auth failures, permission denials, input validation failures
- Include request IDs for traceability

## Slopless Integration
- Every PR MUST pass slopless scan with zero CRITICAL findings
- HIGH findings require explicit justification or fix
- MEDIUM findings should be addressed; LOW findings are advisory
