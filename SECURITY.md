# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x.x   | Yes       |
| < 2.0   | No        |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in DriveClean, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email the maintainer directly with details
3. Include steps to reproduce the vulnerability
4. Allow reasonable time for a fix before any public disclosure

## Security Features

### Session Security
- Session tokens are encrypted with AES-256 before disk storage
- Each session has a unique ID (UUID v4)
- Sessions are invalidated on logout
- Temporary encryption keys are generated if `ENCRYPTION_KEY` is not set (sessions won't survive restart)

### OAuth Security
- State parameter prevents CSRF attacks on OAuth flow
- OAuth states expire after 10 minutes
- `access_type: offline` and `prompt: consent` ensure proper token refresh
- Tokens are never exposed to the client

### API Security
- Rate limiting: 120 requests per minute per IP
- All protected endpoints require valid session header
- Input validation on all endpoints
- Batch operation limits (max 1000 files for delete/restore, 100 for permissions, 50 for undo)

### HTTP Security Headers
- `Content-Security-Policy` - Restricts resource loading to same origin
- `X-Frame-Options: DENY` - Prevents clickjacking
- `X-Content-Type-Options: nosniff` - Prevents MIME type sniffing
- `X-XSS-Protection: 1; mode=block` - XSS filter
- `Referrer-Policy: strict-origin-when-cross-origin` - Controls referrer info
- `Cross-Origin-Opener-Policy: same-origin` - Isolates browsing context

### Data Protection
- No sensitive data logged (tokens, passwords)
- File operations logged with counts, not file names
- Scan data persisted without OAuth tokens
- Encryption key should be stable across restarts to maintain sessions

## Best Practices for Deployment

1. **Never commit `.env` files** - They contain secrets
2. **Use a stable `ENCRYPTION_KEY`** - Changing it invalidates all sessions
3. **Use HTTPS in production** - Required for secure OAuth callbacks
4. **Keep dependencies updated** - Run `npm audit` regularly
5. **Restrict OAuth scopes** - Only request what you need
6. **Monitor logs** - Watch for unusual patterns
7. **Use Render's automatic `ENCRYPTION_KEY` generation** - Don't override after first deploy

## Known Limitations

- Session data is stored in memory (not distributed)
- No brute-force protection on session IDs (rely on UUID entropy)
- Rate limiting is per-process (not shared across instances)
- OAuth tokens are refreshed automatically but not rotated proactively
