# Security Ultra: Plus Ultra Hardening PRDs

> "The best security is invisible to users but impenetrable to attackers."

## Philosophy

These PRDs follow the Jiro principle: **polish the unseen drawer**. Every enhancement must:
1. Be invisible to legitimate users
2. Be verifiable with concrete tests
3. Not introduce complexity that creates new attack vectors
4. Leave the codebase better than we found it

---

## PRD-SEC-ULTRA-001: Cloudflare KV Rate Limiting

**Problem**: In-memory rate limiting resets on deploy, allowing burst attacks during deployments.

**Solution**: Use Cloudflare KV for persistent, distributed rate limiting that survives deploys and scales horizontally.

**Scope**: All projects with rate-limited endpoints (blakecrosley.com, 941return.com, acecitizenship.app)

**Implementation**:
- Create shared `security-ratelimit` KV namespace in Cloudflare
- Build lightweight KV client for FastAPI
- Replace in-memory rate limiters with KV-backed version
- Graceful fallback to in-memory if KV unavailable

**Acceptance Criteria**:
- [ ] Rate limits persist across Railway deploys
- [ ] Rate limit state shared if multiple instances exist
- [ ] Fallback to in-memory works if KV unreachable
- [ ] No added latency perceptible to users (<50ms overhead)
- [ ] Tests verify persistence and fallback behavior

**UX Impact**: None (invisible)

---

## PRD-SEC-ULTRA-002: Cloudflare WAF Rules

**Problem**: Application-level security is the last line of defense. WAF provides edge-level protection.

**Solution**: Configure Cloudflare WAF rules for:
- SQL injection patterns
- XSS attack signatures
- Path traversal attempts
- Suspicious user agents (scanners, bots)
- Rate limiting at edge (before hitting origin)

**Scope**: All domains on Cloudflare (941return.com, 941getbananas.com, acecitizenship.app, blakecrosley.com)

**Implementation**:
- Create WAF ruleset via Cloudflare API/Dashboard
- Block OWASP Top 10 attack patterns
- Challenge suspicious requests (not block—reduces false positives)
- Log blocked requests for monitoring
- Allowlist known good bots (Googlebot, etc.)

**Acceptance Criteria**:
- [ ] WAF rules deployed to all zones
- [ ] OWASP Core Rule Set patterns blocked
- [ ] Googlebot and legitimate crawlers not affected
- [ ] False positive rate <0.1% (monitor for 48hrs)
- [ ] Security headers verified at edge

**UX Impact**: None for legitimate users. Attackers get challenged/blocked.

---

## PRD-SEC-ULTRA-003: Automated Dependency Scanning

**Problem**: Vulnerabilities in dependencies are a common attack vector. Manual checking is error-prone.

**Solution**: Enable GitHub Dependabot + scheduled security audits.

**Scope**: All repositories

**Implementation**:
- Enable Dependabot security updates in all repos
- Add `dependabot.yml` config for weekly scans
- Create GitHub Action for `pip-audit` / `safety` checks on PR
- Configure alerts to notify on critical vulnerabilities

**Acceptance Criteria**:
- [ ] Dependabot enabled on all 5 repos
- [ ] Weekly dependency update PRs generated
- [ ] CI fails on known critical vulnerabilities
- [ ] Security advisories create GitHub issues automatically

**UX Impact**: None (developer workflow only)

---

## PRD-SEC-ULTRA-004: Security Headers Hardening

**Problem**: Current headers are good but not maximum security.

**Solution**: Upgrade to strictest possible security headers without breaking functionality.

**Scope**: All projects

**Implementation**:
- Upgrade CSP to remove 'unsafe-inline' where possible (use nonces)
- Add `Cross-Origin-Embedder-Policy: require-corp`
- Add `Cross-Origin-Opener-Policy: same-origin`
- Add `Cross-Origin-Resource-Policy: same-origin`
- Strengthen `Permissions-Policy` to deny all unused features

**Acceptance Criteria**:
- [ ] SecurityHeaders.com score: A+ on all domains
- [ ] Mozilla Observatory score: A+ on all domains
- [ ] No functionality broken (forms, HTMX, Alpine still work)
- [ ] CSP violations logged (not just blocked) for monitoring

**UX Impact**: None if done correctly. Requires testing.

---

## PRD-SEC-ULTRA-005: Request Signing & Integrity

**Problem**: API endpoints could be replayed or tampered with.

**Solution**: Add request signing for sensitive operations (admin actions, form submissions).

**Scope**: Admin routes, form submissions

**Implementation**:
- Add timestamp + HMAC signature to sensitive requests
- Reject requests older than 5 minutes (replay protection)
- Verify signature server-side before processing
- Integrate with existing CSRF tokens (complementary, not replacement)

**Acceptance Criteria**:
- [ ] Admin actions require valid signature
- [ ] Replayed requests rejected after 5min window
- [ ] Tampered requests rejected (signature mismatch)
- [ ] No UX change (signing happens client-side automatically)

**UX Impact**: None (JavaScript handles signing transparently)

---

## Execution Order

1. **PRD-SEC-ULTRA-003** (Dependabot) - Quickest win, no code changes
2. **PRD-SEC-ULTRA-004** (Headers) - Strengthen existing infrastructure
3. **PRD-SEC-ULTRA-002** (WAF) - Edge protection before origin hardening
4. **PRD-SEC-ULTRA-001** (KV Rate Limiting) - Most complex, highest value
5. **PRD-SEC-ULTRA-005** (Request Signing) - Defense in depth, last layer

---

## Success Metrics

After all PRDs complete:
- SecurityHeaders.com: A+ on all domains
- Mozilla Observatory: A+ on all domains
- Rate limits persist across deploys
- Zero false positives on WAF (monitored 1 week)
- All dependencies at latest secure versions
- Request replay attacks impossible

---

*"Plus Ultra security that users never see, but attackers always feel."*
