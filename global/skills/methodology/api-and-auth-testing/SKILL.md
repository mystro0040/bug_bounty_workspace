---
name: api-and-auth-testing
description: Testing REST/GraphQL APIs and auth systems (JWT, OAuth, SAML) for token handling flaws, mass assignment, broken object/function-level authorization, and rate-limit/MFA bypass; use when the target exposes APIs or complex authentication.
---

# API & Auth Testing

APIs concentrate high-impact bugs: broken authorization, token flaws, mass assignment. Test with **two accounts you control** and keep everything non-destructive and in scope.

## Rules
- In-scope API hosts only; confirm before sending requests.
- Never brute-force credentials of real users or hammer auth endpoints as a stress test — respect rate limits and lockout policies.
- Prove authz gaps by reading one object you shouldn't; do not bulk-harvest.

## Map the API first
- Collect specs: `/swagger.json`, `/openapi.json`, `/api-docs`, `.well-known/`, GraphQL introspection, mobile-app traffic, JS `js_endpoints.txt` from recon.
- Import into Burp/Postman. Note every parameter, role, and object-ID shape.

## REST authorization (BOLA + BFLA)
- **BOLA (object level):** swap object IDs across accounts A/B (see web-vulnerability-hunting IDOR).
- **BFLA (function level):** call admin/privileged endpoints as a low-priv user. Try:
  - HTTP verb tampering: `GET`→`PUT`/`DELETE`/`PATCH`.
  - Force-browse admin routes; remove/rename role params.
  - Automate with `Autorize` (Burp) — replay every request stripped of the high-priv session and diff responses.

## Mass assignment / auto-binding
- **Look for:** object-creation/update endpoints binding JSON straight to models.
- **Confirm:** add unexpected fields to the body and check they persist:
```http
PUT /api/v1/users/me HTTP/1.1
Content-Type: application/json

{"name":"A","role":"admin","is_verified":true,"balance":999999}
```
- If `role`/`is_verified`/`balance`/`org_id` sticks → privilege escalation / tenant crossover. Confirm with your own account only.

## JWT flaws (`jwt_tool`)
```bash
jwt_tool <token> -T           # tamper interactively
jwt_tool <token> -X a         # alg:none downgrade
jwt_tool <token> -X k -pk pub.pem   # RS256->HS256 key confusion (sign with public key)
jwt_tool <token> -C -d wordlist.txt # crack weak HMAC secret
```
- Check: `alg:none`, RS256→HS256 confusion, weak/guessable secret, unverified `kid` (path traversal/SQLi in kid), missing `exp`, accepting expired/other-user tokens, sensitive data in payload.
- **Confirm:** forge a token elevating **your** account, show server accepts it.

## OAuth 2.0 / OIDC
- **redirect_uri abuse:** loose matching, open redirect, `redirect_uri` swap to attacker origin → auth code/token theft.
- **state missing/unvalidated:** CSRF on the OAuth flow → account linking hijack.
- **Leaky code/token:** via Referer, in URL fragment, or logs.
- **Confirm:** capture a code/token delivered to an origin you control; demonstrate account link/takeover on **your** test accounts.
- Also check PKCE downgrade, implicit-flow token leakage, scope escalation.

## SAML
- **Look for:** SP endpoints (`/saml/acs`, `/sso`). Grab a valid `SAMLResponse`.
- **Test:** XML signature stripping/wrapping (XSW), comment-injection in `NameID` (`admin<!---->@target`), unsigned-assertion acceptance, expired-assertion replay.
- Tools: `SAML Raider` (Burp). Confirm by authenticating as a different **test** identity.

## GraphQL
```graphql
# Introspection (if enabled)
{ __schema { types { name fields { name } } } }
```
- If introspection off: `clairvoyance` to infer schema.
- **Authz:** per-field/per-node checks — BOLA via node IDs, mutations lacking authorization.
- **Batching abuse:** aliasing to bypass rate limits / brute OTP in one request:
```graphql
{ a:login(otp:"0000"){t} b:login(otp:"0001"){t} c:login(otp:"0002"){t} }
```
- **DoS caution:** deeply nested/recursive queries can crash servers — do **not** run resource-exhaustion queries; note the missing depth/complexity limit as a lower-severity issue instead of exploiting it.

## Rate-limit & MFA bypass
- **Rate limit bypass techniques** (test at low volume, just enough to prove the control is absent):
  - Header spoofing: `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP` rotation.
  - Case/param/path variation, trailing slash/dot, alternate HTTP versions.
  - GraphQL aliasing/batching (above).
- **MFA/OTP bypass:** reuse pre-MFA session token, skip the MFA step and hit the post-auth endpoint directly, response manipulation (`{"verified":false}`→`true`), OTP without expiry/attempt cap, backup-code weaknesses, race on OTP validation.
- **Confirm** on your own account; do not lock out or brute real users.

## Tooling
`Burp` + `Autorize`/`AuthMatrix`, `jwt_tool`, `SAML Raider`, `Postman`, `graphql-cop`/`clairvoyance`, `nuclei` API templates, `ffuf` for param/endpoint mining.

## De-prioritize
Verbose API errors without data exposure, missing rate limit on non-sensitive endpoints, introspection-enabled alone (report as low unless it exposes an exploitable gap), CORS on endpoints with no credentials/sensitive data.

## Feed forward
Confirmed API/auth bugs → **validation-and-triage**.

## Reconcile identifier spaces before IDOR/BOLA testing
An authenticated user often carries SEVERAL distinct identifiers — a JWT `member_id`, the JWT `sub`, an
analytics/feature-flag key (e.g. LaunchDarkly `user.key`), and an account/URL id — and they are NOT the
same value. Before cross-account testing, map WHICH identifier each endpoint consumes. Broken object
authorization frequently hides in the mismatch: an endpoint that trusts a client-supplied id in a
different space than the token asserts. Also distinguish **token-derived** endpoints (identity comes from
the bearer, no id in path/query — e.g. `/about`, `/me`, `/personal-information`) which have NO IDOR
surface, from **id-parameterized** endpoints (`/family/member/{id}`, `?member_id=`) which do. Enumerate
which is which first; don't waste time fuzzing the token-derived ones.
