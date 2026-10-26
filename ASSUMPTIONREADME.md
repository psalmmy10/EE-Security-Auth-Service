<div align="center">

# Why the Auth Service Issues Its Own OAuth2 Tokens

**ADR-001 · Token issuance without a full OAuth Authorization Server**

![Status](https://img.shields.io/badge/status-accepted-2ea44f?style=for-the-badge)
![Decision date](https://img.shields.io/badge/decided-2026--10--26-blue?style=for-the-badge)
![Type](https://img.shields.io/badge/type-architecture_decision-6f42c1?style=for-the-badge)

[Summary](#summary) ·
[Assumptions](#assumptions) ·
[Context](#context) ·
[Decision](#decision) ·
[Options](#options-considered) ·
[Consequences](#consequences) ·
[Revisit triggers](#revisit-triggers) ·
[Migration path](#migration-path-if-triggered)

</div>

| | |
|---|---|
| **Status** | ✅ Accepted |
| **Date** | 2026-10-26 |
| **Deciders** | Backend / security owner, auth service |
| **Applies to** | `EE-Security-Auth-Service` — user login, token issuance, sessions |
| **Revisit** | When any [revisit trigger](#revisit-triggers) occurs |

---

## TL;DR

> [!IMPORTANT]
> Users log in **without redirects** and with **end-to-end encrypted** payloads. OAuth 2.1 has **no standard redirect-free user login** — the password grant was removed — so a full OAuth Authorization Server would need *more* custom code than we have today.
>
> We therefore **issue OAuth2-standard tokens ourselves** (RS256 JWT, `/oauth2/jwks`, validated by Spring's OAuth2 Resource Server) and will **add Spring Authorization Server later** only where OAuth's standard flows fit: partners, single sign-on, third-party login.

---

## Summary

The auth service **issues its own OAuth2-standard tokens** (RS256-signed JWTs, published via `/oauth2/jwks`, validated by Spring's OAuth2 Resource Server) from an **end-to-end encrypted, redirect-free login API**.

We deliberately did **not** adopt a full OAuth 2.1 Authorization Server (Spring Authorization Server) for user login, because the product requires login **without redirects**, and OAuth 2.1 offers no standard redirect-free user flow for browser or mobile apps.

> [!NOTE]
> This is not "no OAuth". Token **format, signing, key publication and validation** follow OAuth2/JOSE standards using Spring's own components. Only the **issuance flow** (when tokens are minted, rotated and revoked) is implemented in this service.

---

## Assumptions

This decision is valid **only while these assumptions hold**. Each one is a revisit trigger if it changes.

| # | Assumption | Why it matters |
|:-:|---|---|
| A1 | **Login must not redirect.** Users sign in inside our own app screens; the app posts credentials to an API. | Rules out authorization code + PKCE, the only standard OAuth 2.1 user flow. |
| A2 | **Only first-party clients log users in** — pay's own web and mobile apps. No third-party app signs users in "with pay". | First-party apps may collect the password directly; third-party apps must never see it (that is what redirect flows are for). |
| A3 | **Login payloads must be end-to-end encrypted** (RSA-OAEP-256 + AES-256-GCM on top of TLS). | A hosted OAuth login page posts plain form data over TLS; our E2E envelope would not apply. |
| A4 | **Token consumers are our own services**, validating via `/oauth2/jwks`. | Any OAuth2 resource server can verify our tokens; no client registration needed for that. |
| A5 | **No single sign-on** across multiple, separately deployed pay apps is required yet. | SSO needs a central login session, which is what an Authorization Server provides. |
| A6 | **No partner / machine-to-machine access** through this service yet. | Partners need the OAuth client-credentials grant at a standard `/oauth2/token` endpoint. |
| A7 | **Session controls are a product requirement**: refresh-token reuse detection that revokes the whole login, a 30-day absolute session lifetime, and at most 5 concurrent sessions per user. | Spring Authorization Server provides none of these out of the box; they would have to be rebuilt as extensions. |
| A8 | **The team accepts ownership** of the issuance code (rotation, revocation, session limits) — reviewed, tested, and kept current. | The trade-off of not using a framework-maintained issuer. |
| A9 | **Regulators / auditors accept** a documented, tested custom issuance flow built on standard token formats. | If an audit mandates a certified/standard Authorization Server, A9 fails. |

---

## Context

Spring Authorization Server (SAS) issues tokens only through standard OAuth grants:

| Grant | Redirect? | Fits our user login? |
|---|---|---|
| Authorization code + PKCE | **Yes** | ❌ Violates A1 |
| Resource owner password ("send email + password, get tokens") | No | ❌ **Removed in OAuth 2.1, not supported by SAS** |
| Client credentials | No | ❌ Machine-to-machine only — no user |
| Refresh token | No | Only after one of the above |

Using SAS for redirect-free user login would therefore require:

1. A **custom grant type** for email + password (custom code inside SAS).
2. **Custom client authentication** — SAS requires `/oauth2/token` callers to authenticate as a registered client with a secret; browser/mobile apps cannot keep secrets, and SAS allows secret-less (public) clients only in the PKCE redirect flow.
3. **Rebuilding A7's session controls** on SAS extension points (none exist natively).
4. **Performance work** — SAS's JDBC store looks tokens up by full value in an unindexed binary column, versus our single indexed lookup by `jti` per request.

The result would be **more custom code than today, wrapped around SAS**, while losing tested features.

---

## Decision

1. **Keep the self-issued model for user login**:
   - Credentials verified by Spring Security's `AuthenticationManager` (`DaoAuthenticationProvider`, BCrypt, timing protection, status checks after the password).
   - Tokens signed by Spring's `JwtEncoder` (Nimbus, RS256) with keys from the PKCS#12 keystore.
   - Validation by Spring's OAuth2 Resource Server plus an active-session check per request.
   - Rotation, reuse detection, absolute lifetime and session limits implemented in `SessionService`.
2. **Publish keys at `/oauth2/jwks`** so any pay service validates tokens the standard OAuth2 way.
3. **Add Spring Authorization Server later only where OAuth's standard flows apply** — partner/machine-to-machine access (client credentials), introspection, and SSO — sharing the same signing keys.

---

## Options considered

| Option | Verdict | Reason |
|---|---|---|
| **A. Self-issued OAuth2 JWTs, encrypted API login** | ✅ **Chosen** | Meets A1–A9; standard tokens; tested session controls; one indexed lookup per request. |
| B. Full Spring Authorization Server, authorization code + PKCE | ❌ Rejected for now | Requires redirect login (violates A1); login form outside the E2E envelope (A3). Best choice once SSO or third-party login is needed. |
| C. Spring Authorization Server with a custom password grant | ❌ Rejected | Uses a grant removed from OAuth 2.1; needs custom grant **and** custom public-client authentication; A7 controls still custom; slower token lookups. More custom code than A. |
| D. External IdP (Keycloak, Auth0, Okta, Entra ID) | ❌ Rejected for now | Same redirect requirement for standard flows; recurring cost/hosting; data-residency review needed. Reconsider with B. |

---

## Consequences

### Positive

- **Redirect-free, end-to-end encrypted login** exactly as the product requires.
- **Standard tokens**: RS256 JWTs + JWKS — any OAuth2 resource server (Spring, Node, Go) can validate them.
- **Session controls already built and tested**: rotation with family-wide reuse revocation, 30-day absolute lifetime, 5-session limit, immediate revocation on logout / role / status change.
- **Fast per-request checks**: one indexed lookup by `jti`.
- **No extra infrastructure**: no OAuth client registry or OAuth schema.

### Negative / risks

| Risk | Mitigation |
|---|---|
| We own the security of the issuance code | Small, single-purpose classes; unit tests; this ADR; dependency scanning; periodic security review |
| No standard `/oauth2/token`, `/oauth2/revoke`, `/oauth2/introspect`, OpenID discovery | Not needed under A2–A6; add SAS alongside when they are |
| Standard OAuth client libraries can't drive our login | First-party clients use the provided clients (`docs/frontend/payAuthClient.ts`, `tools/E2EClient.java`) |
| Password reaches our app's UI | Acceptable for first-party apps (A2); E2E encryption protects it beyond TLS (A3) |
| An auditor may expect a standard Authorization Server | This ADR documents the reasoning; migration path below |

---

## Revisit triggers

Re-open this decision if **any** of these happen:

- [ ] A **third-party app** needs to sign users in with pay accounts (A2).
- [ ] **Partners or merchants** need machine-to-machine tokens from this service (A6) → add SAS for client credentials alongside.
- [ ] **Single sign-on** across several pay apps is required (A5).
- [ ] Product accepts a **redirect-based login** (A1).
- [ ] An **audit or regulator** requires a standard / certified Authorization Server (A9).
- [ ] The team can no longer **own and review** the issuance code (A8).

---

## Migration path (if triggered)

The current design keeps the move cheap:

1. **Add SAS alongside** (client credentials first) using the **same `KeyProvider`** — one signing key, one JWKS, no change for token consumers.
2. Reuse the existing **`AuthenticationManager` / `AppUserDetailsService` / `UserPrincipal`** to power the SAS login page if moving to authorization code + PKCE.
3. Port session controls to SAS customisers (`OAuth2TokenCustomizer`, a custom `OAuth2AuthorizationService`), then retire `SessionService` and the `user_sessions` table.
4. Move front ends to a standard OIDC client (e.g. `oidc-client-ts`) with PKCE.

Resource servers need **no change** at any step — they keep validating the same JWT format against `/oauth2/jwks`.

---

## References

- OAuth 2.1 draft — removal of the resource owner password grant
- RFC 9700 / OAuth 2.0 Security Best Current Practice — refresh token rotation and reuse detection
- RFC 7517 (JWK), RFC 7519 (JWT), RFC 7638 (JWK thumbprint)
- Spring Authorization Server reference — supported grant types and client authentication methods

---

<div align="center">
<sub>Architecture Decision Record · part of the <a href="../../README.md">EE Security Auth Service</a> documentation</sub>
</div>