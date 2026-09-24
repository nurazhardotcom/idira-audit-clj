# pam-audit-clj

> **Status:** Active — maintained. Synthetic fixtures only, no real estates. See [AI_DISCLOSURE.md](AI_DISCLOSURE.md).

[![CI](https://github.com/nurazhardotcom/pam-audit-clj/actions/workflows/ci.yml/badge.svg)](https://github.com/nurazhardotcom/pam-audit-clj/actions)

> **Enterprise IAM/PAM & Policy-as-Code audit component.**
> Enforces least-privilege access, automated compliance checks, and
> privileged session governance for cloud and enterprise directory platforms.

* **Target environment:** Enterprise hybrid / vault-managed PAM &
  Active Directory (SCIM-shaped mock API built in; point at any
  SCIM/OAuth2 endpoint for live use).
* **Regulatory focus:** SG PDPA compliance-as-code.
* **Core function:** Replaces manual privilege auditing and risky IAM drift
  with deterministic, version-controlled rule evaluation
  (`src/pam_audit/rules.clj` — pure, no I/O).

Zero-dependency Identity & PAM audit CLI in Babashka/Clojure. Queries a
SCIM-shaped PAM REST API (users/groups, tokens, MFA policy) and
emits deterministic EDN/JSON audit reports: orphaned privileged accounts,
dormant privilege, un-vaulted accounts, missing MFA, stale tokens.

> **Scope, stated plainly:** this audits a **shape-compatible mock API**
> (built in) or any SCIM/OAuth2 endpoint you point it at. Endpoint shapes
> follow common PAM patterns (SCIM users/groups, tokens, MFA policy).
> A standalone GraalVM single-binary build was evaluated and **deferred**
> (see [Native binary](#native-binary-deferred-by-decision)); it runs on
> `bb` (itself a GraalVM binary, so startup is already milliseconds).
> AI disclosure: see [AI_DISCLOSURE.md](./AI_DISCLOSURE.md).

## Run (needs only `bb`, no JVM install dance, no deps to fetch)

```bash
bb test                              # 14 tests / 45 assertions
bb audit-demo                        # audit the built-in mock API (deterministic)
bb -m pam-audit.main audit --mock --format json
bb -m pam-audit.main audit --idsvc # audit sibling ../idsvc via /inventory
bb -m pam-audit.main mock-server --port 8899
bb check-native                      # GraalVM readiness report
```

Live API:

```bash
bb -m pam-audit.main audit --base-url https://pam.example \
  --token-url https://pam.example/oauth2/token \
  --client-id LAB --client-secret '...' --format json
# or: --api-token '...' instead of the client-credentials trio
```

## Layout

- `src/pam_audit/rules.clj` — pure rule engine,
  `(audit-users estate now)` → findings. No I/O; caller passes the clock.
  Fail-closed on gaps: never-logged-in privileged accounts and tokens
  without `:created` are findings, never silent passes.
- `src/pam_audit/policy.clj` — MFA / assurance / device-posture evaluation.
- `src/pam_audit/auth.clj` — OAuth2 client-credentials or static API token.
- `src/pam_audit/scim.clj` — fetch + normalize `/Users /Groups /Tokens /Policies`.
- `src/pam_audit/mock.clj` — stub API on JDK `ServerSocket` only; fixed clock
  (`now-fixture`) and fixture estate with exactly 5 findings.
- `src/pam_audit/idsvc.clj` — bridge auditing the sibling `idsvc` service.
- `src/pam_audit/main.clj` — CLI.

## The 5 fixture findings (asserted exactly in tests)

| # | Rule | Subject |
|---|---|---|
| 1 | `orphaned-privileged` (high) | `svc-orphan` — no human owner |
| 2 | `inactive-privileged` (medium) | `svc-dormant` — 120d dormant |
| 3 | `unvaulted-privileged` (high) | `svc-unvaulted` — not vault-managed |
| 4 | `missing-mfa` (medium) | `analyst-nomfa` — no MFA |
| 5 | `stale-token` (medium) | `tok-stale` — 200d old, 180d TTL |

A sixth rule, `never-logged-in-privileged` (high), covers privileged
accounts with no recorded login — exercised with a synthetic estate in
`rules_test.clj`; the 5-finding mock fixture intentionally has none.

## Native binary (deferred by decision)

**Decision (2026-09-22):** standalone GraalVM `native-image` compilation
is **deferred** — Babashka already delivers sub-millisecond startup for
this CLI, so a separate native binary buys nothing today.

Rationale:

* `bb` is itself a GraalVM binary; `bb -m pam-audit.main …` starts in
  milliseconds with zero install friction (one static binary, no JVM).
* The audit path (`rules`/`policy`/`scim`/`auth`) stays `native-image`-safe
  by construction — no reflection, no dynamic classloading, no non-
  `java.base` modules — so the option can be revisited without rework.
* `bb check-native` continues to report GraalVM readiness as a guardrail.

Revisit only if a dependency-free single-file distribution (no `bb`
prerequisite) becomes a hard requirement.

## Automated testing

```bash
bb test          # 14 tests / 45 assertions (rules, policy, HTTP integration)
bb audit-demo    # end-to-end audit of the built-in mock API (exactly 5 findings)
```

Every rule in `rules.clj` is asserted exactly in tests — the 5 fixture
findings table above is the executable contract, not documentation drift.

## CI usage

GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml))
runs on every push to `main` and every pull request:

```yaml
- run: bb test
- run: bb audit-demo
```

Both steps exit non-zero on failure, so the deploy job never runs on a
broken audit.

## License

MIT — see [LICENSE](LICENSE).
