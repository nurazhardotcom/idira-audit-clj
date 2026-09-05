# idira-audit-clj

Zero-dependency Identity & PAM audit CLI in Babashka/Clojure. Queries a
CyberArk/Idira-style REST API (SCIM users/groups, tokens, MFA policy) and
emits deterministic EDN/JSON audit reports: orphaned privileged accounts,
dormant privilege, un-vaulted accounts, missing MFA, stale tokens.

> **Scope, stated plainly:** this audits a **shape-compatible mock API**
> (built in) or any SCIM/OAuth2 endpoint you point it at. There is **no
> CyberArk integration and no affiliation with CyberArk** — "Idira-style"
> means the endpoint shapes, not a partnership. The GraalVM single-binary
> build is a roadmap item; today it runs on `bb` (itself a GraalVM binary,
> so startup is already milliseconds). AI disclosure: see
> [AI_DISCLOSURE.md](./AI_DISCLOSURE.md).

## Run (needs only `bb`, no JVM install dance, no deps to fetch)

```bash
bb test                              # 11 tests / 34 assertions
bb audit-demo                        # audit the built-in mock API (deterministic)
bb -m idira-audit.main audit --mock --format json
bb -m idira-audit.main audit --idsvc # audit sibling ../idsvc via /inventory
bb -m idira-audit.main mock-server --port 8899
bb check-native                      # GraalVM readiness report
```

Live API:

```bash
bb -m idira-audit.main audit --base-url https://idira.example \
  --token-url https://idira.example/oauth2/token \
  --client-id LAB --client-secret '...' --format json
# or: --api-token '...' instead of the client-credentials trio
```

## Layout

- `src/idira_audit/rules.clj` — pure rule engine,
  `(audit-users estate now)` → findings. No I/O; caller passes the clock.
- `src/idira_audit/policy.clj` — MFA / assurance / device-posture evaluation.
- `src/idira_audit/auth.clj` — OAuth2 client-credentials or static API token.
- `src/idira_audit/scim.clj` — fetch + normalize `/Users /Groups /Tokens /Policies`.
- `src/idira_audit/mock.clj` — stub API on JDK `ServerSocket` only; fixed clock
  (`now-fixture`) and fixture estate with exactly 5 findings.
- `src/idira_audit/idsvc.clj` — bridge auditing the sibling `idsvc` service.
- `src/idira_audit/main.clj` — CLI.

## The 5 fixture findings (asserted exactly in tests)

| # | Rule | Subject |
|---|---|---|
| 1 | `orphaned-privileged` (high) | `svc-orphan` — no human owner |
| 2 | `inactive-privileged` (medium) | `svc-dormant` — 120d dormant |
| 3 | `unvaulted-privileged` (high) | `svc-unvaulted` — not vault-managed |
| 4 | `missing-mfa` (medium) | `analyst-nomfa` — no MFA |
| 5 | `stale-token` (medium) | `tok-stale` — 200d old, 180d TTL |

## Native binary (later step — no GraalVM on this box yet)

Namespaces avoid reflection, dynamic classloading, and non-`java.base`
modules, so the audit path (`rules`/`policy`/`scim`/`auth`) is
`native-image`-safe. When GraalVM is available (userspace install, no sudo):

```bash
curl -sL <graalvm-ce-linux-amd64.tar.gz> | tar -xz -C ~/.local
~/.local/graalvm-*/bin/gu install native-image
# then compile the uberscript
```

`bb` itself is already a GraalVM binary, so `bb -m idira-audit.main …`
starts in milliseconds today.
