---
disclosure-default: ai-generated
models-used:
  - muse-spark (Meta, via OpenCode)
  - Space Bunny Free (OpenCode)
providers:
  - Meta
  - OpenCode
scope: |
  Architecture, implementation, tests, refactors, and documentation were
  drafted by AI coding agents under the operator's direction. The operator set
  the project goals, native Babashka path, synthetic-only mock constraint, and
  public-repository scope. Verification is reported below from actual commands;
  browser HTTP and native-image parity are explicitly not claimed.
  Earlier review found and fixed three genuine native bugs: keyword-vs-string
  owner-kind comparison, CLI argument-parser flag drop, and mock-server path
  routing. The CLJC refactor additionally removed a JVM-only vector index call
  from policy ranking without changing its semantics.
  The operator is learning the codebase to defend it; review depth and runtime
  boundaries are stated here rather than implied.
---

# AI disclosure

This repo is **AI-generated with human direction and machine verification**.
The operator (Nur Azhar) owns the brief, constraints, and product decisions;
AI agents drafted the code and documentation. The evidence below was produced
on the operator's machine on 2026-09-25:

- `bb test`: **25 tests, 118 assertions, 0 failures, 0 errors** (portable and
  native HTTP suites).
- `clojure -M:test`: **22 tests, 107 assertions, 0 failures, 0 errors**.
- `clojure -M:test-cljs` plus `node target/cljs-tests.js`: **22 tests, 107
  assertions, 0 failures, 0 errors** on the same portable contract.
- `bb audit-demo`: deterministic report with **exactly 5 findings**.
- `clj-kondo --lint src test --fail-level warning`: **0 errors, 0 warnings**.

These checks establish native Babashka behavior and JVM/CLJS parity only for
the pure shared core. They do not establish browser HTTP/CORS behavior, a
browser CLI, or native-image build/result parity.
