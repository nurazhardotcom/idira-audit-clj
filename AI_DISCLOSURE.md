---
disclosure-default: ai-generated
models-used:
  - muse-spark (Meta, via opencode)
providers:
  - Meta
scope: |
  Architecture, implementation, tests, and docs were drafted by an AI
  coding agent under the operator's direction (project brief, stack
  choice, mock-not-real-API constraint, userspace-only rule).
  Every claim in the README is verified by the test suite
  (`bb test`: 11 tests / 34 assertions) run on the operator's machine.
  Three genuine bugs were found through failing tests and fixed
  (keyword-vs-string kind compare, CLI arg-parser flag drop,
  mock-server path routing). The operator is JIT-learning the codebase
  to defend it live; review depth is honestly stated here, not hidden.
---

# AI disclosure

This repo is **AI-generated with human direction and machine verification**.
The operator (Nur Azhar) set the brief, the stack (Babashka/Clojure,
zero-dependency), and the constraints; the agent wrote the code; the test
suite plus live demo runs are the review evidence. If you interview the
operator about this repo, ask about the tradeoffs — that is the part he
owns and can defend.
