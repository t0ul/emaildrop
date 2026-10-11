# emaildrop

A local email-to-calendar AI agent, built security-first.

emaildrop reads email (school newsletters, in my case) and turns the real dates
into calendar events, running entirely on an Apple Silicon Mac. Nothing leaves the
machine. It is the product built across my AI Security Engineering series, where
every feature is built, attacked, and hardened with Attack-Driven Design.

- The handbook that builds this, lesson by lesson: https://github.com/t0ul/ai-security-engineering
- Posts: https://t0ul.com

## Quick start

Requires an Apple Silicon Mac, Go 1.27+, and llama.cpp (`brew install go llama.cpp`).

Deterministic run, no model needed:

```bash
CGO_ENABLED=0 go build -o emaildrop ./cmd/emaildrop
mkdir -p drop/inbox && cp testdata/emaildrop/samples/3.txt drop/inbox/
EXTRACT_MODE=regex DROP_DIR=./drop ./emaildrop --once
```

Score extraction against the labeled samples:

```bash
EXTRACT_MODE=regex go run ./cmd/eval
```

Bring up the local models and run against them:

```bash
go run ./cmd/prepareassets
go run ./cmd/modeld
```

## Security

The controls are small, dependency-free Go libraries (gledger, gouncer, goflage,
and others). The full red-team scorecard reports the attack-success rate before and
after each defense:

```bash
go run ./cmd/scorecard
```

See the handbook repo for how each control was built and attacked.
