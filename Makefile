# Product gate. It tests reality: the deterministic scorecard, the unit tests,
# and the live suite against the local models. Install the pre-push hook once
# with `make hooks`; after that nothing is pushed while a defense is red.
#
#   make check       scorecard + tests + live (the gate; what the hook runs)
#   make scorecard   34 techniques, attack-success rate before and after each defense
#   make test        unit tests
#   make live        the same attacks against the real local models (planner :11435)
#   make hooks       install .githooks/pre-push

SHELL := /bin/bash

.PHONY: check scorecard test live hooks

check: scorecard test live

scorecard:
	go run ./cmd/scorecard

test:
	go test -count=1 ./...

live:
	go test -count=1 -tags live ./pkg/livetest/...

hooks:
	@git config core.hooksPath .githooks && echo "pre-push hook installed: make check runs before every push"
