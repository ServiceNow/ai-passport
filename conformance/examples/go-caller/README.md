# Go revocation-caller example

A standalone, standard-library Go adapter for the **AI Passport Revocation Check v1** draft's caller role. This is a second-language interoperability example, not an issuer, verifier, signing implementation or complete authorization gateway.

It consumes the conformance runner's newline-delimited JSON protocol and replies with the outcome `proceed`, `deny` or `refetch`. The runner's published fixtures cover failure-closed behaviour, malformed or duplicate JSON members, stale and cached answers, scope rejection, revision floors, issuer/subject mismatches, and monotonic state-version handling.

## Build and verify

From the repository root:

```sh
go build -o /tmp/ai-passport-go-caller conformance/examples/go-caller/main.go

python3 conformance/run.py --role caller \
  --adapter /tmp/ai-passport-go-caller

python3 conformance/run.py --role caller \
  --adapter /tmp/ai-passport-go-caller --http
```

Only Go and Python's standard library are needed. No private ServiceNow credentials or production systems are used. The HTTP test mode exercises the runner's local mock responder.

### What is covered

- **Caller vectors:** parses the pre-supplied revocation response, its cache headers and previous-answer state, then produces an outcome without making network requests.
- **HTTP mode:** fetches a revocation answer with a deadline, refuses redirects, rejects non-200 statuses, bounds response size, strictly parses the response and checks the queried subject.
- **Defensive semantics:** treats missing/invalid status, revocation, revisions, scope entries and freshness data conservatively; refuses duplicate JSON member names (including nested ones).

### Limitations

- This example **does not authenticate** AI agents, verify signed Passports, provide an authoritative revocation responder, or grant permission to perform an action. A result of `proceed` means the *revocation check* does not withdraw the subject under the caller's inputs; a separate policy/authorization decision is still required.
- The adapter accepts a simulated earlier response and clock in vector mode to match the conformance protocol. A production caller must maintain its own trusted cache and clock, bind it to the authenticated subject and issuer, and apply freshness/irreversible-action limits to *actual* effect boundaries.
- No hardened TLS configuration, production storage, credential handling or deployment architecture is provided. Do not copy the example into a production gateway without a security review.
- The specification is draft `1.0-draft.1`; update the example if the specification changes.
- The HTTP test covers cases the runner can exercise using its mock responder. Its suite deliberately skips historical/cached/clock-specific scenarios handled by the vector mode.

The implementation does not reuse any proprietary governance code and follows the public conformance adapter format documented in [../README.md](../README.md).
