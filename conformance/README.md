# AI Passport conformance suite

The test vectors in [vectors/](vectors/) and a runner, `run.py`, that runs them against an
implementation. It tests three conformance roles: verifier, revocation responder and
revocation caller. An issuer can check its Passports by verifying them with a verifier that
passes. Standard library Python only.

```
python3 run.py --selftest
```

checks the suite itself: the reference implementation passes every case, and each
deliberately broken variant of it fails at least one.

[examples/gateway_check.py](examples/gateway_check.py) is the core of a gateway's check in
about 50 lines, as a starting point. It covers the common case only; the suite tells you
when an implementation is complete.

[examples/go-caller/](examples/go-caller/) is an independent standard-library Go caller example,
including actual HTTP response handling. It can run the caller vectors and mock-HTTP
conformance suite through the adapter protocol; it does not issue or verify Passports,
provide identity authentication, or make policy decisions.

## Testing an implementation

| Role | Command | Cases |
|---|---|---|
| Verifier | `run.py --role verifier --adapter ADAPTER_COMMAND` | 81 Passport vectors |
| Caller | `run.py --role caller --adapter ADAPTER_COMMAND` | 41 caller vectors, plus each of the 33 responder answers as a caller receives it |
| Caller, over HTTP | `run.py --role caller --adapter ADAPTER_COMMAND --http` | the same answers served by a local mock responder, including a timeout and a redirect to another origin; 17 cases that need an earlier, expired or reused answer, a set clock or the answering issuer are skipped |
| Responder | `run.py --role responder --adapter ADAPTER_COMMAND` | 33 responder vectors. Add `--no-identity` if the responder does not answer by identity (Revocation Check v1 §3.1) |
| Responder, live | `run.py --role responder --url URL [--subject S] [--header "Name: value"]` | 8 checks against a running endpoint that need no test state |

`ADAPTER_COMMAND` is the command that starts your adapter, quoted, for example
`--adapter "python3 reference/adapter.py"` or `--adapter "node my-gateway-adapter.js"`.

`--report FILE` writes a JSON report with every case's result. `--name` puts the
implementation's name in it. The exit status is 0 when every case passes.

## Adapters

An adapter is a command that connects an implementation to the runner. The runner starts it
once and writes one JSON request per line on its stdin; the adapter writes one JSON answer
per line on stdout. With `--adapter-mode exec` the runner starts the command once per case
instead, with the request on stdin. [reference/adapter.py](reference/adapter.py) is a
complete example.

**Verifier.** Request: `{"role": "verifier", "id", "jwks", "issuer", "input"}`. The
verifier is configured with one trusted issuer, `issuer`, whose key set is `jwks` (AI
Passport v1 §9.1). `input` is the vector's input:
- the Passport, as `passport`, or as `passport_text` where the bytes matter (whitespace,
  duplicate member names, large integers); parse `passport_text` yourself;
- `now`, the time of checking;
- `presenter`, the presenter's identity `{authority, identifier}`, if any, where
  `authority` is the URI the verifier authenticated, matched against a binding's
  `authority.id` (AI Passport v1 §3.3). It was
  authenticated unless it carries `"authenticated": false`;
- `refetched: true` when this Passport is already the one refetch the verification is
  allowed (`fetched_by_presenter_identity: true`, in P16, is a refetch by the presenter's
  pair);
- `trust_anchors`, when present, replaces `issuer` and `jwks` as the whole configuration:
  `{issuer: {"jwks", "responders"}}`, where `responders` lists the origins of responders
  configured for that issuer;
- `revocation`, the revocation answer the verifier receives, in the shape described under
  Caller.

Answer: `{"outcome", "step"}`. The outcome decides the case; a different `step` is reported
but does not fail it. An adapter written before `issuer` was added keeps working where the
Passport's issuer is the configured one, and fails the vectors that test §9.1.

**Caller.** Request: `{"role": "caller", "id", "input"}`, where `input` carries
`holds_passport` (`{subject, revision}`, or null), `previously_applied` (an earlier answer
the caller applied, or null) and `received`. `received` is one of: `{"status", "body"}`;
`{"status", "body_text"}` for a body to parse as received (not valid JSON, or with duplicate
member names); `{"status"}` with no body; `{"error": "timeout"}`; or, with
`"cache_expired": true`, an answer whose `Cache-Control` lifetime has passed. Optional
members:
- `received.headers`: the response headers, where the vector tests `Cache-Control` or `Age`;
- `received.reused: true`: the caller is applying this answer again, after the request
  that brought it;
- `input.asked`: `{"subject"}` when the caller asked by subject (02 §5.1);
- `input.now`: the caller's clock, for checking `evaluated_at` (02 §5.3);
- `input.previously_applied_expired: true`: `previously_applied` is past its directive.

Answer: `{"outcome"}`, one of `proceed`, `deny`, `refetch`.

**Caller over HTTP.** Request: `{"role": "caller", "mode": "http", "id", "holds_passport",
"revocation_url", "timeout_seconds"}`. The adapter makes the real request, with the caller's
own HTTP code and clock, and answers `{"outcome"}`. It asked by the subject in the URL. A
timeout case answers after `timeout_seconds`; a redirect case points at another origin.

**Responder.** Request: `{"role": "responder", "id", "state", "request"}`. The adapter puts
the implementation into `state` (see the vectors README; this is a test hook, never part
of a production interface), uses `state.now` as the time, and answers the `request`, whose
query values are as sent on the wire (percent-encoded). Answer: `{"status", "headers",
"body"}`. Every member of the expected body must be present with the same value and type;
extra members are reported, and `headers` must include each header the vector lists.

## Live checks

A running responder holds its own state, so the live checks use only requests whose answer
the specification fixes whatever the state:

| Check | Request | Expected |
|---|---|---|
| L01 | a random subject | 200, `revoked: true`, `state_version` 0, `reason` `no_passport_issued`, every required member, `Cache-Control` (§5.1–§5.3) |
| L02 | `subject` with `authority` and `identifier` | 400 (§4) |
| L03–L06 | no parameters, empty `subject`, malformed percent-encoding, `authority` alone | 400 (§4) |
| L07 | a random identity | 400 if the responder does not answer by identity, else 200, `subject` null, `revoked: true`, `reason` `unresolved_identity` (§3.1) |
| L08 | `--subject S`, a subject it knows | a complete 200 answer with `Cache-Control` |

Pass credentials with `--header`, for example `--header "Authorization: Bearer $TOKEN"`.
[reference/server.py](reference/server.py) serves the reference responder for trying them.

## Licence

Code and test data in this folder are under the Apache License 2.0 ([LICENSE](LICENSE)).
