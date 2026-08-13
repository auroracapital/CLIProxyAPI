# CLIProxy account reconciler

This hub-only controller reconciles a complete declarative credential inventory against CLIProxyAPI's loopback management endpoints. It is dry-run unless `--apply` is supplied. It never performs interactive login: a credential that cannot refresh is categorized as `auth_required` and waits for an externally staged candidate.

The inventory is sensitive configuration because it contains auth indexes, expected identity metadata, and filesystem paths. Keep it `root:crsproxy` mode `0640`; do not put the real inventory in version control. Supply the HMAC key and optional management API key through a protected environment file readable only by the service user. Neither value belongs in argv.

Candidate files must be regular JSON files with mode `0600`, on the same filesystem as the canonical credential directory, with `disabled` absent or false. Required keys and expected identity fields are matched before promotion. The promoted copy is atomically marked `disabled=false` and `reconcile_state=probing` before it becomes visible, then refreshed and pinned-probed before admission. A failed refresh or probe restores the mode-`0600` rollback archive. The candidate is deleted only after a successful admitted probe.

The inventory must exactly match the runtime `auth_index` and provider set. Missing, duplicate, extra, provider-mismatched, or path-ambiguous entries fail closed before mutation. Attempts are capped per seat per UTC day; failures use exponential backoff with jitter. Global, provider, and seat locks live below `RuntimeDirectory`.

Applied lifecycle work is also recorded in `journal.jsonl` below
`StateDirectory` (normally `/var/lib/cliproxy-account-reconciler`). The service
creates this append-only JSONL file as mode `0600`. Each bounded record has a
monotonic sequence, ISO timestamp, 32-character opaque HMAC seat bucket,
categorical action/outcome/prior/result/reason, and a SHA-256 chain to the prior
record. It never contains auth indexes, providers, models, identities, paths, or
credential material. A malformed, truncated, symlinked, oversized, wrongly owned,
or unwritable journal fails applied reconciliation closed. Verifiers can call
`TransitionJournal.validated_cursor()` to establish the chain-validated baseline
`{inode, offset, seq, hash}` and reject rotation, truncation, or chain drift.

Use `--seat-key` for a single-seat canary. The value is the controller's 32-character opaque HMAC seat key from its categorical logs or state filename, never an auth index, identity, or path. The controller validates the complete inventory first and then applies the seat, provider, health, and maximum-seat filters together; an invalid, unknown, or contradictory selection fails before mutation.

If an interrupted controller version records `rollback_failed`, use
`--recover-rollbacks` to repair every such inventory-managed seat as one automatic
operation. The mode cannot be combined with seat, provider, health, maximum, or
force-probe filters. It validates the complete inventory and the exact latest
pre-failure archive for each selected opaque seat, preserves the current
credential bytes, and restores only archived admission plus a cooling lifecycle
through a generation-fenced service CAS. It never refreshes, probes, promotes,
deletes, or copies a credential. The default remains a non-mutating dry run;
add `--apply` only after the categorical selection is reviewed.

Install `reconciler.py` as `/opt/crsproxy/bin/account-reconciler`, create `/etc/crsproxy/account-inventory.json`, and install the templates from `systemd/`. The supplied unit runs with `--apply`; invoking the program manually without it is a safe dry run.

Generate the real inventory only on `healify-hub` with `generate_inventory.py`. The generator is dry-run by default, accepts the management key only through `CLIPROXY_RECONCILER_API_KEY`, and talks only to CLIProxyAPI's pinned loopback endpoint. It cross-checks every durable runtime seat against its canonical JSON path, stable `auth_index`, provider, and registered models, then selects a probe model from a fixed provider policy. Disabled seats may bootstrap a model from the same provider's file-backed registry, but registry membership proves only that the translation path exists; the later exact-seat probe remains the sole health and admission proof. Dry-run output contains only categorical counts. After reviewing that count, run with `--write`; the default output is atomically installed as `/etc/crsproxy/account-inventory.json`, owner `root:crsproxy`, mode `0640`. The generator never prints identities, paths, tokens, or API response bodies.

```sh
sudo --preserve-env=CLIPROXY_RECONCILER_API_KEY /usr/bin/python3 /opt/crsproxy/bin/generate-account-inventory
sudo --preserve-env=CLIPROXY_RECONCILER_API_KEY /usr/bin/python3 /opt/crsproxy/bin/generate-account-inventory --write
```

Run its fast verification with:

```sh
python3 -m compileall -q reconciler.py tests
python3 -m unittest discover -s tests -v
```
