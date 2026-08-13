# CLIProxy auto-router front service

This is a separate query-aware ingress, not a replacement for the canonical
explicit-model service.

```text
explicit clients -> nginx :8317 -> base CLIProxyAPI 127.0.0.1:8319
auto clients     -> nginx :8321 -> front router 127.0.0.1:8320
                                      |
                                      +-> explicit model request -> base :8319
```

The front process runs the same reviewed CLIProxyAPI binary from
`/opt/crsproxy/auto-router/cliproxy-auto-router`, but owns no OAuth files and
never refreshes provider credentials. It has one OpenAI-compatible loopback
provider representing the base service. A request for `model: auto` is classified
and mapped to an explicit configured model; the front then forwards that explicit
model to `127.0.0.1:8319/v1`. Explicit requests sent to the established `:8317`
endpoint bypass the front process entirely. Configure the base instance with
`routing.auto.mode: reject`; this reserves literal `model: auto` for `:8321`
instead of falling through to CLIProxyAPI's legacy arbitrary auto-model mapping.
Every explicit named model continues through the established path unchanged.
The front runtime uses `routing.auto.mode: exclusive`, so named models sent to
`:8321` are rejected with a boundary error rather than forwarded.

## Files and secrets

Install the secret-free policy as `/etc/crsproxy/auto-router.yaml` from
`auto-router.yaml.example`. The file is JSON, which is a strict subset of YAML;
the renderer intentionally accepts only this constrained schema. List every model
the base service may receive and ensure all routing slates reference that list.

Place the three runtime secrets in root-owned mode-`0600` files:

- `/etc/crsproxy/auto-router-client-key`: key accepted by the `:8321` front.
- `/etc/crsproxy/auto-router-base-api-key`: existing key accepted by base `:8319`.
- `/etc/crsproxy/auto-router-management-key`: independent loopback-only key used
  by the acceptance verifier to read front telemetry counters.

The systemd credentials mechanism exposes them only to the service. `render-config`
combines them with the policy into `/run/cliproxy-auto-router/config.yaml`, mode
`0600`; no secret is placed in argv, the unit environment, this repository, or the
persistent policy. The generated runtime file disappears with the runtime directory.

## Installation layout

```text
/etc/crsproxy/auto-router.yaml
/etc/crsproxy/auto-router-client-key
/etc/crsproxy/auto-router-base-api-key
/etc/crsproxy/auto-router-management-key
/etc/systemd/system/cliproxy-auto-router.service
/etc/nginx/conf.d/cliproxy-auto-router.conf
/opt/crsproxy/auto-router/cliproxy-auto-router
/opt/crsproxy/auto-router/render-config
```

The binary should be copied from the same commit-pinned build as the base binary,
then hashed independently at its final path. Do not symlink the live base binary:
keeping a distinct file permits a reversible front-only rollout without replacing
the base process.

Before enabling the ingress, render once into a protected temporary directory and
start the front on loopback. Verify:

1. `127.0.0.1:8320/v1/models` requires the front client key.
2. A representative `model: auto` request reaches base `:8319` as an explicit model.
3. An explicit request through nginx `:8317` remains byte-for-byte behaviorally
   independent while the front is stopped and restarted.
4. nginx `:8321` reaches only `127.0.0.1:8320`; it never proxies to `:8319` directly.
5. The front has no auth directory entries and no OAuth refresh activity.

Rollback disables/removes only the `:8321` nginx configuration and stops
`cliproxy-auto-router.service`. The `:8317 -> :8319` path is not reloaded or changed.
