# Shared account model prefixes

File-backed credentials may opt into additional model namespaces without
creating another credential or OAuth refresh lifecycle:

```json
{
  "type": "claude",
  "prefix": "work",
  "additional_prefixes": ["general"]
}
```

With `force-model-prefix: true`, this one credential publishes
`work/<model>` and `general/<model>`. Other credentials with `prefix: general`
participate only in `general/<model>`. Bare model IDs remain suppressed when
the primary prefix is nonempty. Extra prefixes are single path segments;
empty, malformed and duplicate entries are ignored. A malformed list grants
no extra namespaces. Omitting or clearing the list removes the extra routes
on the next credential reload.

All routes use the same auth ID, selector weight, reset hints, disabled flag,
upstream model state and cooldown. Streaming, token counting and ordinary
execution strip the matching prefix before invoking the executor. There is no
namespace-specific priority: `soonest-reset-first` orders eligible credentials
within the existing manual priority tier, with existing session affinity.

The setting is credential metadata, not a new management PATCH field or an
access-control boundary. Use the existing file-backed provisioning path. Do
not copy OAuth credentials to simulate shared namespaces.

Synthetic regression checks:

```sh
CGO_ENABLED=0 go test ./sdk/cliproxy/auth ./sdk/cliproxy ./internal/watcher/synthesizer ./sdk/auth
```
