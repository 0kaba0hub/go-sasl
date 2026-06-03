# yarilo-patches branch

This fork of [emersion/go-sasl](https://github.com/emersion/go-sasl)
extends the upstream library with **server-side mechanisms** that the
[Yarilo](https://github.com/0kaba0hub/yarilo) mail server needs but
which upstream does not (yet) ship.

## Branch layout

| Branch | Purpose | Rules |
|:---|:---|:---|
| `master` | **Mirror of `emersion/go-sasl@master`**. NEVER carries downstream commits. | Only fast-forward merges from upstream. Force-push forbidden. |
| `yarilo-patches` | `master` + Yarilo server-side mechanisms. Yarilo's `go.mod` `replace` directive pins to a specific commit on this branch. | Rebased onto `master` whenever upstream moves. Force-push with `--force-with-lease` is expected. |

## What's added

| Mech | RFC | Status | Notes |
|:---|:---|:---|:---|
| LOGIN server | [draft-murchison-sasl-login](https://tools.ietf.org/html/draft-murchison-sasl-login-00) | **landed** | Restored from upstream commit `b788ff2~1` after upstream removed it in [emersion/go-sasl#19](https://github.com/emersion/go-sasl/issues/19) as "legacy". Yarilo needs it for older Outlook / Android MUAs. |
| SCRAM-SHA-256 server | RFC 7677 | **landed** | Operator-managed verifier blob; PBKDF2 default 600 000 rounds; uniform-timing on unknown-user; constant-time proof compare. |
| SCRAM-SHA-256-PLUS server | RFC 5802 + RFC 9266 channel binding | **landed** | Channel binding via TLS exporter (RFC 9266); caller supplies the exporter bytes from the underlying TLS conn. |
| SCRAM-SHA-1 server | RFC 5802 | **landed** | Same state machine as SHA-256, digest swapped. Kept for legacy clients (older Thunderbird / Apple Mail fallback); new deployments should prefer SHA-256. |
| SCRAM-SHA-1-PLUS server | RFC 5802 + channel binding | **landed** | RFC 9266 TLS-exporter channel binding (TLS 1.3+). |
| XOAUTH2 server | Google XOAUTH2 dialect | planned | Likely to follow the LOGIN path — slated for removal upstream per #19. |
| CRAM-MD5 server | RFC 2195 (deprecated but legacy clients) | planned | |
| DIGEST-MD5 server | RFC 2831 (deprecated) | planned | |

Upstream already provides server-side **PLAIN**, **ANONYMOUS**,
**EXTERNAL**, **OAUTHBEARER** — those are used directly.

## How Yarilo consumes this branch

In `0kaba0hub/yarilo` `go.mod`:

```
replace github.com/emersion/go-sasl => github.com/0kaba0hub/go-sasl <commit-hash>
```

The `replace` pins to an explicit commit hash, never the branch name —
this protects Yarilo from silent breakage when `yarilo-patches` is
rebased after an upstream sync.

Update path when this branch advances:

```sh
cd 0kaba0hub/yarilo
go get -u github.com/emersion/go-sasl@<new-yarilo-patches-commit>
go mod tidy
```

## Daily upstream sync

`.github/workflows/sync-upstream.yml` runs on `yarilo-patches` daily
at 06:00 UTC and on `workflow_dispatch`. It has two jobs:

1. **mirror-master** — fast-forwards `master` to
   `emersion/go-sasl@master`. Fails the job (preserves the
   mirror invariant) if our `master` ever carries commits upstream
   does not.
2. **rebase-patches** — only runs when `master` advanced. Rebases
   `yarilo-patches` onto the new `master` and force-pushes with
   lease. On rebase conflict opens an issue labelled
   `upstream-conflict`.

When you see an `upstream-conflict` issue, the action items are:

1. Do the rebase locally, resolving the conflict.
2. Force-push `yarilo-patches`.
3. Update `0kaba0hub/yarilo` `go.mod` `replace` pseudo-version to
   the new commit (`go get -u github.com/emersion/go-sasl@<hash>`).

## Exit plan (per mechanism)

When upstream merges a mechanism we've added:

1. Drop the cherry-pick / merge commit from `yarilo-patches`.
2. Update Yarilo's `go.mod` `replace` to point at the upstream
   tag / commit that includes the merge — or drop the `replace`
   entirely if every patch has landed.
3. Update this file's status table.

When every mechanism has landed upstream, the `replace` directive
disappears and the fork stays as a no-op (zero cost on GitHub).
