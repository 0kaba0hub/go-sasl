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

So far the `yarilo-patches` branch carries nothing beyond `master`.
Server-side mechanisms land here as separate commits as Yarilo's
AUTH-5 phase progresses:

| Mech | RFC | Status |
|:---|:---|:---|
| SCRAM-SHA-1 server | RFC 5802 | planned |
| SCRAM-SHA-1-PLUS server | RFC 5802 + channel binding | planned |
| SCRAM-SHA-256 server | RFC 7677 | planned |
| SCRAM-SHA-256-PLUS server | RFC 7677 + channel binding | planned |
| XOAUTH2 server | Google XOAUTH2 dialect | planned |
| CRAM-MD5 server | RFC 2195 (deprecated but legacy clients) | planned |
| DIGEST-MD5 server | RFC 2831 (deprecated) | planned |

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
