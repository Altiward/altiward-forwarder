# Contributing to altiward-forwarder

Thanks for helping. Bug reports, fixes and documentation improvements are all welcome. For a
larger change, open an issue first so we can agree on the approach before you write code.

## Set up

You need Go 1.27 or later. The forwarder's only dependency outside the standard library is
the SIEM client module from the main Altiward repository,
`github.com/Altiward/altiward/integrations`, and `make deps-check` keeps it that way.

To work on the forwarder and the SIEM clients together, check out
[Altiward/altiward](https://github.com/Altiward/altiward) next to this repository and add a
`go.work` here (it's git-ignored):

```
go 1.25.0

use (
	.
	../altiward/integrations
)
```

## Checks

Run these before you open a pull request. CI runs the same ones:

```sh
make lint test deps-check
```

- `lint`: gofmt, and go vet for Linux and macOS (the hook runs on macOS).
- `test`: every test, with the race detector.
- `deps-check`: fails if a module outside `github.com/Altiward` becomes a dependency.

Tests that touch Privileges' webhook use the bodies in `testdata/privileges-2.6/`. Add a new
body there when Privileges changes what it sends.

## Write it yourself

Build only from SAP Privileges' own source and documentation, which are Apache 2.0, and from
what a real Mac sends. Some related projects publish code without any licence, which means
all rights are reserved, so don't copy code, profiles or configuration from them.

Keep names descriptive: "works with SAP Privileges" is fine, but no product, binary or bundle
name contains "SAP" or "Privileges".

## Sign off your commits (DCO)

Altiward uses the [Developer Certificate of Origin](https://developercertificate.org)
instead of a contributor licence agreement. Add a sign-off to every commit:

```sh
git commit -s -m "Fix the thing"
```

This adds a `Signed-off-by: Your Name <you@example.com>` line. It certifies that you wrote
the change, or have the right to submit it, under the project's open source licence, and
that you understand it is public. Forgot? Run `git commit --amend -s` for the last commit,
or `git rebase --signoff main` for a branch. Every commit must be signed off; we don't merge
pull requests with commits that aren't.

## Security

Please don't report a vulnerability in an issue. See the
[security policy](https://github.com/Altiward/.github/blob/main/SECURITY.md).
