# Contributing to altiward-forwarder

Thanks for helping. Bug reports, fixes and documentation improvements are all welcome. For a
larger change, open an issue first so we can agree on the approach before you write code.

## Set up

You need Go 1.27 or later. The forwarder's only dependency outside the standard library is
the SIEM client module from the main Altiward repository,
`github.com/Altiward/altiward/integrations`, and `make deps-check` keeps it that way.

The released SIEM clients are vendored with a reviewed Splunk acknowledgement fix. CI,
Docker and hook packages build that copy. Keep the patch and the two pinned contract
fixtures when refreshing `vendor/`; the standalone delivery regressions must pass.

To work on the forwarder and the SIEM clients together, check out
[Altiward/altiward](https://github.com/Altiward/altiward) next to this repository and add a
`go.work` here (it's git-ignored):

```
go 1.27.0

use (
	.
	../altiward/integrations
)
```

Run coordinated checks with `GOWORK="$PWD/go.work" make lint test deps-check`. Run the
standalone release checks below as well, because a workspace bypasses the vendored patch.

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

## Releasing

Relay and hook releases are separate. Date the relevant `Relay X.Y.Z` or `Hook X.Y.Z`
section in `CHANGELOG.md` on the actual release day, and run `make lint test deps-check
vulncheck` before releasing. `scripts/release-notes.sh relay X.Y.Z` (or `hook X.Y.Z`)
checks and prints the notes. The relay's `vX.Y.Z` tag runs
[release.yml](.github/workflows/release.yml); the hook's `hook-vX.Y.Z` tag runs
[release-hook.yml](.github/workflows/release-hook.yml). A maintainer approves the relevant
release environment before signing and publication.

After publication, verify the downloaded assets against the release's signed checksums
and the expected repository, workflow and tag identity. For the hook, also verify the
package's Developer ID signature and notarisation, and use the checksum profile from
that same release when deploying it through MDM.

Then open a pull request in [Altiward/altiward.com](https://github.com/Altiward/altiward.com)
to update the forwarder version, release date and tag links in the "Is it released?"
row of `assurance/index.html`. Check the relay and hook separately if their published versions
differ. Use only verified published releases, and keep release candidates out of this
row. A documentation or assurance change alone does not require a new forwarder release.

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
