# Releasing `tripwire`

This repository uses a manual `release.yml` workflow. Versions are independent from the other Tripwire server SDKs.

## Before the first real release

Configure these GitHub settings:

1. Make the repository public.
2. Create a protected GitHub environment named `release` with required reviewer approval.

## Release flow

1. Bump the repo-root `VERSION` file in a pull request.
2. Merge the version bump to `main`.
3. Open GitHub Actions and run `Release`.
4. Set `confirm_version` to the exact `VERSION` value.
5. Run a `dry_run=true` release first.
6. Re-run with `dry_run=false` once the dry run looks correct and the `release` environment approval is in place.

## What the workflow does

- reads the release version from `VERSION`
- reruns the equivalent of the repo checks
- creates a source tarball for the tagged commit
- on real releases:
  - creates tag `vX.Y.Z`
  - creates a GitHub Release with the source tarball attached

Go consumers will fetch tagged versions from the public repository. There is no prerelease channel in this phase.
