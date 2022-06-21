# Releases

This page describes the release process and the currently planned schedule for upcoming releases.

## Release schedule

To be discussed. Currently, there is no specific schedule or cadence for releases.

# How to cut a new release

> This guide is strongly based on the [Prometheus release instructions](https://github.com/prometheus/prometheus/blob/main/RELEASE.md).

## Branch management and versioning strategy

We use [Semantic Versioning](http://semver.org/).

We maintain a separate branch for each minor release, named `release-<major>.<minor>`, e.g. `release-1.1`, `release-2.0`.

The usual flow is to merge new features and changes into the main branch and to merge bug fixes into the latest release branch. Bug fixes are then merged into main from the latest release branch. The main branch should always contain all commits from the latest release branch.

If a bug fix got accidentally merged into main, cherry-pick commits have to be created in the latest release branch, which then have to be merged back into main. Try to avoid that situation.

Maintaining the release branches for older minor releases happens on a best effort basis.

## Prepare your release

The process formally starts with the initial pre-release, but some preparations should be done a few days in advance.

> For a new major or minor release, work from the `main` branch. For a patch release, work in the branch of the minor release you want to patch (e.g. `release-0.3` if you're releasing `v0.3.2`).

* We aim to keep the main branch in a working state as much as possible. In principle, it should be possible to cut a release from main at any time. In practice, things might not work out as nicely. A few days before the pre-release is scheduled, the releaser should check the state of main. Following their best judgement, the releaser should try to expedite bug fixes that are still in progress but should make it into the release. On the other hand, the releaser may hold back merging last-minute invasive and risky changes that are better suited for the next minor release.
* The releaser cuts the first pre-release (using the suffix `-rc.0`) and creates a new branch called  `release-<major>.<minor>` starting at the commit tagged for the pre-release. In general, a pre-release is considered a release candidate (that's what `rc` stands for) and should therefore not contain any known bugs that are planned to be fixed in the final release.
* With the pre-release, the releaser is responsible for running and monitoring a benchmark run of the pre-release for 1 day (https://demo.parca.dev should be used), after which, if successful, the pre-release is promoted to a stable release.
* If regressions or critical bugs are detected, they need to get fixed before cutting a new pre-release (called `-rc.1`, `-rc.2`, etc.).

## Publish the new release

For new minor and major releases, create the `release-<major>.<minor>` branch starting at the PR merge commit.

From now on, all work happens on the `release-<major>.<minor>` branch.

### Via GitHub's UI

Go to https://github.com/parca-dev/parca/releases/new and click on "Choose a tag" where you can type the new tag name.

Click on "Create new tag" in the dropdown and make sure `main` is selected for a new major or minor release or the `release-<major>.<minor>` branch for a patch release.

The title of the release is the tag itself.

You can generate the changelog and then add additional contents from previous a release (like social media links and more).

### Via CLI

Alternatively, you can do the tagging on the commandline:

Tag the new release with a tag named `v<major>.<minor>.<patch>`, e.g. `v2.1.3`. Note the `v` prefix.

```bash
git tag -s "v2.1.3" -m "v2.1.3"
git push origin "v2.1.3"
```

Signed tag with a GPG key is appreciated, but in case you can't add a GPG key to your Github account using the following [procedure](https://help.github.com/articles/generating-a-gpg-key/), you can replace the `-s` flag by `-a` flag of the `git tag` command to only annotate the tag without signing.

## Final steps

Our CI pipeline will automatically push the container images to [ghcr.io](ghcr.io/parca-dev/parca-agent).

Go to https://github.com/parca-dev/parca-dev/releases and check the created release.

For patch releases, submit a pull request to merge back the release branch into the `main` branch.

Take a breath. You're done releasing.
