# Release adapters facts (W3-C)

Verified 2026-11-01. Marks: [V] = read in the primary source, [U] = unverified.

## FACTS

| claim | URL | |
|---|---|---|
| npm trusted publishing needs npm CLI >= 11.5.1 and Node >= 22.14.0 | https://docs.npmjs.com/trusted-publishers | [V] |
| npm needs `id-token: write`; no npm token needed to publish | same | [V] |
| `--provenance` is NOT needed: on GitHub Actions npm generates provenance automatically when package and repo are public | same | [V] |
| npm trusted-publisher config takes the workflow filename only (e.g. `rr-release-npm.yml`), case-sensitive, file in `.github/workflows/` | same | [V] |
| PyPI trusted publishing: job permission `id-token: write` (job level strongly recommended), optional `environment: pypi`, step `pypa/gh-action-pypi-publish@release/v1`, no username/password | https://docs.pypi.org/trusted-publishers/using-a-publisher/ | [V] |
| Packagist updates through a push webhook set up on the GitHub side (auto via GitHub login); token only for manual webhook setup; no publish step in CI | https://packagist.org/about | [V] |
| GHCR publish: job permissions `contents: read`, `packages: write` (docs example also `attestations: write`, `id-token: write` for attestation); `docker/login-action` with `${{ secrets.GITHUB_TOKEN }}` | https://docs.github.com/en/packages/managing-github-packages-using-github-actions-workflows/publishing-and-installing-a-package-with-github-actions | [V] |
| Docs example pins `docker/login-action@65b78e6e13532edd9afa3aa52ac7964289d1a9c1`, `docker/build-push-action@f2a1d5e99d037542a71f64918e516c093c6f3fc4`, uses `actions/checkout@v6`; GitHub recommends SHA pinning | same | [V] |
| Preflight commands: `composer validate --strict`, `composer audit`, `npm pack --dry-run`, `npm publish --dry-run`, `python -m build`, `twine check dist/*`, `docker build` (taken from DES §9.1; not re-read on vendor pages) | DES §9.1 | [U] |
| `npm publish --dry-run` needs no credentials | - | [U] |

## READ
docs.npmjs.com/trusted-publishers, docs.pypi.org/trusted-publishers/using-a-publisher, packagist.org/about, docs.github.com GHCR publishing page.

## Pinning decision
Every action is pinned to a commit SHA. Resolved 2026-11-01 with the GitHub REST API (`gh api repos/<owner>/<repo>/git/ref/tags/<tag>`; annotated tags dereferenced with `git/tags/<sha>`). [V]

| action | ref | commit SHA | source |
|---|---|---|---|
| actions/checkout | v6 | d23441a48e516b6c34aea4fa41551a30e30af803 | https://api.github.com/repos/actions/checkout/git/ref/tags/v6 [V] |
| actions/setup-node | v4 | 49933ea5288caeca8642d1e84afbd3f7d6820020 | https://api.github.com/repos/actions/setup-node/git/ref/tags/v4 [V] |
| actions/setup-python | v5 | a26af69be951a213d495a4c3e4e4022e16d87065 | https://api.github.com/repos/actions/setup-python/git/ref/tags/v5 [V] |
| actions/upload-artifact | v4 | ea165f8d65b6e75b540449e92b4886f43607fa02 | https://api.github.com/repos/actions/upload-artifact/git/ref/tags/v4 [V] |
| actions/download-artifact | v4 | d3f86a106a0bac45b974a628896c90dbdf5c8093 | https://api.github.com/repos/actions/download-artifact/git/ref/tags/v4 [V] |
| shivammathur/setup-php | v2 (annotated tag d52fc211...) | eb7c497e18156a6bbabfef1d3a82760b9eda3962 | https://api.github.com/repos/shivammathur/setup-php/git/tags/d52fc211a0436f8839a587b3b5b8efddab4744ea [V] |
| pypa/gh-action-pypi-publish | branch release/v1 | 7245906fb61fa33a13554f9d5fb856fe61758086 | https://api.github.com/repos/pypa/gh-action-pypi-publish/git/ref/heads/release/v1 [V] |
| docker/login-action | (GitHub docs example) | 65b78e6e13532edd9afa3aa52ac7964289d1a9c1 | GHCR docs page above [V] |
| docker/build-push-action | (GitHub docs example) | f2a1d5e99d037542a71f64918e516c093c6f3fc4 | GHCR docs page above [V] |

Moving tags/branches advance, so these SHAs go stale: refresh on wave 4 / periodically.

## Host execution rule
Host `rr release preflight|dry-run` runs only commands that execute no project code: `composer validate --strict`, `composer audit`, `npm pack|publish --dry-run --ignore-scripts`, `twine check` on an existing `dist/`. `python -m build` (build backend) and `docker build` (RUN steps) run only in the generated CI workflow.

## CONFLICTS
None with DES §9.1. Note: DES lists "provenance" under npm preflight; with trusted publishing it is automatic, so no flag is generated.

## GAPS
- Composer has no verified "dry-run"; DryRun runs `composer validate --strict` [U].
- Trusted publisher registration (npm/PyPI settings) is a human step on the registry, outside the repo.

## COST
4 pages fetched.

## Round 2 facts
| claim | URL | |
|---|---|---|
| `--no-plugins` ("Disables plugins") and `--no-scripts` ("Skips execution of scripts defined in composer.json") are options available with every composer command (so validate and audit) | https://getcomposer.org/doc/03-cli.md | [V] |
| `COMPOSER_HOME` sets composer's home dir; `COMPOSER_ALLOW_SUPERUSER=1` only silences the root warning (we do not set it) | https://getcomposer.org/doc/03-cli.md | [V] |
| npm 11 config documents `script-shell`, `node-options`, `globalconfig`, `ignore-scripts`; `onload-script` does not appear on the page | https://docs.npmjs.com/cli/v11/using-npm/config | [V] / onload-script [U] (set empty anyway) |
| npm config priority lists command-line flags and environment variables before project `.npmrc`, so `NPM_CONFIG_*` env overrides it (implied by the ordering, not stated in one sentence) | same | [V] |
| npm.yml pins `npm@11.5.1`, the documented minimum for trusted publishing | https://docs.npmjs.com/trusted-publishers | [V] |
