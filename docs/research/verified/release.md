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
Docker actions: commit SHAs from the GitHub docs [V]. PyPI action: `release/v1` (the documented, PyPA-maintained moving branch). Others (`actions/checkout@v6` [V]; `actions/setup-node@v4`, `actions/setup-python@v5`, `shivammathur/setup-php@v2` [U]) use major tags: SHAs must not be cited from memory. GAP: pin these to SHAs after verification.

## CONFLICTS
None with DES §9.1. Note: DES lists "provenance" under npm preflight; with trusted publishing it is automatic, so no flag is generated.

## GAPS
- Composer has no verified "dry-run"; DryRun runs `composer validate --strict` [U].
- Trusted publisher registration (npm/PyPI settings) is a human step on the registry, outside the repo.

## COST
4 pages fetched.
