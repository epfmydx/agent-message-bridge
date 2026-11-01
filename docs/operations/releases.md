# Source-only releases

This project distributes source code and Helm templates. It does not build or publish application images or OCI charts. The Dockerfile and Compose files are build instructions for an operator's own environment; no prebuilt application image is promised.

The `release.yaml` workflow runs only on `v*` tag pushes and validates source/version/docs/content/tests against a disposable PostgreSQL service. Branch pushes do not start it. The workflow has no registry login, image-build or publish job and uses no deployment credentials. Local checks are the pre-push gate.

Before an authorized tag, align `bridge.__version__`, chart version and appVersion, run the local gates in [verification](../verification.md), then run:

```sh
python scripts/release.py plan --tag v0.1.0
```

The helper validates canonical version syntax and matching source/chart metadata; it performs no network or publication operation. Use a new version for a later release rather than moving an existing public tag. Check that source archives contain only intended source, documentation, tests and synthetic examples, with no Git history, runtime files, secrets or private data.

Public repository, tag and site changes require the maintainer's authorized task scope. Never put real credentials in an issue, release note or example. An operator who builds the Dockerfile must separately satisfy the licenses of redistributed packages and base-image components; see [third-party notices](../../THIRD_PARTY_NOTICES.md).

The profile webhook documentation describes a local source candidate, not a release, tag or deployment. Version metadata remains `0.1.0`. Before operating this candidate on an existing installation, follow the additive [schema upgrade and recovery guidance](setup.md#schema-and-recovery), including initialization before all API/worker upgrades and the older-worker limitation after notification changes.
