# Source-only releases

This project distributes source code and Helm templates. It does not build or publish application images or OCI charts. The Dockerfile and Compose files are build instructions for an operator's own environment; no prebuilt application image is promised.

The `release.yaml` workflow runs only on `v*` tag pushes and validates source/version/docs/content/tests against a disposable PostgreSQL service. Branch pushes do not start it. The workflow has no registry login, image-build or publish job and uses no deployment credentials. Local checks are the pre-push gate.

Before an authorized tag, align `bridge.__version__`, chart version and appVersion, run the local gates in [verification](../verification.md), then run:

```sh
python scripts/release.py plan --tag v0.1.1
```

The helper validates canonical version syntax and matching source/chart metadata; it performs no network or publication operation. Use a new version for a later release rather than moving an existing public tag. Check that source archives contain only intended source, documentation, tests and synthetic examples, with no Git history, runtime files, secrets or private data.

Public repository, tag and site changes require the maintainer's authorized task scope. Never put real credentials in an issue, release note or example. An operator who builds the Dockerfile must separately satisfy the licenses of redistributed packages and base-image components; see [third-party notices](../../THIRD_PARTY_NOTICES.md).

The combined profile-webhook, credential-management and informational-notification
documentation describes a local **0.1.1 source candidate**, not a release, tag or
deployment. Before operating it on an existing installation, follow the additive
[schema upgrade and recovery guidance](setup.md#schema-and-recovery). Initialize
before upgrading all API/workers and retain compatible credential/notification
recovery; do not enable automatic downgrade to older code. The source-only
workflow and operator-supplied image requirements are unchanged.

## 0.1.1 source candidate notes

- Optional per-profile bearer webhooks under Profiles → Notifications, separate
  from authentication and client-managed signed MCP subscriptions. Existing
  `WEBHOOK_*` configuration and retained webhook deliveries remain compatible.
- Profiles → Credentials adds password reset, one-time replacement API keys and
  explicit selected-key revocation. Unchanged config sync preserves owner edits;
  explicit configured credential changes remain authoritative. Owners still
  cannot grant participant OAuth consent or existing-thread membership.
- New informational messages notify recipient MCP subscribers while remaining
  nonclaimable, without automatic replies. Profile bearer webhooks stay true-only;
  previously silent history is not replayed.
- Native profile selects match the neutral interface, with CSS-only chevrons,
  keyboard focus and disabled/error states. Key timestamps use UTC.
- Newly entered bearer tokens must be single-line HTTP-header-compatible values;
  existing valid tokens and destinations are retained.

This is an additive database upgrade, with initialization required before all API
and worker processes start the new code. Credential and notification changes make
an automatic old-runtime downgrade unsafe; retain current schema/keys and use
compatible recovery. No application image build, registry publication, production
deployment, provider-specific adapter or new quota is part of this source release.
