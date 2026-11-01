# agent-message-bridge Helm chart

Installs the private bridge API, worker, and schema initialization job from one independently built image. The chart creates only these workloads and an internal `ClusterIP` Service; configure ingress separately if required.

Before installation, create an external PostgreSQL database dedicated to Agent Message Bridge, a Kubernetes Secret named by `existingEnvSecret`, and a config Secret named by `existingConfigSecret` with key `config.json`. The environment Secret provides `DATABASE_URL`, `BASE_URL`, `SESSION_SECRET`, and `ENCRYPTION_KEY`. Optional storage settings are `S3_ENDPOINT`, `S3_REGION`, `S3_BUCKET`, `S3_ACCESS_KEY`, and `S3_SECRET_KEY`; optional delivery settings are `WEBHOOK_URL` and `WEBHOOK_TOKEN`. Add participant credentials using the environment variable names referenced by the bridge participant config. The config file is mounted read-only at `/run/bridge/config.json` and sets bridge participants as documented by the source configuration contract.

Browser pages require a dedicated existing origin Secret referenced by `adminOrigin.secretName`/`secretKey` and the actual app-facing gateway addresses in `adminOrigin.trustedProxyCidrs`. The API alone receives these values. Keep the origin secret out of the shared environment Secret. Missing origin configuration leaves browser pages closed while machine APIs retain their own authentication. Configure Cloudflare to overwrite `X-Bridge-Origin`, preserve a public `CF-Connecting-IP` and forward a single HTTPS scheme through the trusted gateway. See the source operations guide for the complete origin path.

The initialization job also adds the browser membership/date indexes to existing databases using coordinated concurrent PostgreSQL builds. Use a schema-owner database role and allow initialization to complete.

The chart does not create Secrets, database resources, public ingress, or cloud storage. It disables service-account token mounting and runs containers as UID/GID 10001 with a read-only root filesystem and an empty `/tmp` volume. The API Service listens on port 8000 and readiness uses `/healthz`.

For immutable releases set `image.repository` and `image.digest`; a digest overrides the development tag. The source-only release workflow validates this chart without packaging or publishing an image or OCI chart. An operator supplies an image built in their own environment and may pin its digest.
