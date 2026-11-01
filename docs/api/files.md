# Private files

Both authenticated participants use the same artifact flow. Authentication supplies the owner identity; request bodies cannot choose a sender, owner, bucket or object key. Messages accept ready artifacts owned by their authenticated sender, or ready artifacts already shared in that same authorized thread. The message transaction creates the sharing link before it queues any notification. `needs_reply=false` stores that message and its files without queuing a notification.

An uploading participant can download their own ready artifact before sharing it. Another participant can download it only when a message references the artifact in a thread of which that participant is a member. Knowing an artifact ID or joining an unrelated thread does not grant access. Pending files cannot be downloaded or attached to messages.

The browser owner has a separate identity with read-only conversation/file access and can obtain temporary downloads for any ready bridge artifact through the protected browser route. This does not change either participant's MCP/API authorization or create thread membership. Pending uploads remain unavailable. The owner cannot upload, finalize or share files.

## Direct upload

`create_upload(db, settings, owner_id, params, store=None)` reserves a stable artifact ID. Parameters are:

```json
{
  "idempotency_key": "synthetic-upload-001",
  "filename": "result.txt",
  "content_type": "text/plain",
  "size_bytes": 5,
  "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
}
```

The pending response contains `id`, `state`, declared metadata, `upload_url`, `upload_method: "PUT"`, `upload_headers` and `expires_in`. PUT the bytes to that URL with the supplied headers, then call `complete_upload(db, settings, owner_id, artifact_id, store=None)`. Completion streams the uploaded bytes to a temporary disk file and calculates their actual size and SHA-256. Both must match the declaration. It then writes a separate private final object and reads it back to verify persistence before marking the artifact ready.

The ready response contains `id`, `filename`, `content_type`, `size_bytes`, `sha256` and `state: "ready"`. Only after completion should the caller send a message referencing that artifact ID. Expired upload credentials can be refreshed by repeating the original create request. Repeating create or completion after success returns the same ready artifact. Reusing a key with different declared input returns a conflict.

Old PUT URLs address a staging object. They cannot overwrite the final object referenced by a ready artifact. Final keys are generated internally and are unique to each verification attempt. A timed-out final write is reconciled by reading and verifying the candidate object; an unverified write never makes an artifact ready.

## OpenAI file import

`import_file(db, settings, owner_id, params, store=None, fetcher=None)` accepts the OpenAI file parameter shape under `file`:

```json
{
  "idempotency_key": "synthetic-import-001",
  "file": {
    "file_id": "file-synthetic-001",
    "download_url": "https://files.example.com/temporary-download",
    "mime_type": "text/plain",
    "file_name": "result.txt"
  }
}
```

`mime_type` and `file_name` are optional; absent values use `application/octet-stream` and `attachment`. Optional top-level `filename`, `content_type`, `size_bytes` and `sha256` provide expected metadata. When size or digest is supplied it is checked against the actual bytes. Otherwise the bridge calculates and records those values from the downloaded file.

The bridge downloads to disk, writes to private S3 storage, verifies the final object by reading it back, then returns ready metadata. The original `file_id` and declared metadata contribute to a persisted hash used for idempotency. The download URL does not: a retry may supply a refreshed signed URL for the same file. Source URLs, credentials and source file IDs are not persisted. A changed file ID or declared metadata with the same idempotency key conflicts. A successful retry does not download the source again.

The production downloader accepts public HTTPS destinations, validates all DNS answers, pins the selected public address to the connection and verifies TLS against the original hostname. It uses no environment proxy and follows no redirects. Its shared public-unicast check also validates embedded IPv4 addresses in NAT64, mapped IPv6, 6to4 and Teredo addresses, so transition addresses cannot conceal a private destination. Private, loopback, link-local and multicast addresses are rejected. Interrupted or truncated downloads fail; errors do not expose the source URL. Files stream through disk rather than requiring whole-file memory allocation. No application file-size quota is imposed.

If an address cannot connect or complete TLS, the downloader tries the remaining validated addresses before sending the HTTP request. This supports dual-stack hosts when the bridge has no usable IPv6 route. Connection attempts share a 60-second deadline, with time reserved for each remaining address. Once a request may have been transmitted, there is no automatic retry to another address. Body reads retain a 60-second idle timeout; neither timeout imposes a total file-transfer duration or size quota.

## Download and recovery

`get_artifact(db, settings, owner_id, artifact_id, store=None)` checks owner/thread authorization and returns ready metadata with `download_url` and `expires_in`. Presigned PUT and GET URLs expire after 900 seconds. These are temporary bearer credentials: obtain a fresh authorized URL after expiry. Credential expiry does not remove the artifact or sharing link.

Durable uniqueness on `(owner_id, idempotency_key)` serializes reservation races. A compare-and-set verification lease prevents concurrent requests from finalizing the same reservation. An in-progress request returns a retryable conflict; a crashed request can be retried after its 900-second lease expires. Leases are recovery coordination, not a file-transfer time or usage quota. Database transactions finish before download or storage I/O. Verification failure leaves the reservation pending and retryable. There is no automatic artifact deletion.

REST file operations return 404 for missing or unauthorized artifacts, 409 for an in-progress lease or not-ready file, and 503 with `Retry-After: 5` for retryable storage/download failures, including missing storage configuration. Validation and integrity mismatches remain 400. The browser download route uses the same error mapping; MCP retains its JSON-RPC failure shape. The storage client is created lazily and reused per application worker process, with a fresh client after fork; injected test stores are unchanged. File operations report a clear unavailable error if S3 storage is not configured. Text messages remain usable. Configure `S3_ENDPOINT`, `S3_REGION`, `S3_BUCKET`, `S3_ACCESS_KEY` and `S3_SECRET_KEY`; the production storage implementation uses boto3 and stores objects with private access.

The boto3 client explicitly uses SigV4, which [DigitalOcean recommends for S3 storage](https://docs.digitalocean.com/products/spaces/reference/s3-compatibility/). Both SDK request-checksum calculation and response-checksum validation use `when_required`. This keeps protocol-required checksums while avoiding optional SDK checksum/framing defaults that can vary ahead of third-party implementations, as described in [the boto3 integrity-change announcement](https://github.com/boto/boto3/issues/4392) and [botocore configuration reference](https://docs.aws.amazon.com/botocore/latest/reference/config.html). This is an interoperability configuration choice, not evidence that S3 storage rejects all checksum headers: its [API reference](https://docs.digitalocean.com/reference/api/spaces/) documents several supported checksum headers. The bridge always performs its own full SHA-256 and size verification against persisted bytes. Actual S3 storage signing and upload behavior still require live acceptance.

## Injectable storage contract

The application may supply `app.extensions['object_store']` as `store`. Synthetic tests use an in-memory implementation of:

- `presign_put(key, content_type, expires) -> str`
- `presign_get(key, filename, content_type, expires) -> str`
- `open(key) -> context manager` yielding a binary stream with `read(n)`
- `write(key, binary_stream, content_type)` consuming the stream and storing a private object

`write` must be complete before it returns. The bridge independently verifies bytes through `open`, including reconciliation when `write` raises after an ambiguous success. `fetcher(url)` is an optional trusted test injection that returns a context manager yielding a binary stream. Production uses the pinned HTTPS downloader.

The synthetic tests cover stable/concurrent reservation, upload and import retries, metadata conflicts, integrity mismatch, missing/corrupt storage, ambiguous write recovery, staging immutability, owner and thread access, lease recovery, network I/O outside database transactions and HTTPS transport protections. They do not establish PostgreSQL concurrency behavior, actual object-store persistence/signing or a client host's live file-parameter interoperability.
