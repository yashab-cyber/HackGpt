# PR #21 follow-up: compatibility and verification notes

## Legacy v2 API transport

The `hackgpt_v2.py` API now requires a configured authentication service and TLS.
Set `HACKGPT_API_TLS_CERT` and `HACKGPT_API_TLS_KEY` to an operator-provisioned
certificate and private key. Startup refuses missing or invalid TLS material.
The listener defaults to `127.0.0.1:8000`; `HACKGPT_API_BIND` is an explicit
operator override. Debug mode and the reloader remain disabled for this listener.
Use a certificate trusted by the connecting client; do not disable certificate
verification. Private keys and credentials do not belong in Git.

All login and bearer-authenticated routes reject cleartext before parsing login
credentials or calling token verification. The non-sensitive health route is the
only route exempt from the application transport check. Forwarded scheme headers
are not trusted automatically. A reverse proxy must use TLS to the backend or a
separately reviewed WSGI deployment contract; adding an arbitrary
`X-Forwarded-Proto: https` header does not enable access. The built-in development
server is not presented as a production edge server.

The former unrestricted CORS configuration is removed. Same-origin clients need
no CORS exceptions. Cross-origin deployments require an explicit, reviewed origin
policy rather than inheriting wildcard access.

The six-phase start route requires `create_session`, `run_active_scans`, and
`run_exploitation` permissions. A role that can create sessions but cannot run all
phases is denied before any worker starts. Persisted creator identity comes from
the verified token, never from the JSON `created_by` field. These checks are user
and operation authorization; they are not proof of ownership of an assessment
target. Operators still need separately established target authorization.

## Scanner occurrence identifiers

Scanner IDs are now a short versioned category plus a SHA-256 digest of a JSON
identity tuple. Complete whitelisted metadata is hashed before display fields
are truncated. This avoids losing distinguishing suffixes when a path, target,
matcher, package, or vendor fingerprint exceeds display limits. Trivy vulnerability,
misconfiguration, and secret-result categories all use the same bounded approach.
Exact duplicate identities are still rejected rather than silently merged.

The tuple does not include scanner request/response bodies, source snippets,
secret matches, extracted values, URL credentials, query strings, or fragments.
Finding output remains candidate-only; a deterministic identifier is not proof of
exploitation or a security guarantee.

This is an identity-format change. Existing stored reports are not rewritten.
Use newly imported reports from the same parser revision when assessing equality
across scans. An unmatched old identifier must not be treated as proof that a
finding was fixed. Existing conservative comparison and missing-coverage rules
remain required.

## Verification scope

The runtime regression suite uses real Flask request routing, real JWT decoding,
and real RBAC decorators, with synthetic credentials and inert worker/DB doubles.
It does not launch an assessment or access an external target. HTTPS WSGI tests
are separate from the owned-loopback TLS regression: the latter creates a
disposable localhost certificate, verifies the certificate on the client, rejects
a cleartext connection, and exchanges only synthetic login data over real TLS.
Startup tests additionally check that a TLS context is loaded and insecure
listener fallback is absent.
