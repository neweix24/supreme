# Supreme Android Key Attestation service

This directory contains the Android hardware-backed key attestation verifier source and tests imported from `neweix24/neweix`.

## Contents

- `supabase/functions/_shared/` — DER, X.509, Google attestation metadata, provisioning information, policy, and verifier modules.
- `supabase/functions/supreme-attestation-verify/` — Edge Function handler and tests.
- `scripts/security/` — reference fixture extraction and upstream differential-test helpers.

## Security status

This is imported source, not a production-ready security certification. Before production use:
- Review the verifier against current Android Key Attestation and Google root metadata requirements.
- Pin and periodically review trust anchors and upstream test fixtures.
- Run all unit, fixture, differential, and negative tests.
- Verify challenge freshness, one-time consumption, replay protection, and server-side binding to the authenticated device/session.
- Ensure no client-provided verdict is trusted without server-side verification.
- Review logs to ensure certificate material and challenge data do not leak secrets or unnecessary personal information.

Do not bypass attestation verification in production if the verifier or trust data is unavailable. Fail closed for operations that require a verified device.
