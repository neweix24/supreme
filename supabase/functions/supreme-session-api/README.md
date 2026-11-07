# Supreme session API

Deploy as the Supabase Edge Function `supreme-session-api`.

## Required server secrets

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY` (or `SUPABASE_PUBLISHABLE_KEY`)
- `SUPABASE_DB_URL` (server-side database connection string; never ship it in the Android app)

The function uses the Auth `/user` endpoint to validate the bearer token before decoding its `session_id`. It then independently checks the active Supreme principal and the device-session records in the private `supreme` schema.

## Endpoints

- `GET /functions/v1/supreme-session-api`: returns the current Auth session's device-bound status. It never treats a valid Supabase user session as sufficient Supreme app authorization.
- `DELETE /functions/v1/supreme-session-api`: revokes only the current Auth session's Supreme device-session record and appends an audit event. It does not revoke another device or the underlying Supabase Auth session.

All responses are private/no-store. The function does not accept a user ID or Auth session ID from the request body.

## Required deployment order

1. Apply the Supreme identity migration.
2. Apply `20261107200000_supreme_device_bound_auth_sessions.sql`.
3. Configure the Custom Access Token Hook as documented in `docs/security/supreme-device-session-hook.md`.
4. Deploy this function with server-only secrets.

## Explicitly not complete

This API does not create device registrations or app sessions. The native login + AAL2 flow and a server-verified attestation receipt bound to the authenticated Supabase session must be implemented before session issuance is enabled. Do not insert session rows manually for production users or treat the preview APK as trusted.
