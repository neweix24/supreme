# Supreme Android production release

This repository deliberately keeps the production signing key out of source control and out of ChatGPT. The debug APK is installable for UI testing, but its debug certificate is not accepted by the Supreme hardware-attestation policy.

## 1. Create the permanent signing key

Run this locally on a trusted computer or your own Termux environment. Keep the keystore and passwords in a secure offline backup. Do not upload the keystore to chat, commit it, or share it in an issue or pull request.

```sh
keytool -genkeypair -v \
  -keystore supreme-production.jks \
  -storetype JKS \
  -keyalg RSA \
  -keysize 3072 \
  -validity 10000 \
  -alias supreme-release
```

Use a strong unique keystore password and key password. Record the alias exactly as `supreme-release`.

Export the public signing certificate and calculate its SHA-256 digest:

```sh
keytool -exportcert \
  -keystore supreme-production.jks \
  -alias supreme-release \
  -file supreme-production-certificate.der
sha256sum supreme-production-certificate.der
```

The digest is the 64-character hexadecimal SHA-256 value. This is public certificate metadata, not the private signing key.

## 2. Configure GitHub production environment

In `neweix24/supreme`, open **Settings → Environments** and create an environment named `production`. Add required reviewers if production releases should require a human approval.

Add these environment secrets:

- `SUPREME_RELEASE_KEYSTORE_BASE64`: one-line Base64 encoding of `supreme-production.jks`. Generate it locally with `base64 supreme-production.jks | tr -d '\n'`.
- `SUPREME_RELEASE_STORE_PASSWORD`: keystore password.
- `SUPREME_RELEASE_KEY_ALIAS`: `supreme-release`.
- `SUPREME_RELEASE_KEY_PASSWORD`: key password.

Add these environment variables:

- `SUPREME_ANDROID_SIGNING_CERT_SHA256`: the certificate SHA-256 digest from step 1, lowercase, no colons or spaces.
- `SUPREME_ANDROID_MIN_VERSION_CODE`: `3` for the current app version; increase it for every later release.
- `SUPREME_ANDROID_VERSION_NAME`: `1.1.0` for the current app version.

The workflow refuses to build if any signing input is missing or if the keystore certificate does not match the configured fingerprint.

## 3. Configure Supabase Edge Function secrets

In the existing Supabase project, open **Project Settings → Edge Functions → Secrets** and set:

- `SUPREME_ANDROID_SIGNING_CERT_SHA256`: the same lowercase certificate digest.
- `SUPREME_ANDROID_MIN_VERSION_CODE`: the same positive version code configured in GitHub.

The deployed `supreme-session-api` must also have its normal server-only Supabase credentials and database connection available. Never put the service-role key or database password in the Android app or GitHub repository files.

## 4. Enable the Supabase Auth hook

In Supabase Dashboard, open **Authentication → Hooks → Custom Access Token** and select the Postgres function:

`public.supreme_custom_access_token_hook`

Enable it and save. The function preserves ordinary claims for non-Supreme users and adds `supreme_app_session` only for the single active Supreme ruler when a matching AAL2 device session is active. The database grants were verified: `supabase_auth_admin` can execute the hook, while `anon` and `authenticated` cannot.

## 5. Build the production APK

After the environment secrets and Supabase configuration are ready, open **Actions → Supreme Android production release → Run workflow**. The workflow:

1. Restores the keystore from the protected GitHub environment secret.
2. Verifies the keystore's certificate digest against the configured fingerprint.
3. Builds the release variant with that permanent signer.
4. Verifies the APK signature and the embedded signer digest.
5. Uploads `app-release.apk` as a 30-day workflow artifact.

## 6. Physical-device acceptance tests

Install only the production-signed artifact for the final security test. Verify:

- Supreme email/password sign-in and TOTP MFA reach AAL2.
- Hardware-backed Android Key Attestation passes on a supported physical device.
- The server registers exactly one device/session binding for the Supabase Auth session.
- Refreshing the token adds the signed `supreme_app_session` claim.
- Registry API access succeeds only from the registered app/device session.
- Session revocation immediately prevents further privileged access after token refresh.
- A debug-signed APK, unsupported device, AAL1 session, and browser session are denied.

A successful build is not a substitute for these physical-device tests. Keep production access fail-closed until all acceptance tests pass.
