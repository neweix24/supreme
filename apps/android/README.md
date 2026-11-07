# Supreme Android app

The Supreme Android app is the only supported sign-in client. Supreme has one separate principal (`public_id = supreme`) in the existing shared Supabase Auth project. Supreme authorization is stored only in `supreme.identities`; it does not require a Neweix Account customer record. Future Neweix Employees remain a separate identity/workforce domain. The WebView/private-route shell has been replaced on the native app branch. The native UI builds, but production sign-in remains fail-closed until the server-side device-session issuer and Supabase Auth hook are deployed and tested.

## Build requirements

- Android Studio with JDK 17 and Android SDK Platform 35, or Gradle 8.9+ with the Android SDK installed. Open this directory in Android Studio if Gradle is not installed on your device.
- The native app must use the existing shared Supabase project and the Supreme-specific authentication/API contract. It must not use Neweix Account customer login. A private URL/path is not an authentication factor and must not be used to grant access.
- Never commit private route secrets, production signing keys, passwords, or production credentials.

The native app must not require or embed a secret web path. Browser login and browser dashboard access must be denied server-side.

## Build a local debug APK

From this directory, run:

```sh
gradle :app:assembleDebug
```

The APK is written to `app/build/outputs/apk/debug/app-debug.apk`.

The project no longer requires a private route path at build time.

## Security notes

- Supreme authentication is native; no WebView or hidden/private URL is used as an authentication factor.
- Supabase service-role credentials and provider secrets are never embedded in the app.
- Android local biometric/PIN unlock does not replace server password, AAL2 MFA, or hardware-backed attestation.
- The website must continue enforcing Supreme role authorization and AAL2 MFA on every protected page and API.
- The production login flow must not rely on Google/Facebook OAuth. Verify the native username/password and TOTP MFA flow on a physical device before release.
- Do not distribute this debug APK as a production release.

This project does not modify storefront routes or customer-facing navigation.

## Hardware-backed attestation client foundation

The Android app includes a native Android Keystore helper at `app/src/main/java/com/neweix/supreme/security/SupremeKeyAttestation.kt`. It creates a fresh P-256 signing key for a server-provided, one-time challenge and returns the certificate chain in leaf-to-root DER/Base64 form.

The native sign-in flow now requests a one-time challenge, creates a hardware-backed key, and posts the certificate chain and proof-of-possession to the existing challenge/verification proxy. The server verifies Google's trust roots and revocation feed, package/signer identity, key security level, verified boot, challenge, and proof. This response is still only an attestation decision: it does not create a Supabase session or bind a device to a Supabase `session_id`. That server-side binding must be completed before registry access can be enabled.

Devices that cannot produce a qualifying attestation chain must not be silently downgraded to an unverified Supreme login once enforcement is enabled.


## App-only Supreme authentication and temporary access lock

- Supreme login is implemented as a native Android screen with Supreme-specific Supabase Auth password sign-in, verified TOTP MFA, fresh AAL2 checks, and server-verified Android app attestation.
- Browser-based Supreme sign-in and dashboard access must be denied server-side.
- Supreme authorization must consult the single active `supreme.identities` principal with `role = ruler` and `public_id = supreme`; it must not require `neweix_accounts`.
- The registry API requires a server-signed `supreme_app_session` claim for an active device-bound attested session. The native flow submits the hardware-attestation proof to the server-side issuer, which verifies the production package signer, records the device, and binds the row to the exact AAL2 Supabase Auth session. The app refreshes the token and verifies the signed claim and live session record before loading registry data.
- **The native debug app is not a production login release.** Keep privileged operations fail-closed until the Auth Hook, persistent device/session binding, production APK signer allowlist, and real-device/browser-denial tests pass.
- The diamond emblem is the temporary app mark and can be replaced later without changing the application ID.

## Remote-first Supreme dashboard (permanent architecture requirement)

The Supreme Android app is a thin, stable native shell. Native app authentication is mandatory; after a verified app-bound session is established, dashboard experiences may be served remotely from the approved Cloudflare origin. Browser sessions must never receive Supreme access.

### Changes that must not require an APK update

- Dashboard pages, layouts, navigation menus, cards, tables, forms, labels, icons delivered by the web app, and visual design.
- New or changed administrative workflows that can be implemented with the existing web platform and supported browser capabilities.
- Server-side business rules, feature availability, role/permission policy, dashboard configuration, and API-backed data.
- Remote feature flags and staged rollouts, provided authorization is enforced by the server for every protected operation.

After a Cloudflare deployment, the next app navigation/reload must load the current deployed Supreme web experience. The app should not bundle a second copy of dashboard pages or freeze feature definitions in native resources. Avoid long-lived WebView caches or service-worker caches that prevent deployed dashboard changes from appearing; provide a reliable refresh/revalidation strategy.

### Changes that may require an APK update

Only changes that genuinely need native Android capabilities or a change to the native shell may require a new APK—for example, Android Keystore/attestation implementation, native device permissions, WebView security/navigation policy, native push notifications, or a required Android SDK/target update.

### Security and compatibility rules

- Remote delivery does not bypass authentication: the server must enforce the Supreme role, AAL2 MFA, device authorization/attestation, and authorization on every API/action.
- Never implement security-critical permissions solely as hidden/disabled UI controls or client-side feature flags.
- Keep stable, versioned API contracts and backward-compatible server changes where possible, so a web deployment remains compatible with the installed shell.
- If a remote feature needs a new native bridge capability, the web app must detect shell capability/version and fail safely or show a clear minimum-app-version notice; do not silently assume the bridge exists.
- The native app must remain pinned to the approved Supreme API/dashboard origin and approved routes. Remote-first does not mean arbitrary remote URL or script execution.
- Cloudflare deployment updates the web-delivered experience; it does not automatically update the native APK binary.

**Acceptance criterion:** a dashboard-only feature or design change is implemented and deployed on Cloudflare and becomes available in the already-installed Supreme app after reload/reopen, with no APK rebuild or reinstall.

## Native implementation status

- Dedicated Supreme Account email/password sign-in; no Neweix Account, Google, or Facebook login.
- Verified TOTP MFA, AAL2 and recent `auth_time` checks.
- Android hardware-backed attestation challenge and proof client.
- Android Keystore AES-256-GCM encrypted refresh-token storage.
- Biometric/device credential app lock and screenshot protection.
- Registry listing is deliberately blocked until the server returns a valid signed app-session claim bound to the same Supabase session.
- GitHub Actions debug build and internal preview artifact pass; debug signing cannot satisfy the production attestation allowlist.

## Production release gates

1. Apply `20261107200000_supreme_device_bound_auth_sessions.sql` and `20261107210000_supreme_attested_session_issuer.sql` after the Supreme identity and registry migrations.
2. Deploy `supreme-session-api` with the Supabase project URL, public API key, and server-only database connection string.
3. Deploy the Cloudflare `/api/supreme/session/issue` route with service-role credentials and the production signing-certificate digest.
4. Enable `public.supreme_custom_access_token_hook` under Supabase Authentication → Hooks → Custom Access Token.
5. Configure the attestation verifier's production signer digest and minimum package version; build and sign the APK with that same permanent key.
6. Deploy and verify the complete flow on a physical production-signed Android device, including session refresh, device revocation, and browser-denial cases.
## Production signing identity — not configured yet

The production signer certificate digest is a security input to Android Key Attestation's
application-identity check. It must come from the actual APK signed with the permanent
production key; it must never be copied from a debug APK or guessed from the package name.

After the production APK is signed, run this helper from the repository root:

```sh
bash scripts/security/print-android-signing-cert.sh path/to/supreme-production.apk
```

It verifies the APK signature with Android SDK `apksigner` and prints the signer
certificate SHA-256 digest in lowercase hexadecimal without separators. Compare it
against the independently recorded certificate fingerprint for the permanent signing
key before configuring the server allowlist.

The repository intentionally does not contain a production keystore, signing password,
or release-signing workflow secrets. Do not create or upload a signing key to GitHub,
commit a keystore, or use the CI debug signer as the production identity. The app
package ID is `com.neweix.supreme`; the package ID alone is not a trusted signer identity.
