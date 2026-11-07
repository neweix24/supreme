# Supreme dashboard source dependency map

The dashboard/API code below is retained as a NEWEIX integration snapshot, not a standalone Supreme app.

## Direct shared imports identified

| Import used by Supreme source | Preserved snapshot path | Notes |
|---|---|---|
| `@/lib/auth` | `integrations/neweix-commerce/next-app/lib/auth.ts` | Legacy snapshot uses NEWEIX `staff_profiles`; this dependency must be removed before the dashboard/API snapshot is activated in the standalone Supreme runtime. |
| `@/lib/permissions` | `integrations/neweix-commerce/next-app/lib/permissions.ts` | Existing role and permission contract; review against the single Supreme ruler identity. |
| `@/lib/supabase/server` | `integrations/neweix-commerce/next-app/lib/supabase/server.ts` | Uses NEWEIX Supabase environment variables and `.neweix.com` cookie domain. |
| `@/lib/phone-verification` | `integrations/neweix-commerce/next-app/lib/phone-verification.ts` | Used by the Supreme NEWEIX+ API; depends on Supabase JS and OpenNext Cloudflare bindings. |
| `@/components/ui/icon` | `integrations/neweix-commerce/next-app/components/ui/icon.tsx` | Shared UI icon component used by Supreme dashboard features. |
| Next middleware | `integrations/neweix-commerce/next-app/middleware.ts` | Preserves the old private Supreme route gate and Supabase SSR refresh behavior, but also contains NEWEIX storefront/admin/workforce routing. |

## Direct dependencies that remain external

- Next.js App Router and `next/server` / `next/headers`.
- React.
- `@supabase/ssr` and `@supabase/supabase-js`.
- `@opennextjs/cloudflare` for the phone-verification helper.

These files are retained so the original implementation and its security decisions are not lost. They are not approved to run as Supreme Core without refactoring.

## Refactor requirements

1. Replace `staff_profiles` and the multi-role NEWEIX staff model with Supreme's single `supreme` identity and explicit service-scoped permissions.
2. Replace NEWEIX Supabase environment names and `.neweix.com` cookie-domain assumptions with a Supreme-owned auth/session contract.
3. Extract only Supreme route checks from the mixed NEWEIX middleware into Supreme-owned middleware; do not copy storefront/admin/workforce routing into the new Core.
4. Move phone verification to a deliberate Supreme identity verification flow or remove it if it is not required.
5. Replace UI dependencies with a Supreme-owned design system after the source snapshot is functionally mapped.
6. Add isolated tests for login, MFA, session refresh, route privacy, role denial, and service-to-service API authorization.

## Verification status

The import scan covered 30 Supreme API/login/dashboard route files and 11 Supreme feature files. It identified the shared imports above. This is a static source dependency inventory, not a successful Next.js build or proof that all transitive runtime dependencies are resolved.
