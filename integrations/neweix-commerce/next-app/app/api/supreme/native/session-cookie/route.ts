import { createServerClient } from "@supabase/ssr";
import { NextResponse } from "next/server";
import { getCloudflareContext } from "@opennextjs/cloudflare";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const NO_STORE = {
  "Cache-Control": "private, no-store, max-age=0",
  Pragma: "no-cache",
  "X-Content-Type-Options": "nosniff",
};
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function fail(message: string, status: number) {
  return NextResponse.json({ error: message }, { status, headers: NO_STORE });
}

export async function POST(request: Request) {
  const authorization = request.headers.get("authorization") ?? "";
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(authorization);
  if (!match) return fail("Supreme sign-in is required.", 401);

  let body: unknown;
  try {
    const length = Number(request.headers.get("content-length") ?? "0");
    if (!Number.isFinite(length) || length > 8_192) return fail("Request is too large.", 413);
    body = await request.json();
  } catch {
    return fail("Invalid session request.", 400);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) return fail("Invalid session request.", 400);
  const tokens = body as Record<string, unknown>;
  if (typeof tokens.access_token !== "string" || tokens.access_token !== match[1] ||
      typeof tokens.refresh_token !== "string" || tokens.refresh_token.length < 20 ||
      tokens.refresh_token.length > 2_048) {
    return fail("Session token pair is invalid.", 400);
  }

  try {
    const { env } = await getCloudflareContext();
    const runtimeEnv = env as Record<string, unknown>;
    const url = runtimeEnv.NEXT_PUBLIC_SUPABASE_URL ?? process.env.NEXT_PUBLIC_SUPABASE_URL;
    const anonKey = runtimeEnv.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
    if (typeof url !== "string" || !url.startsWith("https://") ||
        typeof anonKey !== "string" || !anonKey) return fail("Supreme session service is not configured.", 503);

    const authResponse = await fetch(url.replace(/\/$/, "") + "/auth/v1/user", {
      headers: { apikey: anonKey, authorization: "Bearer " + match[1] },
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(8_000),
    });
    if (!authResponse.ok) return fail("Supreme session is not valid.", 401);
    const user: unknown = await authResponse.json();
    if (!user || typeof user !== "object" || Array.isArray(user) ||
        !UUID.test(String((user as Record<string, unknown>).id))) return fail("Supreme session is invalid.", 401);

    const part = match[1].split(".")[1];
    if (!part) return fail("Supreme session is invalid.", 401);
    const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
    const claims = JSON.parse(atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="))) as Record<string, unknown>;
    if (claims.sub !== (user as Record<string, unknown>).id || claims.aal !== "aal2" ||
        !UUID.test(String(claims.session_id))) return fail("Verified Supreme MFA is required.", 403);

    const statusResponse = await fetch(url.replace(/\/$/, "") + "/functions/v1/supreme-session-api", {
      headers: { apikey: anonKey, authorization: "Bearer " + match[1] },
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(8_000),
    });
    if (!statusResponse.ok) return fail("Active Supreme device authorization is required.", 403);
    const status: unknown = await statusResponse.json();
    if (!status || typeof status !== "object" ||
        (status as Record<string, unknown>).device_session_active !== true) {
      return fail("Active Supreme device authorization is required.", 403);
    }

    const response = NextResponse.json({ session_established: true }, { headers: NO_STORE });
    const supabase = createServerClient(url, anonKey, {
      cookieOptions: {
        path: "/",
        domain: process.env.NODE_ENV === "production" ? ".neweix.com" : undefined,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        httpOnly: true,
        maxAge: 60 * 60 * 12,
      },
      cookies: {
        getAll() { return []; },
        setAll(values, cacheHeaders) {
          values.forEach(({ name, value, options }) => response.cookies.set(name, value, options));
          for (const [name, value] of Object.entries(cacheHeaders)) response.headers.set(name, value);
          response.headers.set("Cache-Control", "private, no-store, max-age=0");
        },
      },
    });
    const { data, error } = await supabase.auth.setSession({
      access_token: match[1],
      refresh_token: tokens.refresh_token,
    });
    if (error || data.session?.user.id !== (user as Record<string, unknown>).id ||
        data.session?.user.id !== claims.sub) {
      return fail("Supreme web session could not be established.", 401);
    }
    return response;
  } catch (error) {
    console.error("Supreme native web session error", String(error));
    return fail("Supreme web session is temporarily unavailable.", 503);
  }
}
