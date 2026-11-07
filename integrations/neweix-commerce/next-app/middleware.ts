import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

export async function middleware(request: NextRequest) {
  let response = NextResponse.next({ request });

  // Use one canonical hostname so browser auth cookies are never split between www and apex.
  if (request.nextUrl.hostname === "www.neweix.com") {
    const canonicalUrl = request.nextUrl.clone();
    canonicalUrl.hostname = "neweix.com";
    return NextResponse.redirect(canonicalUrl, 308);
  }

  const pathname = request.nextUrl.pathname;
  const configuredSupremePath = process.env.SUPREME_PRIVATE_PATH;
  // The private entry must be one high-entropy path segment. Never accept a
  // public-looking or nested value that could overlap storefront routes.
  const hasValidPrivateSupremePath =
    typeof configuredSupremePath === "string" &&
    /^\/control-[A-Fa-f0-9]{48}$/.test(configuredSupremePath);
  const hasInvalidPrivateSupremePath =
    typeof configuredSupremePath === "string" &&
    configuredSupremePath.length > 0 &&
    !hasValidPrivateSupremePath;
  const hasMissingPrivateSupremePath =
    process.env.NODE_ENV === "production" &&
    !hasValidPrivateSupremePath;
  const isCanonicalSupremePath =
    pathname === "/supreme" || pathname.startsWith("/supreme/");
  const isPrivateSupremePath =
    hasValidPrivateSupremePath &&
    (pathname === configuredSupremePath ||
      pathname.startsWith(configuredSupremePath + "/"));

  // If a configured private path is malformed, fail closed instead of
  // silently exposing the legacy /supreme route.
  if ((hasInvalidPrivateSupremePath || hasMissingPrivateSupremePath) && isCanonicalSupremePath) {
    return new NextResponse("Supreme access is temporarily unavailable.", {
      status: 503,
      headers: { "Cache-Control": "private, no-store, max-age=0", "X-Robots-Tag": "noindex, nofollow" },
    });
  }

  // Once the private path is configured, direct requests to the old public
  // route are not served. The authenticated private alias is rewritten below.
  if (hasValidPrivateSupremePath && isCanonicalSupremePath) {
    const privatePath = configuredSupremePath!;
    // Existing in-workspace links still target the internal /supreme route.
    // Redirect those same-origin navigations back onto the private URL so the
    // browser never leaves the private path. Direct/external requests get 404.
    const referer = request.headers.get("referer");
    let cameFromPrivateEntry = false;
    if (referer) {
      try {
        const refererUrl = new URL(referer);
        cameFromPrivateEntry =
          refererUrl.origin === request.nextUrl.origin &&
          (refererUrl.pathname === privatePath ||
            refererUrl.pathname.startsWith(privatePath + "/"));
      } catch {
        cameFromPrivateEntry = false;
      }
    }
    if (cameFromPrivateEntry) {
      const privateDestination = request.nextUrl.clone();
      privateDestination.pathname =
        privatePath + pathname.slice("/supreme".length);
      const redirectResponse = NextResponse.redirect(privateDestination, 307);
      redirectResponse.headers.set("Cache-Control", "private, no-store, max-age=0");
      redirectResponse.headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
      return redirectResponse;
    }
    return new NextResponse(null, {
      status: 404,
      headers: { "Cache-Control": "private, no-store, max-age=0", "X-Robots-Tag": "noindex, nofollow" },
    });
  }

  const isAdminPath = pathname === "/admin" || pathname.startsWith("/admin/");
  const isSupremePath =
    isCanonicalSupremePath || isPrivateSupremePath;
  if (isPrivateSupremePath) {
    response.headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
    response.headers.set("Cache-Control", "private, no-store, max-age=0");
  }
  const isWorkforcePath =
    pathname === "/staff" || pathname.startsWith("/staff/") ||
    pathname === "/manager" || pathname.startsWith("/manager/") ||
    pathname === "/employee" || pathname.startsWith("/employee/");
  const isApiPath = pathname.startsWith("/api/");
  const isSupremeApiPath = pathname.startsWith("/api/supreme/");
  // These routes establish the device-bound session and therefore cannot
  // require an already-existing device-session claim.
  const isSupremeDeviceBootstrapApi =
    pathname === "/api/supreme/session/issue" ||
    pathname === "/api/supreme/attestation/challenge" ||
    pathname === "/api/supreme/attestation/verify";
  const isCustomerApi =
    (pathname.startsWith("/api/account/") &&
      pathname !== "/api/account/phone/send-otp" &&
      pathname !== "/api/account/phone/status" &&
      pathname !== "/api/account/phone/verify-otp" &&
      pathname !== "/api/account/security/register-device" &&
      pathname !== "/api/account/profile") ||
    pathname === "/api/eixpay" ||
    (pathname.startsWith("/api/eixpay/") && pathname !== "/api/eixpay/referral/apply");
  const isCustomerPage =
    pathname === "/account" || pathname.startsWith("/account/") ||
    pathname === "/orders" || pathname.startsWith("/orders/") ||
    pathname === "/wishlist" || pathname.startsWith("/wishlist/") ||
    pathname === "/eixverse" || pathname.startsWith("/eixverse/");
  const isCustomerProtected = isCustomerPage || isCustomerApi;
  const isCustomerLoginPath = pathname === "/auth/customer-login";
  const isSupremeMfaPath = pathname === "/auth/mfa" || pathname === "/auth/mfa/setup";

  // Refresh a present session before every API handler as well as protected
  // pages. API handlers may create their own server client; passing the
  // refreshed request cookies prevents those handlers from trying to rotate
  // the same stale refresh token again. Public APIs remain publicly accessible.
  // Public storefront pages avoid an auth lookup unless they need route gating.
  if (!isAdminPath && !isSupremePath && !isWorkforcePath && !isCustomerProtected && !isCustomerLoginPath && !isSupremeMfaPath && !isApiPath) {
    return response;
  }

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!url || !anonKey) {
    return new NextResponse("Supabase configuration missing.", { status: 500 });
  }

  const supabase = createServerClient(url, anonKey, {
    cookieOptions: {
      path: "/",
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    },
    cookies: {
      getAll() {
        return request.cookies.getAll();
      },
      setAll(cookiesToSet, cacheHeaders) {
        // Make refreshed cookies visible to downstream Server Components in
        // this request, and persist the same values in the browser response.
        cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
        response = NextResponse.next({ request });
        cookiesToSet.forEach(({ name, value, options }) => {
          response.cookies.set(name, value, options);
        });

        // Supabase SSR >=0.10 supplies the cache headers required whenever
        // refreshed auth cookies are written. Prevent Cloudflare/CDN caching.
        for (const [name, value] of Object.entries(cacheHeaders)) {
          response.headers.set(name, value);
        }
        response.headers.set(
          "Cache-Control",
          "private, no-cache, no-store, must-revalidate, max-age=0",
        );
        response.headers.set("Expires", "0");
        response.headers.set("Pragma", "no-cache");
      },
    },
  });

  // Validate signed claims and allow Supabase SSR to refresh expired sessions.
  const { data: claimsData, error: claimsError } = await supabase.auth.getClaims();
  const userId = claimsData?.claims?.sub;
  // Refreshing auth cookies can replace the response object; reapply the
  // private-route indexing policy after claim validation.
  if (isPrivateSupremePath) {
    response.headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
    response.headers.set("Cache-Control", "private, no-store, max-age=0");
  }

  const hasAuthenticatedSession = typeof userId === "string" && userId.length > 0;
  if (!isApiPath || isCustomerProtected || hasAuthenticatedSession || response.cookies.getAll().length > 0) {
    response.headers.set("Cache-Control", "private, no-cache, no-store, must-revalidate, max-age=0");
  }

  // Preserve Supabase's refreshed auth cookies and cache headers on
  // redirects returned after session validation.
  function copySessionState(target: NextResponse) {
    response.cookies.getAll().forEach((cookie) => target.cookies.set(cookie));
    for (const name of ["Cache-Control", "Expires", "Pragma", "X-Robots-Tag"]) {
      const value = response.headers.get(name);
      if (value) target.headers.set(name, value);
    }
    target.headers.set(
      "Cache-Control",
      "private, no-cache, no-store, must-revalidate, max-age=0",
    );
    target.headers.set("Expires", "0");
    target.headers.set("Pragma", "no-cache");
    return target;
  }

  // A valid customer session should never be shown the customer sign-in form.
  // Replace the login history entry with the storefront so Back cannot reopen
  // a stale login screen after a successful sign-in.
  if (isCustomerLoginPath && !claimsError && typeof userId === "string" && userId) {
    const destination = request.nextUrl.clone();
    destination.pathname = "/";
    destination.search = "";
    const redirectResponse = NextResponse.redirect(destination);
    return copySessionState(redirectResponse);
  }

  // Supreme authentication is native-app-only. Browser MFA routes must never
  // become an alternate entry point, even for an otherwise valid Supreme user.
  if (isSupremeMfaPath) {
    if (claimsError || typeof userId !== "string" || !userId) {
      const destination = request.nextUrl.clone();
      // Preserve the existing workforce MFA entry point. If a Supreme
      // account signs in there, the shared login rejects it before MFA.
      destination.pathname = "/auth/login";
      destination.search = "";
      const redirectResponse = NextResponse.redirect(destination);
      return copySessionState(redirectResponse);
    }
    const { data: isSupremeIdentity, error: mfaProfileError } =
      await supabase.rpc("is_current_supreme_ruler");
    if (mfaProfileError) {
      return copySessionState(new NextResponse("MFA authorization unavailable.", {
        status: 503,
        headers: { "Cache-Control": "private, no-store, max-age=0" },
      }));
    }
    if (isSupremeIdentity === true) {
      return copySessionState(new NextResponse(
        "Supreme authentication is available only in the verified Android app.",
        { status: 503, headers: { "Cache-Control": "private, no-store, max-age=0", "X-Robots-Tag": "noindex, nofollow" } },
      ));
    }
    return response;
  }

  // The remaining public routes do not need authorization checks.
  if (!isAdminPath && !isSupremePath && !isCustomerProtected) {
    return response;
  }

  // Protect every Supreme JSON API centrally. Ordinary Supabase cookies and
  // AAL2 alone are insufficient: the access token must carry the signed,
  // server-issued device-session claim and the session API must confirm that
  // the corresponding device/session row is still active.
  if (isSupremeApiPath && !isSupremeDeviceBootstrapApi) {
    if (claimsError || typeof userId !== "string" || !userId) {
      return copySessionState(NextResponse.json(
        { error: "Supreme authentication required.", code: "AUTHENTICATION_REQUIRED" },
        { status: 401, headers: { "Cache-Control": "private, no-store, max-age=0" } },
      ));
    }
    const claims = claimsData?.claims as Record<string, unknown> | undefined;
    if (claims?.aal !== "aal2") {
      return copySessionState(NextResponse.json(
        { error: "Supreme MFA verification required.", code: "AAL2_REQUIRED" },
        { status: 403, headers: { "Cache-Control": "private, no-store, max-age=0" } },
      ));
    }
    const { data: isSupremeIdentity, error: identityError } =
      await supabase.rpc("is_current_supreme_ruler");
    if (identityError || isSupremeIdentity !== true) {
      return copySessionState(NextResponse.json(
        { error: "Active Supreme identity required.", code: "SUPREME_IDENTITY_REQUIRED" },
        { status: 403, headers: { "Cache-Control": "private, no-store, max-age=0" } },
      ));
    }
    const { data: sessionData, error: sessionError } = await supabase.auth.getSession();
    const accessToken = sessionData.session?.access_token;
    if (sessionError || !accessToken || sessionData.session?.user.id !== userId) {
      return copySessionState(NextResponse.json(
        { error: "Supreme session could not be verified.", code: "SESSION_INVALID" },
        { status: 401, headers: { "Cache-Control": "private, no-store, max-age=0" } },
      ));
    }
    try {
      const deviceCheck = await fetch(url.replace(/\\/$/, "") + "/functions/v1/supreme-session-api", {
        method: "GET",
        headers: { apikey: anonKey, Authorization: "Bearer " + accessToken },
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(8_000),
      });
      const deviceResult: unknown = await deviceCheck.json();
      const valid = deviceCheck.ok && !!deviceResult && typeof deviceResult === "object" &&
        !Array.isArray(deviceResult) &&
        (deviceResult as Record<string, unknown>).authenticated === true &&
        (deviceResult as Record<string, unknown>).device_session_active === true;
      if (!valid) {
        return copySessionState(NextResponse.json(
          { error: "Verified Supreme device session required.", code: "DEVICE_SESSION_REQUIRED" },
          { status: 403, headers: { "Cache-Control": "private, no-store, max-age=0" } },
        ));
      }
    } catch {
      return copySessionState(NextResponse.json(
        { error: "Supreme device verification is temporarily unavailable.", code: "DEVICE_VERIFICATION_UNAVAILABLE" },
        { status: 503, headers: { "Cache-Control": "private, no-store, max-age=0" } },
      ));
    }
  }

  // Require verified customer phone numbers before protected account features are accessible.
  if (isCustomerProtected) {
    if (claimsError || typeof userId !== "string" || !userId) {
      if (isCustomerApi) {
        return copySessionState(NextResponse.json(
          { error: "Authentication required.", code: "AUTHENTICATION_REQUIRED" },
          { status: 401, headers: { "Cache-Control": "private, no-store, max-age=0" } }
        ));
      }

      const destination = request.nextUrl.clone();
      destination.pathname = "/auth/customer-login";
      destination.search = "";
      destination.searchParams.set("next", pathname + request.nextUrl.search);
      const redirectResponse = NextResponse.redirect(destination);
      return copySessionState(redirectResponse);
    }

    const { data: customerProfile, error: customerProfileError } = await supabase
      .from("customer_profiles")
      .select("phone, phone_verified_at")
      .eq("user_id", userId)
      .maybeSingle();

    if (customerProfileError || !customerProfile?.phone_verified_at || !customerProfile.phone) {
      // The account root is the phone-verification screen; keep it reachable
      // for authenticated customers who have not completed OTP verification.
      if (pathname === "/account") return response;
      if (isCustomerApi) {
        return NextResponse.json(
          { error: "ফোন নম্বর OTP দিয়ে যাচাই করার পর এই সুবিধা ব্যবহার করতে পারবেন।", code: "PHONE_VERIFICATION_REQUIRED" },
          { status: 403, headers: { "Cache-Control": "private, no-store" } }
        );
      }
      const destination = request.nextUrl.clone();
      destination.pathname = "/account";
      destination.search = "";
      destination.searchParams.set("verifyPhone", "1");
      const redirectResponse = NextResponse.redirect(destination);
      return copySessionState(redirectResponse);
    }
  }

  // Public pages and guest checkout never require a customer or staff login.
  if (!isAdminPath && !isSupremePath) return response;

  function redirectWithCookies(path: string) {
    const destination = request.nextUrl.clone();
    destination.pathname = path;
    destination.search = "";
    if (isPrivateSupremePath && (path === "/auth/mfa" || path === "/auth/mfa/setup")) {
      destination.searchParams.set("next", request.nextUrl.pathname + request.nextUrl.search);
    }
    const redirectResponse = NextResponse.redirect(destination);
    return copySessionState(redirectResponse);
  }

  if (claimsError || typeof userId !== "string" || !userId) {
    const destination = request.nextUrl.clone();
    destination.pathname = isPrivateSupremePath ? "/auth/supreme-login" : "/auth/login";
    destination.search = "";
    destination.searchParams.set("next", request.nextUrl.pathname + request.nextUrl.search);
    const redirectResponse = NextResponse.redirect(destination);
    return copySessionState(redirectResponse);
  }

  const { data: isSupremeIdentity, error: profileError } =
    await supabase.rpc("is_current_supreme_ruler");

  if (profileError || isSupremeIdentity !== true) {
    return redirectWithCookies("/unauthorized");
  }

  // The Supreme identity is not a general workforce/admin login. Even an
  // existing Supreme session must never enter the browser-based /admin area.
  if (isAdminPath && isSupremeIdentity === true) {
    return redirectWithCookies("/unauthorized");
  }

  if (isSupremePath) {
    if (isSupremeIdentity !== true) return redirectWithCookies("/unauthorized");

    // Supreme control access is native-app-only. The Android app completes
    // hardware attestation and server-side device-session verification.
    return copySessionState(new NextResponse(
      "Supreme browser access is disabled. Use the verified Supreme Android app.",
      { status: 503, headers: { "Cache-Control": "private, no-store, max-age=0", "X-Robots-Tag": "noindex, nofollow" } },
    ));
  }

  if (isPrivateSupremePath && hasValidPrivateSupremePath) {
    const privatePath = configuredSupremePath!;
    const destination = request.nextUrl.clone();
    destination.pathname =
      "/supreme" + pathname.slice(privatePath.length);
    const rewriteResponse = NextResponse.rewrite(destination);
    rewriteResponse.headers.set("Cache-Control", "private, no-store, max-age=0");
    rewriteResponse.headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
    response.cookies.getAll().forEach((cookie) => rewriteResponse.cookies.set(cookie));
    return rewriteResponse;
  }

  return response;
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
  ],
};
