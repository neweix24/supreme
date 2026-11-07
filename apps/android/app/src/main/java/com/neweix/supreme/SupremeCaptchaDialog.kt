package com.neweix.supreme

import android.app.AlertDialog
import android.graphics.Color
import android.net.Uri
import android.view.ViewGroup
import android.webkit.CookieManager
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.fragment.app.FragmentActivity
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebMessageCompat
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature

/**
 * Ephemeral Cloudflare Turnstile challenge for the Neweix Supabase Auth project.
 *
 * Only the public site key is embedded. The provider secret remains in Supabase.
 * The bridge accepts messages only from the neweix.com main-frame origin.
 */
internal object SupremeCaptchaDialog {
    private const val SITE_KEY = "0x4AAAAAAFuD44weVKxUV7g"
    private const val APPROVED_ORIGIN = "https://neweix.com"

    fun show(
        activity: FragmentActivity,
        onToken: (String) -> Unit,
        onError: (String) -> Unit,
    ) {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            onError("Security verification requires an updated Android System WebView.")
            return
        }

        val webView = WebView(activity)
        webView.setBackgroundColor(Color.rgb(18, 18, 18))
        webView.layoutParams = ViewGroup.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        )
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = false
            allowContentAccess = false
            javaScriptCanOpenWindowsAutomatically = false
            setSupportMultipleWindows(false)
            safeBrowsingEnabled = true
            mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW
        }
        CookieManager.getInstance().setAcceptCookie(true)
        CookieManager.getInstance().setAcceptThirdPartyCookies(webView, true)

        lateinit var dialog: AlertDialog
        var completed = false

        dialog = AlertDialog.Builder(activity)
            .setTitle("Security verification")
            .setView(webView)
            .setNegativeButton("Cancel", null)
            .create()

        WebViewCompat.addWebMessageListener(
            webView,
            "SupremeCaptchaBridge",
            setOf(APPROVED_ORIGIN),
        ) { _: WebView,
            message: WebMessageCompat,
            sourceOrigin: Uri,
            isMainFrame: Boolean,
            _: JavaScriptReplyProxy ->
            if (!isMainFrame || sourceOrigin.scheme != "https" || sourceOrigin.host != "neweix.com") {
                return@addWebMessageListener
            }

            val value = message.data ?: return@addWebMessageListener
            webView.post {
                if (completed || activity.isFinishing || activity.isDestroyed) return@post
                when {
                    value == "CAPTCHA_ERROR" -> {
                        completed = true
                        dialog.dismiss()
                        onError("Cloudflare security verification could not load. Please try again.")
                    }
                    value == "CAPTCHA_EXPIRED" -> {
                        completed = true
                        dialog.dismiss()
                        onError("Security verification expired. Please try again.")
                    }
                    value.length in 20..4096 -> {
                        completed = true
                        dialog.dismiss()
                        onToken(value)
                    }
                }
            }
        }

        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(
                view: WebView,
                request: WebResourceRequest,
            ): Boolean {
                val uri = request.url
                if (uri.scheme == "about" &&
                    (uri.toString() == "about:blank" || uri.toString() == "about:srcdoc")
                ) {
                    return false
                }
                return uri.scheme != "https" ||
                    (uri.host != "neweix.com" && uri.host != "challenges.cloudflare.com")
            }
        }

        dialog.setOnDismissListener {
            webView.stopLoading()
            webView.destroy()
            if (!completed && !activity.isFinishing && !activity.isDestroyed) {
                onError("Security verification was cancelled.")
            }
        }

        dialog.show()
        dialog.window?.setLayout(
            (activity.resources.displayMetrics.widthPixels * 0.90f).toInt(),
            (activity.resources.displayMetrics.heightPixels * 0.62f).toInt().coerceAtLeast((320 * activity.resources.displayMetrics.density).toInt()),
        )
        webView.loadDataWithBaseURL(
            "$APPROVED_ORIGIN/",
            HTML,
            "text/html",
            "UTF-8",
            null,
        )
    }

    private val HTML = """
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>Supreme security verification</title>
          <style>
            html, body { margin: 0; padding: 0; background: #121212; color: #e5c578; font: 14px Arial, sans-serif; min-height: 100%; }
            body { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 24px 12px; box-sizing: border-box; }
            #message { color: #c9c9c9; text-align: center; margin-bottom: 20px; }
            #widget { min-height: 70px; display: flex; justify-content: center; }
          </style>
          <script>
            function notify(value) { if (window.SupremeCaptchaBridge) window.SupremeCaptchaBridge.postMessage(value); }
            window.onSupremeTurnstileLoaded = function () {
              try {
                if (!window.turnstile || !document.getElementById("widget")) { notify("CAPTCHA_ERROR"); return; }
                window.turnstile.render("#widget", {
                  sitekey: "$SITE_KEY",
                  theme: "dark",
                  callback: function(token) { notify(token); },
                  "error-callback": function() { notify("CAPTCHA_ERROR"); },
                  "expired-callback": function() { notify("CAPTCHA_EXPIRED"); }
                });
              } catch (_) { notify("CAPTCHA_ERROR"); }
            };
            window.setTimeout(function () { if (!window.turnstile) notify("CAPTCHA_ERROR"); }, 20000);
          </script>
          <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onSupremeTurnstileLoaded&render=explicit" async defer onerror="notify('CAPTCHA_ERROR')"></script>
        </head>
        <body>
          <div id="message">Loading Cloudflare security verification…</div>
          <div id="widget"></div>
        </body>
        </html>
    """.trimIndent()
}
