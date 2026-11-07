package com.neweix.supreme

import android.graphics.Color
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.neweix.supreme.auth.SupremeAuthClient
import com.neweix.supreme.auth.SupremeAuthException
import com.neweix.supreme.auth.SupremeSessionStore
import com.neweix.supreme.security.SupremeAttestationClient
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class MainActivity : FragmentActivity() {
    private val background: ExecutorService = Executors.newSingleThreadExecutor()
    private lateinit var sessionStore: SupremeSessionStore
    private lateinit var screen: LinearLayout
    private lateinit var statusText: TextView
    private lateinit var emailInput: EditText
    private lateinit var passwordInput: EditText
    private lateinit var codeInput: EditText
    private lateinit var primaryButton: Button
    private lateinit var lockOverlay: LinearLayout
    private var biometricPrompt: BiometricPrompt? = null
    private var authInProgress = false
    private var isUnlocked = false
    private var isBusy = false
    private var resumeSessionCheck = false
    private var pendingFactorId: String? = null
    private var pendingChallengeId: String? = null
    private var pendingPasswordSession: SupremeAuthClient.AuthSession? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.statusBarColor = Color.rgb(7, 7, 7)
        window.navigationBarColor = Color.rgb(7, 7, 7)
        sessionStore = SupremeSessionStore(this)
        buildInterface()
        configureAppLock()
        authenticateToUnlock()
    }

    private fun buildInterface() {
        val root = FrameLayout(this).apply {
            setBackgroundColor(Color.rgb(7, 7, 7))
        }

        val scroll = ScrollView(this)
        screen = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(26), dp(50), dp(26), dp(36))
        }

        val brand = TextView(this).apply {
            text = "SUPREME"
            textSize = 30f
            letterSpacing = 0.24f
            setTextColor(Color.rgb(229, 197, 120))
            gravity = Gravity.CENTER
        }
        screen.addView(brand, matchWrap())

        val subtitle = TextView(this).apply {
            text = "PRIVATE CONTROL PLATFORM"
            textSize = 10f
            letterSpacing = 0.25f
            setTextColor(Color.rgb(151, 133, 96))
            gravity = Gravity.CENTER
            setPadding(0, dp(8), 0, dp(30))
        }
        screen.addView(subtitle, matchWrap())

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(24), dp(20), dp(24))
            setBackgroundColor(Color.rgb(20, 20, 20))
        }
        screen.addView(card, matchWrap())

        card.addView(TextView(this).apply {
            text = "Supreme Account"
            textSize = 21f
            setTextColor(Color.WHITE)
        }, matchWrap())

        card.addView(TextView(this).apply {
            text = "Sign in with the single, dedicated Supreme identity. No Neweix Account or social login is used."
            textSize = 13f
            setTextColor(Color.rgb(170, 170, 170))
            setPadding(0, dp(8), 0, dp(22))
        }, matchWrap())

        card.addView(label("Supreme account email"))
        emailInput = input("Email address", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS)
        card.addView(emailInput, fieldParams())

        card.addView(label("Password"))
        passwordInput = input("Password", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD)
        card.addView(passwordInput, fieldParams())

        card.addView(label("Authenticator code").apply { visibility = View.GONE })
        codeInput = input("6-digit TOTP code", InputType.TYPE_CLASS_NUMBER)
        codeInput.visibility = View.GONE
        card.addView(codeInput, fieldParams())

        primaryButton = Button(this).apply {
            text = "SIGN IN"
            setTextColor(Color.rgb(18, 16, 10))
            setBackgroundColor(Color.rgb(212, 175, 55))
            setOnClickListener {
                if (pendingFactorId == null) beginPasswordSignIn() else verifyMfaCode()
            }
        }
        val buttonParams = matchWrap()
        buttonParams.topMargin = dp(18)
        card.addView(primaryButton, buttonParams)

        statusText = TextView(this).apply {
            text = "Password and TOTP MFA are required. Device attestation is checked separately."
            textSize = 12f
            setTextColor(Color.rgb(174, 159, 124))
            setPadding(0, dp(20), 0, dp(4))
            gravity = Gravity.CENTER
        }
        screen.addView(statusText, matchWrap())

        screen.addView(TextView(this).apply {
            text = "ACCESS IS VERIFIED SERVER-SIDE · UNAUTHORIZED DEVICES ARE DENIED"
            textSize = 9f
            letterSpacing = 0.06f
            gravity = Gravity.CENTER
            setTextColor(Color.rgb(100, 100, 100))
            setPadding(0, dp(34), 0, 0)
        }, matchWrap())

        scroll.addView(screen)
        root.addView(scroll, FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.MATCH_PARENT,
        ))

        lockOverlay = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(30), dp(30), dp(30), dp(30))
            setBackgroundColor(Color.rgb(7, 7, 7))
            addView(TextView(this@MainActivity).apply {
                text = "SUPREME"
                textSize = 28f
                letterSpacing = 0.2f
                gravity = Gravity.CENTER
                setTextColor(Color.rgb(229, 197, 120))
            }, matchWrap())
            addView(TextView(this@MainActivity).apply {
                text = "Unlock this device to continue"
                textSize = 14f
                gravity = Gravity.CENTER
                setTextColor(Color.LTGRAY)
                setPadding(0, dp(12), 0, dp(20))
            }, matchWrap())
            addView(Button(this@MainActivity).apply {
                text = "UNLOCK SUPREME"
                setOnClickListener { authenticateToUnlock() }
            }, matchWrap())
        }
        root.addView(lockOverlay, FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.MATCH_PARENT,
        ))
        lockOverlay.visibility = View.VISIBLE
        setContentView(root)
    }

    private fun beginPasswordSignIn() {
        val email = emailInput.text.toString().trim()
        val password = passwordInput.text.toString()
        if (isBusy) return
        setBusy(true, "Authenticating Supreme Account…")
        background.execute {
            try {
                val session = SupremeAuthClient.signIn(email, password)
                val factors = SupremeAuthClient.verifiedTotpFactors(session.accessToken)
                if (factors.isEmpty()) {
                    runOnUiThread {
                        passwordInput.text.clear()
                        setBusy(false, "TOTP MFA is not enrolled on the Supreme Account. Access remains locked.")
                    }
                    return@execute
                }
                val factor = factors.first()
                val challenge = SupremeAuthClient.createTotpChallenge(session.accessToken, factor.id)
                runOnUiThread {
                    pendingPasswordSession = session
                    pendingFactorId = factor.id
                    pendingChallengeId = challenge
                    passwordInput.text.clear()
                    emailInput.isEnabled = false
                    passwordInput.visibility = View.GONE
                    codeInput.visibility = View.VISIBLE
                    primaryButton.text = "VERIFY MFA"
                    statusText.text = "Enter the current code from your authenticator app."
                    setBusy(false, null)
                    codeInput.requestFocus()
                }
            } catch (error: Exception) {
                runOnUiThread {
                    passwordInput.text.clear()
                    setBusy(false, safeMessage(error))
                }
            }
        }
    }

    private fun verifyMfaCode() {
        val initial = pendingPasswordSession ?: return
        val factorId = pendingFactorId ?: return
        val challengeId = pendingChallengeId ?: return
        val code = codeInput.text.toString().trim()
        if (isBusy) return

        setBusy(true, "Verifying multi-factor authentication…")
        background.execute {
            try {
                val session = SupremeAuthClient.verifyTotp(
                    initial.accessToken,
                    factorId,
                    challengeId,
                    code,
                )
                if (session.userId != initial.userId || session.assuranceLevel != "aal2") {
                    throw IllegalStateException("Supreme AAL2 verification was not confirmed.")
                }
                val now = System.currentTimeMillis() / 1000L
                if (now - session.authTime > 300L || session.authTime > now + 30L) {
                    throw IllegalStateException("Supreme MFA verification is no longer fresh. Sign in again.")
                }

                val device = SupremeAttestationClient.verifyDevice()
                if (!device.proofOfPossessionVerified ||
                    (device.securityLevel != "TRUSTED_ENVIRONMENT" && device.securityLevel != "STRONG_BOX")
                ) {
                    throw IllegalStateException("This device did not pass Supreme hardware security verification.")
                }

                // The registry API is the server-side authority for whether
                // this attested device is bound to the current AAL2 Auth session.
                val services = SupremeAuthClient.listServices(session.accessToken)
                sessionStore.saveRefreshToken(session.refreshToken)

                runOnUiThread {
                    pendingPasswordSession = null
                    pendingFactorId = null
                    pendingChallengeId = null
                    codeInput.text.clear()
                    renderDashboard(services)
                    setBusy(false, "Supreme device and session checks passed.")
                }
            } catch (error: Exception) {
                runOnUiThread {
                    sessionStore.clear()
                    pendingPasswordSession = null
                    pendingFactorId = null
                    pendingChallengeId = null
                    codeInput.text.clear()
                    passwordInput.visibility = View.VISIBLE
                    emailInput.isEnabled = true
                    codeInput.visibility = View.GONE
                    primaryButton.text = "SIGN IN"
                    setBusy(false, safeMessage(error))
                }
            }
        }
    }

    private fun renderDashboard(services: List<SupremeAuthClient.Service>) {
        screen.removeAllViews()
        screen.addView(TextView(this).apply {
            text = "SUPREME"
            textSize = 28f
            letterSpacing = 0.24f
            setTextColor(Color.rgb(229, 197, 120))
            gravity = Gravity.CENTER
        }, matchWrap())
        screen.addView(TextView(this).apply {
            text = "CONTROL CENTRE"
            textSize = 11f
            letterSpacing = 0.2f
            setTextColor(Color.rgb(170, 150, 108))
            gravity = Gravity.CENTER
            setPadding(0, dp(8), 0, dp(24))
        }, matchWrap())
        statusText = TextView(this).apply {
            text = "Supreme session is active."
            textSize = 12f
            setTextColor(Color.rgb(174, 159, 124))
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, dp(18))
        }
        screen.addView(statusText, matchWrap())
        screen.addView(TextView(this).apply {
            text = "REGISTERED SERVICES"
            textSize = 12f
            setTextColor(Color.LTGRAY)
        }, matchWrap())

        for (service in services) {
            val item = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(16), dp(14), dp(16), dp(14))
                setBackgroundColor(Color.rgb(24, 24, 24))
            }
            item.addView(TextView(this@MainActivity).apply {
                text = service.name
                textSize = 16f
                setTextColor(Color.WHITE)
            }, matchWrap())
            item.addView(TextView(this@MainActivity).apply {
                text = service.id + " · " + service.status.uppercase()
                textSize = 11f
                setTextColor(Color.rgb(210, 180, 110))
                setPadding(0, dp(6), 0, 0)
            }, matchWrap())
            if (service.description.isNotBlank()) {
                item.addView(TextView(this@MainActivity).apply {
                    text = service.description
                    textSize = 12f
                    setTextColor(Color.LTGRAY)
                    setPadding(0, dp(6), 0, 0)
                }, matchWrap())
            }
            val params = matchWrap()
            params.topMargin = dp(10)
            screen.addView(item, params)
        }

        val signOut = Button(this).apply {
            text = "SIGN OUT"
            setOnClickListener { signOut() }
        }
        primaryButton = signOut
        val params = matchWrap()
        params.topMargin = dp(24)
        screen.addView(signOut, params)
    }

    private fun resumeStoredSession() {
        if (resumeSessionCheck || pendingFactorId != null) return
        val refreshToken = sessionStore.readRefreshToken() ?: return
        resumeSessionCheck = true
        setBusy(true, "Restoring the encrypted Supreme session…")
        background.execute {
            try {
                val session = SupremeAuthClient.refresh(refreshToken)
                if (session.assuranceLevel != "aal2") {
                    throw IllegalStateException("Supreme session has fallen below AAL2. Sign in again.")
                }
                val services = SupremeAuthClient.listServices(session.accessToken)
                sessionStore.saveRefreshToken(session.refreshToken)
                runOnUiThread {
                    resumeSessionCheck = false
                    renderDashboard(services)
                    setBusy(false, "Supreme session restored.")
                }
            } catch (error: Exception) {
                val status = (error as? SupremeAuthException)?.statusCode
                if (status == 401 || status == 403) sessionStore.clear()
                runOnUiThread {
                    resumeSessionCheck = false
                    showSignIn()
                    setBusy(false, if (status == 401 || status == 403) {
                        "The previous Supreme app session is no longer authorized. Sign in again."
                    } else {
                        safeMessage(error)
                    })
                }
            }
        }
    }

    private fun signOut() {
        val refresh = sessionStore.readRefreshToken()
        sessionStore.clear()
        if (refresh == null) {
            showSignIn()
            return
        }
        setBusy(true, "Signing out…")
        background.execute {
            try {
                val session = SupremeAuthClient.refresh(refresh)
                SupremeAuthClient.signOut(session.accessToken)
            } catch (_: Exception) {
                // Local credential deletion remains mandatory if the server is offline.
            }
            runOnUiThread {
                showSignIn()
                setBusy(false, "Signed out.")
            }
        }
    }

    private fun showSignIn() {
        buildInterface()
        lockOverlay.visibility = View.GONE
        isUnlocked = true
    }

    private fun configureAppLock() {
        biometricPrompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    authInProgress = false
                    isUnlocked = true
                    lockOverlay.visibility = View.GONE
                    resumeStoredSession()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    authInProgress = false
                    isUnlocked = false
                    lockOverlay.visibility = View.VISIBLE
                    statusText.text = "Device unlock failed. Supreme content remains hidden."
                }

                override fun onAuthenticationFailed() {
                    // Leave the system prompt active; no content is revealed.
                }
            },
        )
    }

    private fun authenticateToUnlock() {
        if (isUnlocked || authInProgress) return
        val prompt = biometricPrompt ?: return
        authInProgress = true
        lockOverlay.visibility = View.VISIBLE
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock Supreme")
            .setSubtitle("Use fingerprint or the device screen-lock PIN")
            .setDescription("This only unlocks the app on this device. Server authentication is still required.")
            .setDeviceCredentialAllowed(true)
            .build()
        try {
            prompt.authenticate(info)
        } catch (_: Exception) {
            authInProgress = false
            lockOverlay.visibility = View.VISIBLE
            statusText.text = "Set up a secure screen lock on this device before opening Supreme."
        }
    }

    private fun setBusy(busy: Boolean, message: String?) {
        isBusy = busy
        primaryButton.isEnabled = !busy
        primaryButton.alpha = if (busy) 0.6f else 1f
        if (!message.isNullOrBlank()) statusText.text = message
    }

    private fun safeMessage(error: Exception): String {
        return when (error) {
            is SupremeAuthException -> when (error.statusCode) {
                400, 401 -> "Supreme sign-in could not be verified. Check the credentials and authenticator code."
                403 -> "Supreme access is denied. The account or verified device is not authorized."
                429 -> "Too many attempts. Wait before trying again."
                503 -> "Supreme security verification is not configured yet. Access remains locked."
                else -> "Supreme service error (HTTP " + error.statusCode + ")."
            }
            else -> error.message?.take(180) ?: "Supreme authentication failed. Access remains locked."
        }
    }

    private fun label(value: String): TextView = TextView(this).apply {
        text = value
        textSize = 12f
        setTextColor(Color.rgb(205, 190, 158))
        setPadding(0, dp(10), 0, dp(6))
    }

    private fun input(hintText: String, type: Int) = EditText(this).apply {
        hint = hintText
        inputType = type
        textSize = 14f
        isSingleLine = true
        setTextColor(Color.WHITE)
        setHintTextColor(Color.rgb(120, 120, 120))
        setPadding(dp(12), dp(12), dp(12), dp(12))
        setBackgroundColor(Color.rgb(9, 9, 9))
    }

    private fun fieldParams(): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            dp(50),
        ).apply { bottomMargin = dp(6) }

    private fun matchWrap(): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        )

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) {
            isUnlocked = false
            lockOverlay.visibility = View.VISIBLE
        }
    }

    override fun onResume() {
        super.onResume()
        if (!isUnlocked && biometricPrompt != null) authenticateToUnlock()
    }

    override fun onDestroy() {
        background.shutdownNow()
        biometricPrompt = null
        super.onDestroy()
    }
}
