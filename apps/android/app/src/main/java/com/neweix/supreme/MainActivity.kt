package com.neweix.supreme

import android.app.AlertDialog
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.text.method.PasswordTransformationMethod
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.Window
import android.os.Build
import android.view.WindowManager.LayoutParams
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.fragment.app.FragmentActivity
import com.neweix.supreme.auth.SupremeAuthClient
import com.neweix.supreme.auth.SupremeAuthException
import com.neweix.supreme.auth.SupremeSessionStore
import com.neweix.supreme.security.SupremeAttestationClient
import com.neweix.supreme.security.SupremeKeyAttestation
import java.security.Signature
import java.util.Base64
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class MainActivity : FragmentActivity() {
    private val background: ExecutorService = Executors.newSingleThreadExecutor()
    private val idleHandler = Handler(Looper.getMainLooper())
    private val idleLockRunnable = Runnable {
        if (isUnlocked && pendingFactorId == null && !isBusy) {
            isUnlocked = false
            if (::lockOverlay.isInitialized) lockOverlay.visibility = View.VISIBLE
            authenticateToUnlock()
        }
    }
    private lateinit var sessionStore: SupremeSessionStore
    private lateinit var screen: LinearLayout
    private lateinit var statusText: TextView
    private lateinit var emailInput: EditText
    private lateinit var passwordInput: EditText
    private lateinit var passwordVisibilityButton: Button
    private var isPasswordVisible = false
    private lateinit var codeInput: EditText
    private lateinit var primaryButton: Button
    private lateinit var lockOverlay: LinearLayout
    private var biometricPrompt: BiometricPrompt? = null
    private var signingBiometricPrompt: BiometricPrompt? = null
    private var authInProgress = false
    private var isUnlocked = false
    private var isBusy = false
    private var resumeSessionCheck = false
    private var currentAccessToken: String? = null
    private var pendingFactorId: String? = null
    private var pendingChallengeId: String? = null
    private var pendingPasswordSession: SupremeAuthClient.AuthSession? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        configureEdgeToEdge(window)
        sessionStore = SupremeSessionStore(this)
        buildInterface()
        configureAppLock()
        authenticateToUnlock()
    }

    private fun configureEdgeToEdge(targetWindow: Window) {
        WindowCompat.setDecorFitsSystemWindows(targetWindow, false)
        targetWindow.statusBarColor = Color.TRANSPARENT
        targetWindow.navigationBarColor = Color.rgb(7, 7, 7)
        WindowCompat.getInsetsController(targetWindow, targetWindow.decorView).apply {
            isAppearanceLightStatusBars = false
            isAppearanceLightNavigationBars = false
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            targetWindow.attributes = targetWindow.attributes.apply {
                layoutInDisplayCutoutMode =
                    LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES
            }
        }
    }

    private fun buildInterface() {
        val root = FrameLayout(this).apply {
            setBackgroundColor(Color.rgb(7, 7, 7))
        }
        // Draw the app surface behind the status bar/camera cutout while
        // keeping interactive content clear of the bottom and side system bars.
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            view.setPadding(bars.left, 0, bars.right, maxOf(bars.bottom, ime.bottom))
            insets
        }

        val scroll = ScrollView(this).apply {
            isFillViewport = true
            clipToPadding = false
        }
        screen = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(22), dp(10), dp(22), dp(18))
        }

        screen.addView(ImageView(this).apply {
            setImageResource(R.drawable.supreme_logo)
            scaleType = ImageView.ScaleType.FIT_CENTER
            contentDescription = "Supreme gold S emblem"
        }, LinearLayout.LayoutParams(dp(84), dp(84)).apply {
            bottomMargin = dp(6)
        })

        val brand = TextView(this).apply {
            text = "SUPREME"
            textSize = 27f
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
            setPadding(0, dp(4), 0, dp(14))
        }
        screen.addView(subtitle, matchWrap())

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
            setBackgroundColor(Color.rgb(20, 20, 20))
        }
        screen.addView(card, matchWrap())

        card.addView(TextView(this).apply {
            text = "Supreme Account"
            textSize = 19f
            setTextColor(Color.WHITE)
        }, matchWrap())

        card.addView(TextView(this).apply {
            text = "Sign in with the single, dedicated Supreme identity. No Neweix Account or social login is used."
            textSize = 13f
            setTextColor(Color.rgb(170, 170, 170))
            setPadding(0, dp(6), 0, dp(14))
        }, matchWrap())

        card.addView(label("Supreme account email"))
        emailInput = input("Email address", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS)
        card.addView(emailInput, fieldParams())

        card.addView(label("Password"))
        passwordInput = input("Password", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD).apply {
            transformationMethod = PasswordTransformationMethod.getInstance()
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            setAutofillHints()
            contentDescription = "Supreme account password"
        }
        passwordVisibilityButton = Button(this).apply {
            text = "SHOW"
            isAllCaps = true
            textSize = 11f
            setTextColor(Color.rgb(229, 197, 120))
            setBackgroundColor(Color.rgb(9, 9, 9))
            contentDescription = "Show password"
            setOnClickListener {
                val selection = passwordInput.selectionStart.coerceAtLeast(0)
                isPasswordVisible = !isPasswordVisible
                passwordInput.transformationMethod = if (isPasswordVisible) {
                    null
                } else {
                    PasswordTransformationMethod.getInstance()
                }
                passwordVisibilityButton.text = if (isPasswordVisible) "HIDE" else "SHOW"
                passwordVisibilityButton.contentDescription =
                    if (isPasswordVisible) "Hide password" else "Show password"
                passwordInput.setSelection(selection.coerceAtMost(passwordInput.text.length))
            }
        }
        val passwordRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(Color.rgb(9, 9, 9))
            addView(passwordInput, LinearLayout.LayoutParams(0, dp(50), 1f))
            addView(passwordVisibilityButton, LinearLayout.LayoutParams(dp(76), dp(50)))
        }
        card.addView(passwordRow, fieldParams())
        passwordInput.imeOptions = EditorInfo.IME_ACTION_DONE
        passwordInput.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                beginPasswordSignIn()
                true
            } else {
                false
            }
        }

        card.addView(label("Authenticator code").apply { visibility = View.GONE })
        codeInput = input("6-digit TOTP code", InputType.TYPE_CLASS_NUMBER).apply {
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            setAutofillHints()
        }
        codeInput.visibility = View.GONE
        card.addView(codeInput, fieldParams())
        codeInput.imeOptions = EditorInfo.IME_ACTION_DONE
        codeInput.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                verifyMfaCode()
                true
            } else {
                false
            }
        }

        primaryButton = Button(this).apply {
            text = "SIGN IN"
            isEnabled = true
            alpha = 1f
            setTextColor(Color.rgb(18, 16, 10))
            setBackgroundColor(Color.rgb(212, 175, 55))
            setOnClickListener {
                if (pendingFactorId == null) beginPasswordSignIn() else verifyMfaCode()
            }
        }
        val buttonParams = matchWrap()
        buttonParams.topMargin = dp(14)
        card.addView(primaryButton, buttonParams)

        statusText = TextView(this).apply {
            text = "Password and TOTP MFA are required. Device attestation is checked separately."
            textSize = 12f
            setTextColor(Color.rgb(174, 159, 124))
            setPadding(0, dp(12), 0, dp(4))
            gravity = Gravity.CENTER
        }
        screen.addView(statusText, matchWrap())

        screen.addView(TextView(this).apply {
            text = "ACCESS IS VERIFIED SERVER-SIDE · UNAUTHORIZED DEVICES ARE DENIED"
            textSize = 9f
            letterSpacing = 0.06f
            gravity = Gravity.CENTER
            setTextColor(Color.rgb(100, 100, 100))
            setPadding(0, dp(12), 0, 0)
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
            addView(ImageView(this@MainActivity).apply {
                setImageResource(R.drawable.supreme_logo)
                scaleType = ImageView.ScaleType.FIT_CENTER
                contentDescription = "Supreme gold S emblem"
            }, LinearLayout.LayoutParams(dp(144), dp(144)).apply {
                bottomMargin = dp(10)
            })
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
        ViewCompat.requestApplyInsets(root)
    }

    private fun beginPasswordSignIn() {
        val email = emailInput.text.toString().trim()
        val password = passwordInput.text.toString()
        if (isBusy) return
        if (email.isBlank() || password.isBlank()) {
            setBusy(false, "Enter the Supreme account email and password.")
            return
        }

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
                    initial.refreshToken,
                    initial.userId,
                )
                if (session.userId != initial.userId || session.assuranceLevel != "aal2") {
                    throw IllegalStateException("Supreme AAL2 verification was not confirmed.")
                }
                // Fresh TOTP verification is enforced by supreme-session-api using
                // the verified TOTP AMR timestamp. auth_time is the original
                // authentication time and can be older than a successful MFA step.

                // Prepare an auth-per-use key operation. The Signature is passed
                // to BiometricPrompt before any payload is supplied or signed.
                val prepared = SupremeAttestationClient.prepareVerification(session.accessToken)
                runOnUiThread {
                    authenticateForSigning(
                        prepared.material.proofSigner,
                        onSigned = { signature ->
                            // Complete the cryptographic operation off the UI thread.
                            // Any Keystore/provider exception is handled as a sign-in
                            // failure rather than escaping the BiometricPrompt callback.
                            background.execute {
                                try {
                                    signature.update(prepared.material.proofPayload)
                                    val proof = Base64.getEncoder().encodeToString(signature.sign())
                                    val device = SupremeAttestationClient.completeVerification(
                                        session.accessToken,
                                        prepared,
                                        proof,
                                    )
                                    if (!device.proofOfPossessionVerified ||
                                        (device.securityLevel != "TRUSTED_ENVIRONMENT" &&
                                            device.securityLevel != "STRONG_BOX")
                                    ) {
                                        throw IllegalStateException(
                                            "This device did not pass Supreme hardware security verification.",
                                        )
                                    }
                                    val refreshed = SupremeAuthClient.refresh(session.refreshToken)
                                    if (refreshed.userId != session.userId ||
                                        refreshed.sessionId != session.sessionId ||
                                        refreshed.assuranceLevel != "aal2"
                                    ) {
                                        throw IllegalStateException(
                                            "Supreme AAL2 session continuity could not be confirmed.",
                                        )
                                    }
                                    SupremeAuthClient.verifyDeviceSession(refreshed.accessToken)
                                    sessionStore.saveRefreshToken(refreshed.refreshToken)
                                    var dashboardWarning: String? = null
                                    val services = try {
                                        SupremeAuthClient.listServices(refreshed.accessToken)
                                    } catch (error: Exception) {
                                        dashboardWarning = safeMessage(error)
                                        emptyList()
                                    }
                                    val requests = try {
                                        SupremeAuthClient.listPendingRequests(refreshed.accessToken)
                                    } catch (error: Exception) {
                                        if (dashboardWarning == null) dashboardWarning = safeMessage(error)
                                        emptyList()
                                    }
                                    runOnUiThread {
                                        currentAccessToken = refreshed.accessToken
                                        pendingPasswordSession = null
                                        pendingFactorId = null
                                        pendingChallengeId = null
                                        codeInput.text.clear()
                                        isUnlocked = true
                                        lockOverlay.visibility = View.GONE
                                        renderDashboard(services, requests)
                                        resetIdleLockTimer()
                                        setBusy(false, dashboardWarning
                                            ?: "Biometric device attestation and Supreme session checks passed.")
                                    }
                                } catch (error: Exception) {
                                    handleMfaDeviceRegistrationFailure(error)
                                }
                            }
                        },
                        onFailure = { message ->
                            handleMfaDeviceRegistrationFailure(IllegalStateException(message))
                        },
                    )
                }
            } catch (error: Exception) {
                handleMfaDeviceRegistrationFailure(error)
            }
        }
    }

    private fun handleMfaDeviceRegistrationFailure(error: Exception) {
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
            val message = if (
                error is SupremeAuthException &&
                (error.statusCode == 400 || error.statusCode == 422)
            ) {
                "Authenticator code was rejected. Wait for a fresh six-digit code and try again."
            } else {
                safeMessage(error)
            }
            setBusy(false, message)
        }
    }

    private fun renderDashboard(
        services: List<SupremeAuthClient.Service>,
        requests: List<SupremeAuthClient.ControlRequest>,
    ) {
        screen.removeAllViews()
        screen.addView(ImageView(this).apply {
            setImageResource(R.drawable.supreme_logo)
            scaleType = ImageView.ScaleType.FIT_CENTER
            contentDescription = "Supreme gold S emblem"
        }, LinearLayout.LayoutParams(dp(96), dp(96)).apply {
            bottomMargin = dp(8)
        })
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
            text = "PENDING APPROVALS · ${requests.size}"
            textSize = 12f
            setTextColor(Color.rgb(229, 197, 120))
            setPadding(0, dp(8), 0, dp(8))
        }, matchWrap())

        screen.addView(TextView(this).apply {
            text = "An approval records the governance decision only. It does not deploy or execute a provider operation."
            textSize = 11f
            setTextColor(Color.rgb(145, 145, 145))
            setPadding(0, 0, 0, dp(8))
        }, matchWrap())

        if (requests.isEmpty()) {
            screen.addView(TextView(this).apply {
                text = "No pending approvals."
                textSize = 12f
                setTextColor(Color.LTGRAY)
                setPadding(0, 0, 0, dp(14))
            }, matchWrap())
        }

        for (request in requests) {
            val item = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(16), dp(14), dp(16), dp(14))
                setBackgroundColor(Color.rgb(24, 24, 24))
            }
            item.addView(TextView(this@MainActivity).apply {
                text = request.action.replace('.', ' ').replace('_', ' ').uppercase()
                textSize = 14f
                setTextColor(Color.WHITE)
            }, matchWrap())
            item.addView(TextView(this@MainActivity).apply {
                text = "Request ${request.id.take(8)} · ${request.requestType} · ${request.serviceId ?: "system"}"
                textSize = 11f
                setTextColor(Color.rgb(210, 180, 110))
                setPadding(0, dp(6), 0, dp(4))
            }, matchWrap())
            item.addView(TextView(this@MainActivity).apply {
                text = "Created: ${request.createdAt}\nExpires: ${request.expiresAt}"
                textSize = 10f
                setTextColor(Color.rgb(150, 150, 150))
            }, matchWrap())
            val actions = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.END
            }
            val reject = Button(this@MainActivity).apply {
                text = "REJECT"
                filterTouchesWhenObscured = true
                setOnClickListener { confirmRequestDecision(request, approve = false) }
            }
            val approve = Button(this@MainActivity).apply {
                text = "APPROVE"
                filterTouchesWhenObscured = true
                setOnClickListener { confirmRequestDecision(request, approve = true) }
            }
            actions.addView(reject, LinearLayout.LayoutParams(0, dp(44), 1f))
            actions.addView(approve, LinearLayout.LayoutParams(0, dp(44), 1f))
            item.addView(actions, matchWrap())
            val params = matchWrap()
            params.topMargin = dp(10)
            screen.addView(item, params)
        }

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

    private fun confirmRequestDecision(
        request: SupremeAuthClient.ControlRequest,
        approve: Boolean,
    ) {
        if (approve) {
            AlertDialog.Builder(this)
                .setTitle("Approve control request?")
                .setMessage(
                    "Approve ${request.action} for ${request.serviceId ?: "the Supreme system"}? " +
                        "This records the decision only; it does not deploy or execute the operation.",
                )
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Approve") { _, _ ->
                    submitRequestDecision(request, "approve", null)
                }
                .show()
            return
        }

        val reason = EditText(this).apply {
            hint = "Reason (at least 8 characters)"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            minLines = 2
            setPadding(dp(14), dp(10), dp(14), dp(10))
        }
        AlertDialog.Builder(this)
            .setTitle("Reject control request?")
            .setMessage("A reason is required and will be written to the audit log.")
            .setView(reason)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Reject") { _, _ ->
                val value = reason.text.toString().trim()
                if (value.length < 8) {
                    statusText.text = "Enter a rejection reason of at least 8 characters."
                } else {
                    submitRequestDecision(request, "reject", value)
                }
            }
            .show()
    }

    private fun submitRequestDecision(
        request: SupremeAuthClient.ControlRequest,
        decision: String,
        reason: String?,
    ) {
        val accessToken = currentAccessToken
        if (accessToken.isNullOrBlank()) {
            statusText.text = "Supreme session is unavailable. Sign in again."
            return
        }
        if (isBusy) return
        setBusy(true, "Preparing biometric approval signature…")
        background.execute {
            try {
                var activeAccessToken: String = accessToken
                val decisionChallenge = try {
                    SupremeAuthClient.issueControlDecisionChallenge(
                        accessToken = activeAccessToken,
                        requestId = request.id,
                        decision = decision,
                        reason = reason,
                    )
                } catch (error: SupremeAuthException) {
                    if (error.statusCode != 401) throw error
                    val storedRefreshToken = sessionStore.readRefreshToken()
                        ?: throw IllegalStateException("Supreme session expired. Sign in again.")
                    val refreshed = SupremeAuthClient.refresh(storedRefreshToken)
                    if (refreshed.assuranceLevel != "aal2") {
                        throw IllegalStateException("Supreme MFA session expired. Sign in again.")
                    }
                    SupremeAuthClient.verifyDeviceSession(refreshed.accessToken)
                    sessionStore.saveRefreshToken(refreshed.refreshToken)
                    activeAccessToken = refreshed.accessToken
                    currentAccessToken = refreshed.accessToken
                    SupremeAuthClient.issueControlDecisionChallenge(
                        accessToken = activeAccessToken,
                        requestId = request.id,
                        decision = decision,
                        reason = reason,
                    )
                }

                val preparedSigner = SupremeKeyAttestation.prepareControlDecisionSignature(
                    challengeId = decisionChallenge.id,
                    nonceBase64Url = decisionChallenge.nonce,
                    requestId = request.id,
                    decision = decision,
                    reason = reason,
                )
                runOnUiThread {
                    authenticateForSigning(
                        preparedSigner.signature,
                        onSigned = { authorizedSigner ->
                            background.execute {
                                try {
                                    authorizedSigner.update(preparedSigner.payload)
                                    val signature = Base64.getEncoder().encodeToString(authorizedSigner.sign())
                                    try {
                                        SupremeAuthClient.decideControlRequest(
                                            accessToken = activeAccessToken,
                                            requestId = request.id,
                                            decision = decision,
                                            reason = reason,
                                            challengeId = decisionChallenge.id,
                                            nonce = decisionChallenge.nonce,
                                            signature = signature,
                                        )
                                    } catch (error: SupremeAuthException) {
                                        if (error.statusCode != 401) throw error
                                        // A 401 occurs before route execution; the challenge
                                        // remains unconsumed and can be retried after rotation.
                                        val storedRefreshToken = sessionStore.readRefreshToken()
                                            ?: throw IllegalStateException("Supreme session expired. Sign in again.")
                                        val refreshed = SupremeAuthClient.refresh(storedRefreshToken)
                                        if (refreshed.assuranceLevel != "aal2") {
                                            throw IllegalStateException("Supreme MFA session expired. Sign in again.")
                                        }
                                        SupremeAuthClient.verifyDeviceSession(refreshed.accessToken)
                                        sessionStore.saveRefreshToken(refreshed.refreshToken)
                                        activeAccessToken = refreshed.accessToken
                                        currentAccessToken = refreshed.accessToken
                                        SupremeAuthClient.decideControlRequest(
                                            accessToken = activeAccessToken,
                                            requestId = request.id,
                                            decision = decision,
                                            reason = reason,
                                            challengeId = decisionChallenge.id,
                                            nonce = decisionChallenge.nonce,
                                            signature = signature,
                                        )
                                    }
                                    val services = SupremeAuthClient.listServices(activeAccessToken)
                                    val requests = SupremeAuthClient.listPendingRequests(activeAccessToken)
                                    runOnUiThread {
                                        renderDashboard(services, requests)
                                        setBusy(false, if (decision == "approve") {
                                            "Biometric approval recorded. Provider execution has not been triggered."
                                        } else {
                                            "Biometric rejection recorded in the Supreme audit log."
                                        })
                                    }
                                } catch (error: Exception) {
                                    runOnUiThread { setBusy(false, safeMessage(error)) }
                                }
                            }
                        },
                        onFailure = { message ->
                            setBusy(false, message)
                        },
                    )
                }
            } catch (error: Exception) {
                runOnUiThread { setBusy(false, safeMessage(error)) }
            }
        }
    }

    private fun resumeStoredSession() {
        if (resumeSessionCheck || pendingFactorId != null) return
        val refreshToken = sessionStore.readRefreshToken()
        if (refreshToken == null) {
            showSignIn()
            setBusy(false, "No saved Supreme session is available. Sign in again.")
            return
        }
        resumeSessionCheck = true
        setBusy(true, "Restoring the encrypted Supreme session…")
        background.execute {
            try {
                val session = SupremeAuthClient.refresh(refreshToken)
                if (session.assuranceLevel != "aal2") {
                    throw IllegalStateException("Supreme session has fallen below AAL2. Sign in again.")
                }
                SupremeAuthClient.verifyDeviceSession(session.accessToken)
                // Refresh-token rotation is committed by Supabase before the next
                // API request. Save the replacement before any downstream operation.
                sessionStore.saveRefreshToken(session.refreshToken)
                var dashboardWarning: String? = null
                val services = try {
                    SupremeAuthClient.listServices(session.accessToken)
                } catch (error: Exception) {
                    dashboardWarning = safeMessage(error)
                    emptyList()
                }
                val requests = try {
                    SupremeAuthClient.listPendingRequests(session.accessToken)
                } catch (error: Exception) {
                    if (dashboardWarning == null) dashboardWarning = safeMessage(error)
                    emptyList()
                }
                runOnUiThread {
                    currentAccessToken = session.accessToken
                    resumeSessionCheck = false
                    isUnlocked = true
                    lockOverlay.visibility = View.GONE
                    renderDashboard(services, requests)
                    resetIdleLockTimer()
                    setBusy(false, dashboardWarning ?: "Supreme session restored.")
                }
            } catch (error: Exception) {
                val status = (error as? SupremeAuthException)?.statusCode
                if (status == 401 || status == 403) sessionStore.clear()
                runOnUiThread {
                    resumeSessionCheck = false
                    if (status == 401 || status == 403) {
                        showSignIn()
                        setBusy(false, "The previous Supreme app session is no longer authorized. Sign in again.")
                    } else {
                        // Keep the session and privileged content locked on transient
                        // network/server errors. The user can retry without signing in again.
                        isUnlocked = false
                        lockOverlay.visibility = View.VISIBLE
                        setBusy(false, "Supreme session could not be checked. Check your connection and tap UNLOCK SUPREME to retry.")
                    }
                }
            }
        }
    }

    private fun signOut() {
        val refresh = sessionStore.readRefreshToken()
        sessionStore.clear()
        currentAccessToken = null
        if (refresh == null) {
            showSignIn()
            return
        }
        setBusy(true, "Signing out…")
        background.execute {
            try {
                val session = SupremeAuthClient.refresh(refresh)
                if (session.assuranceLevel == "aal2") {
                    try { SupremeAuthClient.revokeDeviceSession(session.accessToken) } catch (_: Exception) { }
                }
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
        currentAccessToken = null
        buildInterface()
        lockOverlay.visibility = View.GONE
        isUnlocked = true
        resetIdleLockTimer()
    }

    private fun configureAppLock() {
        biometricPrompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    authInProgress = false
                    // Local biometric success alone must not reveal privileged content.
                    // Keep the overlay visible until the server session is revalidated.
                    isUnlocked = false
                    idleHandler.removeCallbacks(idleLockRunnable)
                    lockOverlay.visibility = View.VISIBLE
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

    /**
     * A separate BIOMETRIC_STRONG prompt is required for Android Keystore
     * CryptoObject operations. Device-credential fallback is intentionally not
     * allowed because the registered key is configured for biometric auth.
     */
    private fun authenticateForSigning(
        signature: Signature,
        onSigned: (Signature) -> Unit,
        onFailure: (String) -> Unit,
    ) {
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    signingBiometricPrompt = null
                    val authorized = result.cryptoObject?.signature
                    if (authorized == null) {
                        onFailure("Biometric signing authorization was not returned by Android.")
                    } else {
                        onSigned(authorized)
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    signingBiometricPrompt = null
                    onFailure("Fingerprint verification was cancelled or failed. No signature was created.")
                }

                override fun onAuthenticationFailed() {
                    // Keep the biometric prompt active for another strong-biometric attempt.
                }
            },
        )
        signingBiometricPrompt = prompt
        try {
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Confirm Supreme security operation")
                .setSubtitle("Fingerprint verification is required to authorize this signature")
                .setDescription("The private key remains protected inside Android Keystore.")
                .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText("Cancel")
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
        } catch (error: Exception) {
            signingBiometricPrompt = null
            onFailure("Strong biometric signing is unavailable on this device.")
        }
    }

    private fun authenticateToUnlock() {
        if (isUnlocked || authInProgress) return
        val prompt = biometricPrompt ?: return
        authInProgress = true
        lockOverlay.visibility = View.VISIBLE
        try {
            val builder = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock Supreme")
                .setSubtitle("Use a strong biometric or the device screen-lock PIN")
                .setDescription("This only unlocks the app on this device. Server authentication is still required.")

            // Android 11+ supports an explicit strong-biometric + device-credential
            // combination. Older supported Android versions use the legacy
            // device-credential switch. Never mix the two builder APIs.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setAllowedAuthenticators(
                    androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                )
            } else {
                builder.setDeviceCredentialAllowed(true)
            }

            // Build inside the guarded block: PromptInfo validation can throw before
            // authenticate() is called, which previously allowed a crash to escape.
            prompt.authenticate(builder.build())
        } catch (_: Exception) {
            authInProgress = false
            lockOverlay.visibility = View.VISIBLE
            statusText.text = "Device unlock is unavailable. Set up a secure screen lock and try again."
        }
    }

    private fun setBusy(busy: Boolean, message: String?) {
        isBusy = busy
        val hasAuthorizedAction = currentAccessToken != null ||
            pendingFactorId != null ||
            primaryButton.text.toString() == "SIGN IN" ||
            primaryButton.text.toString() == "SIGN OUT"
        primaryButton.isEnabled = !busy && hasAuthorizedAction
        primaryButton.alpha = if (primaryButton.isEnabled) 1f else 0.6f
        if (!message.isNullOrBlank()) statusText.text = message
    }

    private fun safeMessage(error: Exception): String {
        return when (error) {
            is SupremeAuthException -> when (error.statusCode) {
                400, 422 -> "Supreme sign-in could not be verified. Check the account credentials."
                401 -> "Supreme session expired or is no longer valid. Sign in again."
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
        isSaveEnabled = false
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

    private fun clearTransientCredentials() {
        if (::passwordInput.isInitialized) {
            passwordInput.text?.clear()
            passwordInput.transformationMethod = PasswordTransformationMethod.getInstance()
            isPasswordVisible = false
            if (::passwordVisibilityButton.isInitialized) {
                passwordVisibilityButton.text = "SHOW"
                passwordVisibilityButton.contentDescription = "Show password"
            }
        }
        if (::codeInput.isInitialized) codeInput.text?.clear()

        // A half-completed password/MFA flow must be restarted after leaving the app.
        pendingPasswordSession = null
        pendingFactorId = null
        pendingChallengeId = null
        if (::passwordInput.isInitialized && pendingFactorId == null &&
            ::codeInput.isInitialized && codeInput.visibility == View.VISIBLE
        ) {
            codeInput.visibility = View.GONE
            passwordInput.visibility = View.VISIBLE
            emailInput.isEnabled = true
            if (::primaryButton.isInitialized) primaryButton.text = "SIGN IN"
        }
    }

    private fun resetIdleLockTimer() {
        idleHandler.removeCallbacks(idleLockRunnable)
        if (isUnlocked && pendingFactorId == null) {
            idleHandler.postDelayed(idleLockRunnable, 5 * 60 * 1000L)
        }
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        resetIdleLockTimer()
    }

    override fun onStop() {
        idleHandler.removeCallbacks(idleLockRunnable)
        // Opening an authenticator app temporarily backgrounds Supreme. Keep the
        // in-memory, short-lived MFA transaction so the user can return and enter
        // the TOTP code; clear the typed code itself and all state on destruction.
        val mfaInProgress = pendingPasswordSession != null && pendingFactorId != null
        if (mfaInProgress) {
            if (::codeInput.isInitialized) codeInput.text?.clear()
        } else {
            clearTransientCredentials()
        }
        super.onStop()
        if (!isChangingConfigurations && !mfaInProgress) {
            isUnlocked = false
            if (::lockOverlay.isInitialized) lockOverlay.visibility = View.VISIBLE
        }
    }

    override fun onResume() {
        super.onResume()
        resetIdleLockTimer()
        val mfaInProgress = pendingPasswordSession != null && pendingFactorId != null
        if (!isUnlocked && !mfaInProgress && biometricPrompt != null) authenticateToUnlock()
    }

    override fun onDestroy() {
        idleHandler.removeCallbacks(idleLockRunnable)
        clearTransientCredentials()
        background.shutdownNow()
        biometricPrompt = null
        super.onDestroy()
    }
}
