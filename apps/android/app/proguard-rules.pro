# Preserve runtime annotations and generic signatures used by AndroidX and Kotlin.
-keepattributes Signature,*Annotation*,InnerClasses,EnclosingMethod
-keep class androidx.biometric.** { *; }
-keep class com.neweix.supreme.auth.** { *; }
-keep class com.neweix.supreme.security.** { *; }
