package codeasus.projects.sentinel.sdk

// JVM/Binder-layer anti-tampering checks for the Sentinel SDK.

// - Kotlin handles anything needing Binder IPC (PackageManager, Settings, Accessibility) or JVM reflection, since they have no syscall equivalent.
// - Native handles /proc, memory, and filesystem checks using raw syscalls. Doing filesystem checks in Kotlin is pointless because libc hooks can lie to Java/NIO too.
// - Exception: gadgetInNativeLibs() starts in Kotlin just to grab ctx.applicationInfo.nativeLibraryDir (a Binder path) before scanning.

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.os.Debug
import android.provider.Settings
import java.lang.reflect.Modifier
import java.security.MessageDigest

// ---------------------------------------------------------------------------
// 1. DEBUG DETECTION — Context/Settings-backed, no native equivalent
// ---------------------------------------------------------------------------
object DebugChecks {

    // Debuggable flag baked into the manifest (catches repackaged debug builds).
    fun isDebuggableFlag(ctx: Context): Boolean =
        (ctx.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

    // Java debugger (JDWP) attached or being waited for — a JVM runtime query (Debug class), not a filesystem read, so this stays here.
    fun isJavaDebuggerAttached(): Boolean =
        Debug.isDebuggerConnected() || Debug.waitingForDebugger()

    // USB debugging enabled on the device — Settings.Global via ContentResolver (Binder). */
    fun isAdbEnabled(ctx: Context): Boolean =
        Settings.Global.getInt(ctx.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1

    // Developer options enabled on the device — same Binder-backed source.
    fun isDeveloperOptionsEnabled(ctx: Context): Boolean =
        Settings.Global.getInt(
            ctx.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
        ) == 1
}

// ---------------------------------------------------------------------------
// 2. HOOKING-FRAMEWORK DETECTION — pure JVM, no native equivalent possible
// ---------------------------------------------------------------------------
object FridaChecks {
    fun gadgetInNativeLibs(ctx: Context): Boolean =
        java.io.File(ctx.applicationInfo.nativeLibraryDir).list()
            ?.any { it.contains("frida", ignoreCase = true) } ?: false

    fun isMethodFlippedToNative(
        clazz: Class<*>, name: String, vararg params: Class<*>
    ): Boolean = try {
        Modifier.isNative(clazz.getDeclaredMethod(name, *params).modifiers)
    } catch (_: Exception) {
        false
    }
}

object HookFrameworkChecks {

    // Xposed/LSPosed presence via classloader — pure JVM, no native path.
    fun xposedClassLoaded(): Boolean = try {
        Class.forName("de.robv.android.xposed.XposedBridge")
        true
    } catch (_: Throwable) {
        false
    }

    fun suspiciousStackFrames(): Boolean = try {
        throw Exception("probe")
    } catch (e: Exception) {
        e.stackTrace.any {
            val c = it.className
            c.contains("de.robv.android.xposed") ||
                    c.contains("com.saurik.substrate") ||
                    c.contains("frida", ignoreCase = true)
        }
    }
}

// ---------------------------------------------------------------------------
// 3. ACCESSIBILITY SERVICE ABUSE — entirely Binder-backed (AccessibilityManager,
//    Settings.Secure), no native equivalent exists or is meaningful here.
// ---------------------------------------------------------------------------
// This is the dominant real-world attack path against banking apps today — more common than Frida, because it needs no root and no device exploit.
object AccessibilityChecks {

    fun isAccessibilityEnabled(ctx: Context): Boolean =
        Settings.Secure.getInt(
            ctx.contentResolver, Settings.Secure.ACCESSIBILITY_ENABLED, 0
        ) == 1

    fun enabledServiceComponents(ctx: Context): List<String> =
        Settings.Secure.getString(
            ctx.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        )?.split(':')?.filter { it.isNotBlank() } ?: emptyList()

    fun suspiciousServices(
        ctx: Context,
        allowlist: Set<String> = setOf(
            "com.google.android.marvin.talkback",
            "com.samsung.android.accessibility",
            "com.google.android.apps.accessibility.voiceaccess"
        )
    ): List<String> =
        enabledServiceComponents(ctx).filterNot { component ->
            allowlist.any { component.startsWith(it) }
        }

    fun servicesWithReadAndInjectCapability(ctx: Context): List<String> {
        val am = ctx.getSystemService(Context.ACCESSIBILITY_SERVICE)
                as? android.view.accessibility.AccessibilityManager ?: return emptyList()
        return am.getEnabledAccessibilityServiceList(
            android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK
        ).filter { info ->
            val caps = info.capabilities
            val canRead = caps and android.accessibilityservice.AccessibilityServiceInfo
                .CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT != 0
            val canGesture = caps and android.accessibilityservice.AccessibilityServiceInfo
                .CAPABILITY_CAN_PERFORM_GESTURES != 0
            canRead && canGesture
        }.map { it.id }
    }

    fun canDrawOverlays(ctx: Context): Boolean =
        Settings.canDrawOverlays(ctx)
}

object TapjackingGuard {
    fun isTouchObscured(event: android.view.MotionEvent): Boolean {
        val obscured = event.flags and android.view.MotionEvent.FLAG_WINDOW_IS_OBSCURED != 0
        val partially =
            event.flags and android.view.MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED != 0
        return obscured || partially
    }
}

// ---------------------------------------------------------------------------
// 4. Environment checks: Build-class checks stay here since they read
// Android system properties instead of files. Root and busybox checks
// moved to SentinelSdk to avoid libc hooking (see note above).
// ---------------------------------------------------------------------------
object EnvironmentChecks {

    fun isTestKeysBuild(): Boolean = Build.TAGS?.contains("test-keys") == true

    fun looksLikeEmulator(): Boolean =
        Build.FINGERPRINT.startsWith("generic") ||
                Build.FINGERPRINT.contains("emulator") ||
                Build.HARDWARE.contains("goldfish") ||
                Build.HARDWARE.contains("ranchu") ||
                Build.PRODUCT.contains("sdk_gphone") ||
                Build.MODEL.contains("Emulator")
}

// ---------------------------------------------------------------------------
// 5. INTEGRITY / REPACKAGING — PackageManager is Binder-only, no native path
// ---------------------------------------------------------------------------
object IntegrityChecks {

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }

    fun signingCertHashes(ctx: Context): List<String> {
        val pm = ctx.packageManager
        val sigs: Array<Signature> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val si = pm.getPackageInfo(
                ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES
            ).signingInfo
            when {
                si == null -> emptyArray()
                si.hasMultipleSigners() -> si.apkContentsSigners
                else -> si.signingCertificateHistory
            }
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES).signatures
                ?: emptyArray()
        }
        return sigs.map { sha256Hex(it.toByteArray()) }
    }

    // expected = SHA-256 hex of YOUR release signing cert(s). Never ship the debug cert here.
    fun isSignatureValid(ctx: Context, expected: Set<String>): Boolean {
        val actual = signingCertHashes(ctx)
        return actual.isNotEmpty() && actual.all { it in expected }
    }

    fun installedFromPlayStore(ctx: Context): Boolean {
        val pm = ctx.packageManager
        val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(ctx.packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(ctx.packageName)
        }
        return installer == "com.android.vending"
    }

    // Unexpected native libs = someone injected a library into the APK.
    fun nativeLibsMatch(ctx: Context, allowed: Set<String>): Boolean =
        java.io.File(ctx.applicationInfo.nativeLibraryDir).list()?.all { it in allowed } ?: true
}

// ---------------------------------------------------------------------------
// SIM CARD PRESENCE — TelephonyManager is Binder-only, no native equivalent.
// Absence of a SIM is a common device-farm / emulator-farm signal: bot
// farms running real hardware on racks frequently skip SIM provisioning
// entirely since the device only needs Wi-Fi. Weak alone but it is very unlikely
// that you do not have a SIM on the same device you have the banking app, suspicious hmmm...
// ---------------------------------------------------------------------------
object SimChecks {
    fun isSimAbsent(ctx: Context): Boolean {
        val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE)
                as? android.telephony.TelephonyManager ?: return false
        return tm.simState == android.telephony.TelephonyManager.SIM_STATE_ABSENT
    }
}

// ---------------------------------------------------------------------------
// 6. JNI bridge to sentinel_native.cpp — all raw /proc, memory, and
// filesystem checks live on the native side.
//
// Heads up: The object name (SentinelSdk) is load-bearing. Every JNIEXPORT
// in the C++ code is tied to it. If you rename or move this object, you
// have to update all the Java_codeasus_projects_sentinel_sdk_SentinelSdk_
// symbols, or you'll get an UnsatisfiedLinkError on the first call.
// ---------------------------------------------------------------------------
object SentinelSdk {
    init {
        System.loadLibrary("sentinel")
    }

    external fun isTraced(): Boolean
    external fun mapsContainFrida(): Boolean
    external fun hasSuspiciousThreads(): Boolean
    external fun checkSuspiciousActivities(): Int

    external fun isAlreadyTraced(): Boolean
    external fun hasExecutableAnonRegion(): Boolean
    external fun environContainsFrida(): Boolean
    external fun unixSocketsSuspicious(): Boolean
    external fun mapsReadMismatch(): Boolean

    external fun anyPortSpeaksFridaProtocol(): Boolean
    external fun anyLoadedLibraryExportsGumSymbols(): Boolean

    external fun suspiciousFds(): Boolean
    external fun looksRooted(): Boolean
    external fun busyboxPresent(): Boolean

    external fun usbConnected(): Boolean

    external fun roDebuggableSet(): Boolean
}

// ---------------------------------------------------------------------------
// 7. AGGREGATION — the one place JVM-layer and native-layer signals merge
// ---------------------------------------------------------------------------
data class TamperReport(val score: Int, val signals: List<String>)

object TamperDetector {

    fun evaluate(ctx: Context, expectedCertHashes: Set<String>): TamperReport {
        val hits = mutableListOf<Pair<String, Int>>()

        fun check(name: String, weight: Int, block: () -> Boolean) {
            if (runCatching(block).getOrDefault(false)) hits += name to weight
        }

        // --- JVM/Binder-only ---
        check("debuggable_flag", 3) { DebugChecks.isDebuggableFlag(ctx) }
        check("java_debugger", 3) { DebugChecks.isJavaDebuggerAttached() }
        check("adb_enabled", 1) { DebugChecks.isAdbEnabled(ctx) }

        check("frida_gadget_lib", 5) { FridaChecks.gadgetInNativeLibs(ctx) }

        check("xposed", 3) { HookFrameworkChecks.xposedClassLoaded() }
        check("hook_stack", 4) { HookFrameworkChecks.suspiciousStackFrames() }

        check("test_keys_build", 1) { EnvironmentChecks.isTestKeysBuild() }
        check("emulator", 2) { EnvironmentChecks.looksLikeEmulator() }

        check("bad_signature", 5) { !IntegrityChecks.isSignatureValid(ctx, expectedCertHashes) }
        check("not_from_play", 1) { !IntegrityChecks.installedFromPlayStore(ctx) }

        check("suspicious_accessibility_service", 5) {
            AccessibilityChecks.suspiciousServices(ctx).isNotEmpty()
        }
        check("accessibility_read_and_gesture", 4) {
            AccessibilityChecks.servicesWithReadAndInjectCapability(ctx).isNotEmpty()
        }
        check("overlay_permission_granted", 2) { AccessibilityChecks.canDrawOverlays(ctx) }

        // --- Native-only (sentinel_native.cpp), single source of truth ---
        check("native_traced", 3) { SentinelSdk.isTraced() }
        check("native_frida_maps", 5) { SentinelSdk.mapsContainFrida() }
        check("native_suspicious_threads", 2) { SentinelSdk.hasSuspiciousThreads() }
        check("native_suspicious_fds", 3) { SentinelSdk.suspiciousFds() }
        check("native_ptrace_blocked", 4) { SentinelSdk.isAlreadyTraced() }
        check("native_rwx_anon_region", 4) { SentinelSdk.hasExecutableAnonRegion() }
        check("native_frida_env", 3) { SentinelSdk.environContainsFrida() }
        check("native_frida_unix_socket", 4) { SentinelSdk.unixSocketsSuspicious() }
        check("native_maps_read_mismatch", 4) { SentinelSdk.mapsReadMismatch() }
        check("native_rooted", 2) { SentinelSdk.looksRooted() }
        check("native_busybox", 1) { SentinelSdk.busyboxPresent() }

        // Rename-resistant — weight at least as high as the name-based checks.
        check("native_frida_protocol_any_port", 5) { SentinelSdk.anyPortSpeaksFridaProtocol() }
        check("native_gum_symbols_any_library", 5) {
            SentinelSdk.anyLoadedLibraryExportsGumSymbols()
        }

        // For USB debugging
        check("native_usb_connected", 1) { SentinelSdk.usbConnected() }

        // SIM card check to identify if it is indeed at least not a bot phone
        check("sim_absent", 1) { SimChecks.isSimAbsent(ctx) }

        check("native_ro_debuggable", 3) { SentinelSdk.roDebuggableSet() }

        return TamperReport(hits.sumOf { it.second }, hits.map { it.first })
    }
}