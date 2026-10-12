    //Network-interception detection for the sentinel SDK:

package codeasus.projects.sentinel.sdk

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.ProxyInfo
import androidx.annotation.RequiresPermission
import java.security.KeyStore
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

// ---------------------------------------------------------------------------
// 1. PROXY / VPN CONFIGURATION — ConnectivityManager is Binder-only
// ---------------------------------------------------------------------------
object ProxyChecks {

    /**
     * JVM-level proxy system properties. Respected by java.net.HttpURLConnection
     * and anything layered on it by default; OkHttp and other clients that
     * build their own OkHttpClient/Proxy explicitly may ignore these, so
     * treat this as a weak, client-dependent signal.
     */
    fun isSystemHttpProxySet(): Boolean {
        val host = System.getProperty("http.proxyHost") ?: System.getProperty("https.proxyHost")
        return !host.isNullOrBlank()
    }

    /** The proxy actually configured on the active network connection (Wi-Fi
     *  manual proxy, or a proxy pushed by a VPN profile) — the setting Burp's
     *  and mitmproxy's own setup instructions tell users to configure by hand. */
    @RequiresPermission(android.Manifest.permission.ACCESS_NETWORK_STATE)
    fun activeNetworkHttpProxy(ctx: Context): ProxyInfo? {
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return null
        val network = cm.activeNetwork ?: return null
        val linkProperties = cm.getLinkProperties(network) ?: return null
        return linkProperties.httpProxy
    }

    @RequiresPermission(android.Manifest.permission.ACCESS_NETWORK_STATE)
    fun isActiveNetworkProxyConfigured(ctx: Context): Boolean {
        val proxy = activeNetworkHttpProxy(ctx) ?: return false
        return !proxy.host.isNullOrBlank()
    }

    /**
     * Any active network (not just the default) reporting itself as a VPN
     * transport. NOTE: this is a WEAK signal on its own — legitimate VPN
     * apps are extremely common and on-device capture tools (PCAPdroid,
     * HttpCanary) also use VPNService for entirely benign reasons (ad
     * blocking, personal traffic monitoring). Don't gate anything on this
     * alone; combine with the cert-trust checks below.
     */
    @RequiresPermission(android.Manifest.permission.ACCESS_NETWORK_STATE)
    fun isVpnActive(ctx: Context): Boolean {
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return false
        return cm.allNetworks.any { net ->
            cm.getNetworkCapabilities(net)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
    }
}

// ---------------------------------------------------------------------------
// 2. TLS TRUST STORE TAMPERING — java.security.KeyStore, pure JVM API
// ---------------------------------------------------------------------------
object CertificateTrustChecks {

    /**
     * User- or admin-installed CA certificates, via the merged
     * "AndroidCAStore" keystore. Historically (and still on most current
     * AOSP-derived implementations) user-added certs are aliased with a
     * "user:" prefix distinct from the "system:" prefix on preinstalled
     * roots — this is how Burp's and mitmproxy's own CA, once manually
     * trusted by the user, shows up. CAVEAT: this is implementation
     * behavior, not a documented stable contract, and some OEM builds or
     * MDM-managed devices alias things differently — treat a miss here as
     * inconclusive, not as proof of a clean trust store. A CA installed as
     * a SYSTEM certificate (e.g. via a Magisk module patching /system) will
     * not show the "user:" prefix at all and this check will not catch it.
     */
    fun userAddedCaAliases(): List<String> = try {
        val ks = KeyStore.getInstance("AndroidCAStore")
        ks.load(null, null)
        ks.aliases().toList().filter { it.startsWith("user:") }
    } catch (_: Exception) {
        emptyList()
    }

    fun hasUserAddedCertificates(): Boolean = userAddedCaAliases().isNotEmpty()
}

// ---------------------------------------------------------------------------
// 3. DEFAULT TRUST MANAGER REPLACED — pure JVM reflection on the TLS stack
// ---------------------------------------------------------------------------
object TrustManagerTamperChecks {

    /**
     * Stock Android's default X509TrustManager implementation class is
     * com.android.org.conscrypt.TrustManagerImpl. SSL-unpinning tooling
     * (SSLKillSwitch/SSLKillSwitch2, JustTrustMe, Frida's universal
     * android-ssl-pinning-bypass scripts) typically works by swapping in a
     * permissive TrustManager at the SSLContext level, which changes this
     * class name. A mismatch here is a meaningfully strong signal, since
     * legitimate apps essentially never touch this.
     */
    fun defaultTrustManagerLooksTampered(): Boolean = try {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        val tm = tmf.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
        val className = tm?.javaClass?.name
        className == null || !className.startsWith("com.android.org.conscrypt")
    } catch (_: Exception) {
        false
    }
}

// ---------------------------------------------------------------------------
// 4. KNOWN ON-DEVICE CAPTURE APPS — PackageManager is Binder-only
// ---------------------------------------------------------------------------
object SnifferAppChecks {

    private val knownCapturePackages = setOf(
        "com.minhui.networkcapture",     // Packet Capture
        "app.greyshirts.sslcapture",     // SSL Capture
        "com.emanuelef.remote_capture",  // PCAPdroid
        "com.emanuelef.remote_capture.debug",
        "com.guoshi.httpcanary",         // HttpCanary
        "com.guoshi.httpcanary.premium",
        "com.minhui.sniffer"
    )

    /**
     * Each package above must be declared in a <queries> block in your own
     * manifest on API 30+ (package visibility) or getPackageInfo will throw
     * NameNotFoundException for all of them regardless of what's installed —
     * this is an Android platform restriction, not a bug in this check.
     */
    fun installedCapturePackages(ctx: Context): List<String> =
        knownCapturePackages.filter { pkg ->
            try {
                ctx.packageManager.getPackageInfo(pkg, 0)
                true
            } catch (_: PackageManager.NameNotFoundException) {
                false
            }
        }
}

// ---------------------------------------------------------------------------
// 5. JNI BRIDGE to network_native.cpp
//
//    Object name is load-bearing: every JNIEXPORT in network_native.cpp is
//    Java_codeasus_projects_sentinel_sdk_SentinelNetworkGuard_<method>.
//    Rename this object only together with every matching symbol there.
//    Loads a SEPARATE .so from SentinelSdk.kt's — build it as its own
//    CMake target (e.g. "network_native") so the two stay independently
//    updatable.
// ---------------------------------------------------------------------------
object NativeNetworkInterceptor {
    init {
        System.loadLibrary("native_network_interceptor")
    }

    /** tun0/tun1/ppp0 present — the interface Android's VPNService creates,
     *  which most on-device capture apps use even though no "VPN" in the
     *  traditional sense is involved. */
    external fun tunnelInterfaceActive(): Boolean

    /** Stronger than interface presence alone: the DEFAULT route specifically
     *  goes through a tunnel interface, meaning all outbound traffic, not
     *  just one app's, is funneled through it right now. */
    external fun defaultRouteViaTunnel(): Boolean

    /** Only catches capture binaries running locally on a rooted device
     *  (tcpdump, mitmdump via Termux, etc) — not a PC-based tool. */
    external fun knownCaptureProcessRunning(): Boolean
}

// ---------------------------------------------------------------------------
// 6. AGGREGATION — separate report/score from TamperDetector's, since this
//    is a distinct risk category (network interception vs. process tampering)
//    you likely want to react to differently (e.g. warn-and-continue for a
//    VPN hit, vs. hard-block for a tampered trust manager).
// ---------------------------------------------------------------------------
data class NetworkTamperReport(val score: Int, val signals: List<String>)

object NetworkDetector {

    @RequiresPermission(android.Manifest.permission.ACCESS_NETWORK_STATE)
    fun evaluate(ctx: Context): NetworkTamperReport {
        val hits = mutableListOf<Pair<String, Int>>()

        fun check(name: String, weight: Int, block: () -> Boolean) {
            if (runCatching(block).getOrDefault(false)) hits += name to weight
        }

        check("system_http_proxy_set", 2) { ProxyChecks.isSystemHttpProxySet() }
        check("active_network_proxy", 4) { ProxyChecks.isActiveNetworkProxyConfigured(ctx) }
        check("vpn_active", 1) { ProxyChecks.isVpnActive(ctx) } // weak alone, see comment above

        check("user_added_ca_cert", 5) { CertificateTrustChecks.hasUserAddedCertificates() }
        check("trust_manager_tampered", 5) { TrustManagerTamperChecks.defaultTrustManagerLooksTampered() }

        check("known_capture_app_installed", 4) {
            SnifferAppChecks.installedCapturePackages(ctx).isNotEmpty()
        }

        check("native_tun_interface", 2) { NativeNetworkInterceptor.tunnelInterfaceActive() }
        check("native_default_route_tunnel", 3) { NativeNetworkInterceptor.defaultRouteViaTunnel() }
        check("native_capture_process", 4) { NativeNetworkInterceptor.knownCaptureProcessRunning() }

        return NetworkTamperReport(hits.sumOf { it.second }, hits.map { it.first })
    }
}