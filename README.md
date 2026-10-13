--------------------------------------------------------------------------------
SENTINEL SDK
--------------------------------------------------------------------------------

A robust runtime SDK for Android that detects application tampering, debugging, reverse engineering, and network interception/sniffing.

--------------------------------------------------------------------------------
OVERVIEW
--------------------------------------------------------------------------------

Sentinel is designed to be embedded in an application and run at runtime to help the host app detect when its environment, integrity, or network traffic is being interfered with. This repository contains the SDK library itself plus a sample application module demonstrating its usage.

--------------------------------------------------------------------------------
REQUIREMENTS
--------------------------------------------------------------------------------

- JDK (resolved automatically via Foojay toolchain resolver)
- Android SDK (resolves Android/Google artifacts from `google()`)
- Gradle wrapper (`gradlew`) included in the project

Dependencies are resolved from:
- Google Maven (`google()`)
- Maven Central (`mavenCentral()`)

--------------------------------------------------------------------------------
GETTING STARTED
--------------------------------------------------------------------------------

1. Clone the repository

   git clone https://github.com/codeasus/sentinel-sdk.git
   cd sentinel-sdk

2. Build the whole project

   Linux / macOS:   ./gradlew build
   Windows:         gradlew.bat build

3. Build only the SDK module

   ./gradlew :sdk:sentinel:build

4. Build / install the sample app

   ./gradlew :app:assembleDebug
   ./gradlew :app:installDebug      (with a device or emulator attached)

--------------------------------------------------------------------------------
USING THE SDK IN YOUR OWN PROJECT
--------------------------------------------------------------------------------

Add the SDK module as a dependency in your app's build file:

// settings.gradle.kts
include(":sdk:sentinel")

// app/build.gradle.kts
dependencies {
    implementation(project(":sdk:sentinel"))
}

### API Usage Example

Call the top-level `check` function to evaluate integrity and network interception reports:

```kotlin
import codeasus.projects.sentinel.sdk.check

// Inside your Activity or Application
check(context)
```

Or invoke individual detectors directly:

```kotlin
import codeasus.projects.sentinel.sdk.TamperDetector
import codeasus.projects.sentinel.sdk.NetworkDetector

// Evaluate tampering / environment threats
val tamperReport = TamperDetector.evaluate(context)

// Evaluate network interception / VPN sniffing threats
val networkReport = NetworkDetector.evaluate(context)
```

--------------------------------------------------------------------------------
WHAT SENTINEL IS INTENDED TO DETECT
--------------------------------------------------------------------------------

### 1. Tampering & Environment Checks (`TamperDetector`)
- **Debugger & Tracing**: Java debugger attachment, `TracerPid` detection, self-tracing (`ptrace`), USB debugging state.
- **Root & Emulators**: Root binaries (`su`, Magisk artifacts), busybox presence, emulator environment indicators (`Build.FINGERPRINT`, test-keys builds).
- **Frida & Hooking Detection**: Memory map scans for `frida-agent`, `frida-gadget`, `linjector`, suspicious thread names, executable anonymous memory (`W^X` violation checks), port sweeps for Frida D-Bus wire protocol, exported symbol scanning (`gum_init_embedded`, etc.), and environment variable checks.
- **Integrity & Device State**: Package installer verification (Play Store check), accessibility service abuse / screen reading / gesture capabilities, tapjacking / window obstruction detection, and SIM card presence checks.

### 2. Network Interception & Sniffing (`NetworkDetector`)
- **Proxy & VPN Detection**: System HTTP proxy configuration, active network HTTP proxies, VPN transport detection.
- **TLS Trust Store Tampering**: User-added CA certificates (`AndroidCAStore`).
- **Trust Manager Tampering**: Inspection of default `X509TrustManager` implementations for SSL pinning bypass hooks.
- **Capture Apps**: Known on-device packet capture packages (Packet Capture, PCAPdroid, HttpCanary, etc.).
- **Native Network Interception**: Raw `/proc/net/dev` interface checks (`tun0`, `tun1`, `ppp0`), default routing table checks via tunnels (`/proc/net/route`), and local capture process scanning (`tcpdump`, `mitmdump`, etc.).

--------------------------------------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------------------------------------

Runtime detection is one layer of defense, not a guarantee. Determined attackers can often bypass client-side checks, so combine Sentinel with other security measures (code obfuscation, server-side validation, secure storage, certificate pinning, etc.) rather than relying on it alone.

--------------------------------------------------------------------------------
CONTRIBUTING
--------------------------------------------------------------------------------

Issues and pull requests are welcome via GitHub:
https://github.com/codeasus/sentinel-sdk/issues

--------------------------------------------------------------------------------
LICENSE
--------------------------------------------------------------------------------

None as of this moment