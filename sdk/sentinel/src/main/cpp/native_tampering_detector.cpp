// Native-layer anti-tampering checks

// Why we're bypassing standard libc wrappers (open, read, strstr, etc.):
// Frida and other instrumentation tools love hooking these symbols via the PLT/GOT.
// Using raw syscall(2) talks directly to the kernel, completely dodging those hooks.

// Real talk: This isn't a silver bullet; it just raises the bar. A determined
// attacker can still hook the syscall entry point, mess with ptrace/seccomp, or
// patch our .text section in memory. Because of that, treat these signals as just
// one data point for a server-side risk score—never rely on them as a standalone
// pass/fail gate on the client side.

// Note: Some help from a LLM model has been used to develop this native library but it is mostly a honest work, haha...
// While I can read and write C++ from basic to mediocre level, I am no expert!
// Additionally, not all of these methods have been tested due to time constraints, the time it takes to setup different mobile environments, lack of different devices and so on.

#include <jni.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <dirent.h>
#include <dlfcn.h>
#include <link.h>

// ---------------------------------------------------------------------------
// Raw syscall wrappers
// ---------------------------------------------------------------------------

namespace raw {

    inline long sys_openat(const char *path, int flags) {
        return syscall(SYS_openat, AT_FDCWD, path, flags);
    }

    inline long sys_read(int fd, void *buf, size_t count) {
        return syscall(SYS_read, fd, buf, count);
    }

    inline long sys_close(int fd) {
        return syscall(SYS_close, fd);
    }

// faccessat is clutch here. open() bombs out with permission errors
// on those 0700 root-only paths, but faccessat checks existence without
// needing read access—exactly what we need for the root/busybox lists below.
    inline bool fileExistsRaw(const char *path) {
        return syscall(SYS_faccessat, AT_FDCWD, path, F_OK, 0) == 0;
    }

// Reads a whole file using raw syscalls (returns "" on failure).
// Capped at maxBytes so we don't get stuck reading forever on pseudo-files
// like /proc/self/maps that keep growing.
    std::string readFileRaw(const char *path, size_t maxBytes = 262144) {
        std::string out;
        long fd = sys_openat(path, O_RDONLY);
        if (fd < 0) return out;

        char buf[4096];
        long n;
        while (out.size() < maxBytes &&
               (n = sys_read(static_cast<int>(fd), buf, sizeof(buf))) > 0) {
            out.append(buf, static_cast<size_t>(n));
        }
        sys_close(static_cast<int>(fd));
        return out;
    }

}

// ---------------------------------------------------------------------------
// 1. Check TracerPid via syscall. Catches gdb/lldb/strace easily,
// though it's a weak signal for Frida since it only ptraces briefly on inject.
// ---------------------------------------------------------------------------
bool nativeIsTraced() {
    std::string status = raw::readFileRaw("/proc/self/status");
    if (status.empty()) return false;

    size_t pos = status.find("TracerPid:");
    if (pos == std::string::npos) return false;

    pos += strlen("TracerPid:");
    while (pos < status.size() && status[pos] == ' ') pos++;

    int pid = 0;
    while (pos < status.size() && status[pos] >= '0' && status[pos] <= '9') {
        pid = pid * 10 + (status[pos] - '0');
        pos++;
    }
    return pid != 0;
}

// ---------------------------------------------------------------------------
// 2. /proc/self/maps scan via raw syscall — looks for frida-agent,
//    frida-gadget, linjector, and generic "frida" substrings mapped into
//    this process's address space.
// ---------------------------------------------------------------------------
bool nativeMapsContainFrida() {
    std::string maps = raw::readFileRaw("/proc/self/maps", 1 << 20);
    if (maps.empty()) return false;

    static const char *needles[] = {
            "frida-agent", "frida-gadget", "linjector", "gum-js-loop", "frida"
    };
    for (const char *needle: needles) {
        if (maps.find(needle) != std::string::npos) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// 3. Scan thread names in /proc/self/task/<tid>/comm.
// Heads up: opendir/readdir are still libc calls, not raw syscalls.
// I used dirent here just to keep it readable—swap in SYS_getdents64
// if you need it 100% pure for production.
// ---------------------------------------------------------------------------
bool nativeHasSuspiciousThreads() {
    static const char *suspiciousNames[] = {
            "gum-js-loop", "gmain", "gdbus", "pool-frida", "pool-spawner"
    };

    DIR *dir = opendir("/proc/self/task");
    if (!dir) return false;

    bool found = false;
    struct dirent *entry;
    while (!found && (entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;

        std::string commPath = std::string("/proc/self/task/") + entry->d_name + "/comm";
        std::string name = raw::readFileRaw(commPath.c_str(), 64);
        while (!name.empty() && (name.back() == '\n' || name.back() == '\0')) {
            name.pop_back();
        }

        for (const char *sus: suspiciousNames) {
            if (name == sus) {
                found = true;
                break;
            }
        }
    }
    closedir(dir);
    return found;
}

// ---------------------------------------------------------------------------
// 4. .text integrity check: compares in-memory function bytes to the on-disk .so.
// Inline hooks overwrite function starts with a jump, so mismatches flag tampering.
//
// Note: Covers our libs out of the box (or others via /proc/self/maps).
// Wire targetFunc and file path to protect anything else.
// ---------------------------------------------------------------------------
bool nativeTextRegionModified(void *targetFunc, const char *soPath,
                              uint64_t fileOffset, size_t compareBytes) {
    if (!targetFunc || !soPath) return false;

    std::string fileBytes = raw::readFileRaw(soPath, fileOffset + compareBytes + 1);
    if (fileBytes.size() < fileOffset + compareBytes) return false;

    const uint8_t *inMemory = reinterpret_cast<const uint8_t *>(targetFunc);
    const uint8_t *onDisk =
            reinterpret_cast<const uint8_t *>(fileBytes.data()) + fileOffset;

    return memcmp(inMemory, onDisk, compareBytes) != 0;
}

// ---------------------------------------------------------------------------
// 5. Hook heuristic: checks for the ARM64 "LDR X16, #8 ; BR X16" jump
// pattern that frameworks like Frida use for inline hooking.
// Just a hint, not hard proof—clean code can occasionally look like this.
// ---------------------------------------------------------------------------
#if defined(__aarch64__)
bool nativeLooksLikeArm64Trampoline(void* funcPtr) {
    if (!funcPtr) return false;
    auto* instr = reinterpret_cast<const uint32_t*>(funcPtr);

    // LDR X16, #8  == 0x58000050  (load PC-relative literal into x16)
    // BR  X16      == 0xD61F0200  (branch to register x16)
    bool ldrX16 = (instr[0] & 0xFF00001FU) == (0x58000010U | 16U);
    bool brX16  = (instr[1] == 0xD61F0200U);
    return ldrX16 && brX16;
}
#endif

// ---------------------------------------------------------------------------
// 6. dlopen vs /proc/self/maps check: if dlsym resolves a library
// but its path isn't in /proc/self/maps, someone's hooking dl* calls.
// ---------------------------------------------------------------------------
bool nativeDlMapsMismatch(const char *libName) {
    void *handle = dlopen(libName, RTLD_NOLOAD);
    if (!handle) return false; // not loaded at all — nothing to cross-check

    std::string maps = raw::readFileRaw("/proc/self/maps", 1 << 20);
    bool presentInMaps = maps.find(libName) != std::string::npos;

    dlclose(handle);
    return !presentInMaps; // dlopen thinks it's loaded, raw maps disagree
}

// ---------------------------------------------------------------------------
// 7. SELF-PTRACE TRICK
// ---------------------------------------------------------------------------
// Ptrace check: only one tracer can hook a process. If PTRACE_TRACEME
// fails with EPERM, a debugger or injector is already attached.
// Run this early on a background thread.
//
// Heads up: if it succeeds, you just traced yourself. Detach immediately
// (PTRACE_DETACH) or crash reporters will break.
//
// Alternative: fork a child to try attaching to the parent. If the child
// fails, you know the parent is already watched.
#include <sys/ptrace.h>

bool nativeIsAlreadyTraced() {
    long result = syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0);
    if (result == -1) {
        // EPERM (already traced) vs other errno — either way, trust it.
        return true;
    }
    // We succeeded in tracing ourselves; detach immediately so we don't
    // interfere with normal process behavior (ANR/crash reporting, etc).
    syscall(SYS_ptrace, PTRACE_DETACH, 0, 0, 0);
    return false;
}

// ---------------------------------------------------------------------------
// 8. EXECUTABLE ANONYMOUS MEMORY SCAN
// ---------------------------------------------------------------------------
// Look for anonymous executable memory (RWX/RX). Frida and JIT tools
// need this for trampolines. Clean apps don't do this—ART uses named
// caches like `/memfd:jit-cache`—so an unnamed executable region is a strong signal.
bool nativeHasExecutableAnonRegion() {
    std::string maps = raw::readFileRaw("/proc/self/maps", 1 << 20);
    if (maps.empty()) return false;

    size_t pos = 0;
    while (pos < maps.size()) {
        size_t lineEnd = maps.find('\n', pos);
        if (lineEnd == std::string::npos) lineEnd = maps.size();
        std::string line = maps.substr(pos, lineEnd - pos);
        pos = lineEnd + 1;

        // Permission field is the second whitespace-delimited column, e.g.
        // "7f1234000000-7f1234001000 rwxp 00000000 00:00 0"
        size_t spacePos = line.find(' ');
        if (spacePos == std::string::npos) continue;
        size_t permEnd = line.find(' ', spacePos + 1);
        if (permEnd == std::string::npos) continue;
        std::string perms = line.substr(spacePos + 1, permEnd - spacePos - 1);

        bool executable = perms.size() >= 3 && perms[2] == 'x';
        bool writable = perms.size() >= 2 && perms[1] == 'w';
        bool anonymous = line.find("/dev/") == std::string::npos &&
                         line.find(".so") == std::string::npos &&
                         line.find(".dex") == std::string::npos &&
                         line.find("/memfd:") == std::string::npos &&
                         line.find("/system/") == std::string::npos &&
                         line.find("/data/app/") == std::string::npos;

        if (executable && writable && anonymous) return true; // W^X violation
    }
    return false;
}

// ---------------------------------------------------------------------------
// 9. /proc/self/environ SCAN
// ---------------------------------------------------------------------------
// Check for leftover env vars like LD_PRELOAD or FRIDA_* from spawn-gating.
// Attackers can easily strip these, so it's a weak signal, but it's cheap to run.
bool nativeEnvironContainsFrida() {
    std::string environ_ = raw::readFileRaw("/proc/self/environ", 1 << 16);
    if (environ_.empty()) return false;
    return environ_.find("frida") != std::string::npos ||
           environ_.find("FRIDA") != std::string::npos ||
           environ_.find("linjector") != std::string::npos;
}

// ---------------------------------------------------------------------------
// 10. /proc/net/unix SCAN FOR FRIDA'S CONTROL SOCKET
// ---------------------------------------------------------------------------
// Frida uses Unix domain sockets alongside TCP. Its abstract sockets
// (starting with `@`) often have giveaway names we can scan for.
bool nativeUnixSocketsSuspicious() {
    std::string netUnix = raw::readFileRaw("/proc/net/unix", 1 << 16);
    if (netUnix.empty()) return false;
    return netUnix.find("frida") != std::string::npos ||
           netUnix.find("gum-js") != std::string::npos ||
           netUnix.find("re.frida") != std::string::npos;
}

// ---------------------------------------------------------------------------
// 11. CROSS-CHECK: raw read of /proc/self/maps vs /proc/<pid>/maps
// ---------------------------------------------------------------------------
// Hooks often target `/proc/self/...` while missing `/proc/<pid>/...` (or vice versa).
// Reading both and comparing them catches this trick—if lengths or contents
// don't match up, someone's selectively filtering paths.
bool nativeMapsReadMismatch() {
    std::string viaSelf = raw::readFileRaw("/proc/self/maps", 1 << 20);

    pid_t pid = getpid();
    char pidPath[64];
    snprintf(pidPath, sizeof(pidPath), "/proc/%d/maps", pid);
    std::string viaPid = raw::readFileRaw(pidPath, 1 << 20);

    if (viaSelf.empty() || viaPid.empty()) return false; // inconclusive

    bool selfHasFrida = viaSelf.find("frida") != std::string::npos;
    bool pidHasFrida = viaPid.find("frida") != std::string::npos;
    if (selfHasFrida != pidHasFrida) return true; // one path is being filtered

    long diff = static_cast<long>(viaSelf.size()) - static_cast<long>(viaPid.size());
    return (diff > 4096 || diff < -4096);
}

// ---------------------------------------------------------------------------
// 12. D-Bus port sweep: catches frida-server even if renamed and moved to a custom port.
// ---------------------------------------------------------------------------
// Attackers easily change binary names or ports, but the D-Bus protocol stays
// the same—frida-server always replies "REJECTED" to a bare AUTH probe.
// Instead of checking port 27042, we scan listening localhost ports from
// `/proc/net/tcp` and test them. Behavioral fingerprinting beats name checks.
//
// Note: Bounded and must run on a background thread.
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace {

    std::vector<int> parseListeningPorts(const std::string &procNetTcp) {
        std::vector<int> ports;
        size_t pos = procNetTcp.find('\n'); // skip header line
        if (pos == std::string::npos) return ports;
        pos += 1;

        while (pos < procNetTcp.size()) {
            size_t lineEnd = procNetTcp.find('\n', pos);
            if (lineEnd == std::string::npos) lineEnd = procNetTcp.size();
            std::string line = procNetTcp.substr(pos, lineEnd - pos);
            pos = lineEnd + 1;

            // Columns are whitespace-separated; col[1] = "local_addr:port" hex,
            // col[3] = connection state hex ("0A" == TCP_LISTEN).
            std::vector<std::string> cols;
            size_t c = 0;
            while (c < line.size()) {
                while (c < line.size() && line[c] == ' ') c++;
                size_t start = c;
                while (c < line.size() && line[c] != ' ') c++;
                if (c > start) cols.push_back(line.substr(start, c - start));
            }
            if (cols.size() < 4) continue;

            const std::string &localAddr = cols[1];
            const std::string &state = cols[3];
            size_t colonPos = localAddr.find(':');
            if (colonPos == std::string::npos) continue;

            if (state == "0A") { // TCP_LISTEN
                int port = static_cast<int>(
                        strtol(localAddr.substr(colonPos + 1).c_str(), nullptr, 16));
                if (port > 0) ports.push_back(port);
            }
        }
        return ports;
    }

    bool probeDbusHandshake(int port) {
        int fd = static_cast<int>(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0));
        if (fd < 0) return false;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port));
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        timeval tv{0, 150000}; // 150ms
        syscall(SYS_setsockopt, fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        syscall(SYS_setsockopt, fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        long rc = syscall(SYS_connect, fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
        if (rc < 0) {
            syscall(SYS_close, fd);
            return false;
        }

        static const char probe[] = "\0AUTH\r\n";
        syscall(SYS_write, fd, probe, sizeof(probe) - 1);

        char buf[64] = {0};
        long n = syscall(SYS_read, fd, buf, sizeof(buf) - 1);
        syscall(SYS_close, fd);

        return n > 0 &&
               std::string(buf, static_cast<size_t>(n)).find("REJECTED") != std::string::npos;
    }
}

bool nativeAnyPortSpeaksFridaProtocol() {
    constexpr size_t MAX_PORTS_TO_PROBE = 40;

    std::string tcp4 = raw::readFileRaw("/proc/net/tcp", 1 << 18);
    std::string tcp6 = raw::readFileRaw("/proc/net/tcp6", 1 << 18);

    std::vector<int> ports = parseListeningPorts(tcp4);
    std::vector<int> ports6 = parseListeningPorts(tcp6);
    ports.insert(ports.end(), ports6.begin(), ports6.end());

    size_t probed = 0;
    for (int port: ports) {
        if (probed++ >= MAX_PORTS_TO_PROBE) break;
        // Skip obviously-benign well-known low ports to cut noise/latency;
        // frida-server defaults to high ports and custom -l values are
        // almost always >1024 too.
        if (port < 1024) continue;
        if (probeDbusHandshake(port)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// 13. Exported-symbol scan: catches frida-gadget.so even if renamed.
// ---------------------------------------------------------------------------
// Attackers can rename `.so` files to dodge string checks, but they can't easily
// hide the export table. Frida's core exports specific C symbols (like
// `gum_init_embedded` or `frida_agent_main`) so its own runtime can find them.
// Stripping those requires a custom source rebuild, way beyond a simple rename.
//
// We walk loaded libraries via dl_iterate_phdr (regardless of their file name)
// and dlsym this shortlist against each one.
#include <link.h>

namespace {

    const char *const kSuspiciousExports[] = {
            "frida_agent_main",
            "gum_init_embedded",
            "gum_interceptor_obtain",
            "gum_script_backend_obtain_qjs",
            "gum_process_get_current_thread_id",
            "gum_memory_scan",
    };

    struct ScanState {
        bool found = false;
    };

    int phdrCallback(struct dl_phdr_info *info, size_t, void *data) {
        auto *state = static_cast<ScanState *>(data);
        if (!info->dlpi_name || info->dlpi_name[0] == '\0') return 0; // skip the main exe

        void *handle = dlopen(info->dlpi_name, RTLD_NOLOAD | RTLD_LAZY);
        if (!handle) return 0; // couldn't re-resolve a handle for this mapping

        for (const char *symbol: kSuspiciousExports) {
            if (dlsym(handle, symbol) != nullptr) {
                state->found = true;
                dlclose(handle);
                return 1; // non-zero stops iteration early
            }
        }
        dlclose(handle);
        return 0;
    }

}

bool nativeAnyLoadedLibraryExportsGumSymbols() {
    ScanState state;
    dl_iterate_phdr(phdrCallback, &state);
    return state.found;
}

// ---------------------------------------------------------------------------
// 14. FD table scan. Files.readSymbolicLink() uses
// Java NIO and hits libc's readlink(), which hooks can easily spoof.
// ---------------------------------------------------------------------------
bool nativeSuspiciousFds() {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) return false;

    bool found = false;
    struct dirent *entry;
    char linkTarget[256];
    while (!found && (entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        std::string fdPath = std::string("/proc/self/fd/") + entry->d_name;
        long n = syscall(SYS_readlinkat, AT_FDCWD, fdPath.c_str(),
                         linkTarget, sizeof(linkTarget) - 1);
        if (n > 0) {
            linkTarget[n] = '\0';
            std::string target(linkTarget);
            if (target.find("frida") != std::string::npos ||
                target.find("linjector") != std::string::npos) {
                found = true;
            }
        }
    }
    closedir(dir);
    return found;
}

// ---------------------------------------------------------------------------
// 15. Root/Busybox checks. Java's File.exists()
// hits libc stat(), which is trivial to hook. Doing it here avoids that trap.
// ---------------------------------------------------------------------------
bool nativeLooksRooted() {
    static const char *paths[] = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
            "/system/app/Superuser.apk", "/data/adb/magisk", "/data/adb/magisk.db",
            "/sbin/.magisk", "/cache/.disable_magisk", "/dev/.magisk.unblock"
    };
    for (const char *p: paths) {
        if (raw::fileExistsRaw(p)) return true;
    }

    // Magisk mount-namespace artifact. Weak/version-fragile signal, same
    // caveat as before: Magisk's DenyList actively tries to scrub this for targeted apps, so a miss here proves nothing.
    std::string mountinfo = raw::readFileRaw("/proc/self/mountinfo", 1 << 17);
    return mountinfo.find("magisk") != std::string::npos;
}

bool nativeBusyboxPresent() {
    static const char *paths[] = {
            "/system/xbin/busybox", "/system/bin/busybox", "/sbin/busybox"
    };
    for (const char *p: paths) {
        if (raw::fileExistsRaw(p)) return true;
    }
    return false;
}


// ---------------------------------------------------------------------------
// 16. USB PHYSICAL CONNECTION STATE
// ---------------------------------------------------------------------------
bool nativeUsbConnected() {
    static const char* candidatePaths[] = {
            "/sys/class/power_supply/usb/online",
            "/sys/class/power_supply/usb/present",
            "/sys/class/android_usb/android0/state", // value "CONFIGURED" when connected
    };

    for (const char* path : candidatePaths) {
        std::string content = raw::readFileRaw(path, 64);
        if (content.empty()) continue;

        if (content.find("CONFIGURED") != std::string::npos) return true;
        if (!content.empty() && content[0] == '1') return true;
    }
    return false;
}


#include <sys/system_properties.h>

// ---------------------------------------------------------------------------
// 17. BUILD-LEVEL DEBUG FLAG (supplements DebugChecks.isDeveloperOptionsEnabled,
//     which only reads a user-toggleable Settings.Global value)
// ---------------------------------------------------------------------------
bool nativeRoDebuggableSet() {
    char value[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.debuggable", value);
    return value[0] == '1';
}

// ---------------------------------------------------------------------------
// JNI bridge for codeasus.projects.sentinel.sdk.SentinelSdk.
// ---------------------------------------------------------------------------

extern "C" {

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeTamperingDetector_isTraced(JNIEnv *, jobject) {
    return nativeIsTraced() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeTamperingDetector_mapsContainFrida(JNIEnv *, jobject) {
    return nativeMapsContainFrida() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeTamperingDetector_hasSuspiciousThreads(JNIEnv *, jobject) {
    return nativeHasSuspiciousThreads() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_SentinelSdk_dlMapsMismatch(JNIEnv *env, jobject, jstring libName) {
    const char *name = env->GetStringUTFChars(libName, nullptr);
    bool result = nativeDlMapsMismatch(name);
    env->ReleaseStringUTFChars(libName, name);
    return result ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeTamperingDetector_isAlreadyTraced(JNIEnv *, jobject) {
    return nativeIsAlreadyTraced() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeTamperingDetector_hasExecutableAnonRegion(JNIEnv *, jobject) {
    return nativeHasExecutableAnonRegion() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeTamperingDetector_environContainsFrida(JNIEnv *, jobject) {
    return nativeEnvironContainsFrida() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeTamperingDetector_unixSocketsSuspicious(JNIEnv *, jobject) {
    return nativeUnixSocketsSuspicious() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeTamperingDetector_mapsReadMismatch(JNIEnv *, jobject) {
    return nativeMapsReadMismatch() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeTamperingDetector_anyPortSpeaksFridaProtocol(JNIEnv *, jobject) {
    return nativeAnyPortSpeaksFridaProtocol() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeTamperingDetector_anyLoadedLibraryExportsGumSymbols(JNIEnv *, jobject) {
    return nativeAnyLoadedLibraryExportsGumSymbols() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeTamperingDetector_suspiciousFds(JNIEnv *, jobject) {
    return nativeSuspiciousFds() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeTamperingDetector_looksRooted(JNIEnv *, jobject) {
    return nativeLooksRooted() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeTamperingDetector_busyboxPresent(JNIEnv *, jobject) {
    return nativeBusyboxPresent() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeTamperingDetector_usbConnected(JNIEnv*, jobject) {
    return nativeUsbConnected() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeTamperingDetector_roDebuggableSet(JNIEnv*, jobject) {
    return nativeRoDebuggableSet() ? JNI_TRUE : JNI_FALSE;
}

// Aggregate score, mirroring the Kotlin-side TamperDetector weights so, native and JVM signals can be combined server-side into one payload.
JNIEXPORT jint JNICALL Java_codeasus_projects_sentinel_sdk_NativeTamperingDetector_checkSuspiciousActivities(JNIEnv *, jobject) {
    int score = 0;
    if (nativeIsTraced()) score += 3;
    if (nativeMapsContainFrida()) score += 5;
    if (nativeHasSuspiciousThreads()) score += 2;
    if (nativeIsAlreadyTraced()) score += 4;
    if (nativeHasExecutableAnonRegion()) score += 4;
    if (nativeEnvironContainsFrida()) score += 3;
    if (nativeUnixSocketsSuspicious()) score += 4;
    if (nativeMapsReadMismatch()) score += 4;
    if (nativeAnyPortSpeaksFridaProtocol()) score += 5; // survives rename+custom port
    if (nativeAnyLoadedLibraryExportsGumSymbols()) score += 5; // survives .so rename
    if (nativeSuspiciousFds()) score += 3;
    if (nativeLooksRooted()) score += 2;
    if (nativeBusyboxPresent()) score += 1;
    if (nativeUsbConnected()) score += 1; // It is a weak signal but still :)
    return score;
}
}