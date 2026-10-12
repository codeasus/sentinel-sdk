// Note: Some help from a LLM model has been used to develop this native library but it is mostly a honest work, haha...
// While I can read and write C++ from basic to mediocre level, I am no expert!
// Additionally, not all of these methods have been tested due to time constraints, the time it takes to setup different mobile environments, lack of different devices and so on.

#include <jni.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <string>
#include <vector>
#include <dirent.h>

namespace raw_net {

    inline long sys_openat(const char* path, int flags) {
        return syscall(SYS_openat, AT_FDCWD, path, flags);
    }

    inline long sys_read(int fd, void* buf, size_t count) {
        return syscall(SYS_read, fd, buf, count);
    }

    inline long sys_close(int fd) {
        return syscall(SYS_close, fd);
    }

    std::string readFileRaw(const char* path, size_t maxBytes = 131072) {
        std::string out;
        long fd = sys_openat(path, O_RDONLY);
        if (fd < 0) return out;

        char buf[2048];
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
// 1. TUNNEL/VPN INTERFACE PRESENCE
// ---------------------------------------------------------------------------
// /proc/net/dev lists every network interface with its traffic counters.
// Most on-device capture tools work by starting Android's VPNService,
// which creates a tun-style interface — true even though no "VPN" in the
// traditional sense is involved; it's simply how Android lets an app see
// all outbound packets without root.
bool nativeTunnelInterfaceActive() {
    std::string dev = raw_net::readFileRaw("/proc/net/dev");
    if (dev.empty()) return false;
    return dev.find("tun0") != std::string::npos ||
           dev.find("tun1") != std::string::npos ||
           dev.find("ppp0") != std::string::npos;
}

// ---------------------------------------------------------------------------
// 2. DEFAULT ROUTE VIA A TUNNEL INTERFACE
// ---------------------------------------------------------------------------
// /proc/net/route lists the kernel routing table; the default route has
// Destination "00000000". If that specific route's interface is a
// tun/ppp device, ALL outbound traffic is currently funneled through a
// capture/VPN layer — a stronger signal than interface presence alone,
// since a tun interface can exist without being the active route (e.g. a
// configured-but-disconnected VPN profile).
bool nativeDefaultRouteViaTunnel() {
    std::string route = raw_net::readFileRaw("/proc/net/route");
    if (route.empty()) return false;

    size_t pos = route.find('\n'); // skip header line
    if (pos == std::string::npos) return false;
    pos += 1;

    while (pos < route.size()) {
        size_t lineEnd = route.find('\n', pos);
        if (lineEnd == std::string::npos) lineEnd = route.size();
        std::string line = route.substr(pos, lineEnd - pos);
        pos = lineEnd + 1;

        // Columns are whitespace/tab separated:
        // Iface Destination Gateway Flags RefCnt Use Metric Mask ...
        std::vector<std::string> cols;
        size_t c = 0;
        while (c < line.size()) {
            while (c < line.size() && (line[c] == ' ' || line[c] == '\t')) c++;
            size_t start = c;
            while (c < line.size() && line[c] != ' ' && line[c] != '\t') c++;
            if (c > start) cols.push_back(line.substr(start, c - start));
        }
        if (cols.size() < 2) continue;

        const std::string& iface = cols[0];
        const std::string& dest = cols[1];
        if (dest == "00000000" &&
            (iface.find("tun") != std::string::npos ||
             iface.find("ppp") != std::string::npos)) {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// 3. KNOWN ON-DEVICE CAPTURE PROCESS SCAN
// ---------------------------------------------------------------------------
// Walks every numeric entry in /proc (i.e. every PID) and raw-reads its
// cmdline, looking for known capture-tool binary names. Only meaningful on
// a rooted device where such a binary can run locally at all — see the
// file-level scope caveat at the top.
bool nativeKnownCaptureProcessRunning() {
    static const char* needles[] = {
            "tcpdump", "mitmdump", "mitmproxy", "ssldump", "burpsuite", "tshark"
    };

    DIR* dir = opendir("/proc");
    if (!dir) return false;

    bool found = false;
    struct dirent* entry;
    while (!found && (entry = readdir(dir)) != nullptr) {
        const char* name = entry->d_name;
        bool numeric = name[0] != '\0';
        for (const char* p = name; *p; ++p) {
            if (*p < '0' || *p > '9') { numeric = false; break; }
        }
        if (!numeric) continue;

        std::string cmdlinePath = std::string("/proc/") + name + "/cmdline";
        std::string cmdline = raw_net::readFileRaw(cmdlinePath.c_str(), 4096);
        if (cmdline.empty()) continue;

        for (const char* needle : needles) {
            if (cmdline.find(needle) != std::string::npos) { found = true; break; }
        }
    }
    closedir(dir);
    return found;
}

// ---------------------------------------------------------------------------
// JNI bridge
// ---------------------------------------------------------------------------
extern "C" {

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeNetworkInterceptor_tunnelInterfaceActive(
        JNIEnv*, jobject) {
    return nativeTunnelInterfaceActive() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeNetworkInterceptor_defaultRouteViaTunnel(
        JNIEnv*, jobject) {
    return nativeDefaultRouteViaTunnel() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_codeasus_projects_sentinel_sdk_NativeNetworkInterceptor_knownCaptureProcessRunning(
        JNIEnv*, jobject) {
    return nativeKnownCaptureProcessRunning() ? JNI_TRUE : JNI_FALSE;
}

}