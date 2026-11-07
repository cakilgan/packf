// packf - pack many text files into one single text file (NOT an archive).
//
// Build (Linux / macOS):   g++ -O2 -std=c++17 -pthread -o packf packf.cpp
//   (GCC 8 additionally needs -lstdc++fs)
// Build (Windows MinGW):   g++ -O2 -std=c++17 -o packf.exe packf.cpp -lshell32
// Build (Windows MSVC):    cl /O2 /std:c++17 /EHsc packf.cpp shell32.lib
//

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <new>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#define popen _popen
#define pclose _pclose
typedef struct _stat64 pf_stat_t;
#define PF_FSTAT _fstat64
#define PF_FILENO _fileno
#define PF_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#else
#include <csignal>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
typedef struct stat pf_stat_t;
#define PF_FSTAT fstat
#define PF_FILENO fileno
#define PF_ISREG(m) S_ISREG(m)
#endif

namespace fs = std::filesystem;

static const char* kVersion = "1.0.0";
static const size_t kSniff = 8192;                 // bytes inspected for text/binary detection
static const uint64_t kInflightBudget = 256ull << 20;  // soft cap of buffered, not yet written data

// ============================================================ platform glue

#ifdef _WIN32
static std::wstring widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}
static std::string narrow(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}
static fs::path P(const std::string& s) { return fs::path(widen(s)); }
static std::string U(const fs::path& p) { return narrow(p.wstring()); }
#else
static fs::path P(const std::string& s) { return fs::path(s); }
static std::string U(const fs::path& p) { return p.string(); }
#endif

static std::vector<std::string> get_args(int argc, char** argv) {
#ifdef _WIN32
    int wn = 0;
    LPWSTR* wv = CommandLineToArgvW(GetCommandLineW(), &wn);
    if (wv) {
        std::vector<std::string> v;
        for (int i = 0; i < wn; ++i) v.push_back(narrow(wv[i]));
        LocalFree(wv);
        return v;
    }
#endif
    return std::vector<std::string>(argv, argv + argc);
}

static FILE* open_rb(const std::string& path) {
#ifdef _WIN32
    return _wfopen(widen(path).c_str(), L"rb");
#else
    return std::fopen(path.c_str(), "rb");
#endif
}

static FILE* open_wb(const std::string& path) {
#ifdef _WIN32
    return _wfopen(widen(path).c_str(), L"wb");
#else
    return std::fopen(path.c_str(), "wb");
#endif
}

static std::string errmsg(int e) { return std::error_code(e, std::generic_category()).message(); }

static void warn(const std::string& m) { std::fprintf(stderr, "packf: %s\n", m.c_str()); }

// ============================================================ small utilities

// Minimal malloc-backed byte buffer: no zero-fill, movable, cheap to grow.
struct Buf {
    char* p = nullptr;
    size_t n = 0, cap = 0;
    Buf() = default;
    Buf(const Buf&) = delete;
    Buf& operator=(const Buf&) = delete;
    Buf(Buf&& o) noexcept : p(o.p), n(o.n), cap(o.cap) { o.p = nullptr; o.n = o.cap = 0; }
    Buf& operator=(Buf&& o) noexcept {
        if (this != &o) { std::free(p); p = o.p; n = o.n; cap = o.cap; o.p = nullptr; o.n = o.cap = 0; }
        return *this;
    }
    ~Buf() { std::free(p); }
    void reserve(size_t c) {
        if (c <= cap) return;
        size_t nc = cap * 2;
        if (nc < c) nc = c;
        if (nc < 64) nc = 64;
        char* q = (char*)std::realloc(p, nc);
        if (!q) throw std::bad_alloc();
        p = q;
        cap = nc;
    }
};

static std::string lower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    return s;
}

static std::string base_of(const std::string& path) {
    size_t s = path.find_last_of('/');
    return s == std::string::npos ? path : path.substr(s + 1);
}

// Extension of a *base name*, lower-cased, without dot. ".bashrc" has none.
static std::string ext_of(const std::string& name) {
    size_t dot = name.rfind('.');
    if (dot == std::string::npos || dot == 0) return std::string();
    return lower(name.substr(dot + 1));
}

static std::string human(uint64_t b) {
    static const char* u[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = (double)b;
    int k = 0;
    while (v >= 1024.0 && k < 4) { v /= 1024.0; ++k; }
    char buf[48];
    if (k == 0) std::snprintf(buf, sizeof buf, "%llu B", (unsigned long long)b);
    else std::snprintf(buf, sizeof buf, "%.1f %s", v, u[k]);
    return buf;
}

// ============================================================ options

enum class Eol { Keep, LF, CRLF };
enum class Enc { CP1252, CP1254, Latin1, ISO8859_9, Raw, Skip };
enum class SortMode { Natural, Name, None };

struct Filter { std::string ext, cmd; };

struct Opts {
    std::string output = "packed.txt";
    std::vector<std::string> inputs;
    std::unordered_set<std::string> ext_in, ext_out;
    std::vector<std::string> inc, exc;
    std::vector<Filter> filters;
    bool recurse = true, hidden = false, follow = false;
    bool header = true, header_custom = false, blank = true;
    std::string header_fmt;
    std::string close_tok;           // comment terminator that must not appear inside a header
    uint64_t max_size = 32ull << 20;
    Enc enc = Enc::CP1252;
    Eol eol = Eol::Keep;
    SortMode sort = SortMode::Natural;
    unsigned jobs = 0;
    bool list = false, verbose = false, quiet = false;
};
static Opts G;

// ============================================================ text detection / decoding

enum class Kind { Text, Utf16LE, Utf16BE, Binary };

static inline uint32_t rd16(const uint8_t* d, size_t k, bool be) {
    return be ? (uint32_t)(d[2 * k] << 8 | d[2 * k + 1]) : (uint32_t)(d[2 * k + 1] << 8 | d[2 * k]);
}

static bool utf16_sane(const uint8_t* d, size_t n, bool be) {
    size_t units = n / 2;
    for (size_t k = 0; k < units; ++k) {
        uint32_t u = rd16(d, k, be);
        if (u >= 0xD800 && u <= 0xDBFF) {
            if (k + 1 == units) break;  // pair cut by the end of the sample
            uint32_t v = rd16(d, k + 1, be);
            if (v < 0xDC00 || v > 0xDFFF) return false;
            ++k;
            continue;
        }
        if (u >= 0xDC00 && u <= 0xDFFF) return false;
        if (u == 0xFFFE || u == 0xFFFF) return false;
        if (u < 32 && u != '\t' && u != '\n' && u != '\r' && u != '\f' && u != '\v' && u != 27 && u != '\b')
            return false;  // also rejects NUL
    }
    return true;
}

// Classify a file from its first bytes. `skip` = BOM length to drop.
static Kind sniff(const uint8_t* d, size_t n, size_t& skip) {
    skip = 0;
    if (n >= 2 && d[0] == 0xFF && d[1] == 0xFE) {
        if (n >= 4 && d[2] == 0 && d[3] == 0) return Kind::Binary;  // UTF-32LE: unsupported
        skip = 2;
        return Kind::Utf16LE;
    }
    if (n >= 2 && d[0] == 0xFE && d[1] == 0xFF) { skip = 2; return Kind::Utf16BE; }
    if (n >= 3 && d[0] == 0xEF && d[1] == 0xBB && d[2] == 0xBF) skip = 3;

    size_t nul = 0, ne = 0, no = 0, ctrl = 0;
    for (size_t i = skip; i < n; ++i) {
        unsigned char c = d[i];
        if (c == 0) { ++nul; ((i & 1) ? no : ne)++; }
        else if (c < 32 ? (c != '\t' && c != '\n' && c != '\r' && c != '\f' && c != '\v' && c != 27 && c != '\b')
                        : c == 127) ++ctrl;
    }
    if (nul == 0) return ctrl * 20 > (n - skip) ? Kind::Binary : Kind::Text;  // >5% control bytes

    if (skip == 0 && n >= 4) {  // BOM-less UTF-16 (mostly-ASCII text only)
        size_t m = n & ~(size_t)1;
        if (ne * 32 <= no && no * 20 >= m && utf16_sane(d, m, false)) return Kind::Utf16LE;
        if (no * 32 <= ne && ne * 20 >= m && utf16_sane(d, m, true)) return Kind::Utf16BE;
    }
    return Kind::Binary;
}

// Strict UTF-8 validation with an 8-bytes-at-a-time ASCII fast path.
static bool utf8_valid(const uint8_t* s, size_t n) {
    size_t i = 0;
    while (i < n) {
        while (i + 8 <= n) {
            uint64_t w;
            std::memcpy(&w, s + i, 8);
            if (w & 0x8080808080808080ull) break;
            i += 8;
        }
        if (i >= n) break;
        uint8_t c = s[i];
        if (c < 0x80) { ++i; continue; }
        auto cont = [&](size_t k) { return k < n && (s[k] & 0xC0) == 0x80; };
        if (c >= 0xC2 && c <= 0xDF) {
            if (!cont(i + 1)) return false;
            i += 2;
        } else if (c == 0xE0) {
            if (!(i + 1 < n && s[i + 1] >= 0xA0 && s[i + 1] <= 0xBF && cont(i + 2))) return false;
            i += 3;
        } else if (c == 0xED) {
            if (!(i + 1 < n && s[i + 1] >= 0x80 && s[i + 1] <= 0x9F && cont(i + 2))) return false;
            i += 3;
        } else if ((c >= 0xE1 && c <= 0xEC) || c == 0xEE || c == 0xEF) {
            if (!(cont(i + 1) && cont(i + 2))) return false;
            i += 3;
        } else if (c == 0xF0) {
            if (!(i + 1 < n && s[i + 1] >= 0x90 && s[i + 1] <= 0xBF && cont(i + 2) && cont(i + 3))) return false;
            i += 4;
        } else if (c >= 0xF1 && c <= 0xF3) {
            if (!(cont(i + 1) && cont(i + 2) && cont(i + 3))) return false;
            i += 4;
        } else if (c == 0xF4) {
            if (!(i + 1 < n && s[i + 1] >= 0x80 && s[i + 1] <= 0x8F && cont(i + 2) && cont(i + 3))) return false;
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

static inline size_t put_utf8(uint8_t* d, uint32_t u) {  // returns bytes written
    if (u < 0x80) { d[0] = (uint8_t)u; return 1; }
    if (u < 0x800) { d[0] = (uint8_t)(0xC0 | (u >> 6)); d[1] = (uint8_t)(0x80 | (u & 0x3F)); return 2; }
    if (u < 0x10000) {
        d[0] = (uint8_t)(0xE0 | (u >> 12)); d[1] = (uint8_t)(0x80 | ((u >> 6) & 0x3F));
        d[2] = (uint8_t)(0x80 | (u & 0x3F));
        return 3;
    }
    d[0] = (uint8_t)(0xF0 | (u >> 18)); d[1] = (uint8_t)(0x80 | ((u >> 12) & 0x3F));
    d[2] = (uint8_t)(0x80 | ((u >> 6) & 0x3F)); d[3] = (uint8_t)(0x80 | (u & 0x3F));
    return 4;
}

static void utf16_to_utf8(const uint8_t* p, size_t n, bool be, Buf& out) {
    out.reserve(n / 2 * 3 + 8);
    uint8_t* d = (uint8_t*)out.p;
    size_t j = 0, units = n / 2;
    for (size_t k = 0; k < units; ++k) {
        uint32_t u = rd16(p, k, be);
        if (u < 0x80) { d[j++] = (uint8_t)u; continue; }
        if (u >= 0xD800 && u <= 0xDBFF) {
            uint32_t v = (k + 1 < units) ? rd16(p, k + 1, be) : 0;
            if (v >= 0xDC00 && v <= 0xDFFF) { u = 0x10000 + ((u - 0xD800) << 10) + (v - 0xDC00); ++k; }
            else u = 0xFFFD;
        } else if (u >= 0xDC00 && u <= 0xDFFF) {
            u = 0xFFFD;
        }
        j += put_utf8(d + j, u);
    }
    if (n & 1) j += put_utf8(d + j, 0xFFFD);
    out.n = j;
}

static uint16_t g_tab[128];  // 0x80..0xFF -> code point for the chosen legacy encoding

static void init_table(Enc e) {
    static const uint16_t w1252[32] = {
        0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
        0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178};
    for (int i = 0; i < 128; ++i) g_tab[i] = (uint16_t)(0x80 + i);
    if (e == Enc::CP1252 || e == Enc::CP1254)
        for (int i = 0; i < 32; ++i) g_tab[i] = w1252[i];
    if (e == Enc::CP1254) { g_tab[0x8E - 0x80] = 0x008E; g_tab[0x9E - 0x80] = 0x009E; }
    if (e == Enc::CP1254 || e == Enc::ISO8859_9) {  // the six Turkish letters
        g_tab[0xD0 - 0x80] = 0x011E; g_tab[0xDD - 0x80] = 0x0130; g_tab[0xDE - 0x80] = 0x015E;
        g_tab[0xF0 - 0x80] = 0x011F; g_tab[0xFD - 0x80] = 0x0131; g_tab[0xFE - 0x80] = 0x015F;
    }
}

static void legacy_to_utf8(const uint8_t* s, size_t n, Buf& out) {
    size_t hi = 0;
    for (size_t i = 0; i < n; ++i) hi += (size_t)(s[i] >> 7);
    out.reserve(n + 2 * hi + 1);
    uint8_t* d = (uint8_t*)out.p;
    size_t j = 0;
    for (size_t i = 0; i < n; ++i) {
        uint8_t c = s[i];
        if (c < 0x80) d[j++] = c;
        else j += put_utf8(d + j, g_tab[c - 0x80]);
    }
    out.n = j;
}

// Normalise line endings. Returns false when the input is already fine (no copy made).
static bool normalize_eol(const char* s, size_t n, Eol mode, Buf& out) {
    if (mode == Eol::LF) {
        if (!std::memchr(s, '\r', n)) return false;
    } else {
        if (!std::memchr(s, '\r', n) && !std::memchr(s, '\n', n)) return false;
    }
    size_t brk = 0;
    for (size_t i = 0; i < n; ++i) brk += (s[i] == '\n' || s[i] == '\r');
    out.reserve(mode == Eol::CRLF ? n + brk + 1 : n + 1);
    char* d = out.p;
    size_t j = 0, i = 0;
    while (i < n) {
        size_t k = i;
        while (k < n && s[k] != '\r' && s[k] != '\n') ++k;
        if (k > i) { std::memcpy(d + j, s + i, k - i); j += k - i; }
        if (k >= n) break;
        if (s[k] == '\r' && k + 1 < n && s[k + 1] == '\n') ++k;  // CRLF counts as one break
        if (mode == Eol::CRLF) d[j++] = '\r';
        d[j++] = '\n';
        i = k + 1;
    }
    out.n = j;
    return true;
}

// ============================================================ reading

enum class RdStatus { Ok, Err, TooBig, Binary, NotRegular };

struct FileCloser {
    FILE* f;
    ~FileCloser() { if (f) std::fclose(f); }
};

static RdStatus read_file(const std::string& path, bool allow_special, Buf& buf, Kind& kind, size_t& skip,
                          uint64_t& fsize, std::string& err) {
    FILE* f = open_rb(path);
    if (!f) { err = errmsg(errno); return RdStatus::Err; }
    FileCloser closer{f};
    std::setvbuf(f, nullptr, _IONBF, 0);  // we do our own big reads

    pf_stat_t sb;
    uint64_t size = 0;
    bool known = false;
    if (PF_FSTAT(PF_FILENO(f), &sb) == 0) {
        if (PF_ISREG(sb.st_mode)) { size = (uint64_t)sb.st_size; known = true; }
        else if (!allow_special) return RdStatus::NotRegular;
    }
    fsize = size;
    if (G.max_size && size > G.max_size) return RdStatus::TooBig;

    buf.reserve(known ? (size_t)size + 1 : 65536);
    auto fill = [&](size_t upto) -> bool {  // read until buf.n >= upto or EOF
        while (buf.n < upto) {
            size_t r = std::fread(buf.p + buf.n, 1, upto - buf.n, f);
            if (r == 0) return !std::ferror(f);
            buf.n += r;
        }
        return true;
    };

    size_t first = known ? (size_t)std::min<uint64_t>(size, kSniff) : kSniff;
    if (!fill(first)) { err = errmsg(errno); return RdStatus::Err; }
    kind = sniff((const uint8_t*)buf.p, std::min(buf.n, kSniff), skip);
    if (kind == Kind::Binary) return RdStatus::Binary;  // bail out before reading the rest

    if (known) {
        if (!fill((size_t)size)) { err = errmsg(errno); return RdStatus::Err; }
    } else {
        for (;;) {  // pipes, /proc files, ...: read to EOF
            if (buf.n == buf.cap) buf.reserve(buf.cap * 2);
            if (G.max_size && buf.n > G.max_size) { fsize = buf.n; return RdStatus::TooBig; }
            size_t r = std::fread(buf.p + buf.n, 1, buf.cap - buf.n, f);
            if (r == 0) {
                if (std::ferror(f)) { err = errmsg(errno); return RdStatus::Err; }
                break;
            }
            buf.n += r;
        }
        fsize = buf.n;
    }
    return RdStatus::Ok;
}

static std::string shell_quote(const std::string& s) {
#ifdef _WIN32
    return "\"" + s + "\"";
#else
    std::string r = "'";
    for (char c : s) { if (c == '\'') r += "'\\''"; else r += c; }
    r += "'";
    return r;
#endif
}

static RdStatus run_filter(const Filter& fl, const std::string& path, Buf& buf, uint64_t& fsize, std::string& err) {
    std::string p = path;
    if (!p.empty() && p[0] == '-') p = "./" + p;
    std::string q = shell_quote(p), cmd;
    if (fl.cmd.find("{}") == std::string::npos) {
        cmd = fl.cmd + " " + q;
    } else {
        for (size_t i = 0; i < fl.cmd.size();) {
            if (fl.cmd.compare(i, 2, "{}") == 0) { cmd += q; i += 2; }
            else cmd += fl.cmd[i++];
        }
    }
    FILE* pp = popen(cmd.c_str(), "r");
    if (!pp) { err = "cannot start filter: " + errmsg(errno); return RdStatus::Err; }
    buf.reserve(65536);
    bool toobig = false;
    for (;;) {
        if (buf.n == buf.cap) buf.reserve(buf.cap * 2);
        size_t r = std::fread(buf.p + buf.n, 1, buf.cap - buf.n, pp);
        if (r == 0) break;
        buf.n += r;
        if (G.max_size && buf.n > G.max_size) { toobig = true; break; }
    }
    int status = pclose(pp);
    fsize = buf.n;
    if (toobig) return RdStatus::TooBig;
#ifdef _WIN32
    int rc = status;
#else
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
#endif
    if (rc != 0) { err = "filter '" + fl.cmd + "' failed (exit " + std::to_string(rc) + ")"; return RdStatus::Err; }
    return RdStatus::Ok;
}

static const Filter* find_filter(const std::string& ext) {
    for (const auto& f : G.filters) if (f.ext == ext) return &f;
    return nullptr;
}

// ============================================================ per-file processing (runs in workers)

struct Item {
    std::string path;       // path used to open the file ('/' separators)
    uint32_t disp_off = 0;  // path.c_str()+disp_off is what we show (leading "./" stripped)
    bool is_explicit = false;
};

enum class St { Ok, SkipBinary, SkipBig, SkipEnc, SkipSpecial, Error };

struct Result {
    St st = St::Error;
    Buf data;               // final UTF-8 content lives at data.p+off, len bytes
    size_t off = 0, len = 0;
    char tail[2] = {0, 0};  // line terminator appended if the file didn't end with one
    unsigned tail_n = 0;
    std::string msg;
    uint64_t fsize = 0;
    uint64_t cost = 0;      // approx. memory held while waiting to be written
};

static void process_impl(const Item& it, Result& r) {
    Buf data;
    Kind kind = Kind::Text;
    size_t skip = 0;
    const Filter* flt = nullptr;
    if (!G.filters.empty()) flt = find_filter(ext_of(base_of(it.path)));

    RdStatus s;
    if (flt) {
        s = run_filter(*flt, it.path, data, r.fsize, r.msg);
        if (s == RdStatus::Ok) {
            kind = sniff((const uint8_t*)data.p, std::min(data.n, kSniff), skip);
            if (kind == Kind::Binary) s = RdStatus::Binary;
        }
    } else {
        s = read_file(it.path, it.is_explicit, data, kind, skip, r.fsize, r.msg);
    }
    switch (s) {
        case RdStatus::Ok: break;
        case RdStatus::Err: r.st = St::Error; return;
        case RdStatus::TooBig: r.st = St::SkipBig; return;
        case RdStatus::Binary: r.st = St::SkipBinary; return;
        case RdStatus::NotRegular: r.st = St::SkipSpecial; return;
    }

    size_t off = skip, len = data.n - skip;
    if (kind == Kind::Utf16LE || kind == Kind::Utf16BE) {
        Buf o;
        utf16_to_utf8((const uint8_t*)data.p + off, len, kind == Kind::Utf16BE, o);
        data = std::move(o);
        off = 0;
        len = data.n;
        if (len && std::memchr(data.p, 0, len)) { r.st = St::SkipBinary; return; }
    } else {
        if (len && std::memchr(data.p + off, 0, len)) { r.st = St::SkipBinary; return; }  // NUL after the sniffed prefix
        if (!utf8_valid((const uint8_t*)data.p + off, len)) {
            if (G.enc == Enc::Skip) { r.st = St::SkipEnc; return; }
            if (G.enc != Enc::Raw) {
                Buf o;
                legacy_to_utf8((const uint8_t*)data.p + off, len, o);
                data = std::move(o);
                off = 0;
                len = data.n;
            }
        }
    }

    if (G.eol != Eol::Keep && len) {
        Buf o;
        if (normalize_eol(data.p + off, len, G.eol, o)) {
            data = std::move(o);
            off = 0;
            len = data.n;
        }
    }

    // Make sure the next file never starts in the middle of this file's last line.
    if (len && data.p[off + len - 1] != '\n') {
        bool crlf;
        if (G.eol == Eol::CRLF) crlf = true;
        else if (G.eol == Eol::LF) crlf = false;
        else {
            const char* nl = (const char*)std::memchr(data.p + off, '\n', len);
            crlf = nl && nl > data.p + off && nl[-1] == '\r';
        }
        if (crlf) { r.tail[0] = '\r'; r.tail[1] = '\n'; r.tail_n = 2; }
        else { r.tail[0] = '\n'; r.tail_n = 1; }
    }

    r.data = std::move(data);
    r.off = off;
    r.len = len;
    r.cost = r.data.cap + 64;
    r.st = St::Ok;
}

static Result process(const Item& it) {
    Result r;
    try {
        process_impl(it, r);
    } catch (const std::bad_alloc&) {
        r.st = St::Error;
        r.msg = "out of memory";
    } catch (const std::exception& e) {
        r.st = St::Error;
        r.msg = e.what();
    }
    return r;
}

// ============================================================ header formatting

struct StyleRow { const char* exts; const char* open; const char* close; };
static const StyleRow kStyles[] = {
    {"c|h|cc|cpp|cxx|c++|hpp|hh|hxx|h++|inl|ipp|tpp|cu|cuh|cs|java|js|mjs|cjs|jsx|ts|tsx|go|rs|swift|kt|kts|scala|"
     "dart|php|proto|glsl|vert|frag|hlsl|mm|groovy|gradle|zig|jsonc|json5",
     "// ", ""},
    {"py|sh|bash|zsh|fish|rb|pl|pm|r|yml|yaml|toml|cmake|mk|make|conf|cfg|properties|ps1|nim|ex|exs|tcl", "# ", ""},
    {"sql|lua|hs|ada|adb|ads|elm", "-- ", ""},
    {"lisp|el|clj|cljs|scm|ini", "; ", ""},
    {"tex|sty|cls|erl|hrl", "% ", ""},
    {"bat|cmd", "REM ", ""},
    {"html|htm|xhtml|xml|svg|xsl|xslt|vue|plist|csproj|xaml", "<!-- ", " -->"},
    {"css|scss|less", "/* ", " */"},
};

static bool in_list(const char* list, const std::string& e) {
    size_t le = e.size();
    for (const char* p = list; *p;) {
        const char* q = std::strchr(p, '|');
        size_t l = q ? (size_t)(q - p) : std::strlen(p);
        if (l == le && std::memcmp(p, e.data(), l) == 0) return true;
        if (!q) break;
        p = q + 1;
    }
    return false;
}

// Default header: a comment in the output language when we know it, plain text otherwise.
static void default_header(const std::string& out_ext) {
    std::string open, close;
    for (const auto& s : kStyles)
        if (in_list(s.exts, out_ext)) { open = s.open; close = s.close; break; }
    G.header_fmt = open + "===== %p =====" + close;
    size_t b = close.find_first_not_of(' ');
    G.close_tok = b == std::string::npos ? std::string() : close.substr(b);
}

static void defuse(std::string& s, const std::string& tok) {  // "*/" -> "* /"
    if (tok.size() < 2) return;
    std::string rep = tok.substr(0, tok.size() - 1) + " " + tok.back();
    for (size_t pos = 0; (pos = s.find(tok, pos)) != std::string::npos; pos += rep.size()) s.replace(pos, tok.size(), rep);
}

static std::string make_header(const char* path, uint64_t idx, uint64_t size) {
    std::string p = path;
    std::string name = base_of(p);
    if (!G.close_tok.empty()) { defuse(p, G.close_tok); defuse(name, G.close_tok); }
    const std::string& f = G.header_fmt;
    std::string out;
    out.reserve(f.size() + p.size() + 16);
    for (size_t i = 0; i < f.size(); ++i) {
        if (f[i] == '%' && i + 1 < f.size()) {
            char c = f[++i];
            switch (c) {
                case 'p': out += p; break;
                case 'n': out += name; break;
                case 'i': out += std::to_string(idx); break;
                case 's': out += std::to_string(size); break;
                case '%': out += '%'; break;
                default: out += '%'; out += c;
            }
        } else {
            out += f[i];
        }
    }
    out += '\n';
    return out;
}

// ============================================================ glob matching

// '*' any run without '/', '**' anything (incl. '/'), '**/' zero or more directories,
// '?' one char, '[a-z]' / '[!a-z]' classes.
static bool glob(const char* p, const char* s) {
    for (;;) {
        switch (*p) {
            case '\0': return *s == '\0';
            case '*': {
                if (p[1] == '*') {
                    const char* q = p + 2;
                    while (*q == '*') ++q;
                    bool seg = (*q == '/');
                    if (seg) ++q;
                    for (const char* t = s;; ++t) {
                        if ((!seg || t == s || t[-1] == '/') && glob(q, t)) return true;
                        if (!*t) return false;
                    }
                }
                ++p;
                for (const char* t = s;; ++t) {
                    if (glob(p, t)) return true;
                    if (!*t || *t == '/') return false;
                }
            }
            case '?':
                if (!*s || *s == '/') return false;
                ++p; ++s;
                break;
            case '[': {
                const char* q = p + 1;
                bool neg = (*q == '!' || *q == '^');
                if (neg) ++q;
                bool ok = false, first = true;
                while (*q && (*q != ']' || first)) {
                    first = false;
                    unsigned char lo = (unsigned char)*q, hi = lo;
                    if (q[1] == '-' && q[2] && q[2] != ']') { hi = (unsigned char)q[2]; q += 3; }
                    else ++q;
                    if ((unsigned char)*s >= lo && (unsigned char)*s <= hi) ok = true;
                }
                if (*q != ']') {  // unterminated: literal '['
                    if (*s != '[') return false;
                    ++p; ++s;
                    break;
                }
                if (!*s || *s == '/' || ok == neg) return false;
                p = q + 1;
                ++s;
                break;
            }
            default:
                if (*p != *s) return false;
                ++p; ++s;
        }
    }
}

static bool pat_match(const std::string& pat, const std::string& name, const char* disp) {
    return glob(pat.c_str(), pat.find('/') != std::string::npos ? disp : name.c_str());
}

// ============================================================ collecting files

struct Stats {
    size_t packed = 0, bin = 0, big = 0, enc = 0, special = 0, err = 0;
    uint64_t bytes = 0;
};

static std::unordered_set<std::string> g_binext;
static std::string g_out_name, g_tmp_name;
static fs::path g_out_canon;

static void init_binext() {
    static const char* e[] = {
        "o", "obj", "a", "lib", "so", "dll", "dylib", "exe", "bin", "class", "jar", "war", "zip", "gz", "tgz", "bz2",
        "xz", "7z", "rar", "zst", "lz4", "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "tif", "tiff", "heic",
        "mp3", "mp4", "mkv", "avi", "mov", "wav", "flac", "ogg", "webm", "m4a", "pdf", "doc", "xls", "ppt", "docx",
        "xlsx", "pptx", "odt", "ods", "odp", "ttf", "otf", "woff", "woff2", "eot", "pyc", "pyo", "iso", "img", "dmg",
        "pdb", "ilk", "lock", "sqlite", "sqlite3", "pack", "idx", "swp"};
    for (const char* x : e) g_binext.insert(x);
}

static bool is_output_file(const std::string& name, const std::string& path) {
    if (g_out_name.empty()) return false;
    if (name == g_tmp_name) return true;
    if (name != g_out_name) return false;
    std::error_code ec;
    fs::path c = fs::weakly_canonical(P(path), ec);
    return !ec && c == g_out_canon;
}

static bool natless(const std::string& a, const std::string& b);

static size_t leading_dots(const std::string& p) {
    if (p == ".") return 2;  // children are "./x"
    size_t k = 0;
    while (p.size() >= k + 2 && p[k] == '.' && p[k + 1] == '/') k += 2;
    return k;
}

static std::string join(const std::string& dir, const std::string& name) {
    return (!dir.empty() && dir.back() == '/') ? dir + name : dir + "/" + name;
}

static bool accept_walked_file(const std::string& name, const std::string& child, const char* disp, Stats& st) {
    std::string ext = ext_of(name);
    if (!G.ext_in.empty() && !G.ext_in.count(ext)) return false;
    if (G.ext_out.count(ext)) return false;
    for (const auto& pat : G.exc) if (pat_match(pat, name, disp)) return false;
    if (!G.inc.empty()) {
        bool any = false;
        for (const auto& pat : G.inc) if (pat_match(pat, name, disp)) { any = true; break; }
        if (!any) return false;
    }
    if (G.ext_in.empty() && g_binext.count(ext) && !(!G.filters.empty() && find_filter(ext))) {
        ++st.bin;  // known binary type: don't even open it
        return false;
    }
    if (is_output_file(name, child)) return false;
    return true;
}

struct Walker {
    std::vector<Item>& items;
    Stats& st;
    std::vector<std::string> stack;  // canonical paths of the directories being scanned (--follow-symlinks only)

    void dir(const std::string& path, size_t disp_off) {
        std::error_code ec;
        if (G.follow) {
            std::string c = U(fs::canonical(P(path), ec));
            if (!ec) {
                if (std::find(stack.begin(), stack.end(), c) != stack.end()) return;  // symlink loop
                stack.push_back(c);
                struct Pop { std::vector<std::string>& s; ~Pop() { s.pop_back(); } } pop{stack};
                scan(path, disp_off);
                return;
            }
            ec.clear();
        }
        scan(path, disp_off);
    }

    void scan(const std::string& path, size_t disp_off) {
        std::error_code ec;
        fs::directory_iterator it(P(path), ec);
        if (ec) { warn("cannot read directory '" + path + "': " + ec.message()); ++st.err; return; }

        std::vector<std::string> files, dirs;
        for (fs::directory_iterator end; it != end; it.increment(ec)) {
            if (ec) { warn("error while reading '" + path + "': " + ec.message()); ++st.err; break; }
            const fs::directory_entry& de = *it;
            std::string name = U(de.path().filename());
            if (name.empty() || (!G.hidden && name[0] == '.')) continue;
            std::error_code e2;
            bool isdir, isreg;
            if (de.is_symlink(e2)) {
                if (!G.follow) continue;
                fs::file_status s = fs::status(de.path(), e2);
                isdir = fs::is_directory(s);
                isreg = fs::is_regular_file(s);
            } else {
                isdir = de.is_directory(e2);
                isreg = !isdir && de.is_regular_file(e2);
            }
            if (isdir) dirs.push_back(std::move(name));
            else if (isreg) files.push_back(std::move(name));
        }
        if (G.sort == SortMode::Natural) {
            std::sort(files.begin(), files.end(), natless);
            std::sort(dirs.begin(), dirs.end(), natless);
        } else if (G.sort == SortMode::Name) {
            std::sort(files.begin(), files.end());
            std::sort(dirs.begin(), dirs.end());
        }

        for (const auto& name : files) {
            std::string child = join(path, name);
            if (!accept_walked_file(name, child, child.c_str() + disp_off, st)) continue;
            Item item;
            item.path = std::move(child);
            item.disp_off = (uint32_t)disp_off;
            items.push_back(std::move(item));
        }
        if (!G.recurse) return;
        for (const auto& name : dirs) {
            std::string child = join(path, name);
            const char* disp = child.c_str() + disp_off;
            bool skip = false;
            for (const auto& pat : G.exc) if (pat_match(pat, name, disp)) { skip = true; break; }
            if (!skip) dir(child, disp_off);
        }
    }
};

// Natural ordering: file2 < file10; ties fall back to byte order.
static bool natless(const std::string& a, const std::string& b) {
    size_t i = 0, j = 0;
    auto dig = [](char c) { return c >= '0' && c <= '9'; };
    while (i < a.size() && j < b.size()) {
        if (dig(a[i]) && dig(b[j])) {
            size_t si = i, sj = j;
            while (si < a.size() && a[si] == '0') ++si;
            while (sj < b.size() && b[sj] == '0') ++sj;
            size_t ei = si, ej = sj;
            while (ei < a.size() && dig(a[ei])) ++ei;
            while (ej < b.size() && dig(b[ej])) ++ej;
            size_t la = ei - si, lb = ej - sj;
            if (la != lb) return la < lb;
            int c = a.compare(si, la, b, sj, lb);
            if (c) return c < 0;
            size_t za = si - i, zb = sj - j;  // same value: fewer leading zeros first
            if (za != zb) return za < zb;
            i = ei;
            j = ej;
        } else {
            if (a[i] != b[j]) return (unsigned char)a[i] < (unsigned char)b[j];
            ++i;
            ++j;
        }
    }
    if (i < a.size()) return false;
    if (j < b.size()) return true;
    return false;
}

static std::string norm_arg(std::string a) {
#ifdef _WIN32
    for (auto& c : a) if (c == '\\') c = '/';
#endif
    while (a.size() > 1 && a.back() == '/') a.pop_back();
    return a;
}

static void collect(std::vector<Item>& items, Stats& st) {
    std::vector<std::string> inputs = G.inputs;
    if (inputs.empty()) inputs.push_back(".");
    bool multi = inputs.size() > 1;
    std::unordered_set<std::string> seen;
    std::string cwd;
    if (multi) { std::error_code ec; cwd = U(fs::current_path(ec)); }
    Walker w{items, st, {}};

    for (const auto& raw : inputs) {
        std::string a = norm_arg(raw);
        std::error_code ec;
        fs::file_status s = fs::status(P(a), ec);
        if (ec || s.type() == fs::file_type::not_found) {
            warn("cannot access '" + raw + "': " + (ec ? ec.message() : std::string("No such file or directory")));
            ++st.err;
            continue;
        }
        size_t before = items.size();
        if (fs::is_directory(s)) {
            w.dir(a, leading_dots(a));
        } else {
            Item item;
            item.path = a;
            item.disp_off = (uint32_t)leading_dots(a);
            item.is_explicit = true;
            items.push_back(std::move(item));
        }
        if (multi) {  // the same file may be reachable via several arguments: keep the first
            size_t keep = before;
            for (size_t i = before; i < items.size(); ++i) {
                std::string key = (!items[i].path.empty() && items[i].path[0] == '/') ? items[i].path
                                                                                        : join(cwd, items[i].path);
                key = U(P(key).lexically_normal());
                if (seen.insert(key).second) { if (keep != i) items[keep] = std::move(items[i]); ++keep; }
            }
            items.resize(keep);
        }
    }
}

// ============================================================ output + pipeline

struct Out {
    FILE* f = nullptr;
    bool any = false;
};

static bool wr(Out& o, const void* p, size_t n) {
    if (!n) return true;
    if (std::fwrite(p, 1, n, o.f) != n) return false;
    return true;
}

// Consume one result in input order (main thread only). Returns false on a write error.
static bool emit(Result& r, const Item& it, Out& out, Stats& st) {
    const char* disp = it.path.c_str() + it.disp_off;
    switch (r.st) {
        case St::Ok: {
            ++st.packed;
            st.bytes += r.len;
            if (G.list) {
                std::fputs(disp, stdout);
                std::fputc('\n', stdout);
            } else {
                if (out.any && G.blank && !wr(out, "\n", 1)) return false;
                if (G.header) {
                    std::string h = make_header(disp, st.packed, r.len);
                    if (!wr(out, h.data(), h.size())) return false;
                }
                if (!wr(out, r.data.p + r.off, r.len)) return false;
                if (!wr(out, r.tail, r.tail_n)) return false;
            }
            out.any = true;
            if (G.verbose) std::fprintf(stderr, "  + %s (%s)\n", disp, human(r.len).c_str());
            break;
        }
        case St::SkipBinary:
            ++st.bin;
            if (G.verbose || it.is_explicit) std::fprintf(stderr, "  - %s: binary, skipped\n", disp);
            break;
        case St::SkipBig:
            ++st.big;
            if (G.verbose || it.is_explicit)
                std::fprintf(stderr, "  - %s: too large (%s > limit %s), skipped\n", disp, human(r.fsize).c_str(),
                             human(G.max_size).c_str());
            break;
        case St::SkipEnc:
            ++st.enc;
            if (G.verbose || it.is_explicit) std::fprintf(stderr, "  - %s: not valid UTF-8, skipped\n", disp);
            break;
        case St::SkipSpecial:
            ++st.special;
            if (G.verbose || it.is_explicit) std::fprintf(stderr, "  - %s: not a regular file, skipped\n", disp);
            break;
        case St::Error:
            ++st.err;
            warn(std::string("'") + disp + "': " + r.msg);
            break;
    }
    return true;
}

struct Slot {
    bool ready = false;
    Result res;
};

static std::string g_tmp_cleanup;  // path removed on SIGINT / failure
#ifndef _WIN32
static char g_sig_path[4096];
static void on_sigint(int) {
    if (g_sig_path[0]) unlink(g_sig_path);
    _exit(130);
}
#endif

static bool run_pipeline(const std::vector<Item>& items, Out& out, Stats& st, unsigned jobs) {
    const size_t n = items.size();
    if (jobs <= 1) {
        for (size_t i = 0; i < n; ++i) {
            Result r = process(items[i]);
            if (!emit(r, items[i], out, st)) return false;
        }
        return true;
    }

    const size_t W = (size_t)jobs * 4;
    std::vector<Slot> ring(W);
    std::mutex mu;
    std::condition_variable cv_work, cv_done;
    size_t head = 0;
    uint64_t inflight = 0;
    bool stop = false;
    std::atomic<size_t> next{0};

    auto worker = [&]() {
        for (;;) {
            size_t i = next.fetch_add(1, std::memory_order_relaxed);
            if (i >= n) return;
            {
                std::unique_lock<std::mutex> lk(mu);
                cv_work.wait(lk, [&] { return stop || (i < head + W && (i == head || inflight <= kInflightBudget)); });
                if (stop) return;
            }
            Result r = process(items[i]);
            {
                std::lock_guard<std::mutex> lk(mu);
                inflight += r.cost;
                Slot& s = ring[i % W];
                s.res = std::move(r);
                s.ready = true;
            }
            cv_done.notify_one();
        }
    };

    std::vector<std::thread> pool;
    for (unsigned t = 0; t < jobs; ++t) pool.emplace_back(worker);

    bool ok = true;
    for (size_t i = 0; i < n; ++i) {
        Result r;
        {
            std::unique_lock<std::mutex> lk(mu);
            cv_done.wait(lk, [&] { return ring[i % W].ready; });
            Slot& s = ring[i % W];
            r = std::move(s.res);
            s.res = Result();
            s.ready = false;
            head = i + 1;
        }
        cv_work.notify_all();
        uint64_t cost = r.cost;
        if (!emit(r, items[i], out, st)) { ok = false; break; }
        r = Result();  // free the buffers now
        {
            std::lock_guard<std::mutex> lk(mu);
            inflight -= cost;
        }
        cv_work.notify_all();
    }
    if (!ok) {
        std::lock_guard<std::mutex> lk(mu);
        stop = true;
        cv_work.notify_all();
    }
    for (auto& t : pool) t.join();
    return ok;
}

// ============================================================ command line

static const char* kHelp =
    "packf " "1.0.0" " - pack many text files into ONE text file (this is not an archive)\n"
    "\n"
    "Usage: packf [OPTIONS] [PATH...]\n"
    "\n"
    "PATH is a file or a directory. Directories are scanned recursively; with no PATH the\n"
    "current directory is packed. Files named explicitly are always packed, in the order given\n"
    "(extension / glob filters only apply to files found by scanning).\n"
    "\n"
    "Output\n"
    "  -o, --output FILE      output file, any extension you like (.txt, .h, .md ...);\n"
    "                         '-' = stdout. Default: packed.txt\n"
    "  -H, --header FMT       header line before every file. %p path, %n name, %i number,\n"
    "                         %s size in bytes, %% percent sign; \\n \\t escapes work.\n"
    "                         Default: '===== %p =====', turned into a comment in the output's\n"
    "                         language, e.g. '// ===== %p =====' for .h/.cpp, '# ...' for .py\n"
    "  -N, --no-header        no header lines at all\n"
    "  -B, --no-blank         no blank line between files\n"
    "      --eol MODE         keep (default) | lf | crlf\n"
    "\n"
    "Selecting files\n"
    "  -e, --ext LIST         only these extensions, e.g. -e h,hpp,c\n"
    "  -x, --exclude-ext LIST skip these extensions\n"
    "  -i, --include GLOB     only paths matching GLOB (repeatable)\n"
    "  -X, --exclude GLOB     skip files/dirs matching GLOB (repeatable), e.g. -X build -X '**/test_*'\n"
    "  -n, --no-recurse       do not descend into sub-directories\n"
    "  -a, --all              include hidden files and directories (names starting with '.')\n"
    "  -L, --follow-symlinks  follow symbolic links while scanning\n"
    "  -S, --sort MODE        natural (default: file2 < file10) | name | none\n"
    "  -m, --max-size SIZE    skip files bigger than SIZE (500k, 64M, 2G; 0 = unlimited). Default 32M\n"
    "\n"
    "Conversion to text\n"
    "  UTF-8 is copied as is; UTF-16 and UTF-8-BOM files are converted automatically, binary\n"
    "  files are detected and skipped.\n"
    "  -E, --encoding ENC     how to read files that are NOT valid UTF-8: cp1252 (default) |\n"
    "                         cp1254 | latin1 | iso-8859-9 | raw (copy bytes) | skip\n"
    "  -F, --filter EXT=CMD   pass files with extension EXT through an external converter\n"
    "                         (repeatable). The file name is appended to CMD or put in place of {};\n"
    "                         CMD's stdout is the text. e.g. -F 'docx=pandoc -t plain'\n"
    "                                                        -F 'pdf=pdftotext -layout {} -'\n"
    "Misc\n"
    "  -j, --jobs N           worker threads (default: number of CPUs, max 16)\n"
    "  -l, --list             dry run: only list the files that would be packed\n"
    "  -v, --verbose          report every file;  -q, --quiet  no summary\n"
    "  -h, --help             this help;  -V, --version\n"
    "\n"
    "Examples\n"
    "  packf                              # everything text under . -> packed.txt\n"
    "  packf src include -o all.txt\n"
    "  packf -e h,hpp -o everything.h include/     # merge headers into one new .h\n"
    "  packf -o notes.md a.txt b.txt c.log         # explicit files, in this order\n"
    "  packf -X node_modules -X build -e c,cpp,h -o - . | wc -c\n";

struct OptSpec { char sh; const char* lg; bool arg; };
static const OptSpec kSpecs[] = {
    {'o', "output", true},  {'e', "ext", true},        {'x', "exclude-ext", true}, {'i', "include", true},
    {'X', "exclude", true}, {'n', "no-recurse", false}, {'a', "all", false},        {'L', "follow-symlinks", false},
    {'S', "sort", true},    {'H', "header", true},     {'N', "no-header", false},  {'B', "no-blank", false},
    {'E', "encoding", true}, {0, "eol", true},         {'m', "max-size", true},    {'F', "filter", true},
    {'j', "jobs", true},    {'l', "list", false},      {'v', "verbose", false},    {'q', "quiet", false},
    {'h', "help", false},   {'V', "version", false},
};

static int usage_err(const std::string& m) {
    std::fprintf(stderr, "packf: %s\nTry 'packf --help'.\n", m.c_str());
    return 2;
}

static void add_exts(std::unordered_set<std::string>& set, const std::string& list) {
    std::string cur;
    auto flush = [&]() {
        std::string e = lower(cur);
        cur.clear();
        while (!e.empty() && (e[0] == '*' || e[0] == '.')) e.erase(0, 1);
        if (!e.empty()) set.insert(e);
    };
    for (char c : list) { if (c == ',' || c == ';' || c == ' ') flush(); else cur += c; }
    flush();
}

static bool parse_size(const std::string& s, uint64_t& out) {
    if (s.empty()) return false;
    char* end = nullptr;
    double v = std::strtod(s.c_str(), &end);
    if (end == s.c_str() || v < 0) return false;
    std::string suf = lower(end);
    uint64_t mul;
    if (suf.empty() || suf == "b") mul = 1;
    else if (suf == "k" || suf == "kb" || suf == "kib") mul = 1ull << 10;
    else if (suf == "m" || suf == "mb" || suf == "mib") mul = 1ull << 20;
    else if (suf == "g" || suf == "gb" || suf == "gib") mul = 1ull << 30;
    else return false;
    out = (uint64_t)(v * (double)mul);
    return true;
}

static std::string clean_glob(std::string g) {
#ifdef _WIN32
    for (auto& c : g) if (c == '\\') c = '/';
#endif
    while (g.compare(0, 2, "./") == 0) g.erase(0, 2);
    while (g.size() > 1 && g.back() == '/') g.pop_back();
    return g;
}

static std::string unescape(const std::string& s) {
    std::string o;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char c = s[i + 1];
            if (c == 'n') { o += '\n'; ++i; }
            else if (c == 't') { o += '\t'; ++i; }
            else if (c == '\\') { o += '\\'; ++i; }
            else o += s[i];
        } else {
            o += s[i];
        }
    }
    return o;
}

static int apply_opt(const OptSpec& sp, const std::string& v) {  // -1 = continue, else exit code
    std::string n = sp.lg;
    if (n == "output") G.output = v;
    else if (n == "ext") add_exts(G.ext_in, v);
    else if (n == "exclude-ext") add_exts(G.ext_out, v);
    else if (n == "include") G.inc.push_back(clean_glob(v));
    else if (n == "exclude") G.exc.push_back(clean_glob(v));
    else if (n == "no-recurse") G.recurse = false;
    else if (n == "all") G.hidden = true;
    else if (n == "follow-symlinks") G.follow = true;
    else if (n == "sort") {
        std::string m = lower(v);
        if (m == "natural") G.sort = SortMode::Natural;
        else if (m == "name") G.sort = SortMode::Name;
        else if (m == "none") G.sort = SortMode::None;
        else return usage_err("--sort: expected natural, name or none");
    } else if (n == "header") {
        G.header_custom = true;
        G.header_fmt = unescape(v);
        if (G.header_fmt.empty()) G.header = false;
    } else if (n == "no-header") G.header = false;
    else if (n == "no-blank") G.blank = false;
    else if (n == "encoding") {
        std::string m = lower(v);
        if (m == "cp1252" || m == "windows-1252") G.enc = Enc::CP1252;
        else if (m == "cp1254" || m == "windows-1254") G.enc = Enc::CP1254;
        else if (m == "latin1" || m == "iso-8859-1") G.enc = Enc::Latin1;
        else if (m == "iso-8859-9" || m == "latin5") G.enc = Enc::ISO8859_9;
        else if (m == "raw") G.enc = Enc::Raw;
        else if (m == "skip") G.enc = Enc::Skip;
        else return usage_err("--encoding: expected cp1252, cp1254, latin1, iso-8859-9, raw or skip");
    } else if (n == "eol") {
        std::string m = lower(v);
        if (m == "keep") G.eol = Eol::Keep;
        else if (m == "lf") G.eol = Eol::LF;
        else if (m == "crlf") G.eol = Eol::CRLF;
        else return usage_err("--eol: expected keep, lf or crlf");
    } else if (n == "max-size") {
        if (!parse_size(v, G.max_size)) return usage_err("--max-size: bad size '" + v + "'");
    } else if (n == "filter") {
        size_t eq = v.find('=');
        if (eq == std::string::npos || eq == 0 || eq + 1 >= v.size()) return usage_err("--filter: expected EXT=COMMAND");
        std::unordered_set<std::string> e;
        add_exts(e, v.substr(0, eq));
        if (e.empty()) return usage_err("--filter: empty extension");
        G.filters.push_back({*e.begin(), v.substr(eq + 1)});
    } else if (n == "jobs") {
        char* end = nullptr;
        long j = std::strtol(v.c_str(), &end, 10);
        if (end == v.c_str() || *end || j < 1 || j > 256) return usage_err("--jobs: expected 1..256");
        G.jobs = (unsigned)j;
    } else if (n == "list") G.list = true;
    else if (n == "verbose") G.verbose = true;
    else if (n == "quiet") G.quiet = true;
    else if (n == "help") { std::fputs(kHelp, stdout); return 0; }
    else if (n == "version") { std::printf("packf %s\n", kVersion); return 0; }
    return -1;
}

static int parse_args(const std::vector<std::string>& a) {
    bool no_more = false;
    for (size_t i = 1; i < a.size(); ++i) {
        const std::string& s = a[i];
        if (no_more || s.size() < 2 || s[0] != '-') { G.inputs.push_back(s); continue; }
        if (s == "--") { no_more = true; continue; }
        if (s[1] == '-') {
            std::string name = s.substr(2), val;
            bool has = false;
            size_t eq = name.find('=');
            if (eq != std::string::npos) { val = name.substr(eq + 1); name.resize(eq); has = true; }
            const OptSpec* sp = nullptr;
            for (const auto& c : kSpecs) if (name == c.lg) sp = &c;
            if (!sp) return usage_err("unknown option '--" + name + "'");
            if (sp->arg) {
                if (!has) {
                    if (i + 1 >= a.size()) return usage_err("option '--" + name + "' needs a value");
                    val = a[++i];
                }
            } else if (has) {
                return usage_err("option '--" + name + "' takes no value");
            }
            int rc = apply_opt(*sp, val);
            if (rc >= 0) return rc;
        } else {
            for (size_t k = 1; k < s.size(); ++k) {
                const OptSpec* sp = nullptr;
                for (const auto& c : kSpecs) if (c.sh && c.sh == s[k]) sp = &c;
                if (!sp) return usage_err(std::string("unknown option '-") + s[k] + "'");
                std::string val;
                if (sp->arg) {
                    if (k + 1 < s.size()) val = s.substr(k + 1);
                    else if (i + 1 < a.size()) val = a[++i];
                    else return usage_err(std::string("option '-") + s[k] + "' needs a value");
                    k = s.size();
                }
                int rc = apply_opt(*sp, val);
                if (rc >= 0) return rc;
            }
        }
    }
    return -1;
}

// ============================================================ main

static int run() {
    auto t0 = std::chrono::steady_clock::now();
    init_table(G.enc);
    init_binext();
    Stats st;

    const bool to_stdout = (G.output == "-");
    std::string out_path = G.output, write_path;
    if (!to_stdout) {
        std::error_code ec;
        fs::path op = P(out_path);
        g_out_name = U(op.filename());
        g_tmp_name = g_out_name + ".packf-tmp";
        g_out_canon = fs::weakly_canonical(op, ec);
        fs::file_status os = fs::status(op, ec);
        bool special = fs::exists(os) && !fs::is_regular_file(os);  // /dev/null, fifo ...: write in place
        write_path = special ? out_path : out_path + ".packf-tmp";
    }
    if (!G.header_custom) {
        std::string oe = to_stdout ? std::string() : ext_of(g_out_name);
        default_header(oe);
    }

    std::vector<Item> items;
    {
        Stats scan;
        collect(items, scan);
        st.err += scan.err;
        st.bin += scan.bin;
    }
    if (items.empty()) {
        if (!G.quiet) warn("no files to pack");
        return 1;
    }

    Out out;
    bool tmp_used = false;
    if (!G.list) {
        if (to_stdout) {
#ifdef _WIN32
            _setmode(_fileno(stdout), _O_BINARY);
#endif
            out.f = stdout;
        } else {
            out.f = open_wb(write_path);
            if (!out.f) {
                warn("cannot create '" + write_path + "': " + errmsg(errno));
                return 2;
            }
            tmp_used = (write_path != out_path);
            if (tmp_used) {
                g_tmp_cleanup = write_path;
#ifndef _WIN32
                std::snprintf(g_sig_path, sizeof g_sig_path, "%s", write_path.c_str());
                std::signal(SIGINT, on_sigint);
                std::signal(SIGTERM, on_sigint);
#endif
            }
        }
        static char iobuf[1 << 20];
        std::setvbuf(out.f, iobuf, _IOFBF, sizeof iobuf);
    }

    unsigned jobs = G.jobs;
    if (!jobs) {
        jobs = std::thread::hardware_concurrency();
        if (jobs == 0) jobs = 2;
        if (jobs > 16) jobs = 16;
    }
    if (jobs > items.size()) jobs = (unsigned)items.size();

    bool ok = run_pipeline(items, out, st, jobs);
    if (!G.list) {
        if (std::fflush(out.f) != 0 || std::ferror(out.f)) ok = false;
        if (out.f != stdout && std::fclose(out.f) != 0) ok = false;
    }
    if (!ok) {
        warn("write error: " + errmsg(errno));
        if (tmp_used) { std::error_code ec; fs::remove(P(write_path), ec); }
        return 2;
    }
    if (st.packed == 0) {
        if (tmp_used) { std::error_code ec; fs::remove(P(write_path), ec); }
        if (!G.quiet) warn("no text files to pack");
        return 1;
    }
    if (tmp_used) {
        std::error_code ec;
        fs::rename(P(write_path), P(out_path), ec);
        if (ec) {
            warn("cannot rename '" + write_path + "' to '" + out_path + "': " + ec.message());
            fs::remove(P(write_path), ec);
            return 2;
        }
#ifndef _WIN32
        g_sig_path[0] = 0;
#endif
    }

    if (!G.quiet) {
        double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        std::string skipped;
        auto add = [&](size_t n, const char* what) {
            if (!n) return;
            skipped += (skipped.empty() ? "" : ", ") + std::to_string(n) + " " + what;
        };
        add(st.bin, "binary");
        add(st.big, "too large");
        add(st.enc, "non-UTF-8");
        add(st.special, "special");
        add(st.err, "failed");
        std::string dest = G.list ? "(dry run)" : "-> " + (to_stdout ? std::string("stdout") : out_path);
        std::fprintf(stderr, "packf: %zu file%s, %s %s in %.3fs%s%s\n", st.packed, st.packed == 1 ? "" : "s",
                     human(st.bytes).c_str(), dest.c_str(), secs, skipped.empty() ? "" : "; skipped/failed: ",
                     skipped.c_str());
    }
    return st.err ? 1 : 0;
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    std::vector<std::string> args = get_args(argc, argv);
    int rc = parse_args(args);
    if (rc >= 0) return rc;
    try {
        return run();
    } catch (const std::exception& e) {
        warn(std::string("fatal: ") + e.what());
        return 2;
    }
}
