// ============================================================================
//  shobf — Shader Obfuscator
//  shader_obfuscate.hpp — single-header GPU string obfuscation
//  (Vulkan compute by default, Direct3D 11 via SHOBF_BACKEND_D3D11)
// ============================================================================
//
//  ENCRYPTION happens on the CPU at COMPILE TIME via macros:
//    SHOBF_OBFUSCATE(str, key)      XOR  -> raw-byte ciphertext (constexpr)
//    SHOBF_OBFUSCATE_RC4(str, key)  RC4  -> raw-byte ciphertext (constexpr)
//  The plaintext literal never exists in the compiled binary, and the
//  ciphertext is stored as opaque RAW BYTES (shobf::Encrypted<N>) — nothing
//  hex- or text-shaped shows up under strings(1). The legacy lowercase-hex
//  form remains available via SHOBF_OBFUSCATE_HEX / SHOBF_OBFUSCATE_HEX_RC4.
//
//  DECRYPTION happens on the GPU behind a tiny backend interface:
//    * XOR stream cipher   (shobf::Algorithm::Xor)
//    * RC4                 (shobf::Algorithm::Rc4)  -- classic KSA/PRGA,
//      parallelized by giving each invocation a private S-box that is
//      fast-forwarded to its own byte offset before decrypting its word.
//  The GPU parses hex ciphertexts itself (two dispatches: hex-decode, then
//  decrypt); Encrypted<> blobs are re-hexed on the CPU into a transient
//  buffer first. All device objects live in a lazily-created engine that is
//  destroyed at process exit.
//
//  BACKENDS
//  --------
//    * Vulkan   (default)     : raw Vulkan C API, SPIR-V embedded in this
//                               header; needs vulkan.h and links vulkan-1.
//    * Direct3D 11            : define SHOBF_BACKEND_D3D11 on a Windows
//                               target. The compute shader can be compiled at
//                               BUILD time into a DXBC blob (build_shader.py,
//                               using d3dcompiler's D3DCompile) and embedded —
//                               define SHOBF_D3D11_PRECOMPILED so the HLSL
//                               source is not in the binary. Without that
//                               define, HLSL source embedded here is compiled
//                               at init via the system d3dcompiler_47.dll
//                               (loaded dynamically — nothing to link).
//  shobf::backendName() reports which one was compiled in.
//
//  USAGE
//  -----
//    #include "shader_obfuscate.hpp"
//
//    // --- Variation 1: you manage the key --------------------------------
//    static const char kCipher[] = "3e1000070e4e1007...";   // hex ciphertext
//    std::string plain = shobf::decrypt(kCipher, "vulkan");
//
//    // --- Compile-time encryption -----------------------------------------
//    // Expands to a constexpr-evaluated Encrypted<> holding the raw
//    // ciphertext bytes; pass it straight back to decrypt().
//    std::string p1 =
//        shobf::decrypt(SHOBF_OBFUSCATE("some secret", "vulkan"), "vulkan");
//    std::string p2 = shobf::decrypt(SHOBF_OBFUSCATE_RC4("more", "vulkan"),
//                                   "vulkan", shobf::Algorithm::Rc4);
//
//    // --- Variation 2: build-seed-derived session key ----------------------
//    // The Auto API uses one key derived at compile time from
//    // SHOBF_BUILD_SEED (pass -DSHOBF_BUILD_SEED=0x<random> when building;
//    // without it, __DATE__/__TIME__ are hashed, so every rebuild changes
//    // the key). The derived key is not stored in the binary.
//    std::string p3 = shobf::decryptAuto(
//        SHOBF_OBFUSCATE("data", shobf::seedKey()));
//    std::string_view k = shobf::runtimeKey();       // inspect the key
//
//  NOTES
//  -----
//   * Ciphertext storage: macros emit RAW BYTES; decrypt()/decryptAuto() also
//     accept plain-hex strings (upper/lower case, no separators) for external
//     tooling. Invalid digits and odd lengths are detected ON THE GPU and
//     reported as shobf::Error with the offending character offset.
//   * This is obfuscation (anti-casual-strings), NOT cryptography.
//   * Thread-safe: one internal mutex serializes GPU submissions.
//   * Validation layers are off by default; call
//     shobf::setValidationEnabled(true) or set SHOBF_VALIDATION=1 before the
//     first crypto call to turn them on.
//   * Define SHOBF_NO_DEBUG when compiling for a release/production build:
//     all validation and debug machinery is compiled out, no exceptions are
//     thrown (failures return empty results), and no diagnostic strings
//     remain in the binary. shobf::Error stays declared for API stability.
//   * Link with -lvulkan. No other dependencies.
// ============================================================================

#pragma once

#if defined(SHOBF_BACKEND_D3D11)
#  if !defined(_WIN32)
#    error "SHOBF_BACKEND_D3D11 requires a Windows target; D3D11 does not exist on this platform. Drop the define to use the Vulkan backend."
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <d3d11.h>
#  if defined(SHOBF_D3D11_PRECOMPILED)
#    include "shader_dxbc.inc"   // generated by build_shader.py (build time)
#    if !defined(SHOBF_D3D11_HAVE_DXBC)
#      error "shader_dxbc.inc is missing the SHOBF_D3D11_HAVE_DXBC canary. Run build_shader.py first (see README, D3D11 backend section)."
#    endif
#  else
#    include <d3dcompiler.h>     // runtime D3DCompile of embedded HLSL string
#  endif
#else
#  include <vulkan/vulkan.h>
#endif

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace shobf {

// Raised for invalid input (malformed hex, empty key) and Vulkan failures.
class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// ---------------------------------------------------------------------------
// Release configuration: define SHOBF_NO_DEBUG to strip every debug artifact
// and disable exceptions. The library then reports failure by returning empty
// results instead of throwing, never touches validation layers, and contains
// no diagnostic strings. (shobf::Error remains declared for API stability,
// but nothing throws it.)
// ---------------------------------------------------------------------------

namespace detail {

// Shared by every backend: opt-in flag for validation layers / debug device.
inline bool& validationRequestedFlag()
{
    static bool flag = false;
    return flag;
}

#ifndef SHOBF_NO_DEBUG

#if !defined(SHOBF_BACKEND_D3D11)
inline const char* vkResultString(VkResult r)
{
    switch (r) {
    case VK_SUCCESS:                   return "VK_SUCCESS";
    case VK_NOT_READY:                 return "VK_NOT_READY";
    case VK_TIMEOUT:                   return "VK_TIMEOUT";
    case VK_ERROR_OUT_OF_HOST_MEMORY:  return "VK_ERROR_OUT_OF_HOST_MEMORY";
    case VK_ERROR_OUT_OF_DEVICE_MEMORY:return "VK_ERROR_OUT_OF_DEVICE_MEMORY";
    case VK_ERROR_INITIALIZATION_FAILED: return "VK_ERROR_INITIALIZATION_FAILED";
    case VK_ERROR_LAYER_NOT_PRESENT:   return "VK_ERROR_LAYER_NOT_PRESENT";
    case VK_ERROR_EXTENSION_NOT_PRESENT: return "VK_ERROR_EXTENSION_NOT_PRESENT";
    case VK_ERROR_FEATURE_NOT_PRESENT: return "VK_ERROR_FEATURE_NOT_PRESENT";
    case VK_ERROR_INCOMPATIBLE_DRIVER: return "VK_ERROR_INCOMPATIBLE_DRIVER";
    default:                           return "<other VkResult>";
    }
}

inline void checkVk(VkResult res, const char* call)
{
    if (res != VK_SUCCESS)
        throw Error(std::string(call) + " failed: " + vkResultString(res));
}
#define SHOBF_CHECK(expr) ::shobf::detail::checkVk((expr), #expr)

inline VKAPI_ATTR VkBool32 VKAPI_CALL debugCallback(
    VkDebugUtilsMessageSeverityFlagBitsEXT      severity,
    VkDebugUtilsMessageTypeFlagsEXT,
    const VkDebugUtilsMessengerCallbackDataEXT* data,
    void*)
{
    if (severity >= VK_DEBUG_UTILS_MESSAGE_SEVERITY_WARNING_BIT_EXT)
        fprintf(stderr, "[shobf validation] %s\n", data->pMessage);
    return VK_FALSE;
}

inline bool instanceLayerAvailable(const char* name)
{
    uint32_t n = 0;
    SHOBF_CHECK(vkEnumerateInstanceLayerProperties(&n, nullptr));
    std::vector<VkLayerProperties> layers(n);
    SHOBF_CHECK(vkEnumerateInstanceLayerProperties(&n, layers.data()));
    for (const auto& l : layers)
        if (strcmp(l.layerName, name) == 0) return true;
    return false;
}

inline bool instanceExtensionAvailable(const char* name)
{
    uint32_t n = 0;
    SHOBF_CHECK(vkEnumerateInstanceExtensionProperties(nullptr, &n, nullptr));
    std::vector<VkExtensionProperties> exts(n);
    SHOBF_CHECK(vkEnumerateInstanceExtensionProperties(nullptr, &n, exts.data()));
    for (const auto& e : exts)
        if (strcmp(e.extensionName, name) == 0) return true;
    return false;
}
#endif // !SHOBF_BACKEND_D3D11

#else // SHOBF_NO_DEBUG

// No diagnostics, no throws: VkResults are evaluated and discarded.
#define SHOBF_CHECK(expr) ((void)(expr))

#endif // SHOBF_NO_DEBUG

// ---------------------------------------------------------------------------
// Vulkan-only helpers (absent from the D3D11 backend build)
// ---------------------------------------------------------------------------
#if !defined(SHOBF_BACKEND_D3D11)

inline uint32_t findMemoryType(VkPhysicalDevice phys, uint32_t typeBits,
                               VkMemoryPropertyFlags wanted)
{
    VkPhysicalDeviceMemoryProperties mp{};
    vkGetPhysicalDeviceMemoryProperties(phys, &mp);
    for (uint32_t i = 0; i < mp.memoryTypeCount; ++i)
        if ((typeBits & (1u << i)) &&
            (mp.memoryTypes[i].propertyFlags & wanted) == wanted)
            return i;
#ifdef SHOBF_NO_DEBUG
    return ~0u;   // caller-side ok-flags turn this into an empty result
#else
    throw Error("shader_obfuscate: no suitable Vulkan memory type found");
#endif
}
#endif // !SHOBF_BACKEND_D3D11

// ---------------------------------------------------------------------------
// Byte / hex helpers
// ---------------------------------------------------------------------------

inline std::vector<uint32_t> packWords(const std::vector<uint8_t>& bytes)
{
    std::vector<uint32_t> words((bytes.size() + 3) / 4, 0u);
    for (size_t i = 0; i < bytes.size(); ++i)
        words[i >> 2] |= uint32_t(bytes[i]) << ((i & 3u) * 8u);
    return words;
}

inline std::vector<uint8_t> unpackWords(const std::vector<uint32_t>& words,
                                        size_t byteLen)
{
    std::vector<uint8_t> bytes(byteLen, 0u);
    for (size_t i = 0; i < byteLen; ++i)
        bytes[i] = uint8_t((words[i >> 2] >> ((i & 3u) * 8u)) & 0xFFu);
    return bytes;
}

// ---------------------------------------------------------------------------
// Compile-time build-seed derivation (powers the Auto API).
//
// The build system should pass a random seed per build:
//     -DSHOBF_BUILD_SEED=0x<16 hex digits>
// If it is not defined, the header falls back to hashing __DATE__/__TIME__,
// which changes on every rebuild — fine for runtime-only use, but it breaks
// ciphertexts persisted across recompiles, so prefer an explicit seed.
// ---------------------------------------------------------------------------

constexpr uint64_t fnv1a(const char* s, size_t n)
{
    uint64_t h = 0xCBF29CE484222325ull;
    for (size_t i = 0; i < n; ++i) {
        h ^= uint64_t(uint8_t(s[i]));
        h *= 0x100000001B3ull;
    }
    return h;
}

constexpr size_t kTimestampSeedLen = sizeof(__DATE__ "/" __TIME__) - 1;

constexpr uint64_t timestampSeed()
{
    constexpr char buf[] = __DATE__ "/" __TIME__;   // "Mmm dd yyyy/hh:mm:ss"
    return fnv1a(buf, kTimestampSeedLen);
}

constexpr uint64_t buildSeedValue()
{
#if defined(SHOBF_BUILD_SEED)
    return uint64_t(SHOBF_BUILD_SEED);
#else
    return timestampSeed();
#endif
}

// splitmix64 finalizer for expanding the 64-bit seed into keystream bytes.
constexpr uint64_t mix64(uint64_t z)
{
    z += 0x9E3779B97F4A7C15ull;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

inline constexpr size_t kAutoKeyLen = 32;   // printable ASCII chars

// ---------------------------------------------------------------------------
// Host-visible storage buffer, persistently mapped (RAII).
// ---------------------------------------------------------------------------

// Push-constant phase selectors shared with the shader.
inline constexpr uint32_t kModeHexDecode  = 0;
inline constexpr uint32_t kModeXorDecrypt = 1;
inline constexpr uint32_t kModeRc4Decrypt = 2;

#if !defined(SHOBF_BACKEND_D3D11)
struct Buffer
{
    VkDevice       device = VK_NULL_HANDLE;
    VkBuffer       handle = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    void*          mapped = nullptr;
    VkDeviceSize   size   = 0;

    Buffer() = default;
    void init(VkPhysicalDevice phys, VkDevice dev, VkDeviceSize byteSize)
    {
        device = dev;
        size   = byteSize;

        VkBufferCreateInfo bi{};
        bi.sType       = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        bi.size        = byteSize;
        bi.usage       = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
        bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
        SHOBF_CHECK(vkCreateBuffer(device, &bi, nullptr, &handle));

        VkMemoryRequirements reqs{};
        vkGetBufferMemoryRequirements(device, handle, &reqs);

        VkMemoryAllocateInfo ai{};
        ai.sType           = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        ai.allocationSize  = reqs.size;
        ai.memoryTypeIndex = findMemoryType(phys, reqs.memoryTypeBits,
            VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
        if (ai.memoryTypeIndex == ~0u) return;  // no suitable memory found
        SHOBF_CHECK(vkAllocateMemory(device, &ai, nullptr, &memory));
        SHOBF_CHECK(vkBindBufferMemory(device, handle, memory, 0));
        SHOBF_CHECK(vkMapMemory(device, memory, 0, size, 0, &mapped));
    }

    // No-op unless a previous allocation actually succeeded (guards against
    // null-mapped memcpy in SHOBF_NO_DEBUG builds where failures are silent).
    void upload(const void* src, VkDeviceSize n) const
    {
        if (mapped && src && n <= size) memcpy(mapped, src, size_t(n));
    }
    void download(void* dst, VkDeviceSize n) const
    {
        if (mapped && dst && n <= size) memcpy(dst, mapped, size_t(n));
    }

    ~Buffer()
    {
        if (device == VK_NULL_HANDLE) return;
        if (memory != VK_NULL_HANDLE && mapped) vkUnmapMemory(device, memory);
        if (handle != VK_NULL_HANDLE) vkDestroyBuffer(device, handle, nullptr);
        if (memory != VK_NULL_HANDLE) vkFreeMemory(device, memory, nullptr);
    }
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;
};
#endif // !SHOBF_BACKEND_D3D11

// ---------------------------------------------------------------------------
// Compute shader: mode-switched hex-decode + XOR, embedded as SPIR-V.
// GLSL source (recompile with:
//   glslangValidator -V --target-env vulkan1.0 xor_hex.comp -o xor_hex.spv ):
// ----------------------------------------------------------------------------
#if 0
#version 450

layout(local_size_x = 256, local_size_y = 1, local_size_z = 1) in;

#define MODE_HEX_DECODE   0u
#define MODE_XOR_DECRYPT  1u
#define MODE_RC4_DECRYPT  2u

layout(push_constant) uniform PushConstants {
    uint mode;     /* MODE_HEX_DECODE, MODE_XOR_DECRYPT or MODE_RC4_DECRYPT */
    uint hexLen;   /* number of ASCII hex chars; ciphertext bytes = hexLen/2 */
    uint keyLen;   /* number of key bytes */
} pc;

/* mode 0: inChars holds ASCII hex characters ("48656c6c6f"...)
 * mode 1: work    holds the ciphertext words produced by mode 0
 * mode 2: work    holds the ciphertext words produced by mode 0 (RC4)    */
layout(std430, binding = 0) readonly buffer InBuf { uint inChars[]; };
layout(std430, binding = 1) readonly buffer KeyBuf { uint keyWords[]; };
layout(std430, binding = 2) buffer WorkBuf { uint work[]; }; /* cipher -> plain, in place */

layout(std430, binding = 3) buffer StatBuf {
    uint errFlag;    /* 0 = ok, 1 = malformed hex input (accessed atomically) */
    uint errOffset;  /* char index of the first problem       (accessed atomically) */
};

uint inByte(uint i)  { return (inChars[i >> 2u]  >> ((i & 3u) * 8u)) & 0xFFu; }
uint keyByte(uint i) { return (keyWords[i >> 2u] >> ((i & 3u) * 8u)) & 0xFFu; }
uint workByte(uint i){ return (work[i >> 2u]     >> ((i & 3u) * 8u)) & 0xFFu; }

uint nibbleVal(uint c)
{
    if (c >= 48u && c <= 57u)  return c - 48u;  /* '0'..'9' -> 0..9  */
    if (c >= 65u && c <= 70u)  return c - 55u;  /* 'A'..'F' -> 10..15*/
    if (c >= 97u && c <= 102u) return c - 87u;  /* 'a'..'f' -> 10..15*/
    return 0xFFu;                               /* invalid           */
}

void flagError(uint charIdx)
{
    atomicExchange(errFlag, 1u);
    atomicMin(errOffset, charIdx);   /* keep the earliest offender */
}

/* XOR: byte i is decrypted with key[i % keyLen] (fully parallel). */
uint xorWord(uint w)
{
    uint dataLen = pc.hexLen >> 1u;
    uint r = 0u;
    for (uint j = 0u; j < 4u; ++j) {
        uint byteIdx = (w << 2u) + j;
        if (byteIdx >= dataLen) break;
        uint encByte = workByte(byteIdx);
        uint kIdx    = byteIdx % pc.keyLen;
        uint keyBt   = keyByte(kIdx);
        r |= ((encByte ^ keyBt) & 0xFFu) << (j * 8u);
    }
    return r;
}

/*
 * RC4: the PRGA is inherently serial (every step swaps entries of a shared,
 * evolving S-box), so true cross-byte parallelism is impossible. Instead each
 * invocation builds its OWN S-box via KSA, then fast-forwards its private
 * PRGA to its word's byte offset, then decrypts that word's 4 bytes. The
 * redundant O(offset) warm-up per invocation buys parallel XOR throughput and
 * keeps every invocation independent (no races on shared state).
 */
uint rc4Word(uint w)
{
    uint s[256];                       /* private S-box (lives in local memory) */

    /* --- Key Scheduling Algorithm --- */
    for (uint k = 0u; k < 256u; ++k) s[k] = k;
    uint j = 0u;
    for (uint i = 0u; i < 256u; ++i) {
        j = (j + s[i] + keyByte(i % pc.keyLen)) & 0xFFu;
        uint t = s[i]; s[i] = s[j]; s[j] = t;
    }

    /* --- PRGA: fast-forward to this word, emit 4 keystream bytes --- */
    uint ii = 0u, jj = 0u;
    uint base = w << 2u;
    uint end  = base + 4u;
    uint r = 0u;
    for (uint n = 0u; n < end; ++n) {
        ii = (ii + 1u) & 0xFFu;
        jj = (jj + s[ii]) & 0xFFu;
        uint t = s[ii]; s[ii] = s[jj]; s[jj] = t;
        uint K = s[(s[ii] + s[jj]) & 0xFFu];
        if (n >= base)
            r |= ((workByte(n) ^ K) & 0xFFu) << ((n - base) * 8u);
    }
    return r;
}

void main()
{
    uint w = gl_GlobalInvocationID.x;

    if (pc.mode == MODE_HEX_DECODE) {
        uint numBytes = pc.hexLen >> 1u;
        uint numW     = (numBytes + 3u) >> 2u;

        if (w == 0u && (pc.hexLen & 1u) != 0u)
            flagError(pc.hexLen - 1u);          /* dangling half-byte */
        if (w >= numW) return;

        uint r = 0u;
        for (uint j = 0u; j < 4u; ++j) {
            uint ci  = (w << 2u) + j;           /* byte index      */
            if (ci >= numBytes) continue;       /* pad byte: never decoded */
            uint chi = ci << 1u;                /* first hex char  */
            uint hi  = nibbleVal(inByte(chi));
            uint lo  = nibbleVal(inByte(chi + 1u));
            if (hi == 0xFFu) flagError(chi);
            if (lo == 0xFFu) flagError(chi + 1u);
            r |= (((hi << 4u) | lo) & 0xFFu) << (j * 8u);
        }
        work[w] = r;
    } else {
        uint dataLen = pc.hexLen >> 1u;
        uint numW    = (dataLen + 3u) >> 2u;
        if (w >= numW) return;

        if (pc.mode == MODE_XOR_DECRYPT)
            work[w] = xorWord(w);
        else /* MODE_RC4_DECRYPT */
            work[w] = rc4Word(w);
    }
}
#endif

// ---------------------------------------------------------------------------
// D3D11 compute shader: same pipeline as the SPIR-V above, in HLSL. Semantics
// are byte-identical: buffers are uint-word packed exactly like the std430
// GLSL version, including the pad-byte and error-flagging rules.
//
// Two build modes, chosen with a compile-time switch:
//   * SHOBF_D3D11_PRECOMPILED  — the shader is compiled at BUILD time by
//       build_shader.py (d3dcompiler's D3DCompile) into a DXBC blob embedded
//       via shader_dxbc.inc; the HLSL source below is NOT compiled into the
//       binary. Only d3d11.dll is needed at runtime.
//   * (default)                — the HLSL source string below is compiled at
//       engine init via the system d3dcompiler_47.dll (present on every
//       Windows 8.1+/wine install); no offline DXBC toolchain is needed.
// ---------------------------------------------------------------------------
#if defined(SHOBF_BACKEND_D3D11)
#if !defined(SHOBF_D3D11_PRECOMPILED)
static const char kShaderHlsl[] = R"HLSL(
#define MODE_HEX_DECODE   0u
#define MODE_XOR_DECRYPT  1u
#define MODE_RC4_DECRYPT  2u

ByteAddressBuffer   gIn     : register(t0); // ASCII hex chars (word packed)
ByteAddressBuffer   gKey    : register(t1); // key bytes       (word packed)
ByteAddressBuffer   gCipher : register(t2); // decoded cipher  (word packed, stride 8)
RWByteAddressBuffer gWork   : register(u0); // stride 8: [plainWord][status]

cbuffer PushConstants : register(b0) {
    uint pcMode;      // MODE_HEX_DECODE / MODE_XOR_DECRYPT / MODE_RC4_DECRYPT
    uint pcHexLen;    // number of ASCII hex chars; ciphertext bytes = hexLen/2
    uint pcKeyLen;    // number of key bytes
    uint pad0;
};

uint inByte(uint i)    { return (gIn.Load(     (i >> 2u) * 4u) >> ((i & 3u) * 8u)) & 0xFFu; }
uint keyByte(uint i)   { return (gKey.Load(    (i >> 2u) * 4u) >> ((i & 3u) * 8u)) & 0xFFu; }
uint cipherByte(uint i){ return (gCipher.Load( (i >> 2u) * 8u) >> ((i & 3u) * 8u)) & 0xFFu; }

uint nibbleVal(uint c)
{
    if (c >= 48u && c <= 57u)  return c - 48u;
    if (c >= 65u && c <= 70u)  return c - 55u;
    if (c >= 97u && c <= 102u) return c - 87u;
    return 0xFFu;
}

uint xorWord(uint w)
{
    uint dataLen = pcHexLen >> 1u;
    uint r = 0u;
    for (uint j = 0u; j < 4u; ++j) {
        uint byteIdx = (w << 2u) + j;
        if (byteIdx >= dataLen) break;
        uint encByte = cipherByte(byteIdx);
        uint keyBt   = keyByte(byteIdx % pcKeyLen);
        r |= ((encByte ^ keyBt) & 0xFFu) << (j * 8u);
    }
    return r;
}

uint rc4Word(uint w)
{
    uint s[256];
    for (uint k = 0u; k < 256u; ++k) s[k] = k;
    uint j = 0u;
    for (uint i = 0u; i < 256u; ++i) {
        j = (j + s[i] + keyByte(i % pcKeyLen)) & 0xFFu;
        uint t = s[i]; s[i] = s[j]; s[j] = t;
    }
    uint ii = 0u, jj = 0u;
    uint base = w << 2u;
    uint end  = base + 4u;
    uint r = 0u;
    for (uint n = 0u; n < end; ++n) {
        ii = (ii + 1u) & 0xFFu;
        jj = (jj + s[ii]) & 0xFFu;
        uint t = s[ii]; s[ii] = s[jj]; s[jj] = t;
        uint K = s[(s[ii] + s[jj]) & 0xFFu];
        if (n >= base)
            r |= ((cipherByte(n) ^ K) & 0xFFu) << ((n - base) * 8u);
    }
    return r;
}

[numthreads(256, 1, 1)]
void main(uint3 tid : SV_DispatchThreadID)
{
    uint w = tid.x;

    if (pcMode == MODE_HEX_DECODE) {
        uint numBytes = pcHexLen >> 1u;
        uint numW     = (numBytes + 3u) >> 2u;

        if (w >= numW) return;

        // status == 0 means "this word is clean"; otherwise it carries the
        // offending character index + 1. The CPU picks the smallest one,
        // which reproduces the atomicMin(earliest offset) semantics of the
        // GLSL version without needing interlocked ops.
        uint status = 0u;
        if (w == 0u && (pcHexLen & 1u) != 0u)
            status = pcHexLen;   // dangling digit at index pcHexLen-1

        uint base = w << 2u;
        uint r = 0u;

        { uint ci = base;
          if (ci < numBytes) {
            uint chi = ci << 1u;
            uint hi  = nibbleVal(inByte(chi));
            uint lo  = nibbleVal(inByte(chi + 1u));
            if (hi == 0xFFu && !status) status = chi + 1u;
            if (lo == 0xFFu && !status) status = chi + 2u;
            r |= (((hi << 4u) | lo) & 0xFFu);
        } }
        { uint ci = base + 1u;
          if (ci < numBytes) {
            uint chi = ci << 1u;
            uint hi  = nibbleVal(inByte(chi));
            uint lo  = nibbleVal(inByte(chi + 1u));
            if (hi == 0xFFu && !status) status = chi + 1u;
            if (lo == 0xFFu && !status) status = chi + 2u;
            r |= (((hi << 4u) | lo) & 0xFFu) << 8u;
        } }
        { uint ci = base + 2u;
          if (ci < numBytes) {
            uint chi = ci << 1u;
            uint hi  = nibbleVal(inByte(chi));
            uint lo  = nibbleVal(inByte(chi + 1u));
            if (hi == 0xFFu && !status) status = chi + 1u;
            if (lo == 0xFFu && !status) status = chi + 2u;
            r |= (((hi << 4u) | lo) & 0xFFu) << 16u;
        } }
        { uint ci = base + 3u;
          if (ci < numBytes) {
            uint chi = ci << 1u;
            uint hi  = nibbleVal(inByte(chi));
            uint lo  = nibbleVal(inByte(chi + 1u));
            if (hi == 0xFFu && !status) status = chi + 1u;
            if (lo == 0xFFu && !status) status = chi + 2u;
            r |= (((hi << 4u) | lo) & 0xFFu) << 24u;
        } }

        gWork.Store(w * 8u,       r);
        gWork.Store(w * 8u + 4u,  status);
    } else {
        uint dataLen = pcHexLen >> 1u;
        uint numW    = (dataLen + 3u) >> 2u;
        if (w >= numW) return;

        if (pcMode == MODE_XOR_DECRYPT)
            gWork.Store(w * 8u, xorWord(w));
        else
            gWork.Store(w * 8u, rc4Word(w));
    }
}
)HLSL";
#endif // !SHOBF_D3D11_PRECOMPILED
#endif // SHOBF_BACKEND_D3D11

static const uint32_t kShaderSpv[] = {
    0x07230203, 0x00010000, 0x0008000b, 0x000001ca, 0x00000000, 0x00020011, 0x00000001,
    0x0006000b, 0x00000001, 0x4c534c47, 0x6474732e, 0x3035342e, 0x00000000, 0x0003000e,
    0x00000000, 0x00000001, 0x0006000f, 0x00000005, 0x00000004, 0x6e69616d, 0x00000000,
    0x00000141, 0x00060010, 0x00000004, 0x00000011, 0x00000100, 0x00000001, 0x00000001,
    0x00030003, 0x00000002, 0x000001c2, 0x00040005, 0x00000004, 0x6e69616d, 0x00000000,
    0x00050005, 0x0000000a, 0x79426e69, 0x75286574, 0x00003b31, 0x00030005, 0x00000009,
    0x00000069, 0x00050005, 0x0000000d, 0x4279656b, 0x28657479, 0x003b3175, 0x00030005,
    0x0000000c, 0x00000069, 0x00060005, 0x00000010, 0x6b726f77, 0x65747942, 0x3b317528,
    0x00000000, 0x00030005, 0x0000000f, 0x00000069, 0x00060005, 0x00000013, 0x6262696e,
    0x6156656c, 0x3175286c, 0x0000003b, 0x00030005, 0x00000012, 0x00000063, 0x00060005,
    0x00000017, 0x67616c66, 0x6f727245, 0x31752872, 0x0000003b, 0x00040005, 0x00000016,
    0x72616863, 0x00786449, 0x00050005, 0x0000001a, 0x57726f78, 0x2864726f, 0x003b3175,
    0x00030005, 0x00000019, 0x00000077, 0x00050005, 0x0000001d, 0x57346372, 0x2864726f,
    0x003b3175, 0x00030005, 0x0000001c, 0x00000077, 0x00040005, 0x00000020, 0x75426e49,
    0x00000066, 0x00050006, 0x00000020, 0x00000000, 0x68436e69, 0x00737261, 0x00030005,
    0x00000022, 0x00000000, 0x00040005, 0x00000036, 0x4279654b, 0x00006675, 0x00060006,
    0x00000036, 0x00000000, 0x5779656b, 0x7364726f, 0x00000000, 0x00030005, 0x00000038,
    0x00000000, 0x00040005, 0x00000045, 0x6b726f57, 0x00667542, 0x00050006, 0x00000045,
    0x00000000, 0x6b726f77, 0x00000000, 0x00030005, 0x00000047, 0x00000000, 0x00040005,
    0x0000007c, 0x74617453, 0x00667542, 0x00050006, 0x0000007c, 0x00000000, 0x46727265,
    0x0067616c, 0x00060006, 0x0000007c, 0x00000001, 0x4f727265, 0x65736666, 0x00000074,
    0x00030005, 0x0000007e, 0x00000000, 0x00040005, 0x00000087, 0x61746164, 0x006e654c,
    0x00060005, 0x00000088, 0x68737550, 0x736e6f43, 0x746e6174, 0x00000073, 0x00050006,
    0x00000088, 0x00000000, 0x65646f6d, 0x00000000, 0x00050006, 0x00000088, 0x00000001,
    0x4c786568, 0x00006e65, 0x00050006, 0x00000088, 0x00000002, 0x4c79656b, 0x00006e65,
    0x00030005, 0x0000008a, 0x00006370, 0x00030005, 0x0000008f, 0x00000072, 0x00030005,
    0x00000090, 0x0000006a, 0x00040005, 0x00000099, 0x65747962, 0x00786449, 0x00040005,
    0x000000a4, 0x42636e65, 0x00657479, 0x00040005, 0x000000a5, 0x61726170, 0x0000006d,
    0x00040005, 0x000000a8, 0x7864496b, 0x00000000, 0x00040005, 0x000000ae, 0x4279656b,
    0x00000074, 0x00040005, 0x000000af, 0x61726170, 0x0000006d, 0x00030005, 0x000000c0,
    0x0000006b, 0x00030005, 0x000000cb, 0x00000073, 0x00030005, 0x000000d1, 0x0000006a,
    0x00030005, 0x000000d2, 0x00000069, 0x00040005, 0x000000e3, 0x61726170, 0x0000006d,
    0x00030005, 0x000000e7, 0x00000074, 0x00030005, 0x000000f5, 0x00006969, 0x00030005,
    0x000000f6, 0x00006a6a, 0x00040005, 0x000000f7, 0x65736162, 0x00000000, 0x00030005,
    0x000000fa, 0x00646e65, 0x00030005, 0x000000fd, 0x00000072, 0x00030005, 0x000000fe,
    0x0000006e, 0x00030005, 0x00000110, 0x00000074, 0x00030005, 0x0000011c, 0x0000004b,
    0x00040005, 0x0000012c, 0x61726170, 0x0000006d, 0x00030005, 0x0000013e, 0x00000077,
    0x00080005, 0x00000141, 0x475f6c67, 0x61626f6c, 0x766e496c, 0x7461636f, 0x496e6f69,
    0x00000044, 0x00050005, 0x0000014a, 0x426d756e, 0x73657479, 0x00000000, 0x00040005,
    0x0000014e, 0x576d756e, 0x00000000, 0x00040005, 0x00000160, 0x61726170, 0x0000006d,
    0x00030005, 0x00000168, 0x00000072, 0x00030005, 0x00000169, 0x0000006a, 0x00030005,
    0x00000171, 0x00006963, 0x00030005, 0x0000017c, 0x00696863, 0x00030005, 0x0000017f,
    0x00006968, 0x00040005, 0x00000180, 0x61726170, 0x0000006d, 0x00040005, 0x00000183,
    0x61726170, 0x0000006d, 0x00030005, 0x00000185, 0x00006f6c, 0x00040005, 0x00000188,
    0x61726170, 0x0000006d, 0x00040005, 0x0000018a, 0x61726170, 0x0000006d, 0x00040005,
    0x00000190, 0x61726170, 0x0000006d, 0x00040005, 0x00000199, 0x61726170, 0x0000006d,
    0x00040005, 0x000001ab, 0x61746164, 0x006e654c, 0x00040005, 0x000001af, 0x576d756e,
    0x00000000, 0x00040005, 0x000001bf, 0x61726170, 0x0000006d, 0x00040005, 0x000001c5,
    0x61726170, 0x0000006d, 0x00040047, 0x0000001f, 0x00000006, 0x00000004, 0x00030047,
    0x00000020, 0x00000003, 0x00040048, 0x00000020, 0x00000000, 0x00000018, 0x00050048,
    0x00000020, 0x00000000, 0x00000023, 0x00000000, 0x00030047, 0x00000022, 0x00000018,
    0x00040047, 0x00000022, 0x00000021, 0x00000000, 0x00040047, 0x00000022, 0x00000022,
    0x00000000, 0x00040047, 0x00000035, 0x00000006, 0x00000004, 0x00030047, 0x00000036,
    0x00000003, 0x00040048, 0x00000036, 0x00000000, 0x00000018, 0x00050048, 0x00000036,
    0x00000000, 0x00000023, 0x00000000, 0x00030047, 0x00000038, 0x00000018, 0x00040047,
    0x00000038, 0x00000021, 0x00000001, 0x00040047, 0x00000038, 0x00000022, 0x00000000,
    0x00040047, 0x00000044, 0x00000006, 0x00000004, 0x00030047, 0x00000045, 0x00000003,
    0x00050048, 0x00000045, 0x00000000, 0x00000023, 0x00000000, 0x00040047, 0x00000047,
    0x00000021, 0x00000002, 0x00040047, 0x00000047, 0x00000022, 0x00000000, 0x00030047,
    0x0000007c, 0x00000003, 0x00050048, 0x0000007c, 0x00000000, 0x00000023, 0x00000000,
    0x00050048, 0x0000007c, 0x00000001, 0x00000023, 0x00000004, 0x00040047, 0x0000007e,
    0x00000021, 0x00000003, 0x00040047, 0x0000007e, 0x00000022, 0x00000000, 0x00030047,
    0x00000088, 0x00000002, 0x00050048, 0x00000088, 0x00000000, 0x00000023, 0x00000000,
    0x00050048, 0x00000088, 0x00000001, 0x00000023, 0x00000004, 0x00050048, 0x00000088,
    0x00000002, 0x00000023, 0x00000008, 0x00040047, 0x00000141, 0x0000000b, 0x0000001c,
    0x00040047, 0x000001c9, 0x0000000b, 0x00000019, 0x00020013, 0x00000002, 0x00030021,
    0x00000003, 0x00000002, 0x00040015, 0x00000006, 0x00000020, 0x00000000, 0x00040020,
    0x00000007, 0x00000007, 0x00000006, 0x00040021, 0x00000008, 0x00000006, 0x00000007,
    0x00040021, 0x00000015, 0x00000002, 0x00000007, 0x0003001d, 0x0000001f, 0x00000006,
    0x0003001e, 0x00000020, 0x0000001f, 0x00040020, 0x00000021, 0x00000002, 0x00000020,
    0x0004003b, 0x00000021, 0x00000022, 0x00000002, 0x00040015, 0x00000023, 0x00000020,
    0x00000001, 0x0004002b, 0x00000023, 0x00000024, 0x00000000, 0x0004002b, 0x00000006,
    0x00000026, 0x00000002, 0x00040020, 0x00000028, 0x00000002, 0x00000006, 0x0004002b,
    0x00000006, 0x0000002c, 0x00000003, 0x0004002b, 0x00000006, 0x0000002e, 0x00000008,
    0x0004002b, 0x00000006, 0x00000031, 0x000000ff, 0x0003001d, 0x00000035, 0x00000006,
    0x0003001e, 0x00000036, 0x00000035, 0x00040020, 0x00000037, 0x00000002, 0x00000036,
    0x0004003b, 0x00000037, 0x00000038, 0x00000002, 0x0003001d, 0x00000044, 0x00000006,
    0x0003001e, 0x00000045, 0x00000044, 0x00040020, 0x00000046, 0x00000002, 0x00000045,
    0x0004003b, 0x00000046, 0x00000047, 0x00000002, 0x0004002b, 0x00000006, 0x00000054,
    0x00000030, 0x00020014, 0x00000055, 0x0004002b, 0x00000006, 0x00000058, 0x00000039,
    0x0004002b, 0x00000006, 0x00000061, 0x00000041, 0x0004002b, 0x00000006, 0x00000064,
    0x00000046, 0x0004002b, 0x00000006, 0x0000006a, 0x00000037, 0x0004002b, 0x00000006,
    0x0000006e, 0x00000061, 0x0004002b, 0x00000006, 0x00000071, 0x00000066, 0x0004002b,
    0x00000006, 0x00000077, 0x00000057, 0x0004001e, 0x0000007c, 0x00000006, 0x00000006,
    0x00040020, 0x0000007d, 0x00000002, 0x0000007c, 0x0004003b, 0x0000007d, 0x0000007e,
    0x00000002, 0x0004002b, 0x00000006, 0x00000080, 0x00000001, 0x0004002b, 0x00000006,
    0x00000081, 0x00000000, 0x0004002b, 0x00000023, 0x00000083, 0x00000001, 0x0005001e,
    0x00000088, 0x00000006, 0x00000006, 0x00000006, 0x00040020, 0x00000089, 0x00000009,
    0x00000088, 0x0004003b, 0x00000089, 0x0000008a, 0x00000009, 0x00040020, 0x0000008b,
    0x00000009, 0x00000006, 0x0004002b, 0x00000006, 0x00000097, 0x00000004, 0x0004002b,
    0x00000023, 0x000000aa, 0x00000002, 0x0004002b, 0x00000006, 0x000000c7, 0x00000100,
    0x0004001c, 0x000000c9, 0x00000006, 0x000000c7, 0x00040020, 0x000000ca, 0x00000007,
    0x000000c9, 0x00040017, 0x0000013f, 0x00000006, 0x00000003, 0x00040020, 0x00000140,
    0x00000001, 0x0000013f, 0x0004003b, 0x00000140, 0x00000141, 0x00000001, 0x00040020,
    0x00000142, 0x00000001, 0x00000006, 0x0006002c, 0x0000013f, 0x000001c9, 0x000000c7,
    0x00000080, 0x00000080, 0x00050036, 0x00000002, 0x00000004, 0x00000000, 0x00000003,
    0x000200f8, 0x00000005, 0x0004003b, 0x00000007, 0x0000013e, 0x00000007, 0x0004003b,
    0x00000007, 0x0000014a, 0x00000007, 0x0004003b, 0x00000007, 0x0000014e, 0x00000007,
    0x0004003b, 0x00000007, 0x00000160, 0x00000007, 0x0004003b, 0x00000007, 0x00000168,
    0x00000007, 0x0004003b, 0x00000007, 0x00000169, 0x00000007, 0x0004003b, 0x00000007,
    0x00000171, 0x00000007, 0x0004003b, 0x00000007, 0x0000017c, 0x00000007, 0x0004003b,
    0x00000007, 0x0000017f, 0x00000007, 0x0004003b, 0x00000007, 0x00000180, 0x00000007,
    0x0004003b, 0x00000007, 0x00000183, 0x00000007, 0x0004003b, 0x00000007, 0x00000185,
    0x00000007, 0x0004003b, 0x00000007, 0x00000188, 0x00000007, 0x0004003b, 0x00000007,
    0x0000018a, 0x00000007, 0x0004003b, 0x00000007, 0x00000190, 0x00000007, 0x0004003b,
    0x00000007, 0x00000199, 0x00000007, 0x0004003b, 0x00000007, 0x000001ab, 0x00000007,
    0x0004003b, 0x00000007, 0x000001af, 0x00000007, 0x0004003b, 0x00000007, 0x000001bf,
    0x00000007, 0x0004003b, 0x00000007, 0x000001c5, 0x00000007, 0x00050041, 0x00000142,
    0x00000143, 0x00000141, 0x00000081, 0x0004003d, 0x00000006, 0x00000144, 0x00000143,
    0x0003003e, 0x0000013e, 0x00000144, 0x00050041, 0x0000008b, 0x00000145, 0x0000008a,
    0x00000024, 0x0004003d, 0x00000006, 0x00000146, 0x00000145, 0x000500aa, 0x00000055,
    0x00000147, 0x00000146, 0x00000081, 0x000300f7, 0x00000149, 0x00000000, 0x000400fa,
    0x00000147, 0x00000148, 0x000001aa, 0x000200f8, 0x00000148, 0x00050041, 0x0000008b,
    0x0000014b, 0x0000008a, 0x00000083, 0x0004003d, 0x00000006, 0x0000014c, 0x0000014b,
    0x000500c2, 0x00000006, 0x0000014d, 0x0000014c, 0x00000080, 0x0003003e, 0x0000014a,
    0x0000014d, 0x0004003d, 0x00000006, 0x0000014f, 0x0000014a, 0x00050080, 0x00000006,
    0x00000150, 0x0000014f, 0x0000002c, 0x000500c2, 0x00000006, 0x00000151, 0x00000150,
    0x00000026, 0x0003003e, 0x0000014e, 0x00000151, 0x0004003d, 0x00000006, 0x00000152,
    0x0000013e, 0x000500aa, 0x00000055, 0x00000153, 0x00000152, 0x00000081, 0x000300f7,
    0x00000155, 0x00000000, 0x000400fa, 0x00000153, 0x00000154, 0x00000155, 0x000200f8,
    0x00000154, 0x00050041, 0x0000008b, 0x00000156, 0x0000008a, 0x00000083, 0x0004003d,
    0x00000006, 0x00000157, 0x00000156, 0x000500c7, 0x00000006, 0x00000158, 0x00000157,
    0x00000080, 0x000500ab, 0x00000055, 0x00000159, 0x00000158, 0x00000081, 0x000200f9,
    0x00000155, 0x000200f8, 0x00000155, 0x000700f5, 0x00000055, 0x0000015a, 0x00000153,
    0x00000148, 0x00000159, 0x00000154, 0x000300f7, 0x0000015c, 0x00000000, 0x000400fa,
    0x0000015a, 0x0000015b, 0x0000015c, 0x000200f8, 0x0000015b, 0x00050041, 0x0000008b,
    0x0000015d, 0x0000008a, 0x00000083, 0x0004003d, 0x00000006, 0x0000015e, 0x0000015d,
    0x00050082, 0x00000006, 0x0000015f, 0x0000015e, 0x00000080, 0x0003003e, 0x00000160,
    0x0000015f, 0x00050039, 0x00000002, 0x00000161, 0x00000017, 0x00000160, 0x000200f9,
    0x0000015c, 0x000200f8, 0x0000015c, 0x0004003d, 0x00000006, 0x00000162, 0x0000013e,
    0x0004003d, 0x00000006, 0x00000163, 0x0000014e, 0x000500ae, 0x00000055, 0x00000164,
    0x00000162, 0x00000163, 0x000300f7, 0x00000166, 0x00000000, 0x000400fa, 0x00000164,
    0x00000165, 0x00000166, 0x000200f8, 0x00000165, 0x000100fd, 0x000200f8, 0x00000166,
    0x0003003e, 0x00000168, 0x00000081, 0x0003003e, 0x00000169, 0x00000081, 0x000200f9,
    0x0000016a, 0x000200f8, 0x0000016a, 0x000400f6, 0x0000016c, 0x0000016d, 0x00000000,
    0x000200f9, 0x0000016e, 0x000200f8, 0x0000016e, 0x0004003d, 0x00000006, 0x0000016f,
    0x00000169, 0x000500b0, 0x00000055, 0x00000170, 0x0000016f, 0x00000097, 0x000400fa,
    0x00000170, 0x0000016b, 0x0000016c, 0x000200f8, 0x0000016b, 0x0004003d, 0x00000006,
    0x00000172, 0x0000013e, 0x000500c4, 0x00000006, 0x00000173, 0x00000172, 0x00000026,
    0x0004003d, 0x00000006, 0x00000174, 0x00000169, 0x00050080, 0x00000006, 0x00000175,
    0x00000173, 0x00000174, 0x0003003e, 0x00000171, 0x00000175, 0x0004003d, 0x00000006,
    0x00000176, 0x00000171, 0x0004003d, 0x00000006, 0x00000177, 0x0000014a, 0x000500ae,
    0x00000055, 0x00000178, 0x00000176, 0x00000177, 0x000300f7, 0x0000017a, 0x00000000,
    0x000400fa, 0x00000178, 0x00000179, 0x0000017a, 0x000200f8, 0x00000179, 0x000200f9,
    0x0000016d, 0x000200f8, 0x0000017a, 0x0004003d, 0x00000006, 0x0000017d, 0x00000171,
    0x000500c4, 0x00000006, 0x0000017e, 0x0000017d, 0x00000080, 0x0003003e, 0x0000017c,
    0x0000017e, 0x0004003d, 0x00000006, 0x00000181, 0x0000017c, 0x0003003e, 0x00000180,
    0x00000181, 0x00050039, 0x00000006, 0x00000182, 0x0000000a, 0x00000180, 0x0003003e,
    0x00000183, 0x00000182, 0x00050039, 0x00000006, 0x00000184, 0x00000013, 0x00000183,
    0x0003003e, 0x0000017f, 0x00000184, 0x0004003d, 0x00000006, 0x00000186, 0x0000017c,
    0x00050080, 0x00000006, 0x00000187, 0x00000186, 0x00000080, 0x0003003e, 0x00000188,
    0x00000187, 0x00050039, 0x00000006, 0x00000189, 0x0000000a, 0x00000188, 0x0003003e,
    0x0000018a, 0x00000189, 0x00050039, 0x00000006, 0x0000018b, 0x00000013, 0x0000018a,
    0x0003003e, 0x00000185, 0x0000018b, 0x0004003d, 0x00000006, 0x0000018c, 0x0000017f,
    0x000500aa, 0x00000055, 0x0000018d, 0x0000018c, 0x00000031, 0x000300f7, 0x0000018f,
    0x00000000, 0x000400fa, 0x0000018d, 0x0000018e, 0x0000018f, 0x000200f8, 0x0000018e,
    0x0004003d, 0x00000006, 0x00000191, 0x0000017c, 0x0003003e, 0x00000190, 0x00000191,
    0x00050039, 0x00000002, 0x00000192, 0x00000017, 0x00000190, 0x000200f9, 0x0000018f,
    0x000200f8, 0x0000018f, 0x0004003d, 0x00000006, 0x00000193, 0x00000185, 0x000500aa,
    0x00000055, 0x00000194, 0x00000193, 0x00000031, 0x000300f7, 0x00000196, 0x00000000,
    0x000400fa, 0x00000194, 0x00000195, 0x00000196, 0x000200f8, 0x00000195, 0x0004003d,
    0x00000006, 0x00000197, 0x0000017c, 0x00050080, 0x00000006, 0x00000198, 0x00000197,
    0x00000080, 0x0003003e, 0x00000199, 0x00000198, 0x00050039, 0x00000002, 0x0000019a,
    0x00000017, 0x00000199, 0x000200f9, 0x00000196, 0x000200f8, 0x00000196, 0x0004003d,
    0x00000006, 0x0000019b, 0x0000017f, 0x000500c4, 0x00000006, 0x0000019c, 0x0000019b,
    0x00000097, 0x0004003d, 0x00000006, 0x0000019d, 0x00000185, 0x000500c5, 0x00000006,
    0x0000019e, 0x0000019c, 0x0000019d, 0x000500c7, 0x00000006, 0x0000019f, 0x0000019e,
    0x00000031, 0x0004003d, 0x00000006, 0x000001a0, 0x00000169, 0x00050084, 0x00000006,
    0x000001a1, 0x000001a0, 0x0000002e, 0x000500c4, 0x00000006, 0x000001a2, 0x0000019f,
    0x000001a1, 0x0004003d, 0x00000006, 0x000001a3, 0x00000168, 0x000500c5, 0x00000006,
    0x000001a4, 0x000001a3, 0x000001a2, 0x0003003e, 0x00000168, 0x000001a4, 0x000200f9,
    0x0000016d, 0x000200f8, 0x0000016d, 0x0004003d, 0x00000006, 0x000001a5, 0x00000169,
    0x00050080, 0x00000006, 0x000001a6, 0x000001a5, 0x00000083, 0x0003003e, 0x00000169,
    0x000001a6, 0x000200f9, 0x0000016a, 0x000200f8, 0x0000016c, 0x0004003d, 0x00000006,
    0x000001a7, 0x0000013e, 0x0004003d, 0x00000006, 0x000001a8, 0x00000168, 0x00060041,
    0x00000028, 0x000001a9, 0x00000047, 0x00000024, 0x000001a7, 0x0003003e, 0x000001a9,
    0x000001a8, 0x000200f9, 0x00000149, 0x000200f8, 0x000001aa, 0x00050041, 0x0000008b,
    0x000001ac, 0x0000008a, 0x00000083, 0x0004003d, 0x00000006, 0x000001ad, 0x000001ac,
    0x000500c2, 0x00000006, 0x000001ae, 0x000001ad, 0x00000080, 0x0003003e, 0x000001ab,
    0x000001ae, 0x0004003d, 0x00000006, 0x000001b0, 0x000001ab, 0x00050080, 0x00000006,
    0x000001b1, 0x000001b0, 0x0000002c, 0x000500c2, 0x00000006, 0x000001b2, 0x000001b1,
    0x00000026, 0x0003003e, 0x000001af, 0x000001b2, 0x0004003d, 0x00000006, 0x000001b3,
    0x0000013e, 0x0004003d, 0x00000006, 0x000001b4, 0x000001af, 0x000500ae, 0x00000055,
    0x000001b5, 0x000001b3, 0x000001b4, 0x000300f7, 0x000001b7, 0x00000000, 0x000400fa,
    0x000001b5, 0x000001b6, 0x000001b7, 0x000200f8, 0x000001b6, 0x000100fd, 0x000200f8,
    0x000001b7, 0x00050041, 0x0000008b, 0x000001b9, 0x0000008a, 0x00000024, 0x0004003d,
    0x00000006, 0x000001ba, 0x000001b9, 0x000500aa, 0x00000055, 0x000001bb, 0x000001ba,
    0x00000080, 0x000300f7, 0x000001bd, 0x00000000, 0x000400fa, 0x000001bb, 0x000001bc,
    0x000001c3, 0x000200f8, 0x000001bc, 0x0004003d, 0x00000006, 0x000001be, 0x0000013e,
    0x0004003d, 0x00000006, 0x000001c0, 0x0000013e, 0x0003003e, 0x000001bf, 0x000001c0,
    0x00050039, 0x00000006, 0x000001c1, 0x0000001a, 0x000001bf, 0x00060041, 0x00000028,
    0x000001c2, 0x00000047, 0x00000024, 0x000001be, 0x0003003e, 0x000001c2, 0x000001c1,
    0x000200f9, 0x000001bd, 0x000200f8, 0x000001c3, 0x0004003d, 0x00000006, 0x000001c4,
    0x0000013e, 0x0004003d, 0x00000006, 0x000001c6, 0x0000013e, 0x0003003e, 0x000001c5,
    0x000001c6, 0x00050039, 0x00000006, 0x000001c7, 0x0000001d, 0x000001c5, 0x00060041,
    0x00000028, 0x000001c8, 0x00000047, 0x00000024, 0x000001c4, 0x0003003e, 0x000001c8,
    0x000001c7, 0x000200f9, 0x000001bd, 0x000200f8, 0x000001bd, 0x000200f9, 0x00000149,
    0x000200f8, 0x00000149, 0x000100fd, 0x00010038, 0x00050036, 0x00000006, 0x0000000a,
    0x00000000, 0x00000008, 0x00030037, 0x00000007, 0x00000009, 0x000200f8, 0x0000000b,
    0x0004003d, 0x00000006, 0x00000025, 0x00000009, 0x000500c2, 0x00000006, 0x00000027,
    0x00000025, 0x00000026, 0x00060041, 0x00000028, 0x00000029, 0x00000022, 0x00000024,
    0x00000027, 0x0004003d, 0x00000006, 0x0000002a, 0x00000029, 0x0004003d, 0x00000006,
    0x0000002b, 0x00000009, 0x000500c7, 0x00000006, 0x0000002d, 0x0000002b, 0x0000002c,
    0x00050084, 0x00000006, 0x0000002f, 0x0000002d, 0x0000002e, 0x000500c2, 0x00000006,
    0x00000030, 0x0000002a, 0x0000002f, 0x000500c7, 0x00000006, 0x00000032, 0x00000030,
    0x00000031, 0x000200fe, 0x00000032, 0x00010038, 0x00050036, 0x00000006, 0x0000000d,
    0x00000000, 0x00000008, 0x00030037, 0x00000007, 0x0000000c, 0x000200f8, 0x0000000e,
    0x0004003d, 0x00000006, 0x00000039, 0x0000000c, 0x000500c2, 0x00000006, 0x0000003a,
    0x00000039, 0x00000026, 0x00060041, 0x00000028, 0x0000003b, 0x00000038, 0x00000024,
    0x0000003a, 0x0004003d, 0x00000006, 0x0000003c, 0x0000003b, 0x0004003d, 0x00000006,
    0x0000003d, 0x0000000c, 0x000500c7, 0x00000006, 0x0000003e, 0x0000003d, 0x0000002c,
    0x00050084, 0x00000006, 0x0000003f, 0x0000003e, 0x0000002e, 0x000500c2, 0x00000006,
    0x00000040, 0x0000003c, 0x0000003f, 0x000500c7, 0x00000006, 0x00000041, 0x00000040,
    0x00000031, 0x000200fe, 0x00000041, 0x00010038, 0x00050036, 0x00000006, 0x00000010,
    0x00000000, 0x00000008, 0x00030037, 0x00000007, 0x0000000f, 0x000200f8, 0x00000011,
    0x0004003d, 0x00000006, 0x00000048, 0x0000000f, 0x000500c2, 0x00000006, 0x00000049,
    0x00000048, 0x00000026, 0x00060041, 0x00000028, 0x0000004a, 0x00000047, 0x00000024,
    0x00000049, 0x0004003d, 0x00000006, 0x0000004b, 0x0000004a, 0x0004003d, 0x00000006,
    0x0000004c, 0x0000000f, 0x000500c7, 0x00000006, 0x0000004d, 0x0000004c, 0x0000002c,
    0x00050084, 0x00000006, 0x0000004e, 0x0000004d, 0x0000002e, 0x000500c2, 0x00000006,
    0x0000004f, 0x0000004b, 0x0000004e, 0x000500c7, 0x00000006, 0x00000050, 0x0000004f,
    0x00000031, 0x000200fe, 0x00000050, 0x00010038, 0x00050036, 0x00000006, 0x00000013,
    0x00000000, 0x00000008, 0x00030037, 0x00000007, 0x00000012, 0x000200f8, 0x00000014,
    0x0004003d, 0x00000006, 0x00000053, 0x00000012, 0x000500ae, 0x00000055, 0x00000056,
    0x00000053, 0x00000054, 0x0004003d, 0x00000006, 0x00000057, 0x00000012, 0x000500b2,
    0x00000055, 0x00000059, 0x00000057, 0x00000058, 0x000500a7, 0x00000055, 0x0000005a,
    0x00000056, 0x00000059, 0x000300f7, 0x0000005c, 0x00000000, 0x000400fa, 0x0000005a,
    0x0000005b, 0x0000005c, 0x000200f8, 0x0000005b, 0x0004003d, 0x00000006, 0x0000005d,
    0x00000012, 0x00050082, 0x00000006, 0x0000005e, 0x0000005d, 0x00000054, 0x000200fe,
    0x0000005e, 0x000200f8, 0x0000005c, 0x0004003d, 0x00000006, 0x00000060, 0x00000012,
    0x000500ae, 0x00000055, 0x00000062, 0x00000060, 0x00000061, 0x0004003d, 0x00000006,
    0x00000063, 0x00000012, 0x000500b2, 0x00000055, 0x00000065, 0x00000063, 0x00000064,
    0x000500a7, 0x00000055, 0x00000066, 0x00000062, 0x00000065, 0x000300f7, 0x00000068,
    0x00000000, 0x000400fa, 0x00000066, 0x00000067, 0x00000068, 0x000200f8, 0x00000067,
    0x0004003d, 0x00000006, 0x00000069, 0x00000012, 0x00050082, 0x00000006, 0x0000006b,
    0x00000069, 0x0000006a, 0x000200fe, 0x0000006b, 0x000200f8, 0x00000068, 0x0004003d,
    0x00000006, 0x0000006d, 0x00000012, 0x000500ae, 0x00000055, 0x0000006f, 0x0000006d,
    0x0000006e, 0x0004003d, 0x00000006, 0x00000070, 0x00000012, 0x000500b2, 0x00000055,
    0x00000072, 0x00000070, 0x00000071, 0x000500a7, 0x00000055, 0x00000073, 0x0000006f,
    0x00000072, 0x000300f7, 0x00000075, 0x00000000, 0x000400fa, 0x00000073, 0x00000074,
    0x00000075, 0x000200f8, 0x00000074, 0x0004003d, 0x00000006, 0x00000076, 0x00000012,
    0x00050082, 0x00000006, 0x00000078, 0x00000076, 0x00000077, 0x000200fe, 0x00000078,
    0x000200f8, 0x00000075, 0x000200fe, 0x00000031, 0x00010038, 0x00050036, 0x00000002,
    0x00000017, 0x00000000, 0x00000015, 0x00030037, 0x00000007, 0x00000016, 0x000200f8,
    0x00000018, 0x00050041, 0x00000028, 0x0000007f, 0x0000007e, 0x00000024, 0x000700e5,
    0x00000006, 0x00000082, 0x0000007f, 0x00000080, 0x00000081, 0x00000080, 0x00050041,
    0x00000028, 0x00000084, 0x0000007e, 0x00000083, 0x0004003d, 0x00000006, 0x00000085,
    0x00000016, 0x000700ed, 0x00000006, 0x00000086, 0x00000084, 0x00000080, 0x00000081,
    0x00000085, 0x000100fd, 0x00010038, 0x00050036, 0x00000006, 0x0000001a, 0x00000000,
    0x00000008, 0x00030037, 0x00000007, 0x00000019, 0x000200f8, 0x0000001b, 0x0004003b,
    0x00000007, 0x00000087, 0x00000007, 0x0004003b, 0x00000007, 0x0000008f, 0x00000007,
    0x0004003b, 0x00000007, 0x00000090, 0x00000007, 0x0004003b, 0x00000007, 0x00000099,
    0x00000007, 0x0004003b, 0x00000007, 0x000000a4, 0x00000007, 0x0004003b, 0x00000007,
    0x000000a5, 0x00000007, 0x0004003b, 0x00000007, 0x000000a8, 0x00000007, 0x0004003b,
    0x00000007, 0x000000ae, 0x00000007, 0x0004003b, 0x00000007, 0x000000af, 0x00000007,
    0x00050041, 0x0000008b, 0x0000008c, 0x0000008a, 0x00000083, 0x0004003d, 0x00000006,
    0x0000008d, 0x0000008c, 0x000500c2, 0x00000006, 0x0000008e, 0x0000008d, 0x00000080,
    0x0003003e, 0x00000087, 0x0000008e, 0x0003003e, 0x0000008f, 0x00000081, 0x0003003e,
    0x00000090, 0x00000081, 0x000200f9, 0x00000091, 0x000200f8, 0x00000091, 0x000400f6,
    0x00000093, 0x00000094, 0x00000000, 0x000200f9, 0x00000095, 0x000200f8, 0x00000095,
    0x0004003d, 0x00000006, 0x00000096, 0x00000090, 0x000500b0, 0x00000055, 0x00000098,
    0x00000096, 0x00000097, 0x000400fa, 0x00000098, 0x00000092, 0x00000093, 0x000200f8,
    0x00000092, 0x0004003d, 0x00000006, 0x0000009a, 0x00000019, 0x000500c4, 0x00000006,
    0x0000009b, 0x0000009a, 0x00000026, 0x0004003d, 0x00000006, 0x0000009c, 0x00000090,
    0x00050080, 0x00000006, 0x0000009d, 0x0000009b, 0x0000009c, 0x0003003e, 0x00000099,
    0x0000009d, 0x0004003d, 0x00000006, 0x0000009e, 0x00000099, 0x0004003d, 0x00000006,
    0x0000009f, 0x00000087, 0x000500ae, 0x00000055, 0x000000a0, 0x0000009e, 0x0000009f,
    0x000300f7, 0x000000a2, 0x00000000, 0x000400fa, 0x000000a0, 0x000000a1, 0x000000a2,
    0x000200f8, 0x000000a1, 0x000200f9, 0x00000093, 0x000200f8, 0x000000a2, 0x0004003d,
    0x00000006, 0x000000a6, 0x00000099, 0x0003003e, 0x000000a5, 0x000000a6, 0x00050039,
    0x00000006, 0x000000a7, 0x00000010, 0x000000a5, 0x0003003e, 0x000000a4, 0x000000a7,
    0x0004003d, 0x00000006, 0x000000a9, 0x00000099, 0x00050041, 0x0000008b, 0x000000ab,
    0x0000008a, 0x000000aa, 0x0004003d, 0x00000006, 0x000000ac, 0x000000ab, 0x00050089,
    0x00000006, 0x000000ad, 0x000000a9, 0x000000ac, 0x0003003e, 0x000000a8, 0x000000ad,
    0x0004003d, 0x00000006, 0x000000b0, 0x000000a8, 0x0003003e, 0x000000af, 0x000000b0,
    0x00050039, 0x00000006, 0x000000b1, 0x0000000d, 0x000000af, 0x0003003e, 0x000000ae,
    0x000000b1, 0x0004003d, 0x00000006, 0x000000b2, 0x000000a4, 0x0004003d, 0x00000006,
    0x000000b3, 0x000000ae, 0x000500c6, 0x00000006, 0x000000b4, 0x000000b2, 0x000000b3,
    0x000500c7, 0x00000006, 0x000000b5, 0x000000b4, 0x00000031, 0x0004003d, 0x00000006,
    0x000000b6, 0x00000090, 0x00050084, 0x00000006, 0x000000b7, 0x000000b6, 0x0000002e,
    0x000500c4, 0x00000006, 0x000000b8, 0x000000b5, 0x000000b7, 0x0004003d, 0x00000006,
    0x000000b9, 0x0000008f, 0x000500c5, 0x00000006, 0x000000ba, 0x000000b9, 0x000000b8,
    0x0003003e, 0x0000008f, 0x000000ba, 0x000200f9, 0x00000094, 0x000200f8, 0x00000094,
    0x0004003d, 0x00000006, 0x000000bb, 0x00000090, 0x00050080, 0x00000006, 0x000000bc,
    0x000000bb, 0x00000083, 0x0003003e, 0x00000090, 0x000000bc, 0x000200f9, 0x00000091,
    0x000200f8, 0x00000093, 0x0004003d, 0x00000006, 0x000000bd, 0x0000008f, 0x000200fe,
    0x000000bd, 0x00010038, 0x00050036, 0x00000006, 0x0000001d, 0x00000000, 0x00000008,
    0x00030037, 0x00000007, 0x0000001c, 0x000200f8, 0x0000001e, 0x0004003b, 0x00000007,
    0x000000c0, 0x00000007, 0x0004003b, 0x000000ca, 0x000000cb, 0x00000007, 0x0004003b,
    0x00000007, 0x000000d1, 0x00000007, 0x0004003b, 0x00000007, 0x000000d2, 0x00000007,
    0x0004003b, 0x00000007, 0x000000e3, 0x00000007, 0x0004003b, 0x00000007, 0x000000e7,
    0x00000007, 0x0004003b, 0x00000007, 0x000000f5, 0x00000007, 0x0004003b, 0x00000007,
    0x000000f6, 0x00000007, 0x0004003b, 0x00000007, 0x000000f7, 0x00000007, 0x0004003b,
    0x00000007, 0x000000fa, 0x00000007, 0x0004003b, 0x00000007, 0x000000fd, 0x00000007,
    0x0004003b, 0x00000007, 0x000000fe, 0x00000007, 0x0004003b, 0x00000007, 0x00000110,
    0x00000007, 0x0004003b, 0x00000007, 0x0000011c, 0x00000007, 0x0004003b, 0x00000007,
    0x0000012c, 0x00000007, 0x0003003e, 0x000000c0, 0x00000081, 0x000200f9, 0x000000c1,
    0x000200f8, 0x000000c1, 0x000400f6, 0x000000c3, 0x000000c4, 0x00000000, 0x000200f9,
    0x000000c5, 0x000200f8, 0x000000c5, 0x0004003d, 0x00000006, 0x000000c6, 0x000000c0,
    0x000500b0, 0x00000055, 0x000000c8, 0x000000c6, 0x000000c7, 0x000400fa, 0x000000c8,
    0x000000c2, 0x000000c3, 0x000200f8, 0x000000c2, 0x0004003d, 0x00000006, 0x000000cc,
    0x000000c0, 0x0004003d, 0x00000006, 0x000000cd, 0x000000c0, 0x00050041, 0x00000007,
    0x000000ce, 0x000000cb, 0x000000cc, 0x0003003e, 0x000000ce, 0x000000cd, 0x000200f9,
    0x000000c4, 0x000200f8, 0x000000c4, 0x0004003d, 0x00000006, 0x000000cf, 0x000000c0,
    0x00050080, 0x00000006, 0x000000d0, 0x000000cf, 0x00000083, 0x0003003e, 0x000000c0,
    0x000000d0, 0x000200f9, 0x000000c1, 0x000200f8, 0x000000c3, 0x0003003e, 0x000000d1,
    0x00000081, 0x0003003e, 0x000000d2, 0x00000081, 0x000200f9, 0x000000d3, 0x000200f8,
    0x000000d3, 0x000400f6, 0x000000d5, 0x000000d6, 0x00000000, 0x000200f9, 0x000000d7,
    0x000200f8, 0x000000d7, 0x0004003d, 0x00000006, 0x000000d8, 0x000000d2, 0x000500b0,
    0x00000055, 0x000000d9, 0x000000d8, 0x000000c7, 0x000400fa, 0x000000d9, 0x000000d4,
    0x000000d5, 0x000200f8, 0x000000d4, 0x0004003d, 0x00000006, 0x000000da, 0x000000d1,
    0x0004003d, 0x00000006, 0x000000db, 0x000000d2, 0x00050041, 0x00000007, 0x000000dc,
    0x000000cb, 0x000000db, 0x0004003d, 0x00000006, 0x000000dd, 0x000000dc, 0x00050080,
    0x00000006, 0x000000de, 0x000000da, 0x000000dd, 0x0004003d, 0x00000006, 0x000000df,
    0x000000d2, 0x00050041, 0x0000008b, 0x000000e0, 0x0000008a, 0x000000aa, 0x0004003d,
    0x00000006, 0x000000e1, 0x000000e0, 0x00050089, 0x00000006, 0x000000e2, 0x000000df,
    0x000000e1, 0x0003003e, 0x000000e3, 0x000000e2, 0x00050039, 0x00000006, 0x000000e4,
    0x0000000d, 0x000000e3, 0x00050080, 0x00000006, 0x000000e5, 0x000000de, 0x000000e4,
    0x000500c7, 0x00000006, 0x000000e6, 0x000000e5, 0x00000031, 0x0003003e, 0x000000d1,
    0x000000e6, 0x0004003d, 0x00000006, 0x000000e8, 0x000000d2, 0x00050041, 0x00000007,
    0x000000e9, 0x000000cb, 0x000000e8, 0x0004003d, 0x00000006, 0x000000ea, 0x000000e9,
    0x0003003e, 0x000000e7, 0x000000ea, 0x0004003d, 0x00000006, 0x000000eb, 0x000000d2,
    0x0004003d, 0x00000006, 0x000000ec, 0x000000d1, 0x00050041, 0x00000007, 0x000000ed,
    0x000000cb, 0x000000ec, 0x0004003d, 0x00000006, 0x000000ee, 0x000000ed, 0x00050041,
    0x00000007, 0x000000ef, 0x000000cb, 0x000000eb, 0x0003003e, 0x000000ef, 0x000000ee,
    0x0004003d, 0x00000006, 0x000000f0, 0x000000d1, 0x0004003d, 0x00000006, 0x000000f1,
    0x000000e7, 0x00050041, 0x00000007, 0x000000f2, 0x000000cb, 0x000000f0, 0x0003003e,
    0x000000f2, 0x000000f1, 0x000200f9, 0x000000d6, 0x000200f8, 0x000000d6, 0x0004003d,
    0x00000006, 0x000000f3, 0x000000d2, 0x00050080, 0x00000006, 0x000000f4, 0x000000f3,
    0x00000083, 0x0003003e, 0x000000d2, 0x000000f4, 0x000200f9, 0x000000d3, 0x000200f8,
    0x000000d5, 0x0003003e, 0x000000f5, 0x00000081, 0x0003003e, 0x000000f6, 0x00000081,
    0x0004003d, 0x00000006, 0x000000f8, 0x0000001c, 0x000500c4, 0x00000006, 0x000000f9,
    0x000000f8, 0x00000026, 0x0003003e, 0x000000f7, 0x000000f9, 0x0004003d, 0x00000006,
    0x000000fb, 0x000000f7, 0x00050080, 0x00000006, 0x000000fc, 0x000000fb, 0x00000097,
    0x0003003e, 0x000000fa, 0x000000fc, 0x0003003e, 0x000000fd, 0x00000081, 0x0003003e,
    0x000000fe, 0x00000081, 0x000200f9, 0x000000ff, 0x000200f8, 0x000000ff, 0x000400f6,
    0x00000101, 0x00000102, 0x00000000, 0x000200f9, 0x00000103, 0x000200f8, 0x00000103,
    0x0004003d, 0x00000006, 0x00000104, 0x000000fe, 0x0004003d, 0x00000006, 0x00000105,
    0x000000fa, 0x000500b0, 0x00000055, 0x00000106, 0x00000104, 0x00000105, 0x000400fa,
    0x00000106, 0x00000100, 0x00000101, 0x000200f8, 0x00000100, 0x0004003d, 0x00000006,
    0x00000107, 0x000000f5, 0x00050080, 0x00000006, 0x00000108, 0x00000107, 0x00000080,
    0x000500c7, 0x00000006, 0x00000109, 0x00000108, 0x00000031, 0x0003003e, 0x000000f5,
    0x00000109, 0x0004003d, 0x00000006, 0x0000010a, 0x000000f6, 0x0004003d, 0x00000006,
    0x0000010b, 0x000000f5, 0x00050041, 0x00000007, 0x0000010c, 0x000000cb, 0x0000010b,
    0x0004003d, 0x00000006, 0x0000010d, 0x0000010c, 0x00050080, 0x00000006, 0x0000010e,
    0x0000010a, 0x0000010d, 0x000500c7, 0x00000006, 0x0000010f, 0x0000010e, 0x00000031,
    0x0003003e, 0x000000f6, 0x0000010f, 0x0004003d, 0x00000006, 0x00000111, 0x000000f5,
    0x00050041, 0x00000007, 0x00000112, 0x000000cb, 0x00000111, 0x0004003d, 0x00000006,
    0x00000113, 0x00000112, 0x0003003e, 0x00000110, 0x00000113, 0x0004003d, 0x00000006,
    0x00000114, 0x000000f5, 0x0004003d, 0x00000006, 0x00000115, 0x000000f6, 0x00050041,
    0x00000007, 0x00000116, 0x000000cb, 0x00000115, 0x0004003d, 0x00000006, 0x00000117,
    0x00000116, 0x00050041, 0x00000007, 0x00000118, 0x000000cb, 0x00000114, 0x0003003e,
    0x00000118, 0x00000117, 0x0004003d, 0x00000006, 0x00000119, 0x000000f6, 0x0004003d,
    0x00000006, 0x0000011a, 0x00000110, 0x00050041, 0x00000007, 0x0000011b, 0x000000cb,
    0x00000119, 0x0003003e, 0x0000011b, 0x0000011a, 0x0004003d, 0x00000006, 0x0000011d,
    0x000000f5, 0x00050041, 0x00000007, 0x0000011e, 0x000000cb, 0x0000011d, 0x0004003d,
    0x00000006, 0x0000011f, 0x0000011e, 0x0004003d, 0x00000006, 0x00000120, 0x000000f6,
    0x00050041, 0x00000007, 0x00000121, 0x000000cb, 0x00000120, 0x0004003d, 0x00000006,
    0x00000122, 0x00000121, 0x00050080, 0x00000006, 0x00000123, 0x0000011f, 0x00000122,
    0x000500c7, 0x00000006, 0x00000124, 0x00000123, 0x00000031, 0x00050041, 0x00000007,
    0x00000125, 0x000000cb, 0x00000124, 0x0004003d, 0x00000006, 0x00000126, 0x00000125,
    0x0003003e, 0x0000011c, 0x00000126, 0x0004003d, 0x00000006, 0x00000127, 0x000000fe,
    0x0004003d, 0x00000006, 0x00000128, 0x000000f7, 0x000500ae, 0x00000055, 0x00000129,
    0x00000127, 0x00000128, 0x000300f7, 0x0000012b, 0x00000000, 0x000400fa, 0x00000129,
    0x0000012a, 0x0000012b, 0x000200f8, 0x0000012a, 0x0004003d, 0x00000006, 0x0000012d,
    0x000000fe, 0x0003003e, 0x0000012c, 0x0000012d, 0x00050039, 0x00000006, 0x0000012e,
    0x00000010, 0x0000012c, 0x0004003d, 0x00000006, 0x0000012f, 0x0000011c, 0x000500c6,
    0x00000006, 0x00000130, 0x0000012e, 0x0000012f, 0x000500c7, 0x00000006, 0x00000131,
    0x00000130, 0x00000031, 0x0004003d, 0x00000006, 0x00000132, 0x000000fe, 0x0004003d,
    0x00000006, 0x00000133, 0x000000f7, 0x00050082, 0x00000006, 0x00000134, 0x00000132,
    0x00000133, 0x00050084, 0x00000006, 0x00000135, 0x00000134, 0x0000002e, 0x000500c4,
    0x00000006, 0x00000136, 0x00000131, 0x00000135, 0x0004003d, 0x00000006, 0x00000137,
    0x000000fd, 0x000500c5, 0x00000006, 0x00000138, 0x00000137, 0x00000136, 0x0003003e,
    0x000000fd, 0x00000138, 0x000200f9, 0x0000012b, 0x000200f8, 0x0000012b, 0x000200f9,
    0x00000102, 0x000200f8, 0x00000102, 0x0004003d, 0x00000006, 0x00000139, 0x000000fe,
    0x00050080, 0x00000006, 0x0000013a, 0x00000139, 0x00000083, 0x0003003e, 0x000000fe,
    0x0000013a, 0x000200f9, 0x000000ff, 0x000200f8, 0x00000101, 0x0004003d, 0x00000006,
    0x0000013b, 0x000000fd, 0x000200fe, 0x0000013b, 0x00010038,
};
static_assert(sizeof(kShaderSpv) % 4 == 0, "SPIR-V must be word-aligned");

static constexpr uint32_t kLocalSizeX = 256;

// Work items -> Dispatch group count along x (shared by every backend).
inline uint32_t numGroupsFor(uint32_t workItems)
{
    return workItems ? (workItems + kLocalSizeX - 1) / kLocalSizeX : 0u;
}

// ---------------------------------------------------------------------------
// Backend-agnostic compute interface.
//
// The decryption pipeline (hex-decode dispatch, then XOR/RC4 decrypt dispatch)
// is expressed once against IBackend; concrete implementations exist for
// Vulkan (default, every platform) and Direct3D 11 (SHOBF_BACKEND_D3D11,
// Windows targets). Backends own their buffers and grow them as needed;
// Engine serializes access and translates failures to shobf::Error (or to
// silent empty results under SHOBF_NO_DEBUG).
// ---------------------------------------------------------------------------
enum class BStatus { Ok, BadHex };

class IBackend
{
public:
    virtual ~IBackend() = default;
    // Bring up device + pipeline. Throws shobf::Error in debug builds when
    // initialization fails; under SHOBF_NO_DEBUG it returns silently and
    // ready() reports the outcome instead.
    virtual void init(bool wantValidation) = 0;
    virtual bool ready() const = 0;
    // Upper bound on the x dimension of one Dispatch.
    virtual uint32_t maxGroupsX() const = 0;
    // Run hex-decode + `mode` decrypt; writes exactly dataLen bytes to
    // plainOut (dataLen == hexLen/2). badOffsetOut receives the offending
    // character index when BStatus::BadHex is returned.
    virtual BStatus run(const char* hex, size_t hexLen,
                        const uint32_t* keyWords, size_t keyWordCount,
                        uint32_t keyLen, uint32_t mode,
                        uint8_t* plainOut,
                        uint32_t& badOffsetOut) = 0;
};

// ---------------------------------------------------------------------------
// Vulkan backend (default): owns all long-lived Vulkan state.
// ---------------------------------------------------------------------------
#if !defined(SHOBF_BACKEND_D3D11)

class VulkanBackend final : public IBackend
{
public:
    explicit VulkanBackend(bool wantValidation) { init(wantValidation); }

    bool ready() const override
    {
#ifndef SHOBF_NO_DEBUG
        return true;   // debug builds throw on failure, so reaching here = ready
#else
        return ready_;
#endif
    }

    uint32_t maxGroupsX() const override
    {
        return limits_.maxComputeWorkGroupCount[0];
    }

    // Runs both dispatches for `hex` against `keyWords`/`keyLen`;
    // writes the plaintext bytes to plainOut.
    BStatus run(const char* hex, size_t hexLen,
                const uint32_t* keyWords, size_t keyWordCount,
                uint32_t keyLen, uint32_t mode,
                uint8_t* plainOut,
                uint32_t& badOffsetOut) override
    {
        const uint32_t   numHexW   = uint32_t((hexLen + 3) / 4);
        const uint32_t   dataLen   = uint32_t(hexLen / 2);
        const uint32_t   numWorkW  = dataLen ? (dataLen + 3) / 4 : 0;

        Buffer inBuf, keyBuf, workBuf, statBuf;
        inBuf.init  (physicalDevice_, device_, VkDeviceSize(numHexW)  * 4);
        keyBuf.init (physicalDevice_, device_, VkDeviceSize(keyWordCount) * 4);
        workBuf.init(physicalDevice_, device_, VkDeviceSize(numWorkW) * 4);
        statBuf.init(physicalDevice_, device_, 2 * 4);

        inBuf.upload(hex, VkDeviceSize(hexLen));
        keyBuf.upload(keyWords, keyBuf.size);
        const uint32_t statInit[2] = {0u, 0xFFFFFFFFu};
        statBuf.upload(statInit, sizeof(statInit));

        writeDescriptors(inBuf, keyBuf, workBuf, statBuf);

        SHOBF_CHECK(vkResetCommandBuffer(commandBuffer_, 0));
        VkCommandBufferBeginInfo bi{};
        bi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        SHOBF_CHECK(vkBeginCommandBuffer(commandBuffer_, &bi));

        vkCmdBindPipeline(commandBuffer_, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline_);
        vkCmdBindDescriptorSets(commandBuffer_, VK_PIPELINE_BIND_POINT_COMPUTE,
                                pipelineLayout_, 0, 1, &descriptorSet_, 0, nullptr);

        dispatchWithMode(kModeHexDecode, hexLen, keyLen);
        insertComputeToComputeBarrier();
        dispatchWithMode(mode, hexLen, keyLen);
        insertComputeToHostBarrier();

        SHOBF_CHECK(vkEndCommandBuffer(commandBuffer_));
        submitAndWait();

        uint32_t stat[2] = {0u, 0u};
        statBuf.download(stat, sizeof(stat));
        if (stat[0] != 0u) {
            badOffsetOut = stat[1];
            return BStatus::BadHex;
        }

        std::vector<uint32_t> outWords(numWorkW);
        workBuf.download(outWords.data(), workBuf.size);
        const std::vector<uint8_t> plain = unpackWords(outWords, dataLen);
        std::memcpy(plainOut, plain.data(), dataLen);
        return BStatus::Ok;
    }

private:
    void init(bool wantValidation)
    {
        createInstance(wantValidation);
        pickPhysicalDevice();
        createDeviceAndQueue();
        createCommandPoolAndBuffer();
        createDescriptors();
        createPipeline();

        VkPhysicalDeviceProperties props{};
        if (physicalDevice_ != VK_NULL_HANDLE) {
            vkGetPhysicalDeviceProperties(physicalDevice_, &props);
            limits_ = props.limits;
        }
#ifdef SHOBF_NO_DEBUG
        // With exceptions disabled, failed init must not crash later calls:
        // ready() reports the outcome and Engine returns empty results.
        ready_ = physicalDevice_ != VK_NULL_HANDLE &&
                 device_         != VK_NULL_HANDLE &&
                 queue_          != VK_NULL_HANDLE &&
                 commandPool_    != VK_NULL_HANDLE &&
                 commandBuffer_  != VK_NULL_HANDLE &&
                 descriptorPool_ != VK_NULL_HANDLE &&
                 setDescription_ != VK_NULL_HANDLE &&
                 pipelineLayout_ != VK_NULL_HANDLE &&
                 pipeline_       != VK_NULL_HANDLE;
#endif
    }

    ~VulkanBackend()
    {
        if (device_ != VK_NULL_HANDLE) vkDeviceWaitIdle(device_);
        if (pipeline_        != VK_NULL_HANDLE) vkDestroyPipeline(device_, pipeline_, nullptr);
        if (pipelineLayout_  != VK_NULL_HANDLE) vkDestroyPipelineLayout(device_, pipelineLayout_, nullptr);
        // descriptorSet_ dies with its pool
        if (descriptorPool_  != VK_NULL_HANDLE) vkDestroyDescriptorPool(device_, descriptorPool_, nullptr);
        if (setDescription_  != VK_NULL_HANDLE) vkDestroyDescriptorSetLayout(device_, setDescription_, nullptr);
        if (commandPool_     != VK_NULL_HANDLE) vkDestroyCommandPool(device_, commandPool_, nullptr);
        if (device_          != VK_NULL_HANDLE) vkDestroyDevice(device_, nullptr);
        if (messenger_ != VK_NULL_HANDLE && destroyMessenger_)
            destroyMessenger_(instance_, messenger_, nullptr);
        if (instance_ != VK_NULL_HANDLE) vkDestroyInstance(instance_, nullptr);
    }

    VulkanBackend(const VulkanBackend&) = delete;
    VulkanBackend& operator=(const VulkanBackend&) = delete;

    void createInstance(bool wantValidation)
    {
        std::vector<const char*> layers, extensions;
#ifndef SHOBF_NO_DEBUG
        bool haveDebugUtils = false;
        if (wantValidation && instanceLayerAvailable("VK_LAYER_KHRONOS_validation")) {
            layers.push_back("VK_LAYER_KHRONOS_validation");
            if (instanceExtensionAvailable(VK_EXT_DEBUG_UTILS_EXTENSION_NAME)) {
                extensions.push_back(VK_EXT_DEBUG_UTILS_EXTENSION_NAME);
                haveDebugUtils = true;
            }
        }
#else
        (void)wantValidation;
#endif

        VkApplicationInfo appInfo{};
        appInfo.sType      = VK_STRUCTURE_TYPE_APPLICATION_INFO;
#ifndef SHOBF_NO_DEBUG
        appInfo.pApplicationName = "shader_obfuscate";
#endif
        appInfo.apiVersion = VK_API_VERSION_1_0;

        VkInstanceCreateInfo ii{};
        ii.sType                   = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
        ii.pApplicationInfo        = &appInfo;
        ii.enabledLayerCount       = uint32_t(layers.size());
        ii.ppEnabledLayerNames     = layers.empty() ? nullptr : layers.data();
        ii.enabledExtensionCount   = uint32_t(extensions.size());
        ii.ppEnabledExtensionNames = extensions.empty() ? nullptr : extensions.data();
        SHOBF_CHECK(vkCreateInstance(&ii, nullptr, &instance_));

#ifndef SHOBF_NO_DEBUG
        if (haveDebugUtils) {
            VkDebugUtilsMessengerCreateInfoEXT di{};
            di.sType           = VK_STRUCTURE_TYPE_DEBUG_UTILS_MESSENGER_CREATE_INFO_EXT;
            di.messageSeverity = VK_DEBUG_UTILS_MESSAGE_SEVERITY_WARNING_BIT_EXT |
                                 VK_DEBUG_UTILS_MESSAGE_SEVERITY_ERROR_BIT_EXT;
            di.messageType     = VK_DEBUG_UTILS_MESSAGE_TYPE_GENERAL_BIT_EXT |
                                 VK_DEBUG_UTILS_MESSAGE_TYPE_VALIDATION_BIT_EXT |
                                 VK_DEBUG_UTILS_MESSAGE_TYPE_PERFORMANCE_BIT_EXT;
            di.pfnUserCallback = debugCallback;
            auto create = reinterpret_cast<PFN_vkCreateDebugUtilsMessengerEXT>(
                vkGetInstanceProcAddr(instance_, "vkCreateDebugUtilsMessengerEXT"));
            destroyMessenger_ = reinterpret_cast<PFN_vkDestroyDebugUtilsMessengerEXT>(
                vkGetInstanceProcAddr(instance_, "vkDestroyDebugUtilsMessengerEXT"));
            if (create) SHOBF_CHECK(create(instance_, &di, nullptr, &messenger_));
        }
#endif // SHOBF_NO_DEBUG
    }

    void pickPhysicalDevice()
    {
        if (instance_ == VK_NULL_HANDLE) return;
        uint32_t n = 0;
        SHOBF_CHECK(vkEnumeratePhysicalDevices(instance_, &n, nullptr));
        if (n == 0) return;   // stays null; caller flags the engine unready
        std::vector<VkPhysicalDevice> devs(n);
        SHOBF_CHECK(vkEnumeratePhysicalDevices(instance_, &n, devs.data()));

        int bestScore = -1;
        for (VkPhysicalDevice cand : devs) {
            uint32_t fc = 0;
            vkGetPhysicalDeviceQueueFamilyProperties(cand, &fc, nullptr);
            std::vector<VkQueueFamilyProperties> fams(fc);
            vkGetPhysicalDeviceQueueFamilyProperties(cand, &fc, fams.data());
            bool hasCompute = false;
            for (const auto& f : fams)
                if (f.queueFlags & VK_QUEUE_COMPUTE_BIT) { hasCompute = true; break; }
            if (!hasCompute) continue;

            VkPhysicalDeviceProperties props{};
            vkGetPhysicalDeviceProperties(cand, &props);
            int score = 1;
            if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU)   score += 1000;
            if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU) score += 100;
            if (score > bestScore) { bestScore = score; physicalDevice_ = cand; }
        }
        if (physicalDevice_ == VK_NULL_HANDLE)
        {
#ifndef SHOBF_NO_DEBUG
            throw Error("shader_obfuscate: no device with a compute queue found");
#endif
            return;   // NO_DEBUG: engine will be flagged unready
        }
    }

    void createDeviceAndQueue()
    {
        if (physicalDevice_ == VK_NULL_HANDLE) return;
        uint32_t fc = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(physicalDevice_, &fc, nullptr);
        std::vector<VkQueueFamilyProperties> fams(fc);
        vkGetPhysicalDeviceQueueFamilyProperties(physicalDevice_, &fc, fams.data());
        for (uint32_t i = 0; i < fc; ++i)
            if (fams[i].queueFlags & VK_QUEUE_COMPUTE_BIT) { computeFamily_ = i; break; }

        const float prio = 1.0f;
        VkDeviceQueueCreateInfo qci{};
        qci.sType            = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
        qci.queueFamilyIndex = computeFamily_;
        qci.queueCount       = 1;
        qci.pQueuePriorities = &prio;

        VkDeviceCreateInfo dci{};
        dci.sType                = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
        dci.queueCreateInfoCount = 1;
        dci.pQueueCreateInfos    = &qci;
        SHOBF_CHECK(vkCreateDevice(physicalDevice_, &dci, nullptr, &device_));
        vkGetDeviceQueue(device_, computeFamily_, 0, &queue_);
    }

    void createCommandPoolAndBuffer()
    {
        if (device_ == VK_NULL_HANDLE) return;
        VkCommandPoolCreateInfo cpi{};
        cpi.sType            = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
        cpi.flags            = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
        cpi.queueFamilyIndex = computeFamily_;
        SHOBF_CHECK(vkCreateCommandPool(device_, &cpi, nullptr, &commandPool_));

        VkCommandBufferAllocateInfo cbi{};
        cbi.sType              = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        cbi.commandPool        = commandPool_;
        cbi.level              = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        cbi.commandBufferCount = 1;
        SHOBF_CHECK(vkAllocateCommandBuffers(device_, &cbi, &commandBuffer_));
    }

    void createDescriptors()
    {
        if (device_ == VK_NULL_HANDLE) return;
        const VkDescriptorSetLayoutBinding bindings[4] = {
            {0, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, nullptr},
            {1, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, nullptr},
            {2, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, nullptr},
            {3, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, nullptr},
        };
        VkDescriptorSetLayoutCreateInfo sli{};
        sli.sType        = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
        sli.bindingCount = 4;
        sli.pBindings    = bindings;
        SHOBF_CHECK(vkCreateDescriptorSetLayout(device_, &sli, nullptr, &setDescription_));

        VkDescriptorPoolSize ps{};
        ps.type            = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        ps.descriptorCount = 4;
        VkDescriptorPoolCreateInfo dpi{};
        dpi.sType         = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
        dpi.maxSets       = 1;
        dpi.poolSizeCount = 1;
        dpi.pPoolSizes    = &ps;
        SHOBF_CHECK(vkCreateDescriptorPool(device_, &dpi, nullptr, &descriptorPool_));

        VkDescriptorSetAllocateInfo dai{};
        dai.sType              = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
        dai.descriptorPool     = descriptorPool_;
        dai.descriptorSetCount = 1;
        dai.pSetLayouts        = &setDescription_;
        SHOBF_CHECK(vkAllocateDescriptorSets(device_, &dai, &descriptorSet_));
    }

    void writeDescriptors(const Buffer& in, const Buffer& key,
                          const Buffer& work, const Buffer& stat)
    {
        const VkDescriptorBufferInfo infos[4] = {
            {in.handle,   0, VK_WHOLE_SIZE},
            {key.handle,  0, VK_WHOLE_SIZE},
            {work.handle, 0, VK_WHOLE_SIZE},
            {stat.handle, 0, VK_WHOLE_SIZE},
        };
        VkWriteDescriptorSet writes[4]{};
        for (uint32_t b = 0; b < 4; ++b) {
            writes[b].sType           = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
            writes[b].dstSet          = descriptorSet_;
            writes[b].dstBinding      = b;
            writes[b].descriptorCount = 1;
            writes[b].descriptorType  = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
            writes[b].pBufferInfo     = &infos[b];
        }
        vkUpdateDescriptorSets(device_, 4, writes, 0, nullptr);
    }

    void createPipeline()
    {
        if (device_ == VK_NULL_HANDLE) return;
        VkPushConstantRange pcr{};
        pcr.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
        pcr.offset     = 0;
        pcr.size       = 3 * sizeof(uint32_t);        // mode, hexLen, keyLen

        VkPipelineLayoutCreateInfo pli{};
        pli.sType                  = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
        pli.setLayoutCount         = 1;
        pli.pSetLayouts            = &setDescription_;
        pli.pushConstantRangeCount = 1;
        pli.pPushConstantRanges    = &pcr;
        SHOBF_CHECK(vkCreatePipelineLayout(device_, &pli, nullptr, &pipelineLayout_));

        VkShaderModuleCreateInfo smi{};
        smi.sType    = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
        smi.codeSize = sizeof(kShaderSpv);
        smi.pCode    = kShaderSpv;
        VkShaderModule shader = VK_NULL_HANDLE;
        SHOBF_CHECK(vkCreateShaderModule(device_, &smi, nullptr, &shader));

        VkPipelineShaderStageCreateInfo stage{};
        stage.sType  = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
        stage.stage  = VK_SHADER_STAGE_COMPUTE_BIT;
        stage.module = shader;
        stage.pName  = "main";

        VkComputePipelineCreateInfo cpip{};
        cpip.sType  = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
        cpip.stage  = stage;
        cpip.layout = pipelineLayout_;
        SHOBF_CHECK(vkCreateComputePipelines(device_, VK_NULL_HANDLE, 1, &cpip,
                                            nullptr, &pipeline_));
        vkDestroyShaderModule(device_, shader, nullptr);
    }

    uint32_t numGroupsFor(uint32_t numWorkWords) const
    {
        return (numWorkWords + kLocalSizeX - 1) / kLocalSizeX;
    }

    void dispatchWithMode(uint32_t mode, size_t hexLen, uint32_t keyLen)
    {
        const uint32_t pc[3] = {mode, uint32_t(hexLen), keyLen};
        vkCmdPushConstants(commandBuffer_, pipelineLayout_,
                           VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pc), pc);
        const uint32_t numWorkWords = (uint32_t(hexLen / 2) + 3) / 4;
        vkCmdDispatch(commandBuffer_, numGroupsFor(numWorkWords), 1, 1);
    }

    void insertComputeToComputeBarrier()
    {
        VkMemoryBarrier b{};
        b.sType         = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
        b.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
        b.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
        vkCmdPipelineBarrier(commandBuffer_,
                             VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                             VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                             0, 1, &b, 0, nullptr, 0, nullptr);
    }

    void insertComputeToHostBarrier()
    {
        VkMemoryBarrier b{};
        b.sType         = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
        b.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
        b.dstAccessMask = VK_ACCESS_HOST_READ_BIT;
        vkCmdPipelineBarrier(commandBuffer_,
                             VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                             VK_PIPELINE_STAGE_HOST_BIT,
                             0, 1, &b, 0, nullptr, 0, nullptr);
    }

    void submitAndWait()
    {
        VkFenceCreateInfo fci{};
        fci.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        VkFence fence = VK_NULL_HANDLE;
        SHOBF_CHECK(vkCreateFence(device_, &fci, nullptr, &fence));

        VkSubmitInfo si{};
        si.sType              = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        si.commandBufferCount = 1;
        si.pCommandBuffers    = &commandBuffer_;
        SHOBF_CHECK(vkQueueSubmit(queue_, 1, &si, fence));
        SHOBF_CHECK(vkWaitForFences(device_, 1, &fence, VK_TRUE, UINT64_MAX));
        vkDestroyFence(device_, fence, nullptr);
    }

#ifdef SHOBF_NO_DEBUG
    bool ready_ = false;   // set after init; gates decrypt() when throws are off
#endif

    VkInstance                instance_        = VK_NULL_HANDLE;
    PFN_vkDestroyDebugUtilsMessengerEXT destroyMessenger_ = nullptr;
    VkDebugUtilsMessengerEXT  messenger_       = VK_NULL_HANDLE;
    VkPhysicalDevice          physicalDevice_  = VK_NULL_HANDLE;
    uint32_t                  computeFamily_   = 0;
    VkDevice                  device_          = VK_NULL_HANDLE;
    VkQueue                   queue_           = VK_NULL_HANDLE;
    VkCommandPool             commandPool_     = VK_NULL_HANDLE;
    VkCommandBuffer           commandBuffer_   = VK_NULL_HANDLE;
    VkDescriptorSetLayout     setDescription_  = VK_NULL_HANDLE;
    VkDescriptorPool          descriptorPool_  = VK_NULL_HANDLE;
    VkDescriptorSet           descriptorSet_   = VK_NULL_HANDLE;
    VkPipelineLayout          pipelineLayout_  = VK_NULL_HANDLE;
    VkPipeline                pipeline_        = VK_NULL_HANDLE;
    VkPhysicalDeviceLimits    limits_{};
};
#endif // !SHOBF_BACKEND_D3D11

// ---------------------------------------------------------------------------
// Direct3D 11 backend (SHOBF_BACKEND_D3D11, Windows targets only).
//
// Same pipeline as the Vulkan path: two Dispatches over word-packed buffers
// (in/key as raw SRVs, work/stat as raw UAVs, params in a cbuffer). Buffers
// are grown on demand; CPU<->GPU traffic goes through staging buffers.
//
// Shader source is selected at compile time:
//   * SHOBF_D3D11_PRECOMPILED: a DXBC blob embedded via shader_dxbc.inc
//     (generated by build_shader.py / d3dcompiler's D3DCompile) is handed
//     straight to CreateComputeShader — no runtime shader compilation, HLSL
//     string absent.
//   * otherwise: the shader is compiled once at init from kShaderHlsl via the
//     system d3dcompiler_47.dll (loaded dynamically — no import library).
// ---------------------------------------------------------------------------
#if defined(SHOBF_BACKEND_D3D11)

template <typename T>
class ComPtr
{
public:
    ComPtr() = default;
    ~ComPtr() { if (p_) p_->Release(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    T**       put()       { reset(); return &p_; }
    T*        get() const { return p_; }
    T*        operator->() const { return p_; }
    void      reset()     { if (p_) { p_->Release(); p_ = nullptr; } }
private:
    T* p_ = nullptr;
};

struct IDXGIAdapter;
using PFN_shobfD3D11CreateDevice = HRESULT (WINAPI *)(
    IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT,
    const D3D_FEATURE_LEVEL*, UINT, UINT, ID3D11Device**,
    D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);

// pD3DCompile is usually provided by d3dcompiler.h; provide a fallback
// typedef for SDK versions that may lack it.
#ifndef pD3DCompile
using pD3DCompile = HRESULT (WINAPI *)(
    LPCVOID, SIZE_T, LPCSTR, const D3D_SHADER_MACRO*,
    ID3DInclude*, LPCSTR, LPCSTR, UINT, UINT,
    ID3DBlob**, ID3DBlob**);
#endif

class D3D11Backend final : public IBackend
{
public:
    explicit D3D11Backend(bool wantValidation) { init(wantValidation); }

    bool ready() const override
    {
#ifndef SHOBF_NO_DEBUG
        return true;
#else
        return ready_;
#endif
    }

    uint32_t maxGroupsX() const override { return 65535u; }   // D3D11 dispatch limit

    BStatus run(const char* hex, size_t hexLen,
                const uint32_t* keyWords, size_t keyWordCount,
                uint32_t keyLen, uint32_t mode,
                uint8_t* plainOut,
                uint32_t& badOffsetOut) override
    {
        const size_t numHexW  = (hexLen + 3) / 4;
        const size_t dataLen  = hexLen / 2;
        const size_t numWorkW = dataLen ? (dataLen + 3) / 4 : 0;

        ensureSlot(in_,   numHexW * 4, BIND_SRV);
        ensureSlot(key_,  keyWordCount * 4, BIND_SRV);
        ensureSlot(work_, numWorkW * 8, BIND_UAV);   // stride 8: word+status
        ensureSlot(cipher_, numWorkW * 8, BIND_SRV);  // stride-8 mirror

        upload(in_, hex, hexLen);
        upload(key_, keyWords, keyWordCount * 4);

        createViews();

        // Both phases' parameters are uploaded up front; swapping constant
        // buffers between Dispatches is more portable than updating one
        // in-flight (some runtimes defer UpdateSubresource unpredictably).
        updateParams(paramsPhase1_, kModeHexDecode, uint32_t(hexLen), keyLen);
        updateParams(paramsPhase2_, mode,           uint32_t(hexLen), keyLen);

        // --- dispatch 1: hex decode -------------------------------------
        bindAndDispatch(paramsPhase1_.get(), numGroupsFor(uint32_t(numWorkW)));

        // Hand the decoded words to the read-only cipher view that
        // dispatch 2 consumes (RWByteAddressBuffer::Load is unavailable on
        // some D3D compilers, e.g. wine's vkd3d-shader backend). The copy
        // keeps the stride-8 [word][status] layout of the decode output and
        // happens with bindings cleared (CopyResource proved unreliable for
        // CS-bound resources under some runtimes).  We use a D3D11_BOX to
        // copy exactly the bytes we need, because ensureSlot() is grow-only
        // and work_.buf may be larger than cipher_.buf.
        unbindAll();
        {
            const UINT copyBytes = UINT(numWorkW * 8);
            D3D11_BOX srcBox = {};
            srcBox.left   = 0;
            srcBox.top    = 0;
            srcBox.front  = 0;
            srcBox.right  = copyBytes;
            srcBox.bottom = 1;
            srcBox.back   = 1;
            ctx_->CopySubresourceRegion(cipher_.buf.get(), 0, 0, 0, 0,
                                        work_.buf.get(), 0, &srcBox);
        }

        // --- dispatch 2: xor / rc4 decrypt -------------------------------
        bindAndDispatch(paramsPhase2_.get(), numGroupsFor(uint32_t(numWorkW)));
        unbindAll();

        // --- read back work (stride 8: [plain][status]) -------------------
        std::vector<uint32_t> raw(numWorkW * 2);
        download(work_, raw.data(), numWorkW * 8);

        uint32_t badOffset = 0;
        bool     bad       = false;
        for (size_t i = 0; i < numWorkW; ++i) {
            const uint32_t st = raw[i * 2 + 1];
            if (st != 0u && (!bad || st - 1u < badOffset)) {
                bad       = true;
                badOffset = st - 1u;
            }
        }
        if (bad) {
            badOffsetOut = badOffset;
            return BStatus::BadHex;
        }

        std::vector<uint32_t> outWords(numWorkW);
        for (size_t i = 0; i < numWorkW; ++i) outWords[i] = raw[i * 2];
        const std::vector<uint8_t> plain = unpackWords(outWords, uint32_t(dataLen));
        std::memcpy(plainOut, plain.data(), dataLen);
        return BStatus::Ok;
    }

private:
    void init(bool wantValidation)
    {
#ifdef SHOBF_NO_DEBUG
        (void)wantValidation;   // debug device is a debug-build concern only
#endif

        // Obtain the compute shader bytecode. In SHOBF_D3D11_PRECOMPILED mode
        // it was already compiled at build time (build_shader.py via
        // d3dcompiler's D3DCompile) into kShaderDxbc, so no runtime shader
        // compiler is touched. Otherwise compile the embedded HLSL string at
        // init via the system d3dcompiler_47.dll.
        const void*    codePtr = nullptr;
        SIZE_T         codeSize = 0;
        ID3DBlob*      compiled = nullptr;
#if defined(SHOBF_D3D11_PRECOMPILED)
        codePtr = kShaderDxbc;
        codeSize = kShaderDxbcSize;
#else
        for (const char* name : {"d3dcompiler_47.dll", "d3dcompiler_43.dll"}) {
            d3dcompiler_ = LoadLibraryA(name);
            if (d3dcompiler_) break;
        }
#ifdef SHOBF_NO_DEBUG
        if (!d3dcompiler_) return;
#else
        if (!d3dcompiler_)
            throw Error("shader_obfuscate: no d3dcompiler_47.dll/43.dll found");
#endif

        auto compileFn = reinterpret_cast<pD3DCompile>(
            reinterpret_cast<void*>(
                GetProcAddress(d3dcompiler_, "D3DCompile")));
#ifdef SHOBF_NO_DEBUG
        if (!compileFn) return;
#else
        if (!compileFn)
            throw Error("shader_obfuscate: D3DCompile not found in d3dcompiler");
#endif

        {
            ID3DBlob* errs = nullptr;
            HRESULT   hr   = compileFn(kShaderHlsl, sizeof(kShaderHlsl) - 1,
                                       "shobf_shader", nullptr, nullptr,
                                       "main", "cs_5_0", 0x00000004 /*D3DCOMPILE_SKIP_OPTIMIZATION*/, 0, &compiled, &errs);
#ifdef SHOBF_NO_DEBUG
            if (FAILED(hr)) return;
#else
            if (FAILED(hr))
            {
                std::string msg("shader_obfuscate: HLSL compute shader failed to compile");
                if (errs && errs->GetBufferPointer())
                    msg += ": " + std::string(
                        static_cast<const char*>(errs->GetBufferPointer()),
                        errs->GetBufferSize());
                if (errs) errs->Release();
                throw Error(msg);
            }
#endif
            if (errs) errs->Release();
        }
        codePtr  = compiled->GetBufferPointer();
        codeSize = compiled->GetBufferSize();
#endif // SHOBF_D3D11_PRECOMPILED

        HMODULE d3d11 = LoadLibraryA("d3d11.dll");
        if (!d3d11) {
            if (compiled) compiled->Release();
#ifdef SHOBF_NO_DEBUG
            return;
#else
            throw Error("shader_obfuscate: d3d11.dll could not be loaded");
#endif
        }
        auto createFn = reinterpret_cast<PFN_shobfD3D11CreateDevice>(
            reinterpret_cast<void*>(
                GetProcAddress(d3d11, "D3D11CreateDevice")));
        if (!createFn) {
            if (compiled) compiled->Release();
#ifdef SHOBF_NO_DEBUG
            return;
#else
            throw Error("shader_obfuscate: D3D11CreateDevice not found in d3d11.dll");
#endif
        }

        UINT flags = 0;
#ifndef SHOBF_NO_DEBUG
        if (wantValidation) flags |= D3D11_CREATE_DEVICE_DEBUG;
#endif
        static const D3D_FEATURE_LEVEL wanted[] = {D3D_FEATURE_LEVEL_11_0};
        HRESULT hr = createFn(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags,
                              wanted, UINT(ARRAYSIZE(wanted)), D3D11_SDK_VERSION,
                              dev_.put(), &featureLevel_, ctx_.put());
#ifndef SHOBF_NO_DEBUG
        if (FAILED(hr) && wantValidation) {
            // The debug layer is an optional Windows feature (Graphics
            // Tools); fall back to a plain device so debugging still works.
            flags = 0;
            hr = createFn(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags,
                          wanted, UINT(ARRAYSIZE(wanted)), D3D11_SDK_VERSION,
                          dev_.put(), &featureLevel_, ctx_.put());
        }
#endif
#ifdef SHOBF_NO_DEBUG
        if (FAILED(hr)) {
            if (compiled) compiled->Release();
            return;
        }
#else
        if (FAILED(hr)) {
            if (compiled) compiled->Release();
            throw Error("shader_obfuscate: D3D11CreateDevice failed "
                        "(no Direct3D 11 hardware adapter?)");
        }
#endif

        hr = dev_->CreateComputeShader(codePtr, codeSize, nullptr, cs_.put());
        if (compiled) compiled->Release();
#ifdef SHOBF_NO_DEBUG
        if (FAILED(hr)) return;
#else
        if (FAILED(hr))
            throw Error("shader_obfuscate: CreateComputeShader failed");
#endif

        // Push-constant stand-ins: {mode, hexLen, keyLen, pad}. One per
        // pipeline phase, both uploaded up front (see run()).
        D3D11_BUFFER_DESC cbd{};
        cbd.ByteWidth = 16;
        cbd.Usage     = D3D11_USAGE_DEFAULT;
        cbd.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
        hr = dev_->CreateBuffer(&cbd, nullptr, paramsPhase1_.put());
#ifdef SHOBF_NO_DEBUG
        if (FAILED(hr)) return;
#else
        if (FAILED(hr))
            throw Error("shader_obfuscate: constant buffer creation failed");
#endif
        hr = dev_->CreateBuffer(&cbd, nullptr, paramsPhase2_.put());
#ifdef SHOBF_NO_DEBUG
        if (FAILED(hr)) return;
#else
        if (FAILED(hr))
            throw Error("shader_obfuscate: constant buffer creation failed");
#endif

#ifdef SHOBF_NO_DEBUG
        ready_ = dev_.get()          != nullptr && ctx_.get() != nullptr &&
                 cs_.get()           != nullptr &&
                 paramsPhase1_.get() != nullptr && paramsPhase2_.get() != nullptr;
#endif
    }

    enum Bind { BIND_SRV, BIND_UAV };   // kept for call-site readability

    // One pipeline resource: the GPU buffer plus matching STAGING mirrors.
    // CopyResource requires identical ByteWidth on both ends, so all three
    // are grown together (grow-only across calls).
    struct Slot
    {
        ComPtr<ID3D11Buffer> buf;    // device-local
        ComPtr<ID3D11Buffer> stUp;   // CPU -> GPU
        ComPtr<ID3D11Buffer> stDown; // GPU -> CPU
        size_t               cap = 0;
    };

    void ensureSlot(Slot& s, size_t bytes, Bind)
    {
        if (s.buf.get() && s.cap >= bytes) return;

        // All pipeline buffers share one descriptor shape (both bind flags,
        // raw-view misc): some D3D runtimes reject CopyResource between
        // buffers whose descriptors differ.
        D3D11_BUFFER_DESC d{};
        d.ByteWidth = UINT(bytes);
        d.Usage     = D3D11_USAGE_DEFAULT;
        d.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_UNORDERED_ACCESS;
        d.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_ALLOW_RAW_VIEWS;

        D3D11_BUFFER_DESC upDesc{};
        upDesc.ByteWidth      = UINT(bytes);
        upDesc.Usage          = D3D11_USAGE_STAGING;
        upDesc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;

        D3D11_BUFFER_DESC downDesc{};
        downDesc.ByteWidth      = UINT(bytes);
        downDesc.Usage          = D3D11_USAGE_STAGING;
        downDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;

        dev_->CreateBuffer(&d,       nullptr, s.buf.put());
        dev_->CreateBuffer(&upDesc,  nullptr, s.stUp.put());
        dev_->CreateBuffer(&downDesc,nullptr, s.stDown.put());
        if (s.buf.get())
            s.cap = bytes;
    }

    void upload(Slot& s, const void* src, size_t bytes)
    {
        (void)bytes;
        ctx_->UpdateSubresource(s.buf.get(), 0, nullptr, src, 0, 0);
    }

    void download(Slot& s, void* dst, size_t bytes)
    {
        ctx_->CopyResource(s.stDown.get(), s.buf.get());
        D3D11_MAPPED_SUBRESOURCE m{};
        ctx_->Map(s.stDown.get(), 0, D3D11_MAP_READ, 0, &m);
        std::memcpy(dst, m.pData, bytes < s.cap ? bytes : s.cap);
        ctx_->Unmap(s.stDown.get(), 0);
    }

    // Raw byte-addressed views over the current buffers; recreated whenever
    // a buffer grew (views pin their buffer).
    void createViews()
    {
        srvIn_.reset(); srvKey_.reset(); srvCipher_.reset();
        uavWork_.reset();

        D3D11_SHADER_RESOURCE_VIEW_DESC sd{};
        sd.Format        = DXGI_FORMAT_R32_TYPELESS;
        sd.ViewDimension = D3D11_SRV_DIMENSION_BUFFEREX;
        sd.BufferEx.Flags = D3D11_BUFFEREX_SRV_FLAG_RAW;
        sd.BufferEx.NumElements = UINT(in_.cap / 4);
        dev_->CreateShaderResourceView(in_.buf.get(), &sd, srvIn_.put());
        sd.BufferEx.NumElements = UINT(key_.cap / 4);
        dev_->CreateShaderResourceView(key_.buf.get(), &sd, srvKey_.put());
        sd.BufferEx.NumElements = UINT(cipher_.cap / 4);
        dev_->CreateShaderResourceView(cipher_.buf.get(), &sd, srvCipher_.put());

        D3D11_UNORDERED_ACCESS_VIEW_DESC ud{};
        ud.Format        = DXGI_FORMAT_R32_TYPELESS;
        ud.ViewDimension = D3D11_UAV_DIMENSION_BUFFER;
        ud.Buffer.Flags  = D3D11_BUFFER_UAV_FLAG_RAW;   // RWByteAddressBuffer
        ud.Buffer.NumElements = UINT(work_.cap / 4);
        HRESULT uavHr = dev_->CreateUnorderedAccessView(work_.buf.get(), &ud,
                                                        uavWork_.put());
        HRESULT srvHr = srvIn_.get() && srvKey_.get() && srvCipher_.get()
                            ? S_OK : E_FAIL;
#ifdef SHOBF_NO_DEBUG
        (void)uavHr; (void)srvHr;
#else
        if (FAILED(uavHr))
        {
            char b[16];
            snprintf(b, sizeof(b), "%lx", (unsigned long)uavHr);
            throw Error(std::string("shader_obfuscate: work UAV creation "
                                    "failed hr=0x") + b);
        }
        if (FAILED(srvHr))
            throw Error("shader_obfuscate: raw SRV creation failed");
#endif
    }

    void updateParams(ComPtr<ID3D11Buffer>& cb, uint32_t mode, uint32_t hexLen,
                      uint32_t keyLen)
    {
        const uint32_t p[4] = {mode, hexLen, keyLen, 0u};
        ctx_->UpdateSubresource(cb.get(), 0, nullptr, p, 0, 0);
    }

    void bindAll(ID3D11Buffer* params)
    {
        ID3D11Buffer*              cb[1]   = {params};
        ID3D11ShaderResourceView*  srvs[3] = {srvIn_.get(), srvKey_.get(),
                                              srvCipher_.get()};
        ID3D11UnorderedAccessView* uavs[1] = {uavWork_.get()};
        ctx_->CSSetShader(cs_.get(), nullptr, 0);
        ctx_->CSSetConstantBuffers(0, 1, cb);
        ctx_->CSSetShaderResources(0, 3, srvs);
        ctx_->CSSetUnorderedAccessViews(0, 1, uavs, nullptr);
    }

    void bindAndDispatch(ID3D11Buffer* params, uint32_t groups)
    {
        bindAll(params);
        ctx_->Dispatch(groups, 1, 1);
    }

    void unbindAll()
    {
        ID3D11Buffer*              cb[1]   = {nullptr};
        ID3D11ShaderResourceView*  srvs[3] = {nullptr, nullptr, nullptr};
        ID3D11UnorderedAccessView* uavs[1] = {nullptr};
        ctx_->CSSetShader(nullptr, nullptr, 0);
        ctx_->CSSetConstantBuffers(0, 1, cb);
        ctx_->CSSetShaderResources(0, 3, srvs);
        ctx_->CSSetUnorderedAccessViews(0, 1, uavs, nullptr);
    }

    Slot in_, key_, work_, cipher_;
    ComPtr<ID3D11Device>             dev_;
    ComPtr<ID3D11DeviceContext>      ctx_;
    ComPtr<ID3D11ComputeShader>      cs_;
    ComPtr<ID3D11Buffer>             paramsPhase1_, paramsPhase2_;
    ComPtr<ID3D11ShaderResourceView> srvIn_, srvKey_, srvCipher_;
    ComPtr<ID3D11UnorderedAccessView> uavWork_;
    D3D_FEATURE_LEVEL featureLevel_{};
#if !defined(SHOBF_D3D11_PRECOMPILED)
    HMODULE d3dcompiler_ = nullptr;   // process-lifetime, never freed
#endif

#ifdef SHOBF_NO_DEBUG
    bool ready_ = false;
#endif
};
#endif // SHOBF_BACKEND_D3D11

// Backend selection ---------------------------------------------------------
#if defined(SHOBF_BACKEND_D3D11)
using ActiveBackend = D3D11Backend;
#else
using ActiveBackend = VulkanBackend;
#endif

class Engine
{
public:
    static Engine& instance()
    {
        static Engine engine;
        return engine;
    }

    // Runs both dispatches for `hex` against `keyWords`/`keyLen`;
    // returns the plaintext bytes. Throws shobf::Error on any problem
    // (returns an empty vector instead when built with SHOBF_NO_DEBUG).
    std::vector<uint8_t> decrypt(std::string_view hex,
                                 const std::vector<uint32_t>& keyWords,
                                 uint32_t keyLen, uint32_t secondPhaseMode)
    {
#ifdef SHOBF_NO_DEBUG
        if (!backend_->ready()) return {};   // engine never came up; stay silent
#endif
        std::lock_guard<std::mutex> lock(mutex_);

        const size_t hexLen     = hex.size();
        const uint32_t dataLen  = uint32_t(hexLen / 2);
        const uint32_t numWorkW = dataLen ? (dataLen + 3) / 4 : 0;

        if (dataLen == 0) return {};
        if (numGroupsFor(numWorkW) > backend_->maxGroupsX()) {
#ifndef SHOBF_NO_DEBUG
            throw Error("shader_obfuscate: input too large for maxComputeWorkGroupCount");
#else
            return {};
#endif
        }

        std::vector<uint8_t> plain(dataLen);
        uint32_t badOffset = 0;
        const BStatus st =
            backend_->run(hex.data(), hexLen, keyWords.data(), keyWords.size(),
                          keyLen, secondPhaseMode, plain.data(), badOffset);
#ifndef SHOBF_NO_DEBUG
        if (st == BStatus::BadHex) {
            if (badOffset == hexLen - 1 && (hexLen & 1u))
                throw Error("shader_obfuscate: hex input has an odd number of digits");
            throw Error("shader_obfuscate: invalid hex digit at char offset " +
                        std::to_string(badOffset));
        }
#else
        if (st == BStatus::BadHex) return {};
#endif
        return plain;
    }

private:
    Engine() : backend_(new ActiveBackend(validationRequestedFlag())) {}

    std::mutex mutex_;
    std::unique_ptr<IBackend> backend_;
};

} // namespace detail

// ===========================================================================
// Public API
// ===========================================================================

// Cipher selection for decryption. Xor: byte i ^= key[i % keyLen]. Rc4:
// classic RC4 keystream (KSA + PRGA) executed on the GPU. Encryption with
// either cipher happens at compile time via SHOBF_OBFUSCATE[_RC4].
enum class Algorithm { Xor, Rc4 };

// Name of the compute backend compiled in ("vulkan" by default, "d3d11"
// with SHOBF_BACKEND_D3D11).
inline const char* backendName()
{
#if defined(SHOBF_BACKEND_D3D11)
    return "d3d11";
#else
    return "vulkan";
#endif
}

namespace detail {
inline uint32_t secondPhaseModeFor(Algorithm a)
{
    return a == Algorithm::Rc4 ? kModeRc4Decrypt : kModeXorDecrypt;
}
} // namespace detail

// Opt into Khronos validation layers (debugging). Must be called before the
// first crypto call; SHOBF_VALIDATION=1 achieves the same. No-op (and the
// validation machinery is not compiled at all) when SHOBF_NO_DEBUG is defined.
inline void setValidationEnabled(bool enabled)
{
#ifndef SHOBF_NO_DEBUG
    detail::validationRequestedFlag() = enabled;
#else
    (void)enabled;
#endif
}

// --------------------------------------------------------------------------
// Variation 1: explicit key.
// --------------------------------------------------------------------------

// Decrypt a hex ciphertext with `key`; returns raw plaintext bytes.
// Throws shobf::Error on bad input (returns an empty vector instead when
// built with SHOBF_NO_DEBUG).
inline std::vector<uint8_t> decryptBytes(std::string_view hexCipher,
                                         std::string_view key,
                                         Algorithm algo = Algorithm::Xor)
{
#ifndef SHOBF_NO_DEBUG
    if (key.empty()) throw Error("shader_obfuscate: key must not be empty");
#else
    if (key.empty()) return {};
#endif
    const std::vector<uint8_t> keyBytes(key.begin(), key.end());
    const std::vector<uint32_t> keyWords = detail::packWords(keyBytes);
    return detail::Engine::instance().decrypt(hexCipher, keyWords,
                                              uint32_t(keyBytes.size()),
                                              detail::secondPhaseModeFor(algo));
}

// Decrypt a hex ciphertext with `key`; returns plaintext as a string
// (binary-safe).
inline std::string decrypt(std::string_view hexCipher, std::string_view key,
                           Algorithm algo = Algorithm::Xor)
{
    const auto bytes = decryptBytes(hexCipher, key, algo);
    return std::string(bytes.begin(), bytes.end());
}

// --------------------------------------------------------------------------
// Compile-time encryption (CPU, via constexpr evaluation).
//
// SHOBF_OBFUSCATE(str, key)      XOR-encrypts  -> use with Algorithm::Xor
// SHOBF_OBFUSCATE_RC4(str, key)  RC4-encrypts  -> use with Algorithm::Rc4
//
// Both macros expand to an immediate lambda evaluated entirely at COMPILE
// time, yielding an shobf::Encrypted<N> that holds the RAW ciphertext bytes.
// The plaintext literal never reaches the binary; only opaque binary data
// does, so nothing hex- or text-shaped shows up under strings(1).
// Pass the result straight back to decrypt()/decryptBytes() through the
// typed overloads:
//
//     shobf::decrypt(SHOBF_OBFUSCATE("secret", "vulkan"), "vulkan");
//
// If you want the old lowercase-hex form (eyeballing ciphertexts, cross-
// checking against external tools), use SHOBF_OBFUSCATE_HEX /
// SHOBF_OBFUSCATE_HEX_RC4 instead; their shobf::Obfuscated<N> result feeds
// the same decrypt functions via its string_view conversion.
//
// `str` must be a non-empty string literal (its bytes are consumed by the
// compiler). `key` may be a string literal OR any constexpr key object such
// as shobf::seedKey() — the seed-derived Auto key:
//
//     shobf::decryptAuto(SHOBF_OBFUSCATE("secret", shobf::seedKey()));
// --------------------------------------------------------------------------

template <size_t N>
struct Obfuscated
{
    char data[N];

    // Number of ciphertext characters (excluding the terminating NUL).
    constexpr size_t size() const { return N - 1; }
    constexpr char operator[](size_t i) const { return data[i]; }

    operator const char*() const noexcept { return data; }
    operator std::string_view() const noexcept { return data; }
};

// Raw-binary ciphertext produced by the SHOBF_OBFUSCATE macros. Deliberately
// NOT convertible to const char*/string_view: raw bytes are not text, and an
// implicit conversion would let them slip into the hex-based API unnoticed.
// Use the typed decrypt()/decryptBytes()/decryptAuto()/decryptAutoBytes()
// overloads below instead.
template <size_t N>
struct Encrypted
{
    uint8_t data[N];

    constexpr size_t size() const { return N; }
    constexpr uint8_t operator[](size_t i) const { return data[i]; }
};

namespace detail {

constexpr char hexDigit(uint8_t v)
{
    return v < 10 ? char('0' + v) : char('a' + v - 10);
}

// XOR: byte i ^= key[i % keyLen], then render as two lowercase hex digits.
// Key length excludes the terminating NUL (matches runtime decrypt()).
template <size_t SN, size_t KN>
constexpr Obfuscated<2 * (SN - 1) + 1> xorEncode(const char (&s)[SN],
                                                 const char (&k)[KN])
{
    static_assert(SN > 1, "SHOBF_OBFUSCATE requires a non-empty string literal");
    constexpr size_t Len = SN - 1;
    Obfuscated<2 * Len + 1> out{};
    for (size_t i = 0; i < Len; ++i) {
        const uint8_t c = uint8_t(s[i]) ^ uint8_t(k[i % (KN - 1)]);
        out.data[2 * i]     = hexDigit(c >> 4);
        out.data[2 * i + 1] = hexDigit(c & 0xF);
    }
    out.data[2 * Len] = '\0';
    return out;
}

template <size_t SN, size_t KN>
constexpr Obfuscated<2 * (SN - 1) + 1> xorEncode(const char (&s)[SN],
                                                 const Obfuscated<KN>& k)
{
    return xorEncode(s, k.data);
}

// RC4: KSA + PRGA executed by the compiler; keystream byte n encrypts s[n].
template <size_t SN, size_t KN>
constexpr Obfuscated<2 * (SN - 1) + 1> rc4Encode(const char (&s)[SN],
                                                 const char (&k)[KN])
{
    static_assert(SN > 1, "SHOBF_OBFUSCATE_RC4 requires a non-empty string literal");
    constexpr size_t Len = SN - 1;
    constexpr size_t KL  = KN - 1;
    uint8_t box[256]{};
    for (size_t i = 0; i < 256; ++i) box[i] = uint8_t(i);
    uint8_t j = 0;
    for (size_t i = 0; i < 256; ++i) {
        j = uint8_t(j + box[i] + uint8_t(k[i % KL]));
        const uint8_t t = box[i]; box[i] = box[j]; box[j] = t;
    }
    Obfuscated<2 * Len + 1> out{};
    uint8_t x = 0, y = 0;
    for (size_t n = 0; n < Len; ++n) {
        x = uint8_t(x + 1);
        y = uint8_t(y + box[x]);
        const uint8_t t = box[x]; box[x] = box[y]; box[y] = t;
        const uint8_t c = uint8_t(s[n]) ^ box[uint8_t(box[x] + box[y])];
        out.data[2 * n]     = hexDigit(c >> 4);
        out.data[2 * n + 1] = hexDigit(c & 0xF);
    }
    out.data[2 * Len] = '\0';
    return out;
}

template <size_t SN, size_t KN>
constexpr Obfuscated<2 * (SN - 1) + 1> rc4Encode(const char (&s)[SN],
                                                 const Obfuscated<KN>& k)
{
    return rc4Encode(s, k.data);
}

// Decode an encoder's lowercase-hex output into the raw-byte form the public
// macros return. HN is odd (2*Len + 1 including the NUL), so the result holds
// exactly Len bytes.
template <size_t HN>
constexpr Encrypted<HN / 2> hexToBytes(const Obfuscated<HN>& h)
{
    constexpr size_t Len = HN / 2;
    Encrypted<Len> out{};
    const auto nib = [](char c) -> uint8_t {
        return c <= '9' ? uint8_t(c - '0') : uint8_t(c - 'a' + 10);
    };
    for (size_t i = 0; i < Len; ++i)
        out.data[i] = uint8_t(nib(h.data[2 * i]) << 4 |
                              nib(h.data[2 * i + 1]));
    return out;
}

} // namespace detail

#define SHOBF_OBFUSCATE(str, key)                                              \
    []() -> ::shobf::Encrypted<(sizeof(str) - 1)> {                            \
        constexpr char g_str_[] = str;                                        \
        return ::shobf::detail::hexToBytes(                                   \
            ::shobf::detail::xorEncode(g_str_, key));                         \
    }()

#define SHOBF_OBFUSCATE_RC4(str, key)                                          \
    []() -> ::shobf::Encrypted<(sizeof(str) - 1)> {                            \
        constexpr char g_str_[] = str;                                        \
        return ::shobf::detail::hexToBytes(                                   \
            ::shobf::detail::rc4Encode(g_str_, key));                         \
    }()

#define SHOBF_OBFUSCATE_HEX(str, key)                                          \
    []() -> ::shobf::Obfuscated<2 * (sizeof(str) - 1) + 1> {                   \
        constexpr char g_str_[] = str;                                        \
        return ::shobf::detail::xorEncode(g_str_, key);                        \
    }()

#define SHOBF_OBFUSCATE_HEX_RC4(str, key)                                      \
    []() -> ::shobf::Obfuscated<2 * (sizeof(str) - 1) + 1> {                   \
        constexpr char g_str_[] = str;                                        \
        return ::shobf::detail::rc4Encode(g_str_, key);                        \
    }()

// --------------------------------------------------------------------------
// Variation 2: build-seed-derived session key.
//
// The Auto API uses one process-wide key derived at COMPILE TIME from
// SHOBF_BUILD_SEED (a random 64-bit value your build system passes with
// -DSHOBF_BUILD_SEED=0x...). Without the define, __DATE__/__TIME__ are hashed
// instead — the key then changes on every rebuild. The derived key itself is
// not stored in the binary; only the seed is.
// --------------------------------------------------------------------------

// The seed-derived Auto key (32 printable ASCII chars). Fully constexpr, so
// it can be used both as a macro key argument and inspected at runtime.
inline constexpr Obfuscated<detail::kAutoKeyLen + 1> seedKey()
{
    constexpr size_t Len = detail::kAutoKeyLen;
    Obfuscated<Len + 1> out{};
    uint64_t z = detail::buildSeedValue();
    for (size_t i = 0; i < Len; ++i) {
        z = detail::mix64(z);                       // splitmix64 stream
        // Map to printable ASCII (33..126): safe to log, safe in strings.
        out.data[i] = char(33 + ((z >> 33) % 94));
    }
    out.data[Len] = '\0';
    return out;
}

// The same key as a runtime view; used by every decryptAuto() call.
// (static so the view actually refers to storage that outlives the call.)
inline std::string_view runtimeKey()
{
    static constexpr auto key = seedKey();
    return std::string_view(key.data);
}

// Decrypt a hex ciphertext using the shared runtime key.
inline std::vector<uint8_t> decryptAutoBytes(std::string_view hexCipher,
                                             Algorithm algo = Algorithm::Xor)
{
    return decryptBytes(hexCipher, runtimeKey(), algo);
}

// Decrypt a hex ciphertext using the shared runtime key.
inline std::string decryptAuto(std::string_view hexCipher,
                               Algorithm algo = Algorithm::Xor)
{
    const auto bytes = decryptAutoBytes(hexCipher, algo);
    return std::string(bytes.begin(), bytes.end());
}

// --------------------------------------------------------------------------
// Typed overloads for macro-produced raw ciphertext (shobf::Encrypted<N>).
// The bytes are re-hexed on the CPU into a transient buffer, then handed to
// the regular GPU pipeline — identical results, no shader involvement.
// --------------------------------------------------------------------------

template <size_t N>
inline std::vector<uint8_t> decryptBytes(const Encrypted<N>& cipher,
                                         std::string_view key,
                                         Algorithm algo = Algorithm::Xor)
{
    std::string hx(N * 2, '\0');
    for (size_t i = 0; i < N; ++i) {
        const uint8_t b = cipher.data[i];
        hx[2 * i]       = detail::hexDigit(uint8_t(b >> 4));
        hx[2 * i + 1]   = detail::hexDigit(uint8_t(b & 0xF));
    }
    return decryptBytes(std::string_view(hx), key, algo);
}

template <size_t N>
inline std::string decrypt(const Encrypted<N>& cipher,
                           std::string_view key,
                           Algorithm algo = Algorithm::Xor)
{
    const auto bytes = decryptBytes(cipher, key, algo);
    return std::string(bytes.begin(), bytes.end());
}

template <size_t N>
inline std::vector<uint8_t> decryptAutoBytes(const Encrypted<N>& cipher,
                                             Algorithm algo = Algorithm::Xor)
{
    return decryptBytes(cipher, runtimeKey(), algo);
}

template <size_t N>
inline std::string decryptAuto(const Encrypted<N>& cipher,
                               Algorithm algo = Algorithm::Xor)
{
    const auto bytes = decryptAutoBytes(cipher, algo);
    return std::string(bytes.begin(), bytes.end());
}

} // namespace shobf
