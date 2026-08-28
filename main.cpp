// ============================================================================
// main.cpp — usage example for shader_obfuscate.hpp
//
// Encryption happens on the CPU at COMPILE TIME (SHOBF_OBFUSCATE /
// SHOBF_OBFUSCATE_RC4 macros); decryption happens on the GPU at runtime.
// The plaintext below never exists in the compiled binary, and the
// ciphertext is stored as opaque RAW BYTES — nothing text-shaped shows up:
//     strings ./shader-obfuscator | grep "This string was decrypted"   (no match)
//     strings ./shader-obfuscator | grep -E '^[0-9a-f]{16,}$'           (no match)
//
// Configuration is a set of macros defined BEFORE the #include (standard
// single-header pattern). In this repo the CMake project drives the backend,
// SHOBF_NO_DEBUG and shader precompilation via -DSHOBF_* options (see
// crackme.cpp's header comment for the full list); the seed below is one you
// can set right here in source.
//
// Build: cmake -S . -B build && cmake --build build
//        (SHOBF_BUILD_SEED below is optional; without it __DATE__/__TIME__ are
//         hashed, which changes the Auto key on every rebuild.)
// ============================================================================

// Seed for the compile-time session key (any 64-bit value). Optional here.
#define SHOBF_BUILD_SEED 0x0123456789ABCDEF

#include "shader_obfuscate.hpp"

#include <cstdio>
#include <iostream>
#include <string>

// Interop helpers for the demo only: render raw ciphertext bytes as lowercase
// hex (the format SHOBF_OBFUSCATE_HEX produces directly).
inline char hexDigit(uint8_t v) { return v < 10 ? char('0' + v) : char('a' + v - 10); }
static std::string toHex(const uint8_t* p, size_t n)
{
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out += hexDigit(uint8_t(p[i] >> 4));
        out += hexDigit(uint8_t(p[i] & 0xF));
    }
    return out;
}
template <size_t N>
static std::string toHex(const shobf::Encrypted<N>& c)
{
    return toHex(c.data, N);
}

int main()
{
    // shobf::setValidationEnabled(true);   // optional: Khronos validation layers

    // === CONFIG =============================================================
    // These two literals are encrypted by the compiler (constexpr evaluation)
    // into raw-byte ciphertexts. Only those bytes end up in the binary.
    // =========================================================================
    static constexpr char kDemoKey[] = "vulkan";

    // XOR-encrypted at compile time -> decrypt with Algorithm::Xor (default)
    static const auto kEncrypted =
        SHOBF_OBFUSCATE(
            "Hello from the GPU! This string was decrypted by a GPU "
            "compute shader.", "vulkan");

    // Same plaintext, RC4-encrypted at compile time -> Algorithm::Rc4
    static const auto kRc4Encrypted =
        SHOBF_OBFUSCATE_RC4(
            "Hello from the GPU! This string was decrypted by a GPU "
            "compute shader.", "vulkan");

    try {
        std::cout << "=====================================================\n";
        std::cout << " Shader Obfuscator demo (compile-time encrypt, GPU decrypt)\n";
        std::cout << " backend: " << shobf::backendName() << "\n";
        std::cout << "=====================================================\n\n";

        // ------------------------------------------------------------------
        // Variation 1: explicit key. Ciphertext was produced by the compiler;
        // decryption runs on the GPU.
        // ------------------------------------------------------------------
        std::cout << "[1] VARIATION 1 - decrypt with an explicit key\n";
        std::cout << "    Ciphertext (hex): " << toHex(kEncrypted) << "\n";
        std::cout << "    Key used        : \"" << kDemoKey << "\"\n";

        const std::string secret = shobf::decrypt(kEncrypted, kDemoKey);
        std::cout << "    Decrypted text  : " << secret << "\n\n";

        // ------------------------------------------------------------------
        // Variation 2: the Auto API uses one session key derived at COMPILE
        // TIME from SHOBF_BUILD_SEED (or __DATE__/__TIME__ if the define is
        // absent). Ciphertexts made with shobf::seedKey() as the macro key
        // decrypt through decryptAuto() — no key literal appears anywhere.
        // ------------------------------------------------------------------
        std::cout << "[2] VARIATION 2 - seed-derived session key\n";
        std::cout << "    Session key         : \"" << shobf::runtimeKey() << "\"\n";

        // Compile-time XOR ciphertext under the derived key (no literal key!)
        static const auto kAuto = SHOBF_OBFUSCATE(
            "Hello from the GPU! This string was decrypted by a GPU "
            "compute shader.", shobf::seedKey());
        std::cout << "    Ciphertext (hex)    : " << toHex(kAuto) << "\n";
        std::cout << "    Decrypted text      : " << shobf::decryptAuto(kAuto) << "\n";
        std::cout << "    Same as variation 1 : "
                  << (shobf::decryptAuto(kAuto) == secret ? "yes" : "NO") << "\n\n";

        // ------------------------------------------------------------------
        // RC4 algorithm: identical flow, Algorithm::Rc4 instead of Xor.
        // ------------------------------------------------------------------
        std::cout << "[3] RC4 ALGORITHM - decrypt with an explicit key\n";
        std::cout << "    Ciphertext (hex): " << toHex(kRc4Encrypted) << "\n";
        std::cout << "    Key used        : \"" << kDemoKey << "\"\n";

        const std::string rc4Secret = shobf::decrypt(kRc4Encrypted, kDemoKey,
                                                     shobf::Algorithm::Rc4);
        std::cout << "    Decrypted text  : " << rc4Secret << "\n";
        std::cout << "    Same as XOR     : "
                  << (rc4Secret == secret ? "yes" : "NO") << "\n\n";

        // ------------------------------------------------------------------
        // Known-answer test: published RC4 vector. Decrypting the published
        // ciphertext bbf316e8d940af0ad3 with key "Key" must give "Plaintext".
        // (Stored as raw bytes here so no hex text lands in the binary.)
        // ------------------------------------------------------------------
        std::cout << "[4] RC4 KNOWN-ANSWER TEST (published vector)\n";
        static const uint8_t katCt[] = {0xbb, 0xf3, 0x16, 0xe8,
                                        0xd9, 0x40, 0xaf, 0x0a, 0xd3};
        const std::string katPlain = shobf::decrypt(toHex(katCt, sizeof katCt),
                                                    "Key", shobf::Algorithm::Rc4);
        std::cout << "    Key              : \"Key\"\n";
        std::cout << "    Ciphertext (hex) : " << toHex(katCt, sizeof katCt) << "\n";
        std::cout << "    Expected         : \"Plaintext\"\n";
        std::cout << "    Got              : \"" << katPlain << "\"\n";
        std::cout << "    Result           : "
                  << (katPlain == "Plaintext" ? "PASS" : "FAIL") << "\n\n";

        // ------------------------------------------------------------------
        // Error handling demo: these two calls use DELIBERATELY BROKEN input,
        // so the library throws an exception. We catch each one and print its
        // message to show what happens with malformed ciphertexts. This is
        // intentional — not a bug in this program.
        // ------------------------------------------------------------------
        std::cout << "[5] ERROR HANDLING DEMO - intentionally broken ciphertexts\n";
        std::cout << "    (the library throws shobf::Error; caught & printed below)\n";

        try {
            const char badOdd[] = "48656c6c6";               // 9 digits: no full byte pair at the end
            std::cout << "    Test A - odd number of hex digits: \"" << badOdd << "\"\n";
            (void)shobf::decrypt(badOdd, kDemoKey);
            std::cout << "      -> unexpectedly succeeded\n";
        } catch (const shobf::Error& e) {
            std::cout << "      -> error thrown, as expected: " << e.what() << "\n";
        }

        try {
            const char badDigit[] = "4g656c6c6f";             // 'g' is not a hex digit
            std::cout << "    Test B - invalid hex character  : \"" << badDigit << "\"\n";
            (void)shobf::decrypt(badDigit, kDemoKey);
            std::cout << "      -> unexpectedly succeeded\n";
        } catch (const shobf::Error& e) {
            std::cout << "      -> error thrown, as expected: " << e.what() << "\n";
        }

        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "fatal: %s\n", e.what());
        return EXIT_FAILURE;
    }
}
