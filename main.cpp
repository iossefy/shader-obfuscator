// Seed for the compile-time session key.
#define SHOBF_BUILD_SEED 0x0123456789ABCDEF

#include "shader_obfuscate.hpp"

#include <cstdio>
#include <iostream>
#include <string>

// Demo-only helpers: render raw ciphertext bytes as lowercase hex.
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
    static constexpr char kDemoKey[] = "vulkan";

    // XOR-encrypted at compile time.
    static const auto kEncrypted =
        SHOBF_OBFUSCATE(
            "Hello from the GPU! This string was decrypted by a GPU "
            "compute shader.", "vulkan");

    // Same plaintext, RC4-encrypted.
    static const auto kRc4Encrypted =
        SHOBF_OBFUSCATE_RC4(
            "Hello from the GPU! This string was decrypted by a GPU "
            "compute shader.", "vulkan");

    try {
        std::cout << "=====================================================\n";
        std::cout << " Shader Obfuscator demo (compile-time encrypt, GPU decrypt)\n";
        std::cout << " backend: " << shobf::backendName() << "\n";
        std::cout << "=====================================================\n\n";

        std::cout << "[1] VARIATION 1 - decrypt with an explicit key\n";
        std::cout << "    Ciphertext (hex): " << toHex(kEncrypted) << "\n";
        std::cout << "    Key used        : \"" << kDemoKey << "\"\n";

        const std::string secret = shobf::decrypt(kEncrypted, kDemoKey);
        std::cout << "    Decrypted text  : " << secret << "\n\n";

        // Auto API: session key derived at compile time from SHOBF_BUILD_SEED;
        // no key literal appears anywhere.
        std::cout << "[2] VARIATION 2 - seed-derived session key\n";
        std::cout << "    Session key         : \"" << shobf::runtimeKey() << "\"\n";

        static const auto kAuto = SHOBF_OBFUSCATE(
            "Hello from the GPU! This string was decrypted by a GPU "
            "compute shader.", shobf::seedKey());
        std::cout << "    Ciphertext (hex)    : " << toHex(kAuto) << "\n";
        std::cout << "    Decrypted text      : " << shobf::decryptAuto(kAuto) << "\n";
        std::cout << "    Same as variation 1 : "
                  << (shobf::decryptAuto(kAuto) == secret ? "yes" : "NO") << "\n\n";

        std::cout << "[3] RC4 ALGORITHM - decrypt with an explicit key\n";
        std::cout << "    Ciphertext (hex): " << toHex(kRc4Encrypted) << "\n";
        std::cout << "    Key used        : \"" << kDemoKey << "\"\n";

        const std::string rc4Secret = shobf::decrypt(kRc4Encrypted, kDemoKey,
                                                     shobf::Algorithm::Rc4);
        std::cout << "    Decrypted text  : " << rc4Secret << "\n";
        std::cout << "    Same as XOR     : "
                  << (rc4Secret == secret ? "yes" : "NO") << "\n\n";

        // Known-answer test: key "Key", ciphertext bbf316e8d940af0ad3, must
        // give "Plaintext". Raw bytes so no hex text lands in the binary.
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

        // Error handling: intentionally broken ciphertexts must throw.
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