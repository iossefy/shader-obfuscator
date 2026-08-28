// ============================================================================
// crackme.cpp — shobf (Shader Obfuscator) showcase crackme
//
// Every string — banner, prompt, the secret passphrase, win/fail messages —
// is encrypted at compile time and only decrypted on the GPU at runtime.
// Static analysis sees opaque binary ciphertexts (raw bytes, invisible to
// strings(1)) and a build seed; neither plaintext nor key literals exist in
// this binary.
//
// shader_obfuscate.hpp is a single-header library: every option is a macro you
// #define BEFORE the #include. In this repo the CMake project configures most
// of them for you via -DSHOBF_* cache options. Everything is equivalent:
// a -DSHOBF_* flag on the command line and a #define here have the same effect.
//
// What CMake controls (see CMakeLists.txt / README):
//   * SHOBF_BACKEND_D3D11  - backend:: Direct3D 11 (Windows) vs Vulkan (default)
//   * SHOBF_D3D11_PRECOMPILED - D3D11: embed prebuilt shader, no HLSL in binary
//   * SHOBF_NO_DEBUG       - Release build types define this automatically
//
// The block below is the manual/fallback way to set the same macros in source
// (edit it, then include; defaults are the safe path):
//
//   * Backend — uncomment to select Direct3D 11 instead of Vulkan:
//       //#define SHOBF_BACKEND_D3D11
//   * D3D11 shader source (only when SHOBF_BACKEND_D3D11 is set):
//       SHOBF_D3D11_PRECOMPILED defined  -> shader compiled at BUILD time and
//         embedded as a DXBC blob (run `python3 build_shader.py` once); the
//         HLSL string is NOT in the binary and only d3d11.dll is needed at
//         runtime.
//       (leave undefined)                 -> shader compiled at engine init via
//         the system d3dcompiler_47.dll.
//   * Release vs debug:
//       //#define SHOBF_NO_DEBUG   -> strip validation, exceptions and all
//         diagnostic strings; failures return empty results silently.
//   * Seed for the compile-time session key (any 64-bit value):
//       #define SHOBF_BUILD_SEED 0x...    -> if omitted, __DATE__/__TIME__ are
//         hashed (key changes on every rebuild).
//
// Build: configure with CMake (see README for all -DSHOBF_* options).
//
// Crack it: find the seed, reimplement the splitmix64 key derivation, decode
// the ciphertexts... or just let a GPU breakpoint do the work.
// ============================================================================

// ---- configuration -------------------------------------------------------
// Backend: uncomment for Direct3D 11 (Windows target); leave commented for
// the default Vulkan backend.
//#define SHOBF_BACKEND_D3D11

// D3D11 shader source mode (only meaningful with SHOBF_BACKEND_D3D11):
// uncomment to use the build-time-precompiled, embedded DXBC blob.
//#define SHOBF_D3D11_PRECOMPILED

// Release vs debug: controlled by the CMake build type (Release/RelWithDebInfo
// automatically define SHOBF_NO_DEBUG). Leave this commented out.
//#define SHOBF_NO_DEBUG

// Seed for the compile-time session key. Rebuild must keep the same seed for
// persisted ciphertexts to keep decrypting.
#define SHOBF_BUILD_SEED 0xA5F07E11D3C24B96
// --------------------------------------------------------------------------

#include "shader_obfuscate.hpp"

#include <iostream>
#include <string>

namespace {

// All compile-time encrypted under the seed-derived session key. No literal
// keys anywhere: SHOBF_BUILD_SEED is the only secret material in the binary.
const auto kBanner = SHOBF_OBFUSCATE(
    "\n=== shobf crackme ===\n"
    "The vault opens for those who speak the passphrase.\n",
    shobf::seedKey());

const auto kPrompt = SHOBF_OBFUSCATE(
    "passphrase> ", shobf::seedKey());

const auto kPass = SHOBF_OBFUSCATE(
    "vulk4n_1s_n0t_crypt0", shobf::seedKey());

const auto kWin = SHOBF_OBFUSCATE(
    "\n[ACCESS GRANTED] The vault hums open.\n"
    "FLAG{gpu_kn3w_y0u_w3r3_tro4ble}\n",
    shobf::seedKey());

const auto kFail = SHOBF_OBFUSCATE(
    "[denied] wrong passphrase.\n", shobf::seedKey());

} // namespace

int main()
{
    // Decrypt everything once up front (GPU round trips), then play.
    const std::string banner    = shobf::decryptAuto(kBanner);
    const std::string prompt    = shobf::decryptAuto(kPrompt);
    const std::string password  = shobf::decryptAuto(kPass);
    const std::string winMsg    = shobf::decryptAuto(kWin);
    const std::string failMsg   = shobf::decryptAuto(kFail);

    unsigned attempts = 0;
    std::cout << banner;
    for (;;) {
        std::cout << "[" << ++attempts << "] " << prompt << std::flush;

        std::string guess;
        if (!std::getline(std::cin, guess))
            return 0;                       // EOF / closed stdin

        if (guess == password) {
            std::cout << winMsg << std::flush;
            return 0;
        }
        std::cout << failMsg;
    }
}
