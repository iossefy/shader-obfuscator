// Backend: leave commented for Vulkan (default), uncomment for D3D11.
//#define SHOBF_BACKEND_D3D11
// Embed prebuilt DXBC, no HLSL text in binary.
//#define SHOBF_D3D11_PRECOMPILED
// Strip validation/exceptions; CMake Release build types define this.
//#define SHOBF_NO_DEBUG

#define SHOBF_BUILD_SEED 0xA5F07E11D3C24B96

#include "shader_obfuscate.hpp"

#include <iostream>
#include <string>

namespace {

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

}

int main()
{
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
            return 0;

        if (guess == password) {
            std::cout << winMsg << std::flush;
            return 0;
        }
        std::cout << failMsg;
    }
}
