# Shader Obfuscator

A single-header C++17 library that hides strings from `strings(1)` and casual
static analysis by encrypting them at compile time and decrypting them at
runtime **on the GPU**.

## Why

I have been researching malware anti-analysis techniques and the idea of
utilizing the GPU instead of the CPU seemed interesting to me so i experimented
a bit and made this POC.

GPU-based obfuscation is designed to break emulation and basic sandboxes.

The technique exploits the fact that:

- Most sandboxes and CPU emulators (Unicorn, QEMU-based sandboxes, x86 emulation
  in tools like CAPE) only emulate the CPU instruction stream. They have no GPU
  device model at all.

- If the decryption routine offloads the actual rc4/XOR/whatever work to a
  compute kernel via vulkan and d3d11 api, a pure-CPU emulator either:
  - Fails the API call (no real GPU driver present) and the malware branches to
    a bail-out/sleep path, or
  - Hangs/errors out because the emulator doesn't know how to service the driver
	call at all.  Either way, the strings never get decrypted in that
	environment, so string-based detection, static "decrypt and dump" scripts,
	and behavioral sandboxes that rely on seeing plaintext IOCs all come up
	empty.

![any.run analysis](assets/anyrun.png)

## Trade-offs

From the malware author's side, this technique trades stealth for a lot of
fragility. Downsides:

- Requires an actual GPU with a compatible driver. A huge share of real-world
  targets (servers, VDI instances, budget laptops, virtualized corporate
  endpoints, etc...) have no discrete GPU or only a basic integrated one without
  full compute driver support installed.
- If the target has no GPU/driver, the malware's decryption never succeeds, so
  the payload simply fails to execute correctly on a meaningful fraction of
  intended victims. That's a self-inflicted loss of reach that pure-CPU crypto
  doesn't have.
- Loading `d3d11.dll` or vulkan from a process that has no legitimate reason to
  touch a GPU is itself an anomalous, fairly rare signal and easy for the EDR to
  flag.


## What it does

- You write `shobf::decrypt(SHOBF_OBFUSCATE("Hello, world!", "key"))` in plain
  C++.
- At compile time the literal is encrypted into opaque ciphertext bytes.
- At runtime a tiny GPU compute shader (Vulkan, or Direct3D 11 on Windows)
  decrypts it back, so a reverse engineer has to chase the data through the GPU
  to recover it.


## Usage

See `crackme.cpp` and `main.cpp` as example usages.

### Encrypting strings

```cpp
// XOR cipher (default)
std::string a = shobf::decrypt(SHOBF_OBFUSCATE("secret", "key"));

// RC4 cipher
std::string b = shobf::decrypt(SHOBF_OBFUSCATE_RC4("secret", "key"),
                               "key", shobf::Algorithm::Rc4);

// Auto: key derived from SHOBF_BUILD_SEED
std::string c = shobf::decryptAuto(SHOBF_OBFUSCATE("secret", shobf::seedKey()));
```

A complete program with a runtime flag check:

```cpp
#include "shader_obfuscate.hpp"
#include <iostream>
#include <string>

int main()
{
    // Compile-time encrypted; SHOBF_BUILD_SEED is the only secret in the binary.
    const auto obfFlag = SHOBF_OBFUSCATE("FLAG{sh4d3r_0bfusc4t3d}", shobf::seedKey());
    const std::string flag = shobf::decryptAuto(obfFlag);

    std::string guess;
    std::cout << "Enter flag: ";
    std::getline(std::cin, guess);

    std::cout << (guess == flag ? "Correct!" : "Wrong!") << std::endl;
}
```


## Quick start

```sh
cmake -S . -B build
cmake --build build -j
./build/crackme          # guess: vulk4n_1s_n0t_crypt0
./build/shader-obfuscator
```

Or build just one target:

```sh
cmake --build build --target crackme
```

## Building on Linux

The default Vulkan backend builds natively on Linux with g++ or clang++ and a
Vulkan SDK (or distro Vulkan headers + loader). Requirements: CMake >= 3.16, a
C++17 compiler, and the Vulkan headers/loader (e.g.  `vulkan-headers` /
`vulkan-loader` on most distros).

```sh
cmake -S . -B build
cmake --build build -j
./build/crackme          # guess: vulk4n_1s_n0t_crypt0
./build/shader-obfuscator
```

A clean release-only build of a single target:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target crackme -j
```

## Building on Windows

Builds with Visual Studio (MSVC) or MinGW-w64. Backends: Vulkan (default) or
Direct3D 11.

**Vulkan** needs the Vulkan SDK (`VULKAN_SDK`):

```sh
cmake -S . -B build
cmake --build build --config Release -j
build\Release\crackme.exe          # guess: vulk4n_1s_n0t_crypt0
build\Release\shader-obfuscator.exe
```

**Direct3D 11** (`d3d11.dll` ships with Windows, no Vulkan SDK):

```sh
cmake -S . -B build-d3d -DSHOBF_BACKEND_D3D11=ON
cmake --build build-d3d --config Release
build-d3d\Release\crackme.exe
```

Add `-DSHOBF_D3D11_PRECOMPILED=ON` to embed a precompiled DXBC blob instead of
HLSL text. CMake runs `build_shader.py` (needs Python 3 + MSVC `cl.exe` via `vcvarsall.bat`; `SHOBF_MSVC_VCVARS` overrides the path).

## Configuration

Every option is a macro you `#define` **before** `#include "shader_obfuscate.hpp"`.
CMake forwards them as compile definitions:

```sh
cmake -S . -B build -DSHOBF_BACKEND_D3D11=ON -DSHOBF_D3D11_PRECOMPILED=ON
```

| Define / option | What it does |
|--------|--------------|
| `SHOBF_BACKEND_D3D11` | Use D3D11 instead of Vulkan (non-Windows fails with `#error`). |
| `SHOBF_D3D11_PRECOMPILED` | Embed a prebuilt DXBC blob so no HLSL text ships (with D3D11 backend). |
| `SHOBF_NO_DEBUG` | No validation/exceptions and failures return empty. |
| `SHOBF_BUILD_SEED` | 64-bit seed for the `decryptAuto` session key. |

If `SHOBF_BUILD_SEED` is omitted, the header hashes `__DATE__`/`__TIME__`, so
the key changes on every rebuild.

## The crackme example

`crackme.cpp` is a small game that decrypts its banner, prompt, secret
passphrase, and win/fail messages on the GPU at runtime.

```sh
cmake --build build --target crackme -j     # built by the default config

strings build/crackme | grep -c passphrase  # 0
./build/crackme                             # guess: vulk4n_1s_n0t_crypt0
```

To cross-compile a Windows/D3D11 build from Linux, configure with CMake and a
MinGW toolchain file and set `SHOBF_BACKEND_D3D11=ON` (add
`SHOBF_D3D11_PRECOMPILED=ON` to embed a prebuilt shader.

## Requirements

- C++17 compiler (g++ / clang++ / MinGW-w64 / MSVC), CMake >== 3.16, and python.
- **Vulkan** (default): Vulkan headers + loader and a GPU with a compute queue.
- **D3D11** (`SHOBF_BACKEND_D3D11`, Windows): `d3d11.dll`. Precompiled mode
  (`SHOBF_D3D11_PRECOMPILED`) additionally needs Python 3 and either
  MinGW-w64 `g++` or the MSVC toolchain (found automatically), plus `wine64`
  when cross-compiling on Linux.

## Disclaimer

This project is intended **strictly for research purposes**.

It was developed to explore GPU-based obfuscation techniques, anti-analysis
methods, and the practical challenges of offloading decryption to graphics
hardware.


## AI Disclosure

This project was developed with the assistance of AI-powered tools for code
generation, documentation, and debugging. The underlying research, threat
modeling, and obfuscation techniques are the original work of the author.

## License

MIT License.
