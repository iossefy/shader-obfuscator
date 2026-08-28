// gen_shader_dxbc.cpp — build-time helper that compiles shader_obfuscate.hlsl
// to a cs_5_0 DXBC blob using d3dcompiler_47.dll's D3DCompile.
//
// Used by build_shader.py (SHOBF_D3D11_PRECOMPILED mode) so the HLSL source is
// never embedded in the shipped binary. It is deliberately the SAME compiler
// (and same D3DCOMPILE_SKIP_OPTIMIZATION) that the runtime path uses, so the
// produced blob is accepted by both native Windows D3D11 and wine's
// vkd3d-shader-backed CreateComputeShader — unlike standalone dxc.exe output.
//
// The emitted .dxbc is a build artifact only; this helper itself is never
// shipped. On a Linux cross-build it is compiled with mingw and run under
// wine; on native Windows it runs directly.
//
// Usage: gen_shader_dxbc.exe out.dxbc  (reads shader_obfuscate.hlsl from CWD)
#include <windows.h>
#include <d3dcompiler.h>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::fprintf(stderr, "usage: gen_shader_dxbc.exe out.dxbc\n");
        return 2;
    }

    std::ifstream in("shader_obfuscate.hlsl", std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "error: shader_obfuscate.hlsl not found in CWD\n");
        return 2;
    }
    const std::string src((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());

    ID3DBlob* code = nullptr;
    ID3DBlob* errs = nullptr;
    HRESULT hr = D3DCompile(src.data(), src.size(), "shader_obfuscate.hlsl",
                            nullptr, nullptr, "main", "cs_5_0",
                            0x00000004 /*D3DCOMPILE_SKIP_OPTIMIZATION*/, 0,
                            &code, &errs);
    if (FAILED(hr)) {
        if (errs && errs->GetBufferPointer())
            std::fprintf(stderr, "%s\n",
                         static_cast<const char*>(errs->GetBufferPointer()));
        if (errs) errs->Release();
        std::fprintf(stderr, "D3DCompile failed: hr=%08lx\n",
                     static_cast<unsigned long>(hr));
        return 1;
    }
    if (errs) errs->Release();

    std::ofstream out(argv[1], std::ios::binary);
    out.write(static_cast<const char*>(code->GetBufferPointer()),
              static_cast<std::streamsize>(code->GetBufferSize()));
    const bool ok = out.good();
    std::printf("wrote %s size=%lu\n", argv[1],
                static_cast<unsigned long>(code->GetBufferSize()));
    code->Release();
    return ok ? 0 : 1;
}
