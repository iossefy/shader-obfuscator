#!/usr/bin/env python3
"""build_shader.py — compile shader_obfuscate.hlsl to a DXBC blob at build time.

Emits `shader_dxbc.inc`, a C++ header holding the pre-compiled cs_5_0 blob as a
byte array (kShaderDxbc / kShaderDxbcSize) plus a SHOBF_D3D11_HAVE_DXBC canary
macro. Consumed by shader_obfuscate.hpp when SHOBF_D3D11_PRECOMPILED is defined
so the HLSL *source* string is never embedded in the binary.

Blob producer (important): the default uses the tiny D3DCompile helper
gen_shader_dxbc.cpp, i.e. d3dcompiler_47.dll's D3DCompile. That is the same
compiler the runtime path uses, so the blob is accepted by BOTH native Windows
D3D11 and wine's vkd3d-shader-backed CreateComputeShader. A blob from the
standalone Windows-SDK dxc.exe is rejected by wine and is therefore only an
opt-in (`SHOBF_PRODUCER=dxc`).

Cross-platform: works on native Windows, MSYS2, and Linux (where Windows PE
helpers are invoked through wine64). On native Windows the helper is built with
MinGW-w64 when available and falls back to the MSVC toolchain (cl.exe under
vcvarsall.bat) otherwise.

Usage:
    python3 build_shader.py [--out DIR]
    SHOBF_PRODUCER=dxc  python3 build_shader.py   # opt-in, not wine-compatible
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

PROFILE = "cs_5_0"
ENTRY = "main"
HELPER = "gen_shader_dxbc.cpp"
HELPER_EXE = "gen_shader_dxbc.exe"

WIN64_TOOLCHAIN_CANDIDATES = (
    r"C:\Program Files (x86)\Windows Kits\10\bin",
    "/opt/msvc-toolchain/Windows Kits/10/bin",
)

# MinGW C++ compiler used to build the D3DCompile helper on Windows/MSYS2.
MINGW_CANDIDATES = ("x86_64-w64-mingw32-g++", "x86_64-w64-mingw32-g++-posix",
                    "g++")

# Override for the MSVC vcvarsall.bat path (otherwise auto-detected via
# vswhere / common Visual Studio install locations).
VCVARS_ENV = "SHOBF_MSVC_VCVARS"


def is_win():
    return os.name == "nt"


def wine_cmd() -> list[str] | None:
    for w in ("wine64", "wine"):
        p = shutil.which(w)
        if p:
            return [p]
    return None


def run(cmd, **kw):
    print("+", " ".join(str(c) for c in cmd))
    return subprocess.run([str(c) for c in cmd], **kw)


def producer_dxc() -> tuple[list[str], bool]:
    """Return (dxc command line prefix, under_wine) for the standalone dxc.exe."""
    env = os.environ.get("SHOBF_DXC")
    if env:
        return [env], env.lower().endswith(".exe") and not is_win()
    exe = shutil.which("dxc") or shutil.which("dxc.exe")
    if exe:
        return [exe], exe.lower().endswith(".exe") and not is_win()
    for root in WIN64_TOOLCHAIN_CANDIDATES:
        root = Path(root)
        if not root.exists():
            continue
        for sdk in sorted(root.iterdir(), reverse=True):
            for arch in ("x64", "x86"):
                cand = sdk / arch / "dxc.exe"
                if cand.exists():
                    return [str(cand)], not is_win()
    return None, False


def find_vcvarsall() -> str | None:
    """Locate vcvarsall.bat for an installed MSVC toolchain (native Windows)."""
    override = os.environ.get(VCVARS_ENV)
    if override:
        return override if os.path.exists(override) else None

    vswhere = r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
    if os.path.exists(vswhere):
        proc = subprocess.run(
            [vswhere, "-latest", "-products", "*", "-property",
             "installationPath"], capture_output=True, text=True)
        p = proc.stdout.strip()
        if proc.returncode == 0 and p:
            cand = os.path.join(p, "VC", "Auxiliary", "Build",
                                "vcvarsall.bat")
            if os.path.exists(cand):
                return cand

    for base in (r"C:\Program Files\Microsoft Visual Studio",
                 r"C:\Program Files (x86)\Microsoft Visual Studio"):
        if not os.path.isdir(base):
            continue
        for inst in os.listdir(base):
            for sub in ("BuildTools", "Community", "Professional",
                        "Enterprise"):
                cand = os.path.join(base, inst, sub, "VC", "Auxiliary",
                                    "Build", "vcvarsall.bat")
                if os.path.exists(cand):
                    return cand
    return None


def compile_msvc(src: Path, out: Path, vcvarsall: str) -> bool:
    """Compile src with cl.exe under the vcvarsall environment (x64)."""
    cmd = (f'call "{vcvarsall}" x64 >nul && cl /nologo /O2 /EHsc '
           f'"{src}" d3dcompiler.lib /Fe:"{out}"')
    print("+", cmd)
    proc = subprocess.run(cmd, shell=True)
    return proc.returncode == 0 and out.exists()


def compile_helper(out_dir: Path) -> Path:
    """Compile gen_shader_dxbc.cpp into gen_shader_dxbc.exe and return its path."""
    src = out_dir / HELPER
    out = out_dir / HELPER_EXE
    if out.exists():
        out.unlink()

    # Prefer MinGW-w64 when present (the only option on non-Windows hosts,
    # where the PE helper is then run under wine64).
    cxx = next((c for c in MINGW_CANDIDATES if shutil.which(c)), None)
    if cxx is not None:
        # MinGW ships a d3dcompiler import lib, so the helper links without any
        # external dependency (same approach the runtime build already relies on).
        proc = run([cxx, "-std=c++17", "-O2", "-s", str(src), "-o", str(out),
                    "-ld3dcompiler"])
        if proc.returncode == 0 and out.exists():
            return out

    # Fall back to MSVC cl.exe on native Windows (VS / Build Tools via
    # vcvarsall.bat), which resolves d3dcompiler.lib through the LIB env.
    if is_win():
        vcvarsall = find_vcvarsall()
        if vcvarsall is not None:
            if compile_msvc(src, out, vcvarsall):
                return out
            sys.exit(f"error: MSVC cl failed to build {HELPER_EXE}")

    sys.exit("error: no C++ toolchain found to build the D3DCompile helper "
             "(looked for MinGW-w64 and, on Windows, MSVC cl.exe)")


def emit_inc(dxbc: Path, out: Path) -> None:
    data = dxbc.read_bytes()
    lines = ["#define SHOBF_D3D11_HAVE_DXBC 1",
             "",
             "static const unsigned char kShaderDxbc[] = {"]
    for i in range(0, len(data), 12):
        chunk = ", ".join(f"0x{b:02x}" for b in data[i:i + 12])
        lines.append("    " + chunk + ",")
    lines.append("};")
    lines.append(f"static const unsigned kShaderDxbcSize = {len(data)};")
    lines.append("")
    out.write_text("\n".join(lines))
    print(f"wrote {out} ({len(data)} bytes)")


def main() -> int:
    out_dir = Path(os.path.abspath(os.path.dirname(__file__)))
    if "--out" in sys.argv[1:]:
        out_dir = Path(os.path.abspath(sys.argv[sys.argv.index("--out") + 1]))

    hlsl = out_dir / "shader_obfuscate.hlsl"
    if not hlsl.exists():
        sys.exit(f"error: {hlsl} not found")

    dxbc = out_dir / "shader.dxbc"
    inc = out_dir / "shader_dxbc.inc"

    producer = os.environ.get("SHOBF_PRODUCER", "d3dcompile")

    if producer == "dxc":
        cmd, under_wine = producer_dxc()
        if cmd is None:
            sys.exit("error (SHOBF_PRODUCER=dxc): DXC not found. Set SHOBF_DXC "
                     "or put dxc on PATH. (Note: standalone DXC blobs are not "
                     "accepted by wine's CreateComputeShader.)")
        full = []
        if under_wine:
            w = wine_cmd()
            if not w:
                sys.exit("error: dxc is a Windows PE and wine/wine64 was not "
                         "found on PATH")
            full += w
        full += cmd + ["-T", PROFILE, "-E", ENTRY, "-Fo", str(dxbc), str(hlsl)]
        proc = run(full)
        if proc.returncode != 0 or not dxbc.exists():
            sys.exit(f"error: dxc failed with exit code {proc.returncode}")
    else:
        helper = compile_helper(out_dir)
        full = []
        if not is_win():
            w = wine_cmd()
            if not w:
                sys.exit("error: gen_shader_dxbc.exe is a Windows PE and "
                         "wine/wine64 was not found on PATH")
            full += w
        full += [helper, str(dxbc)]
        proc = run(full, cwd=str(out_dir))
        if proc.returncode != 0 or not dxbc.exists():
            sys.exit("error: D3DCompile helper failed")

    emit_inc(dxbc, inc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
