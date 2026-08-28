cmake_minimum_required(VERSION 3.16)
project(shobf
        VERSION 0.1.0
        DESCRIPTION "Shader-based GPU string obfuscation (single header)"
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# ---- options -----------------------------------------------------------------
option(SHOBF_BACKEND_D3D11 "Use the Direct3D 11 backend instead of Vulkan (Windows only)" OFF)
option(SHOBF_D3D11_PRECOMPILED "D3D11: embed precompiled shader (run build_shader.py); no HLSL in binary" OFF)

if(SHOBF_BACKEND_D3D11 AND NOT WIN32)
    message(SEND_ERROR "SHOBF_BACKEND_D3D11 requires a Windows target (the header #errors otherwise). Use the default Vulkan backend on this platform.")
endif()
if(SHOBF_D3D11_PRECOMPILED AND NOT SHOBF_BACKEND_D3D11)
    message(SEND_ERROR "SHOBF_D3D11_PRECOMPILED requires SHOBF_BACKEND_D3D11=ON.")
endif()

# ---- vulkan ------------------------------------------------------------------
if(NOT SHOBF_BACKEND_D3D11)
    find_package(Vulkan REQUIRED)
endif()

# ---- build the precompiled D3D11 shader ---------------------------------------
# Only active in SHOBF_D3D11_PRECOMPILED mode; otherwise this is a no-op phase
# target (a stale shader_dxbc.inc is harmless — the header only reads it when
# SHOBF_D3D11_PRECOMPILED is defined).
set(SHOBF_INC "${CMAKE_CURRENT_SOURCE_DIR}/shader_dxbc.inc")
if(SHOBF_D3D11_PRECOMPILED)
    # Canonical generator pattern: the target depends on the generated file, so
    # the OUTPUT rule below runs build_shader.py whenever the inc is missing or
    # older than its inputs. (Previously a POST_BUILD / DEPENDS hack, which
    # CMake >= 4.0 rejects under policy CMP0175.)
    add_custom_target(shobf_dxbc_inc DEPENDS "${SHOBF_INC}")
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_custom_command(
        OUTPUT  "${SHOBF_INC}"
        COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/build_shader.py"
                --out "${CMAKE_CURRENT_SOURCE_DIR}"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/shader_obfuscate.hlsl"
                "${CMAKE_CURRENT_SOURCE_DIR}/gen_shader_dxbc.cpp"
                "${CMAKE_CURRENT_SOURCE_DIR}/build_shader.py"
        COMMENT "Precompiling shader_obfuscate.hlsl -> shader_dxbc.inc"
        VERBATIM)
else()
    add_custom_target(shobf_dxbc_inc)
endif()

# ---- shared setup ------------------------------------------------------------
set(SHOBF_D3D11_DEFS
    SHOBF_BACKEND_D3D11
    $<$<BOOL:${SHOBF_D3D11_PRECOMPILED}>:SHOBF_D3D11_PRECOMPILED>)

set(SHOBF_RELEASE_DEFS
    $<$<CONFIG:Release>:SHOBF_NO_DEBUG>
    $<$<CONFIG:RelWithDebInfo>:SHOBF_NO_DEBUG>
    $<$<CONFIG:MinSizeRel>:SHOBF_NO_DEBUG>)

function(shobf_setup target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /GR-)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra)
    endif()
    add_dependencies(${target} shobf_dxbc_inc)
    target_compile_definitions(${target} PRIVATE ${SHOBF_RELEASE_DEFS})
    if(SHOBF_BACKEND_D3D11)
        target_compile_definitions(${target} PRIVATE ${SHOBF_D3D11_DEFS})
        if(MINGW OR MSVC)
            target_link_libraries(${target} PRIVATE d3d11)
        endif()
    else()
        target_link_libraries(${target} PRIVATE Vulkan::Vulkan)
    endif()
endfunction()

add_executable(crackme crackme.cpp)
shobf_setup(crackme)

add_executable(shader-obfuscator main.cpp)
shobf_setup(shader-obfuscator)
