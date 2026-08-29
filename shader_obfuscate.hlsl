// D3D11 compute shader Compiled at build time by build_shader.py
// into a DXBC blob embedded through shader_dxbc.inc
// when SHOBF_D3D11_PRECOMPILED is defined; otherwise
// this same source is embedded in shader_obfuscate.hpp and compiled at engine
// init via d3dcompiler_47.dll.
// Target profile: cs_5_0, entry point: main.
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
