// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"


/*
 * Copyright 2009 Henri Verbeet for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#include <malloc.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <ntsecapi.h>
#include "bcrypt.h"
#include <stdio.h>

#define SONAME_LIBMBEDTLS

#ifdef SONAME_LIBMBEDTLS
#include <mbedtls/md.h>
#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#endif

void WARN(const char* format, ...);
void TRACE(const char* format, ...);
void FIXME(const char* format, ...);
void ERR(const char* format, ...);
char* wide_to_char(LPCWSTR wide_str);

static HINSTANCE instance;


//WINE_DECLARE_DEBUG_CHANNEL(winediag);

static BOOL mbedtls_initialize(void)
{

    return TRUE;

}


/*
enum alg_id
{
    ALG_ID_MD5,
    ALG_ID_RNG,
    ALG_ID_SHA1,
    ALG_ID_SHA256,
    ALG_ID_SHA384,
    ALG_ID_SHA512,
    ALG_ID_ECDSA_P256,
    ALG_ID_ECDSA_P384,
};*/

enum alg_id
{
    /* cipher */
    ALG_ID_3DES,
    ALG_ID_AES,

    /* hash */
    ALG_ID_SHA256,
    ALG_ID_SHA384,
    ALG_ID_SHA512,
    ALG_ID_SHA1,
    ALG_ID_MD5,
    ALG_ID_MD4,
    ALG_ID_MD2,

    /* asymmetric encryption */
    ALG_ID_RSA,

    /* secret agreement */
    ALG_ID_ECDH_P256,
    ALG_ID_ECDH_P384,

    /* signature */
    ALG_ID_RSA_SIGN,
    ALG_ID_ECDSA_P256,
    ALG_ID_ECDSA_P384,
    ALG_ID_DSA,

    /* rng */
    ALG_ID_RNG,
};

enum chain_mode
{
    CHAIN_MODE_CBC,
    CHAIN_MODE_ECB,
    CHAIN_MODE_CFB,
    CHAIN_MODE_CCM,
    CHAIN_MODE_GCM,
};

static const struct {
    ULONG hash_length;
    const WCHAR* alg_name;
} alg_props[] = {
    /* ALG_ID_MD5    */ { 16, BCRYPT_MD5_ALGORITHM },
    /* ALG_ID_RNG    */ {  0, BCRYPT_RNG_ALGORITHM },
    /* ALG_ID_SHA1   */ { 20, BCRYPT_SHA1_ALGORITHM },
    /* ALG_ID_SHA256 */ { 32, BCRYPT_SHA256_ALGORITHM },
    /* ALG_ID_SHA384 */ { 48, BCRYPT_SHA384_ALGORITHM },
    /* ALG_ID_SHA512 */ { 64, BCRYPT_SHA512_ALGORITHM },
    /* ALG_ID_ECDSA_P256 */ { 0, BCRYPT_ECDSA_P256_ALGORITHM },
    /* ALG_ID_ECDSA_P384 */ { 0, BCRYPT_ECDSA_P384_ALGORITHM },
};


struct algorithm
{
    struct object hdr;
    enum alg_id   id;
    BOOL hmac;
};


typedef  BOOLEAN(WINAPI*
    RtlGenRandom36)
    (__out_bcount(RandomBufferLength) PVOID RandomBuffer,
        __in ULONG RandomBufferLength);

RtlGenRandom36 SystemFunction36;
#define KUSER_SHARED_DATA 0x0000007FFE0000
NTSTATUS WINAPI BCryptGenRandom(BCRYPT_ALG_HANDLE handle, UCHAR* buffer, ULONG count, ULONG flags)
{
    const DWORD supported_flags = BCRYPT_USE_SYSTEM_PREFERRED_RNG;
    struct algorithm* algorithm0 = reinterpret_cast<algorithm*>(handle);

    TRACE("%p, %p, %u, %08x - semi-stub\n", handle, buffer, count, flags);

    if (!algorithm0)
    {
        /* It's valid to call without an algorithm if BCRYPT_USE_SYSTEM_PREFERRED_RNG
         * is set. In this case the preferred system RNG is used.
         */
        if (!(flags & BCRYPT_USE_SYSTEM_PREFERRED_RNG))
            return STATUS_INVALID_HANDLE;
    }
    else if (algorithm0->hdr.magic != MAGIC_ALG || algorithm0->id != ALG_ID_RNG)
        return STATUS_INVALID_HANDLE;

    if (!buffer)
        return STATUS_INVALID_PARAMETER;

    if (flags & ~supported_flags)
        FIXME("unsupported flags %08x\n", flags & ~supported_flags);

    if (algorithm0)
        FIXME("ignoring selected algorithm\n");

    /* When zero bytes are requested the function returns success too. */
    if (!count)
        return STATUS_SUCCESS;

    if (algorithm0 || (flags & BCRYPT_USE_SYSTEM_PREFERRED_RNG))
    {
        if (SystemFunction36)
        {
            /*
                if (RtlGenRandom(buffer, count))
                return STATUS_SUCCESS;
            */
            if (SystemFunction36(buffer, count))
                return STATUS_SUCCESS;
        }
        else
        {
        HMODULE avd32 = ::LoadLibrary(L"advapi32.dll");
            if(avd32)
            {
                SystemFunction36 = (RtlGenRandom36)::GetProcAddress(avd32, "SystemFunction036");
                if (SystemFunction36)
                {
                    /*
                        if (RtlGenRandom(buffer, count))
                        return STATUS_SUCCESS;
                    */
                    if (SystemFunction36(buffer, count))
                        return STATUS_SUCCESS;
                }//end if (SystemFunction036)
                else
                {
                    if (count)
                    {
                        //manual random
                        PKUSER_SHARED_DATA k_random = reinterpret_cast<PKUSER_SHARED_DATA>(KUSER_SHARED_DATA);
                        UCHAR* k_r = reinterpret_cast<UCHAR*>(&k_random->InterruptTime);
                        k_r += 4; //shift to LO byte
                        do
                        {
                            *buffer++ = *k_r;
                            Sleep(2);
                        } while (--count);
                    }//end if (count)
                    
                }
            }//end  if(avd32)
        }//else  if (SystemFunction36)
    }

    FIXME("called with unsupported parameters, returning error\n");
    return STATUS_NOT_IMPLEMENTED;
}

/* ordered by class, keep in sync with enum alg_id */
static const struct
{
    const WCHAR* name;
    ULONG        CLASS;
    ULONG        object_length;
    ULONG        hash_length;
    ULONG        block_bits;
}
builtin_algorithms[] =
{
    {  BCRYPT_3DES_ALGORITHM,       BCRYPT_CIPHER_INTERFACE,                522,    0,    0 },
    {  BCRYPT_AES_ALGORITHM,        BCRYPT_CIPHER_INTERFACE,                654,    0,    0 },
    {  BCRYPT_SHA256_ALGORITHM,     BCRYPT_HASH_INTERFACE,                  286,   32,  512 },
    {  BCRYPT_SHA384_ALGORITHM,     BCRYPT_HASH_INTERFACE,                  382,   48, 1024 },
    {  BCRYPT_SHA512_ALGORITHM,     BCRYPT_HASH_INTERFACE,                  382,   64, 1024 },
    {  BCRYPT_SHA1_ALGORITHM,       BCRYPT_HASH_INTERFACE,                  278,   20,  512 },
    {  BCRYPT_MD5_ALGORITHM,        BCRYPT_HASH_INTERFACE,                  274,   16,  512 },
    {  BCRYPT_MD4_ALGORITHM,        BCRYPT_HASH_INTERFACE,                  270,   16,  512 },
    {  BCRYPT_MD2_ALGORITHM,        BCRYPT_HASH_INTERFACE,                  270,   16,  128 },
    {  BCRYPT_RSA_ALGORITHM,        BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE, 0,      0,    0 },
    {  BCRYPT_ECDH_P256_ALGORITHM,  BCRYPT_SECRET_AGREEMENT_INTERFACE,      0,      0,    0 },
    {  BCRYPT_ECDH_P384_ALGORITHM,  BCRYPT_SECRET_AGREEMENT_INTERFACE,      0,      0,    0 },
    {  BCRYPT_RSA_SIGN_ALGORITHM,   BCRYPT_SIGNATURE_INTERFACE,             0,      0,    0 },
    {  BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_SIGNATURE_INTERFACE,             0,      0,    0 },
    {  BCRYPT_ECDSA_P384_ALGORITHM, BCRYPT_SIGNATURE_INTERFACE,             0,      0,    0 },
    {  BCRYPT_DSA_ALGORITHM,        BCRYPT_SIGNATURE_INTERFACE,             0,      0,    0 },
    {  BCRYPT_RNG_ALGORITHM,        BCRYPT_RNG_INTERFACE,                   0,      0,    0 },
};

static BOOL match_operation_type(ULONG type, ULONG CLASS)
{
    if (!type) return TRUE;
    switch (CLASS)
    {
    case BCRYPT_CIPHER_INTERFACE:                return type & BCRYPT_CIPHER_OPERATION;
    case BCRYPT_HASH_INTERFACE:                  return type & BCRYPT_HASH_OPERATION;
    case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE: return type & BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION;
    case BCRYPT_SECRET_AGREEMENT_INTERFACE:      return type & BCRYPT_SECRET_AGREEMENT_OPERATION;
    case BCRYPT_SIGNATURE_INTERFACE:             return type & BCRYPT_SIGNATURE_OPERATION;
    case BCRYPT_RNG_INTERFACE:                   return type & BCRYPT_RNG_OPERATION;
    default: break;
    }
    return FALSE;
}

NTSTATUS WINAPI BCryptEnumAlgorithms(ULONG type, ULONG* ret_count, BCRYPT_ALGORITHM_IDENTIFIER** ret_list, ULONG flags)
{
    static const ULONG supported = BCRYPT_CIPHER_OPERATION | \
        BCRYPT_HASH_OPERATION | \
        BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION | \
        BCRYPT_SECRET_AGREEMENT_OPERATION | \
        BCRYPT_SIGNATURE_OPERATION | \
        BCRYPT_RNG_OPERATION;
    BCRYPT_ALGORITHM_IDENTIFIER* list;
    ULONG i, j, count = 0;

    TRACE("%#lx, %p, %p, %#lx\n", type, ret_count, ret_list, flags);

    if (!ret_count || !ret_list || (type & ~supported)) return STATUS_INVALID_PARAMETER;

    for (i = 0; i < ARRAYSIZE(builtin_algorithms); i++)
    {
        if (match_operation_type(type, builtin_algorithms[i].CLASS)) count++;
    }

    if (!(list = (BCRYPT_ALGORITHM_IDENTIFIER*)malloc(count * sizeof(*list)))) return STATUS_NO_MEMORY;

    for (i = 0, j = 0; i < ARRAYSIZE(builtin_algorithms); i++)
    {
        if (!match_operation_type(type, builtin_algorithms[i].CLASS)) continue;
        list[j].pszName = (WCHAR*)builtin_algorithms[i].name;
        list[j].dwClass = builtin_algorithms[i].CLASS;
        list[j].dwFlags = 0;
        j++;
    }

    *ret_count = count;
    *ret_list = list;
    return STATUS_SUCCESS;
}


struct algorithm2
{
    struct object   hdr;
    enum alg_id     id;
    enum chain_mode mode;
    unsigned        flags;
};

static const struct algorithm2 pseudo_algorithms[] =
{
    {{ MAGIC_ALG }, ALG_ID_MD2 },
    {{ MAGIC_ALG }, ALG_ID_MD4 },
    {{ MAGIC_ALG }, ALG_ID_MD5 },
    {{ MAGIC_ALG }, ALG_ID_SHA1 },
    {{ MAGIC_ALG }, ALG_ID_SHA256 },
    {{ MAGIC_ALG }, ALG_ID_SHA384 },
    {{ MAGIC_ALG }, ALG_ID_SHA512 },
    {{ 0 }}, /* RC4 */
    {{ MAGIC_ALG }, ALG_ID_RNG },
    {{ MAGIC_ALG }, ALG_ID_MD5, CHAIN_MODE_CBC, BCRYPT_ALG_HANDLE_HMAC_FLAG },
    {{ MAGIC_ALG }, ALG_ID_SHA1, CHAIN_MODE_CBC, BCRYPT_ALG_HANDLE_HMAC_FLAG },
    {{ MAGIC_ALG }, ALG_ID_SHA256, CHAIN_MODE_CBC, BCRYPT_ALG_HANDLE_HMAC_FLAG },
    {{ MAGIC_ALG }, ALG_ID_SHA384, CHAIN_MODE_CBC, BCRYPT_ALG_HANDLE_HMAC_FLAG },
    {{ MAGIC_ALG }, ALG_ID_SHA512, CHAIN_MODE_CBC, BCRYPT_ALG_HANDLE_HMAC_FLAG },
    {{ MAGIC_ALG }, ALG_ID_RSA },
    {{ 0 }}, /* ECDSA */
    {{ 0 }}, /* AES_CMAC */
    {{ 0 }}, /* AES_GMAC */
    {{ MAGIC_ALG }, ALG_ID_MD2, CHAIN_MODE_CBC, BCRYPT_ALG_HANDLE_HMAC_FLAG },
    {{ MAGIC_ALG }, ALG_ID_MD4, CHAIN_MODE_CBC, BCRYPT_ALG_HANDLE_HMAC_FLAG },
    {{ MAGIC_ALG }, ALG_ID_3DES, CHAIN_MODE_CBC },
    {{ MAGIC_ALG }, ALG_ID_3DES, CHAIN_MODE_ECB },
    {{ MAGIC_ALG }, ALG_ID_3DES, CHAIN_MODE_CFB },
    {{ 0 }}, /* 3DES_112_CBC */
    {{ 0 }}, /* 3DES_112_ECB */
    {{ 0 }}, /* 3DES_112_CFB */
    {{ MAGIC_ALG }, ALG_ID_AES, CHAIN_MODE_CBC },
    {{ MAGIC_ALG }, ALG_ID_AES, CHAIN_MODE_ECB },
    {{ MAGIC_ALG }, ALG_ID_AES, CHAIN_MODE_CFB },
    {{ MAGIC_ALG }, ALG_ID_AES, CHAIN_MODE_CCM },
    {{ MAGIC_ALG }, ALG_ID_AES, CHAIN_MODE_GCM },
    {{ 0 }}, /* DES_CBC */
    {{ 0 }}, /* DES_ECB */
    {{ 0 }}, /* DES_CFB */
    {{ 0 }}, /* DESX_CBC */
    {{ 0 }}, /* DESX_ECB */
    {{ 0 }}, /* DESX_CFB */
    {{ 0 }}, /* RC2_CBC */
    {{ 0 }}, /* RC2_ECB */
    {{ 0 }}, /* RC2_CFB */
    {{ 0 }}, /* DH */
    {{ 0 }}, /* ECDH */
    {{ MAGIC_ALG }, ALG_ID_ECDH_P256 },
    {{ MAGIC_ALG }, ALG_ID_ECDH_P384 },
    {{ 0 }}, /* ECDH_P512 */
    {{ MAGIC_ALG }, ALG_ID_DSA },
    {{ MAGIC_ALG }, ALG_ID_ECDSA_P256 },
    {{ MAGIC_ALG }, ALG_ID_ECDSA_P384 },
    {{ 0 }}, /* ECDSA_P512 */
    {{ MAGIC_ALG }, ALG_ID_RSA_SIGN },
};

/* Algorithm pseudo-handles are denoted by having the lowest bit set.
 * An aligned algorithm pointer will never have this bit set.
 */
static inline BOOL is_alg_pseudo_handle(BCRYPT_ALG_HANDLE handle)
{
    return (((ULONG_PTR)handle & 1) == 1);
}

static struct object* get_object(BCRYPT_HANDLE handle, ULONG magic)
{
    ULONG idx;

    if (!handle) return NULL;

    if (!is_alg_pseudo_handle(handle))
    {
        struct object* obj = (object*)handle;
        if (magic && obj->magic != magic) return NULL;
        return obj;
    }

    idx = (ULONG_PTR)handle >> 4;
    if (idx > ARRAYSIZE(pseudo_algorithms) || !pseudo_algorithms[idx].hdr.magic)
    {
        FIXME("pseudo-handle %p not supported\n", handle);
        return NULL;
    }
    return (struct object*)&pseudo_algorithms[idx];
}

static inline struct algorithm* get_alg_object(BCRYPT_ALG_HANDLE handle)
{
    return (struct algorithm*)get_object(handle, MAGIC_ALG);
}

static inline struct hash* get_hash_object(BCRYPT_HASH_HANDLE handle)
{
    return (struct hash*)get_object(handle, MAGIC_HASH);
}

static inline struct key* get_key_object(BCRYPT_KEY_HANDLE handle)
{
    return (struct key*)get_object(handle, MAGIC_KEY);
}

static inline struct secret* get_secret_object(BCRYPT_SECRET_HANDLE handle)
{
    return (struct secret*)get_object(handle, MAGIC_SECRET);
}


NTSTATUS WINAPI BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* handle, LPCWSTR id, LPCWSTR implementation, DWORD flags)
{
    struct algorithm* alg;
    enum alg_id alg_id;

    const DWORD supported_flags = BCRYPT_ALG_HANDLE_HMAC_FLAG;

    TRACE("%p, %s, %s, %08x\n", handle, wide_to_char(id), wide_to_char(implementation), flags);

    if (!handle || !id) return STATUS_INVALID_PARAMETER;
    if (flags & ~supported_flags)
    {
        FIXME("unsupported flags %08x\n", flags & ~supported_flags);
        return STATUS_NOT_IMPLEMENTED;
    }

    if (!wcscmp(id, BCRYPT_SHA1_ALGORITHM)) alg_id = ALG_ID_SHA1;
    else if (!wcscmp(id, BCRYPT_MD5_ALGORITHM)) alg_id = ALG_ID_MD5;
    else if (!wcscmp(id, BCRYPT_RNG_ALGORITHM)) alg_id = ALG_ID_RNG;
    else if (!wcscmp(id, BCRYPT_SHA256_ALGORITHM)) alg_id = ALG_ID_SHA256;
    else if (!wcscmp(id, BCRYPT_SHA384_ALGORITHM)) alg_id = ALG_ID_SHA384;
    else if (!wcscmp(id, BCRYPT_SHA512_ALGORITHM)) alg_id = ALG_ID_SHA512;
    else if (!wcscmp(id, BCRYPT_ECDSA_P256_ALGORITHM)) alg_id = ALG_ID_ECDSA_P256;
    else if (!wcscmp(id, BCRYPT_ECDSA_P384_ALGORITHM)) alg_id = ALG_ID_ECDSA_P384;
    else
    {
        FIXME("algorithm %s not supported\n", wide_to_char(id));
        return STATUS_NOT_IMPLEMENTED;
    }
    if (implementation && wcscmp(implementation, MS_PRIMITIVE_PROVIDER))
    {
        FIXME("implementation %s not supported\n", wide_to_char(implementation));
        return STATUS_NOT_IMPLEMENTED;
    }

    if (!(alg = (algorithm*)HeapAlloc(GetProcessHeap(), 0, sizeof(*alg)))) return STATUS_NO_MEMORY;
    alg->hdr.magic = MAGIC_ALG;
    alg->id = alg_id;
    alg->hmac = flags & BCRYPT_ALG_HANDLE_HMAC_FLAG;

    *handle = alg;
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE handle, DWORD flags)
{
    struct algorithm* alg = (algorithm*)handle;

    TRACE("%p, %08x\n", handle, flags);

    if (!alg || alg->hdr.magic != MAGIC_ALG) return STATUS_INVALID_HANDLE;
    HeapFree(GetProcessHeap(), 0, alg);
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptGetFipsAlgorithmMode(BOOLEAN* enabled)
{
    FIXME("%p - semi-stub\n", enabled);

    if (!enabled)
        return STATUS_INVALID_PARAMETER;

    *enabled = FALSE;
    return STATUS_SUCCESS;
}

#ifdef HAVE_COMMONCRYPTO_COMMONDIGEST_H
struct hash
{
    struct object hdr;
    enum alg_id   alg_id;
    BOOL hmac;
    union
    {
        CC_MD5_CTX    md5_ctx;
        CC_SHA1_CTX   sha1_ctx;
        CC_SHA256_CTX sha256_ctx;
        CC_SHA512_CTX sha512_ctx;
        CCHmacContext hmac_ctx;
    } u;
};

static NTSTATUS hash_init(struct hash* hash)
{
    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        CC_MD5_Init(&hash->u.md5_ctx);
        break;

    case ALG_ID_SHA1:
        CC_SHA1_Init(&hash->u.sha1_ctx);
        break;

    case ALG_ID_SHA256:
        CC_SHA256_Init(&hash->u.sha256_ctx);
        break;

    case ALG_ID_SHA384:
        CC_SHA384_Init(&hash->u.sha512_ctx);
        break;

    case ALG_ID_SHA512:
        CC_SHA512_Init(&hash->u.sha512_ctx);
        break;

    default:
        ERR("unhandled id %u\n", hash->alg_id);
        return STATUS_NOT_IMPLEMENTED;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS hmac_init(struct hash* hash, UCHAR* key, ULONG key_size)
{
    CCHmacAlgorithm cc_algorithm;
    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        cc_algorithm = kCCHmacAlgMD5;
        break;

    case ALG_ID_SHA1:
        cc_algorithm = kCCHmacAlgSHA1;
        break;

    case ALG_ID_SHA256:
        cc_algorithm = kCCHmacAlgSHA256;
        break;

    case ALG_ID_SHA384:
        cc_algorithm = kCCHmacAlgSHA384;
        break;

    case ALG_ID_SHA512:
        cc_algorithm = kCCHmacAlgSHA512;
        break;

    default:
        ERR("unhandled id %u\n", hash->alg_id);
        return STATUS_NOT_IMPLEMENTED;
    }

    CCHmacInit(&hash->u.hmac_ctx, cc_algorithm, key, key_size);
    return STATUS_SUCCESS;
}


static NTSTATUS hash_update(struct hash* hash, UCHAR* input, ULONG size)
{
    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        CC_MD5_Update(&hash->u.md5_ctx, input, size);
        break;

    case ALG_ID_SHA1:
        CC_SHA1_Update(&hash->u.sha1_ctx, input, size);
        break;

    case ALG_ID_SHA256:
        CC_SHA256_Update(&hash->u.sha256_ctx, input, size);
        break;

    case ALG_ID_SHA384:
        CC_SHA384_Update(&hash->u.sha512_ctx, input, size);
        break;

    case ALG_ID_SHA512:
        CC_SHA512_Update(&hash->u.sha512_ctx, input, size);
        break;

    default:
        ERR("unhandled id %u\n", hash->alg_id);
        return STATUS_NOT_IMPLEMENTED;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS hmac_update(struct hash* hash, UCHAR* input, ULONG size)
{
    CCHmacUpdate(&hash->u.hmac_ctx, input, size);
    return STATUS_SUCCESS;
}

static NTSTATUS hash_finish(struct hash* hash, UCHAR* output, ULONG size)
{
    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        CC_MD5_Final(output, &hash->u.md5_ctx);
        break;

    case ALG_ID_SHA1:
        CC_SHA1_Final(output, &hash->u.sha1_ctx);
        break;

    case ALG_ID_SHA256:
        CC_SHA256_Final(output, &hash->u.sha256_ctx);
        break;

    case ALG_ID_SHA384:
        CC_SHA384_Final(output, &hash->u.sha512_ctx);
        break;

    case ALG_ID_SHA512:
        CC_SHA512_Final(output, &hash->u.sha512_ctx);
        break;

    default:
        ERR("unhandled id %u\n", hash->alg_id);
        break;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS hmac_finish(struct hash* hash, UCHAR* output, ULONG size)
{
    CCHmacFinal(&hash->u.hmac_ctx, output);

    return STATUS_SUCCESS;
}
#elif defined(HAVE_GNUTLS_HASH)
struct hash
{
    struct object    hdr;
    enum alg_id      alg_id;
    BOOL hmac;
    union
    {
        gnutls_hash_hd_t hash_handle;
        gnutls_hmac_hd_t hmac_handle;
    } u;
};

static NTSTATUS hash_init(struct hash* hash)
{
    gnutls_digest_algorithm_t alg;

    if (!libgnutls_handle) return STATUS_INTERNAL_ERROR;

    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        alg = GNUTLS_DIG_MD5;
        break;
    case ALG_ID_SHA1:
        alg = GNUTLS_DIG_SHA1;
        break;

    case ALG_ID_SHA256:
        alg = GNUTLS_DIG_SHA256;
        break;

    case ALG_ID_SHA384:
        alg = GNUTLS_DIG_SHA384;
        break;

    case ALG_ID_SHA512:
        alg = GNUTLS_DIG_SHA512;
        break;

    default:
        ERR("unhandled id %u\n", hash->alg_id);
        return STATUS_NOT_IMPLEMENTED;
    }

    if (pgnutls_hash_init(&hash->u.hash_handle, alg)) return STATUS_INTERNAL_ERROR;
    return STATUS_SUCCESS;
}

static NTSTATUS hmac_init(struct hash* hash, UCHAR* key, ULONG key_size)
{
    gnutls_mac_algorithm_t alg;

    if (!libgnutls_handle) return STATUS_INTERNAL_ERROR;

    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        alg = GNUTLS_MAC_MD5;
        break;
    case ALG_ID_SHA1:
        alg = GNUTLS_MAC_SHA1;
        break;

    case ALG_ID_SHA256:
        alg = GNUTLS_MAC_SHA256;
        break;

    case ALG_ID_SHA384:
        alg = GNUTLS_MAC_SHA384;
        break;

    case ALG_ID_SHA512:
        alg = GNUTLS_MAC_SHA512;
        break;

    default:
        ERR("unhandled id %u\n", hash->alg_id);
        return STATUS_NOT_IMPLEMENTED;
    }

    if (pgnutls_hmac_init(&hash->u.hmac_handle, alg, key, key_size)) return STATUS_INTERNAL_ERROR;
    return STATUS_SUCCESS;
}

static NTSTATUS hash_update(struct hash* hash, UCHAR* input, ULONG size)
{
    if (pgnutls_hash(hash->u.hash_handle, input, size)) return STATUS_INTERNAL_ERROR;
    return STATUS_SUCCESS;
}

static NTSTATUS hmac_update(struct hash* hash, UCHAR* input, ULONG size)
{
    if (pgnutls_hmac(hash->u.hmac_handle, input, size)) return STATUS_INTERNAL_ERROR;
    return STATUS_SUCCESS;
}

static NTSTATUS hash_finish(struct hash* hash, UCHAR* output, ULONG size)
{
    pgnutls_hash_deinit(hash->u.hash_handle, output);
    return STATUS_SUCCESS;
}

static NTSTATUS hmac_finish(struct hash* hash, UCHAR* output, ULONG size)
{
    pgnutls_hmac_deinit(hash->u.hmac_handle, output);
    return STATUS_SUCCESS;
}
#elif defined(SONAME_LIBMBEDTLS)
struct hash
{
    struct object hdr;
    BOOL hmac;
    enum alg_id   alg_id;
    union
    {
        mbedtls_md5_context    md5_ctx;
        mbedtls_sha1_context   sha1_ctx;
        mbedtls_sha256_context sha256_ctx;
        mbedtls_sha512_context sha512_ctx;
        mbedtls_md_context_t   hmac_ctx;
    } u;
};

static NTSTATUS hash_init(struct hash* hash)
{

    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        mbedtls_md5_init(&hash->u.md5_ctx);
        mbedtls_md5_starts(&hash->u.md5_ctx);
        break;

    case ALG_ID_SHA1:
        mbedtls_sha1_init(&hash->u.sha1_ctx);
        mbedtls_sha1_starts(&hash->u.sha1_ctx);
        break;

    case ALG_ID_SHA256:
        mbedtls_sha256_init(&hash->u.sha256_ctx);
        mbedtls_sha256_starts(&hash->u.sha256_ctx, FALSE);
        break;

    case ALG_ID_SHA384:
    case ALG_ID_SHA512:
        mbedtls_sha512_init(&hash->u.sha512_ctx);
        mbedtls_sha512_starts(&hash->u.sha512_ctx, hash->alg_id == ALG_ID_SHA384);
        break;

    default:
        ERR("unhandled id %u\n", hash->alg_id);
        return STATUS_NOT_IMPLEMENTED;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS hmac_init(struct hash* hash, UCHAR* key, ULONG key_size)
{
    const mbedtls_md_info_t* md_info;
    mbedtls_md_type_t md_type;
    int ret;

    mbedtls_md_init(&hash->u.hmac_ctx);
    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        md_type = MBEDTLS_MD_MD5;
        break;

    case ALG_ID_SHA1:
        md_type = MBEDTLS_MD_SHA1;
        break;

    case ALG_ID_SHA256:
        md_type = MBEDTLS_MD_SHA256;
        break;

    case ALG_ID_SHA384:
        md_type = MBEDTLS_MD_SHA384;
        break;

    case ALG_ID_SHA512:
        md_type = MBEDTLS_MD_SHA512;
        break;

    default:
        ERR("unhandled id %u\n", hash->alg_id);
        return STATUS_NOT_IMPLEMENTED;
    }
    if ((md_info = mbedtls_md_info_from_type(md_type)) == NULL)
    {
        mbedtls_md_free(&hash->u.hmac_ctx);
        return STATUS_INTERNAL_ERROR;
    }

    if ((ret = mbedtls_md_setup(&hash->u.hmac_ctx, md_info, 1)) != 0)
    {
        mbedtls_md_free(&hash->u.hmac_ctx);
        return STATUS_INTERNAL_ERROR;
    }

    mbedtls_md_hmac_starts(&hash->u.hmac_ctx, key, key_size);

    return STATUS_SUCCESS;
}

static NTSTATUS hash_update(struct hash* hash, UCHAR* input, ULONG size)
{

    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        mbedtls_md5_update(&hash->u.md5_ctx, input, size);
        break;

    case ALG_ID_SHA1:
        mbedtls_sha1_update(&hash->u.sha1_ctx, input, size);
        break;

    case ALG_ID_SHA256:
        mbedtls_sha256_update(&hash->u.sha256_ctx, input, size);
        break;

    case ALG_ID_SHA384:
    case ALG_ID_SHA512:
        mbedtls_sha512_update(&hash->u.sha512_ctx, input, size);
        break;

    default:
        ERR("unhandled id %u\n", hash->alg_id);
        return STATUS_NOT_IMPLEMENTED;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS hmac_update(struct hash* hash, UCHAR* input, ULONG size)
{

    mbedtls_md_update(&hash->u.hmac_ctx, input, size);

    return STATUS_SUCCESS;
}

static NTSTATUS hash_finish(struct hash* hash, UCHAR* output, ULONG size)
{

    switch (hash->alg_id)
    {
    case ALG_ID_MD5:
        mbedtls_md5_finish(&hash->u.md5_ctx, output);
        mbedtls_md5_free(&hash->u.md5_ctx);
        break;

    case ALG_ID_SHA1:
        mbedtls_sha1_finish(&hash->u.sha1_ctx, output);
        mbedtls_sha1_free(&hash->u.sha1_ctx);
        break;

    case ALG_ID_SHA256:
        mbedtls_sha256_finish(&hash->u.sha256_ctx, output);
        mbedtls_sha256_free(&hash->u.sha256_ctx);
        break;

    case ALG_ID_SHA384:
    case ALG_ID_SHA512:
        mbedtls_sha512_finish(&hash->u.sha512_ctx, output);
        mbedtls_sha512_free(&hash->u.sha512_ctx);
        break;

    default:
        ERR("unhandled id %u\n", hash->alg_id);
        return STATUS_NOT_IMPLEMENTED;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS hmac_finish(struct hash* hash, UCHAR* output, ULONG size)
{

    mbedtls_md_hmac_finish(&hash->u.hmac_ctx, output);
    mbedtls_md_free(&hash->u.hmac_ctx);

    return STATUS_SUCCESS;
}
#endif

#define OBJECT_LENGTH_MD5       274
#define OBJECT_LENGTH_SHA1      278
#define OBJECT_LENGTH_SHA256    286
#define OBJECT_LENGTH_SHA384    382
#define OBJECT_LENGTH_SHA512    382

static NTSTATUS generic_alg_property(enum alg_id id, const WCHAR* prop, UCHAR* buf, ULONG size, ULONG* ret_size)
{
    if (!wcscmp(prop, BCRYPT_HASH_LENGTH))
    {
        *ret_size = sizeof(ULONG);
        if (size < sizeof(ULONG))
            return STATUS_BUFFER_TOO_SMALL;
        if (buf)
            *(ULONG*)buf = alg_props[id].hash_length;
        return STATUS_SUCCESS;
    }

    if (!wcscmp(prop, BCRYPT_ALGORITHM_NAME))
    {
        *ret_size = (wcslen(alg_props[id].alg_name) + 1) * sizeof(WCHAR);
        if (size < *ret_size)
            return STATUS_BUFFER_TOO_SMALL;
        if (buf)
            memcpy(buf, alg_props[id].alg_name, *ret_size);
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS get_alg_property(enum alg_id id, const WCHAR* prop, UCHAR* buf, ULONG size, ULONG* ret_size)
{
    NTSTATUS status;
    ULONG value;

    status = generic_alg_property(id, prop, buf, size, ret_size);
    if (status != STATUS_NOT_IMPLEMENTED)
        return status;
    
    switch (id)
    {
    case ALG_ID_MD5:
        if (!wcscmp(prop, BCRYPT_OBJECT_LENGTH))
        {
            value = OBJECT_LENGTH_MD5;
            break;
        }
        FIXME("unsupported md5 algorithm property %s\n", wide_to_char(prop));
        return STATUS_NOT_IMPLEMENTED;

    case ALG_ID_RNG:
        if (!wcscmp(prop, BCRYPT_OBJECT_LENGTH)) return STATUS_NOT_SUPPORTED;
        FIXME("unsupported rng algorithm property %s\n", wide_to_char(prop));
        return STATUS_NOT_IMPLEMENTED;

    case ALG_ID_SHA1:
        if (!wcscmp(prop, BCRYPT_OBJECT_LENGTH))
        {
            value = OBJECT_LENGTH_SHA1;
            break;
        }
        FIXME("unsupported sha1 algorithm property %s\n", wide_to_char(prop));
        return STATUS_NOT_IMPLEMENTED;

    case ALG_ID_SHA256:
        if (!wcscmp(prop, BCRYPT_OBJECT_LENGTH))
        {
            value = OBJECT_LENGTH_SHA256;
            break;
        }
        FIXME("unsupported sha256 algorithm property %s\n", wide_to_char(prop));
        return STATUS_NOT_IMPLEMENTED;

    case ALG_ID_SHA384:
        if (!wcscmp(prop, BCRYPT_OBJECT_LENGTH))
        {
            value = OBJECT_LENGTH_SHA384;
            break;
        }
        FIXME("unsupported sha384 algorithm property %s\n", wide_to_char(prop));
        return STATUS_NOT_IMPLEMENTED;

    case ALG_ID_SHA512:
        if (!wcscmp(prop, BCRYPT_OBJECT_LENGTH))
        {
            value = OBJECT_LENGTH_SHA512;
            break;
        }
        FIXME("unsupported sha512 algorithm property %s\n", wide_to_char(prop));
        return STATUS_NOT_IMPLEMENTED;

    default:
        FIXME("unsupported algorithm %u\n", id);
        return STATUS_NOT_IMPLEMENTED;
    }

    if (size < sizeof(ULONG))
    {
        *ret_size = sizeof(ULONG);
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (buf) *(ULONG*)buf = value;
    *ret_size = sizeof(ULONG);

    return STATUS_SUCCESS;
}

static NTSTATUS get_hash_property(enum alg_id id, const WCHAR* prop, UCHAR* buf, ULONG size, ULONG* ret_size)
{
    NTSTATUS status;

    status = generic_alg_property(id, prop, buf, size, ret_size);
    if (status == STATUS_NOT_IMPLEMENTED)
        FIXME("unsupported property %s\n", wide_to_char(prop));
    return status;
}

NTSTATUS WINAPI BCryptGetProperty(BCRYPT_HANDLE handle, LPCWSTR prop, UCHAR* buffer, ULONG count, ULONG* res, ULONG flags)
{
    struct object* object0 = (object*)handle;

    TRACE("%p, %s, %p, %u, %p, %08x\n", handle, wide_to_char(prop), buffer, count, res, flags);

    if (!object0) return STATUS_INVALID_HANDLE;
    if (!prop || !res) return STATUS_INVALID_PARAMETER;

    switch (object0->magic)
    {
    case MAGIC_ALG:
    {
        const struct algorithm* alg = (const struct algorithm*)object0;
        return get_alg_property(alg->id, prop, buffer, count, res);
    }
    case MAGIC_HASH:
    {
        const struct hash* hash = (const struct hash*)object0;
        return get_hash_property(hash->alg_id, prop, buffer, count, res);
    }
    default:
        WARN("unknown magic %08x\n", object0->magic);
        return STATUS_INVALID_HANDLE;
    }
}

NTSTATUS WINAPI BCryptCreateHash(BCRYPT_ALG_HANDLE algorithm1, BCRYPT_HASH_HANDLE* handle, UCHAR* object, ULONG objectlen,
    UCHAR* secret, ULONG secretlen, ULONG flags)
{
    struct algorithm* alg = (algorithm*)algorithm1;
    struct hash* hash0;
    NTSTATUS status;

    TRACE("%p, %p, %p, %u, %p, %u, %08x - stub\n", algorithm1, handle, object, objectlen,
        secret, secretlen, flags);
    if (flags)
    {
        FIXME("unimplemented flags %08x\n", flags);
        return STATUS_NOT_IMPLEMENTED;
    }

    if (!alg || alg->hdr.magic != MAGIC_ALG) return STATUS_INVALID_HANDLE;
    if (object) FIXME("ignoring object buffer\n");

    if (!(hash0 = (hash*)HeapAlloc(GetProcessHeap(), 0, sizeof(hash)))) return STATUS_NO_MEMORY;
    hash0->hdr.magic = MAGIC_HASH;
    hash0->alg_id = alg->id;
    hash0->hmac = alg->hmac;

    if (hash0->hmac)
    {
        status = hmac_init(hash0, secret, secretlen);
    }
    else
    {
        status = hash_init(hash0);
    }

    if (status != STATUS_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, hash0);
        return status;
    }

    *handle = hash0;
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptDestroyHash(BCRYPT_HASH_HANDLE handle)
{
    struct hash* hash0 =(hash*)handle;

    TRACE("%p\n", handle);

    if (!hash0 || hash0->hdr.magic != MAGIC_HASH) return STATUS_INVALID_HANDLE;
    HeapFree(GetProcessHeap(), 0, hash0);
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptHashData(BCRYPT_HASH_HANDLE handle, UCHAR* input, ULONG size, ULONG flags)
{
    struct hash* hash0 = (hash*)handle;

    TRACE("%p, %p, %u, %08x\n", handle, input, size, flags);

    if (!hash0 || hash0->hdr.magic != MAGIC_HASH) return STATUS_INVALID_HANDLE;
    if (!input) return STATUS_SUCCESS;

    if (hash0->hmac)
    {
        return hmac_update(hash0, input, size);
    }
    else
    {
        return hash_update(hash0, input, size);
    }
}

NTSTATUS WINAPI BCryptFinishHash(BCRYPT_HASH_HANDLE handle, UCHAR* output, ULONG size, ULONG flags)
{
    struct hash* hash0 = (hash*)handle;

    TRACE("%p, %p, %u, %08x\n", handle, output, size, flags);

    if (!hash0 || hash0->hdr.magic != MAGIC_HASH) return STATUS_INVALID_HANDLE;
    if (!output) return STATUS_INVALID_PARAMETER;

    if (hash0->hmac)
    {
        return hmac_finish(hash0, output, size);
    }
    else
    {
        return hash_finish(hash0, output, size);
    }
}

NTSTATUS WINAPI BCryptHash(BCRYPT_ALG_HANDLE algorithm, UCHAR* secret, ULONG secretlen,
    UCHAR* input, ULONG inputlen, UCHAR* output, ULONG outputlen)
{
    NTSTATUS status;
    BCRYPT_HASH_HANDLE handle;

    TRACE("%p, %p, %u, %p, %u, %p, %u\n", algorithm, secret, secretlen,
        input, inputlen, output, outputlen);

    status = BCryptCreateHash(algorithm, &handle, NULL, 0, secret, secretlen, 0);
    if (status != STATUS_SUCCESS)
    {
        return status;
    }

    status = BCryptHashData(handle, input, inputlen, 0);
    if (status != STATUS_SUCCESS)
    {
        BCryptDestroyHash(handle);
        return status;
    }

    status = BCryptFinishHash(handle, output, outputlen, 0);
    if (status != STATUS_SUCCESS)
    {
        BCryptDestroyHash(handle);
        return status;
    }

    return BCryptDestroyHash(handle);
}

NTSTATUS WINAPI BCryptDuplicateKey(
    BCRYPT_KEY_HANDLE hKey,
    BCRYPT_KEY_HANDLE* phNewKey,
    PUCHAR            pbKeyObject,
    ULONG             cbKeyObject,
    ULONG             dwFlags)
{
    return STATUS_SUCCESS;
}
NTSTATUS WINAPI BCryptEnumContextFunctionProviders(
    ULONG                             dwTable,
    LPCWSTR                           pszContext,
    ULONG                             dwInterface,
    LPCWSTR                           pszFunction,
    ULONG* pcbBuffer,
    PCRYPT_CONTEXT_FUNCTION_PROVIDERS* ppBuffer
)
{
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptEnumContexts(
    ULONG           dwTable,
    ULONG* pcbBuffer,
    PCRYPT_CONTEXTS* ppBuffer
) 
{
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptRegisterConfigChangeNotify(
    PVOID* pEvent
)
{
    return STATUS_SUCCESS;

}

NTSTATUS WINAPI BCryptSecretAgreement(
    BCRYPT_KEY_HANDLE    hPrivKey,
    BCRYPT_KEY_HANDLE    hPubKey,
    BCRYPT_SECRET_HANDLE* phAgreedSecret,
    ULONG                dwFlags
)
{
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptResolveProviders(
    LPCWSTR              pszContext,
    ULONG                dwInterface,
    LPCWSTR              pszFunction,
    LPCWSTR              pszProvider,
    ULONG                dwMode,
    ULONG                dwFlags,
    ULONG* pcbBuffer,
    PCRYPT_PROVIDER_REFS* ppBuffer
)
{
    return STATUS_SUCCESS;
}

////////////////////////////////
static BOOL key_is_symmetric(struct key* key)
{
    return builtin_algorithms[key->alg_id].CLASS == BCRYPT_CIPHER_INTERFACE;
}

NTSTATUS WINAPI BCryptEncrypt(
    BCRYPT_KEY_HANDLE hKey,
    PUCHAR pbInput,
    ULONG cbInput,
    void* pPaddingInfo,
    PUCHAR pbIV,
    ULONG cbIV,
    PUCHAR pbOutput,
    ULONG cbOutput,
    ULONG* pcbResult,
    ULONG dwFlags)
{

    struct key* key = get_key_object(hKey);

    NTSTATUS ret;


    if (!key) return STATUS_INVALID_HANDLE;

    if (key_is_symmetric(key))
    {
        if (dwFlags & ~BCRYPT_BLOCK_PADDING)
        {
            FIXME("flags %#lx not implemented\n", dwFlags);
            return STATUS_NOT_IMPLEMENTED;
        }
        EnterCriticalSection(&key->u.s.cs);
      //  ret = key_symmetric_encrypt(key, input, input_len, padding, iv, iv_len, output, output_len, ret_len, flags);
        LeaveCriticalSection(&key->u.s.cs);
    }
    else
    {
        if (dwFlags & BCRYPT_PAD_NONE || dwFlags & BCRYPT_PAD_OAEP)
        {
            FIXME("flags %#lx not implemented\n", dwFlags);
            return STATUS_NOT_IMPLEMENTED;
        }
      
    
    }
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptDecrypt(
    BCRYPT_KEY_HANDLE hKey,
    PUCHAR pbInput,
    ULONG cbInput,
    void* pPaddingInfo,
    PUCHAR pbIV,
    ULONG cbIV,
    PUCHAR pbOutput,
    ULONG cbOutput,
    ULONG* pcbResult,
    ULONG dwFlags)
{
    struct key* key = get_key_object(hKey);

    if (!key) return STATUS_INVALID_HANDLE;

    if (key_is_symmetric(key))
    {
        if (dwFlags & ~BCRYPT_BLOCK_PADDING)
        {
            FIXME("flags %#lx not supported\n", dwFlags);
            return STATUS_NOT_IMPLEMENTED;
        }

        EnterCriticalSection(&key->u.s.cs);
      //  ret = key_symmetric_decrypt(key, input, input_len, padding, iv, iv_len, output, output_len, ret_len, flags);
        LeaveCriticalSection(&key->u.s.cs);
    }
    else
    {
        if (dwFlags & BCRYPT_PAD_NONE || dwFlags & BCRYPT_PAD_OAEP)
        {
            FIXME("flags %#lx not implemented\n", dwFlags);
            return STATUS_NOT_IMPLEMENTED;
        }
    }

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptDestroyKey(BCRYPT_KEY_HANDLE hKey)
{

    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptDuplicateHash(
    BCRYPT_HASH_HANDLE hHash,
    BCRYPT_HASH_HANDLE* phNewHash,
    PUCHAR pbHashObject,
    ULONG cbHashObject,
    ULONG dwFlags)
{
    struct hash* hash_orig = get_hash_object(hHash);
    struct hash* hash_copy;


    if (!hash_orig) return STATUS_INVALID_HANDLE;
    if (!phNewHash) return STATUS_INVALID_PARAMETER;
    if (pbHashObject) FIXME("ignoring object buffer\n");

    if (!(hash_copy = (hash*)malloc(sizeof(*hash_copy)))) return STATUS_NO_MEMORY;
    /*
    memcpy(hash_copy, hash_orig, sizeof(*hash_orig));
    if (hash_orig->secret && !(hash_copy->secret = malloc(hash_orig->secret_len)))
    {
        free(hash_copy);
        return STATUS_NO_MEMORY;
    }
    memcpy(hash_copy->secret, hash_orig->secret, hash_orig->secret_len);
    */
    *phNewHash = hash_copy;
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptGenerateSymmetricKey(
    BCRYPT_ALG_HANDLE hAlgorithm,
    BCRYPT_KEY_HANDLE* phKey,
    PUCHAR pbKeyObject,
    ULONG cbKeyObject,
    PUCHAR pbSecret,
    ULONG cbSecret,
    ULONG dwFlags)
{

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptImportKeyPair(
    BCRYPT_ALG_HANDLE hAlgorithm,
    BCRYPT_KEY_HANDLE hImportKey,
    LPCWSTR pszBlobType,
    BCRYPT_KEY_HANDLE* phKey,
    PUCHAR pbInput,
    ULONG cbInput,
    ULONG dwFlags)
{
    
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptSetProperty(
    BCRYPT_HANDLE hObject,
    LPCWSTR pszProperty,
    PUCHAR pbInput,
    ULONG cbInput,
    ULONG dwFlags)
{

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptVerifySignature(
    BCRYPT_KEY_HANDLE hKey,
    void* pPaddingInfo,
    PUCHAR pbHash,
    ULONG cbHash,
    PUCHAR pbSignature,
    ULONG cbSignature,
    ULONG dwFlags)
{

    return STATUS_NOT_IMPLEMENTED;
}
static void destroy_object(struct object* obj)
{
    obj->magic = 0;
    free(obj);
}

NTSTATUS WINAPI BCryptDestroySecret(BCRYPT_SECRET_HANDLE handle)
{
    struct secret* secret = get_secret_object(handle);

    FIXME("%p\n", handle);

    if (!secret) return STATUS_INVALID_HANDLE;
    destroy_object(&secret->hdr);
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptDeriveKey(BCRYPT_SECRET_HANDLE handle, const WCHAR* kdf, void* parameter,
    UCHAR* derived, ULONG derived_size, ULONG* result, ULONG flags)
{
    struct secret* secret = get_secret_object(handle);

    FIXME("%p, %s, %p, %p, %lu, %p, %#lx\n", secret, (kdf), parameter, derived, derived_size, result, flags);

    if (!secret) return STATUS_INVALID_HANDLE;
    if (!kdf) return STATUS_INVALID_PARAMETER;

    return STATUS_INTERNAL_ERROR;
}

NTSTATUS WINAPI BCryptAddContextFunction(ULONG table, const WCHAR* ctx, ULONG iface, const WCHAR* func, ULONG pos)
{
    FIXME("%#lx, %s, %#lx, %s, %lu: stub\n", table, (ctx), iface, (func), pos);
    return STATUS_SUCCESS;
}


NTSTATUS WINAPI BCryptAddContextFunctionProvider(ULONG table, const WCHAR* ctx, ULONG iface, const WCHAR* func,
    const WCHAR* provider, ULONG pos)
{
    FIXME("%#lx, %s, %#lx, %s, %s, %lu: stub\n", table, (ctx), iface, (func),
        (provider), pos);
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptRemoveContextFunction(ULONG table, const WCHAR* ctx, ULONG iface, const WCHAR* func)
{
    FIXME("%#lx, %s, %#lx, %s: stub\n", table, (ctx), iface, (func));
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptRemoveContextFunctionProvider(ULONG table, const WCHAR* ctx, ULONG iface, const WCHAR* func,
    const WCHAR* provider)
{
    FIXME("%#lx, %s, %#lx, %s, %s: stub\n", table, (ctx), iface, (func), (provider));
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptEnumContextFunctions(ULONG table, const WCHAR* ctx, ULONG iface, ULONG* buflen,
    CRYPT_CONTEXT_FUNCTIONS** buffer)
{
    FIXME("%#lx, %s, %#lx, %p, %p\n", table, (ctx), iface, buflen, buffer);
    return STATUS_NOT_IMPLEMENTED;
}

void WINAPI BCryptFreeBuffer(void* buffer)
{
    free(buffer);
}

NTSTATUS WINAPI BCryptRegisterProvider(const WCHAR* provider, ULONG flags, CRYPT_PROVIDER_REG* reg)
{
    FIXME("%s, %#lx, %p: stub\n", (provider), flags, reg);
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptUnregisterProvider(const WCHAR* provider)
{
    FIXME("%s: stub\n", (provider));
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptSetAuditingInterface()
{
    HANDLE TokenHandle = 0;

    NTSTATUS LastError = STATUS_SUCCESS;;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &TokenHandle))
    {
        if (GetLastError() > 0)
            LastError = GetLastError() | 0xC0070000;
        else
            LastError = GetLastError();

        if (TokenHandle)
            CloseHandle(TokenHandle);
            return LastError;
       }//end if (!OpenProcessToken

    BOOL pfResult = false;
    PRIVILEGE_SET RequiredPrivileges;
    LUID lu;
    lu.HighPart = 0;
    lu.LowPart = 7;
    memset(&RequiredPrivileges, 0, sizeof(RequiredPrivileges));
    RequiredPrivileges.Control = 0;
    RequiredPrivileges.Privilege[0].Attributes = 0;
    RequiredPrivileges.Privilege[0].Luid = lu;
    if (!PrivilegeCheck(TokenHandle, &RequiredPrivileges, &pfResult))
    {
        if (GetLastError() > 0)
            LastError = GetLastError() | 0xC0070000;
        else
            LastError = GetLastError();

        if (TokenHandle)
            CloseHandle(TokenHandle);
        return LastError;
    }

    if (pfResult)
    {
        LastError = STATUS_SUCCESS;
    }

    return LastError;
}

NTSTATUS WINAPI BCryptUnregisterConfigChangeNotify(HANDLE hEvent)
{
    GetCurrentProcess();

    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptConfigureContext(ULONG dwTable, LPCWSTR pszContext, PCRYPT_CONTEXT_CONFIG pConfig)
{
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptConfigureContextFunction(
    ULONG dwTable,
    LPCWSTR pszContext,
    ULONG dwInterface,
    LPCWSTR pszFunction,
    PCRYPT_CONTEXT_FUNCTION_CONFIG pConfig)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptCreateContext(ULONG dwTable, LPCWSTR pszContext, PCRYPT_CONTEXT_CONFIG pConfig)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptCreateMultiHash(
     BCRYPT_ALG_HANDLE  hAlgorithm,
        BCRYPT_HASH_HANDLE* phHash,
       ULONG              nHashes,
      PUCHAR             pbHashObject,
         ULONG              cbHashObject,
        PUCHAR             pbSecret,
        ULONG              cbSecret,
         ULONG              dwFlags
)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptDeleteContext(ULONG   dwTable, LPCWSTR pszContext)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptDeriveKeyCapi(
    BCRYPT_HASH_HANDLE hHash,
    BCRYPT_ALG_HANDLE  hTargetAlg,
    PUCHAR             pbDerivedKey,
    ULONG              cbDerivedKey,
    ULONG              dwFlags
)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptDeriveKeyPBKDF2(
    BCRYPT_ALG_HANDLE hPrf,
    PUCHAR            pbPassword,
    ULONG             cbPassword,
    PUCHAR            pbSalt,
    ULONG             cbSalt,
    ULONGLONG         cIterations,
    PUCHAR            pbDerivedKey,
    ULONG             cbDerivedKey,
    ULONG             dwFlags
)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptEnumProviders(
    LPCWSTR              pszAlgId,
    ULONG* pImplCount,
    BCRYPT_PROVIDER_NAME** ppImplList,
    ULONG                dwFlags
)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptEnumRegisteredProviders(
    ULONG* pcbBuffer,
    PCRYPT_PROVIDERS* ppBuffer
)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptExportKey(
    BCRYPT_KEY_HANDLE hKey,
    BCRYPT_KEY_HANDLE hExportKey,
    LPCWSTR           pszBlobType,
    PUCHAR            pbOutput,
    ULONG             cbOutput,
    ULONG* pcbResult,
    ULONG             dwFlags
)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptFinalizeKeyPair(
    BCRYPT_KEY_HANDLE hKey,
    ULONG             dwFlags
)
{
    return STATUS_NOT_IMPLEMENTED;

}

NTSTATUS WINAPI BCryptGenerateKeyPair(
    BCRYPT_ALG_HANDLE hAlgorithm,
    BCRYPT_KEY_HANDLE* phKey,
    ULONG             dwLength,
    ULONG             dwFlags
)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptImportKey(
    BCRYPT_ALG_HANDLE hAlgorithm,
    BCRYPT_KEY_HANDLE hImportKey,
    LPCWSTR           pszBlobType,
    BCRYPT_KEY_HANDLE* phKey,
    PUCHAR            pbKeyObject,
    ULONG             cbKeyObject,
    PUCHAR            pbInput,
    ULONG             cbInput,
    ULONG             dwFlags
)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptKeyDerivation(
    BCRYPT_KEY_HANDLE hKey,
    BCryptBufferDesc* pParameterList,
    PUCHAR            pbDerivedKey,
    ULONG             cbDerivedKey,
    ULONG* pcbResult,
    ULONG             dwFlags
)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptProcessMultiOperations(
    BCRYPT_HANDLE               hObject,
    BCRYPT_MULTI_OPERATION_TYPE operationType,
    PVOID                       pOperations,
    ULONG                       cbOperations,
    ULONG                       dwFlags
)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptQueryContextConfiguration(
    ULONG                 dwTable,
    LPCWSTR               pszContext,
    ULONG* pcbBuffer,
    PCRYPT_CONTEXT_CONFIG* ppBuffer
)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptQueryContextFunctionConfiguration(
    ULONG                          dwTable,
    LPCWSTR                        pszContext,
    ULONG                          dwInterface,
    LPCWSTR                        pszFunction,
    ULONG* pcbBuffer,
    PCRYPT_CONTEXT_FUNCTION_CONFIG* ppBuffer
)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptQueryContextFunctionProperty(
    ULONG   dwTable,
    LPCWSTR pszContext,
    ULONG   dwInterface,
    LPCWSTR pszFunction,
    LPCWSTR pszProperty,
    ULONG* pcbValue,
    PUCHAR* ppbValue
)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptQueryProviderRegistration(
    LPCWSTR             pszProvider,
    ULONG               dwMode,
    ULONG               dwInterface,
    ULONG* pcbBuffer,
    PCRYPT_PROVIDER_REG* ppBuffer
)
{
    return STATUS_NOT_IMPLEMENTED;
}



NTSTATUS WINAPI BCryptSetContextFunctionProperty(
    ULONG   dwTable,
    LPCWSTR pszContext,
    ULONG   dwInterface,
    LPCWSTR pszFunction,
    LPCWSTR pszProperty,
    ULONG   cbValue,
    PUCHAR  pbValue
)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI BCryptSignHash(
    BCRYPT_KEY_HANDLE hKey,
    VOID* pPaddingInfo,
    PUCHAR            pbInput,
    ULONG             cbInput,
    PUCHAR            pbOutput,
    ULONG             cbOutput,
    ULONG*            pcbResult,
    ULONG             dwFlags
)
{
    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI BCryptUnregisterConfigChangeNotify(
    PVOID* pEvent
)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI  BCryptUnregisterProvider(WORD* Src)
{
    return STATUS_SUCCESS;
}

////////////////////////////////


BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        instance = hinst;
        DisableThreadLibraryCalls(hinst);
        break;

    case DLL_PROCESS_DETACH:
        if (reserved) break;
        break;
    }
    return TRUE;
}

void TRACE(const char* format, ...)
{
    va_list	listp;

    va_start(listp, format);
    printf(listp);
    ::OutputDebugStringA(listp);
    va_end(listp);

}

void FIXME(const char* format, ...)
{
    va_list	listp;

    va_start(listp, format);
    printf(listp);
    ::OutputDebugStringA(listp);
    va_end(listp);
}

void WARN(const char* format, ...)
{
    va_list	listp;

    va_start(listp, format);
    printf(listp);
    ::OutputDebugStringA(listp);
    va_end(listp);
}

void ERR(const char* format, ...)
{
    va_list	listp;

    va_start(listp, format);
    printf(listp);
    ::OutputDebugStringA(listp);
    va_end(listp);
}

static char ret[] = "[convert_need]";
char* wide_to_char(LPCWSTR wide_str)
{
    WideCharToMultiByte(CP_ACP,
        0,
        wide_str,
        -1,
        NULL,
        0, NULL, NULL);

    return ret;
}
