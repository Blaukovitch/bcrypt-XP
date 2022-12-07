#pragma once
#include "pch.h"



/*
* Copyright(C) 2007 Francois Gouget
*
*This library is free software; you can redistribute itand /or
*modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
*This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110 - 1301, USA
*/
#ifndef __WINE_BCRYPT_H
#define __WINE_BCRYPT_H

#ifndef WINAPI
#define WINAPI __stdcall
#endif

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef OPTIONAL
#define OPTIONAL
#endif

#ifndef _NTDEF_
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS* PNTSTATUS;
#endif

//
// Interfaces
//

#define BCRYPT_CIPHER_INTERFACE                 0x00000001
#define BCRYPT_HASH_INTERFACE                   0x00000002
#define BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE  0x00000003
#define BCRYPT_SECRET_AGREEMENT_INTERFACE       0x00000004
#define BCRYPT_SIGNATURE_INTERFACE              0x00000005
#define BCRYPT_RNG_INTERFACE                    0x00000006

// AlgOperations flags for use with BCryptEnumAlgorithms()
#define BCRYPT_CIPHER_OPERATION                 0x00000001
#define BCRYPT_HASH_OPERATION                   0x00000002
#define BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION  0x00000004
#define BCRYPT_SECRET_AGREEMENT_OPERATION       0x00000008
#define BCRYPT_SIGNATURE_OPERATION              0x00000010
#define BCRYPT_RNG_OPERATION                    0x00000020

#define BCRYPT_ALGORITHM_NAME L"AlgorithmName"
#define BCRYPT_AUTH_TAG_LENGTH L"AuthTagLength"
#define BCRYPT_BLOCK_LENGTH L"BlockLength"
#define BCRYPT_BLOCK_SIZE_LIST L"BlockSizeList"
#define BCRYPT_CHAINING_MODE L"ChainingMode"
#define BCRYPT_EFFECTIVE_KEY_LENGTH L"EffectiveKeyLength"
#define BCRYPT_HASH_BLOCK_LENGTH L"HashBlockLength"
#define BCRYPT_HASH_LENGTH L"HashDigestLength"
#define BCRYPT_HASH_OID_LIST L"HashOIDList"
#define BCRYPT_KEY_LENGTH L"KeyLength"
#define BCRYPT_KEY_LENGTHS L"KeyLengths"
#define BCRYPT_KEY_OBJECT_LENGTH L"KeyObjectLength"
#define BCRYPT_KEY_STRENGTH L"KeyStrength"
#define BCRYPT_OBJECT_LENGTH L"ObjectLength"
#define BCRYPT_PADDING_SCHEMES L"PaddingSchemes"
#define BCRYPT_PROVIDER_HANDLE L"ProviderHandle"
#define BCRYPT_SIGNATURE_LENGTH L"SignatureLength"

#define BCRYPT_OPAQUE_KEY_BLOB   L"OpaqueKeyBlob"
#define BCRYPT_KEY_DATA_BLOB     L"KeyDataBlob"
#define BCRYPT_AES_WRAP_KEY_BLOB L"Rfc3565KeyWrapBlob"
#define BCRYPT_ECCPUBLIC_BLOB    L"ECCPUBLICBLOB"
#define BCRYPT_ECCPRIVATE_BLOB   L"ECCPRIVATEBLOB"
#define BCRYPT_RSAPUBLIC_BLOB    L"RSAPUBLICBLOB"
#define BCRYPT_RSAPRIVATE_BLOB   L"RSAPRIVATEBLOB"

#define MS_PRIMITIVE_PROVIDER L"Microsoft Primitive Provider"
#define MS_PLATFORM_CRYPTO_PROVIDER L"Microsoft Platform Crypto Provider"


#define BCRYPT_RSA_ALGORITHM                    L"RSA"
#define BCRYPT_RSA_SIGN_ALGORITHM               L"RSA_SIGN"
#define BCRYPT_DH_ALGORITHM                     L"DH"
#define BCRYPT_DSA_ALGORITHM                    L"DSA"
#define BCRYPT_RC2_ALGORITHM                    L"RC2"
#define BCRYPT_RC4_ALGORITHM                    L"RC4"
#define BCRYPT_AES_ALGORITHM                    L"AES"
#define BCRYPT_DES_ALGORITHM                    L"DES"
#define BCRYPT_DESX_ALGORITHM                   L"DESX"
#define BCRYPT_3DES_ALGORITHM                   L"3DES"
#define BCRYPT_3DES_112_ALGORITHM               L"3DES_112"
#define BCRYPT_MD2_ALGORITHM                    L"MD2"
#define BCRYPT_MD4_ALGORITHM                    L"MD4"
#define BCRYPT_MD5_ALGORITHM                    L"MD5"
#define BCRYPT_SHA1_ALGORITHM                   L"SHA1"
#define BCRYPT_SHA256_ALGORITHM                 L"SHA256"
#define BCRYPT_SHA384_ALGORITHM                 L"SHA384"
#define BCRYPT_SHA512_ALGORITHM                 L"SHA512"
#define BCRYPT_AES_GMAC_ALGORITHM               L"AES-GMAC"
#define BCRYPT_AES_CMAC_ALGORITHM               L"AES-CMAC"
#define BCRYPT_ECDSA_P256_ALGORITHM             L"ECDSA_P256"
#define BCRYPT_ECDSA_P384_ALGORITHM             L"ECDSA_P384"
#define BCRYPT_ECDSA_P521_ALGORITHM             L"ECDSA_P521"
#define BCRYPT_ECDH_P256_ALGORITHM              L"ECDH_P256"
#define BCRYPT_ECDH_P384_ALGORITHM              L"ECDH_P384"
#define BCRYPT_ECDH_P521_ALGORITHM              L"ECDH_P521"
#define BCRYPT_RNG_ALGORITHM                    L"RNG"
#define BCRYPT_RNG_FIPS186_DSA_ALGORITHM        L"FIPS186DSARNG"
#define BCRYPT_RNG_DUAL_EC_ALGORITHM            L"DUALECRNG"

#define BCRYPT_ECDSA_PUBLIC_P256_MAGIC  0x31534345
#define BCRYPT_ECDSA_PRIVATE_P256_MAGIC 0x32534345
#define BCRYPT_ECDSA_PUBLIC_P384_MAGIC  0x33534345
#define BCRYPT_ECDSA_PRIVATE_P384_MAGIC 0x34534345
#define BCRYPT_ECDSA_PUBLIC_P521_MAGIC  0x35534345
#define BCRYPT_ECDSA_PRIVATE_P521_MAGIC 0x36534345


// Additional BCryptGetProperty strings for the RNG Platform Crypto Provider
#define BCRYPT_PCP_PLATFORM_TYPE_PROPERTY    L"PCP_PLATFORM_TYPE"
#define BCRYPT_PCP_PROVIDER_VERSION_PROPERTY L"PCP_PROVIDER_VERSION"

#if (NTDDI_VERSION > NTDDI_WINBLUE || (NTDDI_VERSION == NTDDI_WINBLUE && defined(WINBLUE_KBSPRING14)))
#define BCRYPT_MULTI_OBJECT_LENGTH  L"MultiObjectLength"
#endif

// BCryptSetProperty strings
#define BCRYPT_INITIALIZATION_VECTOR    L"IV"

// Property Strings
#define BCRYPT_CHAIN_MODE_NA        L"ChainingModeN/A"
#define BCRYPT_CHAIN_MODE_CBC       L"ChainingModeCBC"
#define BCRYPT_CHAIN_MODE_ECB       L"ChainingModeECB"
#define BCRYPT_CHAIN_MODE_CFB       L"ChainingModeCFB"
#define BCRYPT_CHAIN_MODE_CCM       L"ChainingModeCCM"
#define BCRYPT_CHAIN_MODE_GCM       L"ChainingModeGCM"

// Supported RSA Padding Types
#define BCRYPT_SUPPORTED_PAD_ROUTER     0x00000001
#define BCRYPT_SUPPORTED_PAD_PKCS1_ENC  0x00000002
#define BCRYPT_SUPPORTED_PAD_PKCS1_SIG  0x00000004
#define BCRYPT_SUPPORTED_PAD_OAEP       0x00000008
#define BCRYPT_SUPPORTED_PAD_PSS        0x00000010


//
//      BCrypt Flags
//

#define BCRYPT_PROV_DISPATCH        0x00000001  // BCryptOpenAlgorithmProvider

#define BCRYPT_BLOCK_PADDING        0x00000001  // BCryptEncrypt/Decrypt

// RSA padding schemes
#define BCRYPT_PAD_NONE             0x00000001
#define BCRYPT_PAD_PKCS1            0x00000002  // BCryptEncrypt/Decrypt BCryptSignHash/VerifySignature
#define BCRYPT_PAD_OAEP             0x00000004  // BCryptEncrypt/Decrypt
#define BCRYPT_PAD_PSS              0x00000008  // BCryptSignHash/VerifySignature


typedef enum {
    BCRYPT_OPERATION_TYPE_HASH = 1
} BCRYPT_MULTI_OPERATION_TYPE;


typedef struct _BCRYPT_ALGORITHM_IDENTIFIER
{
    LPWSTR pszName;
    ULONG  dwClass;
    ULONG  dwFlags;
} BCRYPT_ALGORITHM_IDENTIFIER;

typedef struct __BCRYPT_KEY_LENGTHS_STRUCT
{
    ULONG dwMinLength;
    ULONG dwMaxLength;
    ULONG dwIncrement;
} BCRYPT_KEY_LENGTHS_STRUCT, BCRYPT_AUTH_TAG_LENGTHS_STRUCT;

typedef struct _BCRYPT_KEY_DATA_BLOB_HEADER
{
    ULONG dwMagic;
    ULONG dwVersion;
    ULONG cbKeyData;
} BCRYPT_KEY_DATA_BLOB_HEADER, * PBCRYPT_KEY_DATA_BLOB_HEADER;

typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
{
    ULONG cbSize;
    ULONG dwInfoVersion;
    UCHAR* pbNonce;
    ULONG cbNonce;
    UCHAR* pbAuthData;
    ULONG cbAuthData;
    UCHAR* pbTag;
    ULONG cbTag;
    UCHAR* pbMacContext;
    ULONG cbMacContext;
    ULONG cbAAD;
    ULONGLONG cbData;
    ULONG dwFlags;
} BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, * PBCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;

typedef struct _BCRYPT_ECCKEY_BLOB
{
    ULONG dwMagic;
    ULONG cbKey;
} BCRYPT_ECCKEY_BLOB, * PBCRYPT_ECCKEY_BLOB;

#define BCRYPT_RSAPUBLIC_MAGIC      0x31415352
#define BCRYPT_RSAPRIVATE_MAGIC     0x32415352
#define BCRYPT_RSAFULLPRIVATE_MAGIC 0x33415352

typedef struct _BCRYPT_RSAKEY_BLOB
{
    ULONG Magic;
    ULONG BitLength;
    ULONG cbPublicExp;
    ULONG cbModulus;
    ULONG cbPrime1;
    ULONG cbPrime2;
} BCRYPT_RSAKEY_BLOB;

typedef struct _BCRYPT_PKCS1_PADDING_INFO
{
    LPCWSTR pszAlgId;
} BCRYPT_PKCS1_PADDING_INFO;


///////////////////////
typedef struct _KSYSTEM_TIME
{
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, * PKSYSTEM_TIME;

typedef enum _NT_PRODUCT_TYPE
{
    NtProductWinNt = 1,
    NtProductLanManNt = 2,
    NtProductServer = 3
} NT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
    StandardDesign = 0,
    NEC98x86 = 1,
    EndAlternatives = 2
} ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KUSER_SHARED_DATA
{
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;
    KSYSTEM_TIME InterruptTime;
    KSYSTEM_TIME SystemTime;
    KSYSTEM_TIME TimeZoneBias;
    WORD ImageNumberLow;
    WORD ImageNumberHigh;
    WCHAR NtSystemRoot[260];
    ULONG MaxStackTraceDepth;
    ULONG CryptoExponent;
    ULONG TimeZoneId;
    ULONG LargePageMinimum;
    ULONG Reserved2[7];
    NT_PRODUCT_TYPE NtProductType;
    UCHAR ProductTypeIsValid;
    ULONG NtMajorVersion;
    ULONG NtMinorVersion;
    UCHAR ProcessorFeatures[64];
    ULONG Reserved1;
    ULONG Reserved3;
    ULONG TimeSlip;
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    LARGE_INTEGER SystemExpirationDate;
    ULONG SuiteMask;
    UCHAR KdDebuggerEnabled;
    UCHAR NXSupportPolicy;
    ULONG ActiveConsoleId;
    ULONG DismountCount;
    ULONG ComPlusPackage;
    ULONG LastSystemRITEventTickCount;
    ULONG NumberOfPhysicalPages;
    UCHAR SafeBootMode;
    ULONG SharedDataFlags;
    ULONG DbgErrorPortPresent : 1;
    ULONG DbgElevationEnabled : 1;
    ULONG DbgVirtEnabled : 1;
    ULONG DbgInstallerDetectEnabled : 1;
    ULONG SystemDllRelocated : 1;
    ULONG SpareBits : 27;
    UINT64 TestRetInstruction;
    ULONG SystemCall;
    ULONG SystemCallReturn;
    UINT64 SystemCallPad[3];
    union
    {
        KSYSTEM_TIME TickCount;
        UINT64 TickCountQuad;
    };
    ULONG Cookie;
    INT64 ConsoleSessionForegroundProcessId;
    ULONG Wow64SharedInformation[16];
    WORD UserModeGlobalLogger[8];
    ULONG HeapTracingPid[2];
    ULONG CritSecTracingPid[2];
    ULONG ImageFileExecutionOptions;
    union
    {
        UINT64 AffinityPad;
        ULONG ActiveProcessorAffinity;
    };
    UINT64 InterruptTimeBias;
} KUSER_SHARED_DATA, * PKUSER_SHARED_DATA;


#define MAGIC_ALG  (('A' << 24) | ('L' << 16) | ('G' << 8) | '0')
#define MAGIC_HASH (('H' << 24) | ('A' << 16) | ('S' << 8) | 'H')
#define MAGIC_KEY  (('K' << 24) | ('E' << 16) | ('Y' << 8) | '0')
#define MAGIC_SECRET (('S' << 24) | ('C' << 16) | ('R' << 8) | 'T')
struct object
{
    ULONG magic;
};


#define BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION 1

#define BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG 0x00000001
#define BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG 0x00000002

typedef struct _CRYPT_INTERFACE_REG
{
    ULONG dwInterface;
    ULONG dwFlags;
    ULONG cFunctions;
    PWSTR* rgpszFunctions;
} CRYPT_INTERFACE_REG, * PCRYPT_INTERFACE_REG;

typedef struct _CRYPT_IMAGE_REG
{
    PWSTR pszImage;
    ULONG cInterfaces;
    PCRYPT_INTERFACE_REG* rgpInterfaces;
} CRYPT_IMAGE_REG, * PCRYPT_IMAGE_REG;

typedef struct _CRYPT_CONTEXT_FUNCTIONS
{
    ULONG cFunctions;
    WCHAR** rgpszFunctions;
} CRYPT_CONTEXT_FUNCTIONS, * PCRYPT_CONTEXT_FUNCTIONS;

typedef struct _CRYPT_PROVIDER_REG
{
    ULONG cAliases;
    PWSTR* rgpszAliases;
    PCRYPT_IMAGE_REG pUM;
    PCRYPT_IMAGE_REG pKM;
} CRYPT_PROVIDER_REG, * PCRYPT_PROVIDER_REG;

typedef struct _CRYPT_CONTEXT_CONFIG {
    ULONG dwFlags;
    ULONG dwReserved;
} CRYPT_CONTEXT_CONFIG, * PCRYPT_CONTEXT_CONFIG;

typedef struct _CRYPT_CONTEXT_FUNCTION_CONFIG {
    ULONG dwFlags;
    ULONG dwReserved;
} CRYPT_CONTEXT_FUNCTION_CONFIG, * PCRYPT_CONTEXT_FUNCTION_CONFIG;

typedef struct _CRYPT_CONTEXT_FUNCTION_PROVIDERS {
    ULONG cProviders;
    PWSTR* rgpszProviders;
} CRYPT_CONTEXT_FUNCTION_PROVIDERS, * PCRYPT_CONTEXT_FUNCTION_PROVIDERS;

typedef struct _CRYPT_CONTEXTS {
    ULONG cContexts;
    PWSTR* rgpszContexts;
} CRYPT_CONTEXTS, * PCRYPT_CONTEXTS;

typedef struct _BCRYPT_PROVIDER_NAME {
    LPWSTR pszProviderName;
} BCRYPT_PROVIDER_NAME;

typedef struct _CRYPT_PROVIDERS {
    ULONG cProviders;
    PWSTR* rgpszProviders;
} CRYPT_PROVIDERS, * PCRYPT_PROVIDERS;

typedef struct _BCryptBuffer {
    ULONG   cbBuffer;             // Length of buffer, in bytes
    ULONG   BufferType;           // Buffer type
    PVOID   pvBuffer;             // Pointer to buffer
} BCryptBuffer, * PBCryptBuffer;

typedef struct _BCryptBufferDesc {
    ULONG   ulVersion;            // Version number
    ULONG   cBuffers;             // Number of buffers
    PBCryptBuffer pBuffers;       // Pointer to array of buffers

} BCryptBufferDesc, * PBCryptBufferDesc;

typedef struct _CRYPT_PROPERTY_REF {
    PWSTR  pszProperty;
    ULONG  cbValue;
    PUCHAR pbValue;
} CRYPT_PROPERTY_REF, * PCRYPT_PROPERTY_REF;

typedef struct _CRYPT_IMAGE_REF {
    PWSTR pszImage;
    ULONG dwFlags;
} CRYPT_IMAGE_REF, * PCRYPT_IMAGE_REF;

typedef struct _CRYPT_PROVIDER_REF {
    ULONG               dwInterface;
    PWSTR               pszFunction;
    PWSTR               pszProvider;
    ULONG               cProperties;
    PCRYPT_PROPERTY_REF* rgpProperties;
    PCRYPT_IMAGE_REF    pUM;
    PCRYPT_IMAGE_REF    pKM;
} CRYPT_PROVIDER_REF, * PCRYPT_PROVIDER_REF;

typedef struct _CRYPT_PROVIDER_REFS {
    ULONG               cProviders;
    PCRYPT_PROVIDER_REF* rgpProviders;
} CRYPT_PROVIDER_REFS, * PCRYPT_PROVIDER_REFS;

struct key_symmetric
{
    enum chain_mode  mode;
    ULONG            block_size;
    UCHAR* vector;
    ULONG            vector_len;
    UCHAR* secret;
    unsigned         secret_len;
    CRITICAL_SECTION cs;
};

#define KEY_FLAG_LEGACY_DSA_V2  0x00000001

typedef struct _DSSSEED {
    DWORD counter;
    BYTE  seed[20];
} DSSSEED;

struct key_asymmetric
{
    ULONG             bitlen;     /* ignored for ECC keys */
    unsigned          flags;
    DSSSEED           dss_seed;
};

struct key
{
    struct object hdr;
    enum alg_id   alg_id;
    UINT64        PRIVATE[2];  /* private data for backend */
    union
    {
        struct key_symmetric s;
        struct key_asymmetric a;
    } u;
};

struct secret
{
    struct object hdr;
};

struct key_symmetric_set_auth_data_params
{
    struct key* key;
    UCHAR* auth_data;
    ULONG        len;
};

struct key_symmetric_encrypt_params
{
    struct key* key;
    const UCHAR* input;
    unsigned     input_len;
    UCHAR* output;
    ULONG        output_len;
};

struct key_symmetric_decrypt_params
{
    struct key* key;
    const UCHAR* input;
    unsigned     input_len;
    UCHAR* output;
    ULONG        output_len;
};

struct key_symmetric_get_tag_params
{
    struct key* key;
    UCHAR* tag;
    ULONG        len;
};

struct key_asymmetric_decrypt_params
{
    struct key* key;
    UCHAR* input;
    unsigned     input_len;
    UCHAR* output;
    ULONG        output_len;
    ULONG* ret_len;
};

struct key_asymmetric_encrypt_params
{
    struct key* key;
    UCHAR* input;
    unsigned    input_len;
    UCHAR* output;
    ULONG       output_len;
    ULONG* ret_len;
};

struct key_asymmetric_duplicate_params
{
    struct key* key_orig;
    struct key* key_copy;
};

struct key_asymmetric_sign_params
{
    struct key* key;
    void* padding;
    UCHAR* input;
    unsigned     input_len;
    UCHAR* output;
    ULONG        output_len;
    ULONG* ret_len;
    unsigned     flags;
};

struct key_asymmetric_verify_params
{
    struct key* key;
    void* padding;
    UCHAR* hash;
    unsigned    hash_len;
    UCHAR* signature;
    ULONG       signature_len;
    unsigned    flags;
};

#define KEY_EXPORT_FLAG_PUBLIC   0x00000001
#define KEY_EXPORT_FLAG_RSA_FULL 0x00000002
struct key_asymmetric_export_params
{
    struct key* key;
    ULONG        flags;
    UCHAR* buf;
    ULONG        len;
    ULONG* ret_len;
};

#define KEY_IMPORT_FLAG_PUBLIC   0x00000001
struct key_asymmetric_import_params
{
    struct key* key;
    ULONG        flags;
    UCHAR* buf;
    ULONG        len;
};

enum key_funcs
{
    unix_process_attach,
    unix_process_detach,
    unix_key_symmetric_vector_reset,
    unix_key_symmetric_set_auth_data,
    unix_key_symmetric_encrypt,
    unix_key_symmetric_decrypt,
    unix_key_symmetric_get_tag,
    unix_key_symmetric_destroy,
    unix_key_asymmetric_generate,
    unix_key_asymmetric_decrypt,
    unix_key_asymmetric_encrypt,
    unix_key_asymmetric_duplicate,
    unix_key_asymmetric_sign,
    unix_key_asymmetric_verify,
    unix_key_asymmetric_destroy,
    unix_key_asymmetric_export,
    unix_key_asymmetric_import,
};


#define BCRYPT_PAD_NONE   0x00000001
#define BCRYPT_PAD_PKCS1  0x00000002
#define BCRYPT_PAD_OAEP   0x00000004
#define BCRYPT_PAD_PSS    0x00000008

#define BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION 1

#define BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG 0x00000001
#define BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG 0x00000002

#define BCRYPT_KEY_DATA_BLOB_MAGIC    0x4d42444b
#define BCRYPT_KEY_DATA_BLOB_VERSION1 1

typedef PVOID BCRYPT_ALG_HANDLE;
typedef PVOID BCRYPT_KEY_HANDLE;
typedef PVOID BCRYPT_HANDLE;
typedef PVOID BCRYPT_HASH_HANDLE;
typedef PVOID BCRYPT_SECRET_HANDLE;

#define BCRYPT_RNG_USE_ENTROPY_IN_BUFFER 0x00000001
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG  0x00000002
#define BCRYPT_ALG_HANDLE_HMAC_FLAG 0x00000008
extern "C"
{
    __declspec(dllexport) NTSTATUS WINAPI BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE, ULONG);
    __declspec(dllexport) NTSTATUS WINAPI BCryptCreateHash(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
    __declspec(dllexport) NTSTATUS WINAPI BCryptDecrypt(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
    __declspec(dllexport) NTSTATUS WINAPI BCryptDestroyHash(BCRYPT_HASH_HANDLE);
    __declspec(dllexport) NTSTATUS WINAPI BCryptDestroyKey(BCRYPT_KEY_HANDLE);
    __declspec(dllexport) NTSTATUS WINAPI BCryptEncrypt(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
    __declspec(dllexport) NTSTATUS WINAPI BCryptEnumAlgorithms(ULONG, ULONG*, BCRYPT_ALGORITHM_IDENTIFIER**, ULONG);
    __declspec(dllexport) NTSTATUS WINAPI BCryptFinishHash(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
    __declspec(dllexport) NTSTATUS WINAPI BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
    __declspec(dllexport) NTSTATUS WINAPI BCryptGenRandom(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);
    __declspec(dllexport) NTSTATUS WINAPI BCryptGetFipsAlgorithmMode(BOOLEAN*);
    __declspec(dllexport) NTSTATUS WINAPI BCryptGetProperty(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG);
    __declspec(dllexport) NTSTATUS WINAPI BCryptHash(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, PUCHAR, ULONG, PUCHAR, ULONG);
    __declspec(dllexport) NTSTATUS WINAPI BCryptHashData(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
    __declspec(dllexport) NTSTATUS WINAPI BCryptImportKeyPair(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, BCRYPT_KEY_HANDLE*, UCHAR*, ULONG, ULONG);
    __declspec(dllexport) NTSTATUS WINAPI BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
    __declspec(dllexport) NTSTATUS WINAPI BCryptSetProperty(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
    __declspec(dllexport) NTSTATUS WINAPI BCryptDuplicateHash(BCRYPT_HASH_HANDLE, BCRYPT_HASH_HANDLE*, UCHAR*, ULONG, ULONG);
    __declspec(dllexport) NTSTATUS WINAPI BCryptVerifySignature(BCRYPT_KEY_HANDLE, void*, UCHAR*, ULONG, UCHAR*, ULONG, ULONG);
    __declspec(dllexport) NTSTATUS WINAPI BCryptAddContextFunction(ULONG table, const WCHAR* ctx, ULONG iface, const WCHAR* func, ULONG pos);
    __declspec(dllexport) NTSTATUS WINAPI BCryptGetFipsAlgorithmMode(BOOLEAN* enabled);
    __declspec(dllexport) NTSTATUS WINAPI BCryptUnregisterProvider(const WCHAR* provider);
    __declspec(dllexport) NTSTATUS WINAPI BCryptRegisterProvider(const WCHAR* provider, ULONG flags, CRYPT_PROVIDER_REG* reg);
    __declspec(dllexport) NTSTATUS WINAPI BCryptDestroySecret(BCRYPT_SECRET_HANDLE handle);
    __declspec(dllexport) NTSTATUS WINAPI BCryptDeriveKey(BCRYPT_SECRET_HANDLE handle, const WCHAR* kdf, void* parameter, UCHAR* derived, ULONG derived_size, ULONG* result, ULONG flags);
    __declspec(dllexport) NTSTATUS WINAPI BCryptSetAuditingInterface();
    __declspec(dllexport) NTSTATUS WINAPI BCryptUnregisterConfigChangeNotify(HANDLE hEvent);
    __declspec(dllexport) NTSTATUS WINAPI BCryptConfigureContext(ULONG dwTable, LPCWSTR pszContext, PCRYPT_CONTEXT_CONFIG pConfig);
    __declspec(dllexport) NTSTATUS WINAPI BCryptConfigureContextFunction(ULONG dwTable, LPCWSTR pszContext, ULONG dwInterface, LPCWSTR pszFunction, PCRYPT_CONTEXT_FUNCTION_CONFIG pConfig);
    __declspec(dllexport) NTSTATUS WINAPI BCryptCreateContext(ULONG dwTable, LPCWSTR pszContext, PCRYPT_CONTEXT_CONFIG pConfig);
    __declspec(dllexport) NTSTATUS WINAPI BCryptCreateMultiHash(BCRYPT_ALG_HANDLE  hAlgorithm, BCRYPT_HASH_HANDLE* phHash, ULONG  nHashes,
        PUCHAR             pbHashObject,
        ULONG              cbHashObject,
        PUCHAR             pbSecret,
        ULONG              cbSecret,
        ULONG              dwFlags
    );
    __declspec(dllexport) NTSTATUS WINAPI BCryptDeleteContext(ULONG   dwTable, LPCWSTR pszContext);
    __declspec(dllexport) NTSTATUS WINAPI BCryptDeriveKeyCapi(
        BCRYPT_HASH_HANDLE hHash,
        BCRYPT_ALG_HANDLE  hTargetAlg,
        PUCHAR             pbDerivedKey,
        ULONG              cbDerivedKey,
        ULONG              dwFlags
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptDeriveKeyPBKDF2(
        BCRYPT_ALG_HANDLE hPrf,
        PUCHAR            pbPassword,
        ULONG             cbPassword,
        PUCHAR            pbSalt,
        ULONG             cbSalt,
        ULONGLONG         cIterations,
        PUCHAR            pbDerivedKey,
        ULONG             cbDerivedKey,
        ULONG             dwFlags
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptDuplicateKey(
        BCRYPT_KEY_HANDLE hKey,
        BCRYPT_KEY_HANDLE* phNewKey,
        PUCHAR            pbKeyObject,
        ULONG             cbKeyObject,
        ULONG             dwFlags
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptEnumContextFunctionProviders(
        ULONG                             dwTable,
        LPCWSTR                           pszContext,
        ULONG                             dwInterface,
        LPCWSTR                           pszFunction,
        ULONG* pcbBuffer,
        PCRYPT_CONTEXT_FUNCTION_PROVIDERS* ppBuffer
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptEnumContexts(
        ULONG           dwTable,
        ULONG* pcbBuffer,
        PCRYPT_CONTEXTS* ppBuffer
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptEnumProviders(
         LPCWSTR              pszAlgId,
        ULONG* pImplCount,
        BCRYPT_PROVIDER_NAME** ppImplList,
        ULONG                dwFlags
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptEnumRegisteredProviders(
       ULONG* pcbBuffer,
       PCRYPT_PROVIDERS* ppBuffer
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptExportKey(
        BCRYPT_KEY_HANDLE hKey,
        BCRYPT_KEY_HANDLE hExportKey,
        LPCWSTR           pszBlobType,
        PUCHAR            pbOutput,
        ULONG             cbOutput,
        ULONG* pcbResult,
        ULONG             dwFlags
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptFinalizeKeyPair(
       BCRYPT_KEY_HANDLE hKey,
       ULONG             dwFlags
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptGenerateKeyPair(
        BCRYPT_ALG_HANDLE hAlgorithm,
        BCRYPT_KEY_HANDLE* phKey,
        ULONG             dwLength,
        ULONG             dwFlags
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptImportKey(
        BCRYPT_ALG_HANDLE hAlgorithm,
        BCRYPT_KEY_HANDLE hImportKey,
        LPCWSTR           pszBlobType,
        BCRYPT_KEY_HANDLE* phKey,
        PUCHAR            pbKeyObject,
        ULONG             cbKeyObject,
        PUCHAR            pbInput,
        ULONG             cbInput,
        ULONG             dwFlags
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptKeyDerivation(
        BCRYPT_KEY_HANDLE hKey,
        BCryptBufferDesc* pParameterList,
        PUCHAR            pbDerivedKey,
        ULONG             cbDerivedKey,
        ULONG* pcbResult,
        ULONG             dwFlags
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptProcessMultiOperations(
        BCRYPT_HANDLE               hObject,
        BCRYPT_MULTI_OPERATION_TYPE operationType,
        PVOID                       pOperations,
        ULONG                       cbOperations,
        ULONG                       dwFlags
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptQueryContextConfiguration(
        ULONG                 dwTable,
        LPCWSTR               pszContext,
        ULONG* pcbBuffer,
        PCRYPT_CONTEXT_CONFIG* ppBuffer
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptQueryContextFunctionConfiguration(
        ULONG                          dwTable,
        LPCWSTR                        pszContext,
        ULONG                          dwInterface,
        LPCWSTR                        pszFunction,
        ULONG* pcbBuffer,
        PCRYPT_CONTEXT_FUNCTION_CONFIG* ppBuffer
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptQueryContextFunctionProperty(
        ULONG   dwTable,
        LPCWSTR pszContext,
        ULONG   dwInterface,
        LPCWSTR pszFunction,
        LPCWSTR pszProperty,
        ULONG* pcbValue,
        PUCHAR* ppbValue
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptQueryProviderRegistration(
        LPCWSTR             pszProvider,
        ULONG               dwMode,
        ULONG               dwInterface,
        ULONG* pcbBuffer,
        PCRYPT_PROVIDER_REG* ppBuffer
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptRegisterConfigChangeNotify(
        PVOID* pEvent
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptResolveProviders(
        LPCWSTR              pszContext,
        ULONG                dwInterface,
        LPCWSTR              pszFunction,
        LPCWSTR              pszProvider,
        ULONG                dwMode,
        ULONG                dwFlags,
        ULONG* pcbBuffer,
        PCRYPT_PROVIDER_REFS* ppBuffer
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptSecretAgreement(
        BCRYPT_KEY_HANDLE    hPrivKey,
        BCRYPT_KEY_HANDLE    hPubKey,
        BCRYPT_SECRET_HANDLE* phAgreedSecret,
        ULONG                dwFlags
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptSetContextFunctionProperty(
        ULONG   dwTable,
        LPCWSTR pszContext,
        ULONG   dwInterface,
        LPCWSTR pszFunction,
        LPCWSTR pszProperty,
        ULONG   cbValue,
        PUCHAR  pbValue
    );

    __declspec(dllexport) NTSTATUS WINAPI BCryptSignHash(
        BCRYPT_KEY_HANDLE hKey,
        VOID* pPaddingInfo,
        PUCHAR            pbInput,
        ULONG             cbInput,
        PUCHAR            pbOutput,
        ULONG             cbOutput,
        ULONG* pcbResult,
        ULONG             dwFlags
    );

}
#endif  /* __WINE_BCRYPT_H */