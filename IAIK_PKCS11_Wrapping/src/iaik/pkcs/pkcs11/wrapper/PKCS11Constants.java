// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
// 
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
// 
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
// 
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from this
//    software without prior written permission.
// 
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
// 
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package iaik.pkcs.pkcs11.wrapper;

/**
 * This interface holds constants of the PKCS#11 v2.11 standard. This is mainly the content of the
 * 'pkcs11t.h' header file.
 * <p>
 * Mapping of primitiv data types to Java types:
 *
 * <pre>
 *   TRUE .......................................... true
 *   FALSE ......................................... false
 *   CK_BYTE ....................................... byte
 *   CK_CHAR ....................................... char
 *   CK_UTF8CHAR ................................... char
 *   CK_BBOOL ...................................... boolean
 *   CK_ULONG ...................................... long
 *   CK_LONG ....................................... long
 *   CK_FLAGS ...................................... long
 *   CK_NOTIFICATION ............................... long
 *   CK_SLOT_ID .................................... long
 *   CK_SESSION_HANDLE ............................. long
 *   CK_USER_TYPE .................................. long
 *   CK_SESSION_HANDLE ............................. long
 *   CK_STATE ...................................... long
 *   CK_OBJECT_HANDLE .............................. long
 *   CK_OBJECT_CLASS ............................... long
 *   CK_HW_FEATURE_TYPE ............................ long
 *   CK_KEY_TYPE ................................... long
 *   CK_CERTIFICATE_TYPE ........................... long
 *   CK_ATTRIBUTE_TYPE ............................. long
 *   CK_VOID_PTR ................................... Object[]
 *   CK_BYTE_PTR ................................... byte[]
 *   CK_CHAR_PTR ................................... char[]
 *   CK_UTF8CHAR_PTR ............................... char[]
 *   CK_MECHANISM_TYPE ............................. long
 *   CK_RV ......................................... long
 *   CK_RSA_PKCS_OAEP_MGF_TYPE ..................... long
 *   CK_RSA_PKCS_OAEP_SOURCE_TYPE .................. long
 *   CK_RC2_PARAMS ................................. long
 *   CK_MAC_GENERAL_PARAMS ......................... long
 *   CK_EXTRACT_PARAMS ............................. long
 *   CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE .... long
 *   CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE .............. long
 *   CK_EC_KDF_TYPE ................................ long
 *   CK_X9_42_DH_KDF_TYPE .......................... long
 * </pre>
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public interface PKCS11Constants {

    boolean TRUE = true;

    boolean FALSE = false;

    Object NULL_PTR = null;

    /* some special values for certain CK_ULONG variables */
    long CK_UNAVAILABLE_INFORMATION = 4294967295L;
    long CK_EFFECTIVELY_INFINITE = 0L;

    /* The following value is always invalid if used as a session */
    /* handle or object handle */
    long CK_INVALID_HANDLE = 0L;

    /*
     * CK_NOTIFICATION enumerates the types of notifications that Cryptoki provides to an application
     */
    /*
     * CK_NOTIFICATION has been changed from an enum to a CK_ULONG for v2.0
     */
    long CKN_SURRENDER = 0L;
    long CKN_OTP_CHANGED = 1L;


    /*
     * flags: bit flags that provide capabilities of the slot Bit Flag Mask Meaning
     */
    long CKF_TOKEN_PRESENT = 0x00000001L;
    long CKF_REMOVABLE_DEVICE = 0x00000002L;
    long CKF_HW_SLOT = 0x00000004L;

    /*
     * The flags parameter is defined as follows: Bit Flag Mask Meaning
     */
    /* has random # generator */
    long CKF_RNG = 0x00000001L;

    /* token is write-protected */
    long CKF_WRITE_PROTECTED = 0x00000002L;

    /* user must login */
    long CKF_LOGIN_REQUIRED = 0x00000004L;

    /* normal user's PIN is set */
    long CKF_USER_PIN_INITIALIZED = 0x00000008L;

    /*
     * CKF_RESTORE_KEY_NOT_NEEDED is new for v2.0. If it is set, that means that *every* time the
     * state of cryptographic operations of a session is successfully saved, all keys needed to
     * continue those operations are stored in the state
     */
    long CKF_RESTORE_KEY_NOT_NEEDED = 0x00000020L;

    /*
     * CKF_CLOCK_ON_TOKEN is new for v2.0. If it is set, that means that the token has some sort of
     * clock. The time on that clock is returned in the token info structure
     */
    long CKF_CLOCK_ON_TOKEN = 0x00000040L;

    /*
     * CKF_PROTECTED_AUTHENTICATION_PATH is new for v2.0. If it is set, that means that there is some
     * way for the user to login without sending a PIN through the Cryptoki library itself
     */
    long CKF_PROTECTED_AUTHENTICATION_PATH = 0x00000100L;

    /*
     * CKF_DUAL_CRYPTO_OPERATIONS is new for v2.0. If it is true, that means that a single session
     * with the token can perform dual simultaneous cryptographic operations (digest and encrypt;
     * decrypt and digest; sign and encrypt; and decrypt and sign)
     */
    long CKF_DUAL_CRYPTO_OPERATIONS = 0x00000200L;

    /*
     * CKF_TOKEN_INITIALIZED if new for v2.10. If it is true, the token has been initialized using
     * C_InitializeToken or an equivalent mechanism outside the scope of PKCS #11. Calling
     * C_InitializeToken when this flag is set will cause the token to be reinitialized.
     */
    long CKF_TOKEN_INITIALIZED = 0x00000400L;

    /*
     * CKF_SECONDARY_AUTHENTICATION if new for v2.10. If it is true, the token supports secondary
     * authentication for private key objects.
     */
    long CKF_SECONDARY_AUTHENTICATION = 0x00000800L;

    /*
     * CKF_USER_PIN_COUNT_LOW if new for v2.10. If it is true, an incorrect user login PIN has been
     * entered at least once since the last successful authentication.
     */
    long CKF_USER_PIN_COUNT_LOW = 0x00010000L;

    /*
     * CKF_USER_PIN_FINAL_TRY if new for v2.10. If it is true, supplying an incorrect user PIN will it
     * to become locked.
     */
    long CKF_USER_PIN_FINAL_TRY = 0x00020000L;

    /*
     * CKF_USER_PIN_LOCKED if new for v2.10. If it is true, the user PIN has been locked. User login
     * to the token is not possible.
     */
    long CKF_USER_PIN_LOCKED = 0x00040000L;

    /*
     * CKF_USER_PIN_TO_BE_CHANGED if new for v2.10. If it is true, the user PIN value is the default
     * value set by token initialization or manufacturing.
     */
    long CKF_USER_PIN_TO_BE_CHANGED = 0x00080000L;

    /*
     * CKF_SO_PIN_COUNT_LOW if new for v2.10. If it is true, an incorrect SO login PIN has been
     * entered at least once since the last successful authentication.
     */
    long CKF_SO_PIN_COUNT_LOW = 0x00100000L;

    /*
     * CKF_SO_PIN_FINAL_TRY if new for v2.10. If it is true, supplying an incorrect SO PIN will it to
     * become locked.
     */
    long CKF_SO_PIN_FINAL_TRY = 0x00200000L;

    /*
     * CKF_SO_PIN_LOCKED if new for v2.10. If it is true, the SO PIN has been locked. SO login to the
     * token is not possible.
     */
    long CKF_SO_PIN_LOCKED = 0x00400000L;

    /*
     * CKF_SO_PIN_TO_BE_CHANGED if new for v2.10. If it is true, the SO PIN value is the default value
     * set by token initialization or manufacturing.
     */
    long CKF_SO_PIN_TO_BE_CHANGED = 0x00800000L;

    long CKF_ERROR_STATE = 0x01000000L;

    /*
     * New Flags for v3.0
     */

    long CKF_END_OF_MESSAGE = 0x00000001L;

    /* CK_USER_TYPE enumerates the types of Cryptoki users */
    /*
     * CK_USER_TYPE has been changed from an enum to a CK_ULONG for v2.0
     */
    /* Security Officer */
    long CKU_SO = 0L;
    /* Normal user */
    long CKU_USER = 1L;
    /* Context specific (added in v2.20) */
    long CKU_CONTEXT_SPECIFIC = 2L;

    /* CK_STATE enumerates the session states */
    /*
     * CK_STATE has been changed from an enum to a CK_ULONG for v2.0
     */
    long CKS_RO_PUBLIC_SESSION = 0L;
    long CKS_RO_USER_FUNCTIONS = 1L;
    long CKS_RW_PUBLIC_SESSION = 2L;
    long CKS_RW_USER_FUNCTIONS = 3L;
    long CKS_RW_SO_FUNCTIONS = 4L;

    /*
     * The flags are defined in the following table: Bit Flag Mask Meaning
     */
    long CKF_RW_SESSION = 0x00000002L; /* session is r/w */
    long CKF_SERIAL_SESSION = 0x00000004L; /* no parallel */

    /* The following classes of objects are defined: */
    /* CKO_HW_FEATURE is new for v2.10 */
    /* CKO_DOMAIN_PARAMETERS is new for v2.11 */
    /* CKO_MECHANISM is new for v2.20 */
    long CKO_DATA = 0x00000000L;
    long CKO_CERTIFICATE = 0x00000001L;
    long CKO_PUBLIC_KEY = 0x00000002L;
    long CKO_PRIVATE_KEY = 0x00000003L;
    long CKO_SECRET_KEY = 0x00000004L;
    long CKO_HW_FEATURE = 0x00000005L;
    long CKO_DOMAIN_PARAMETERS = 0x00000006L;
    long CKO_MECHANISM = 0x00000007L;

    /* new in update to 3.0 */
    long CKO_OTP_KEY = 0x00000008L;
    long CKO_PROFILE = 0x00000009L;

    long CKO_VENDOR_DEFINED = 0x80000000L;

    /* Profile ID's (new in update to 3.0)*/
    long CKP_INVALID_ID                = 0x00000000L;
    long CKP_BASELINE_PROVIDER         = 0x00000001L;
    long CKP_EXTENDED_PROVIDER         = 0x00000002L;
    long CKP_AUTHENTICATION_TOKEN      = 0x00000003L;
    long CKP_PUBLIC_CERTIFICATES_TOKEN = 0x00000004L;
    long CKP_VENDOR_DEFINED            = 0x80000000L;

    /* The following hardware feature types are defined */
    /* CKH_USER_INTERFACE is new for v2.20 */
    long CKH_MONOTONIC_COUNTER = 0x00000001L;
    long CKH_CLOCK = 0x00000002L;
    long CKH_USER_INTERFACE = 0x00000003L;
    long CKH_VENDOR_DEFINED = 0x80000000L;

    /* the following key types are defined: */
    long CKK_RSA = 0x00000000L;
    long CKK_DSA = 0x00000001L;
    long CKK_DH = 0x00000002L;

    /* CKK_ECDSA and CKK_KEA are new for v2.0 */
    /* CKK_ECDSA is deprecated in v2.11, CKK_EC is preferred. */
    long CKK_ECDSA = 0x00000003L;
    long CKK_EC = 0x00000003L;
    long CKK_X9_42_DH = 0x00000004L;
    long CKK_KEA = 0x00000005L;

    long CKK_GENERIC_SECRET = 0x00000010L;
    long CKK_RC2 = 0x00000011L;
    long CKK_RC4 = 0x00000012L;
    long CKK_DES = 0x00000013L;
    long CKK_DES2 = 0x00000014L;
    long CKK_DES3 = 0x00000015L;

    /* all these key types are new for v2.0 */
    long CKK_CAST = 0x00000016L;
    long CKK_CAST3 = 0x00000017L;
    /* CKK_CAST5 is deprecated in v2.11, CKK_CAST128 is preferred. */
    long CKK_CAST5 = 0x00000018L;
    long CKK_CAST128 = 0x00000018L; /* CAST128=CAST5 */
    long CKK_RC5 = 0x00000019L;
    long CKK_IDEA = 0x0000001AL;
    long CKK_SKIPJACK = 0x0000001BL;
    long CKK_BATON = 0x0000001CL;
    long CKK_JUNIPER = 0x0000001DL;
    long CKK_CDMF = 0x0000001EL;
    long CKK_AES = 0x0000001FL;

    /* BlowFish and TwoFish are new for v2.20 */
    long CKK_BLOWFISH = 0x00000020L;
    long CKK_TWOFISH = 0x00000021L;

    /* new in update to 2.40*/
    long CKK_SECURID = 0x00000022L;
    long CKK_HOTP = 0x00000023L;
    long CKK_ACTI = 0x00000024L;
    long CKK_CAMELLIA = 0x00000025L;
    long CKK_ARIA = 0x00000026L;
    long CKK_MD5_HMAC = 0x00000027L;
    long CKK_SHA_1_HMAC = 0x00000028L;
    long CKK_RIPEMD128_HMAC = 0x00000029L;
    long CKK_RIPEMD160_HMAC = 0x0000002AL;
    long CKK_SHA256_HMAC = 0x0000002BL;
    long CKK_SHA384_HMAC = 0x0000002CL;
    long CKK_SHA512_HMAC = 0x0000002DL;
    long CKK_SHA224_HMAC = 0x0000002EL;
    long CKK_SEED = 0x0000002FL;
    long CKK_GOSTR3410 = 0x00000030L;
    long CKK_GOSTR3411 = 0x00000031L;
    long CKK_GOST28147 = 0x00000032L;
    
    long CKK_CHACHA20            = 0x00000033L;
    long CKK_POLY1305            = 0x00000034L;
    long CKK_AES_XTS             = 0x00000035L;
    long CKK_SHA3_224_HMAC       = 0x00000036L;
    long CKK_SHA3_256_HMAC       = 0x00000037L;
    long CKK_SHA3_384_HMAC       = 0x00000038L;
    long CKK_SHA3_512_HMAC       = 0x00000039L;
    long CKK_BLAKE2B_160_HMAC    = 0x0000003aL;
    long CKK_BLAKE2B_256_HMAC    = 0x0000003bL;
    long CKK_BLAKE2B_384_HMAC    = 0x0000003cL;
    long CKK_BLAKE2B_512_HMAC    = 0x0000003dL;
    long CKK_SALSA20             = 0x0000003eL;
    long CKK_X2RATCHET           = 0x0000003fL;
    long CKK_EC_EDWARDS          = 0x00000040L;
    long CKK_EC_MONTGOMERY       = 0x00000041L;
    long CKK_HKDF                = 0x00000042L;
    
    long CKK_SHA512_224_HMAC     = 0x00000043L;
    long CKK_SHA512_256_HMAC     = 0x00000044L;
    long CKK_SHA512_T_HMAC       = 0x00000045L;


    long CKK_VENDOR_DEFINED = 0x80000000L;

    /* The following certificate types are defined: */
    /* CKC_X_509_ATTR_CERT is new for v2.10 */
    /* CKC_WTLS is new for v2.20 */
    long CKC_X_509 = 0x00000000L;
    long CKC_X_509_ATTR_CERT = 0x00000001L;
    long CKC_WTLS = 0x00000002L;

    long CKC_VENDOR_DEFINED = 0x80000000L;

    /* new in update to 3.0 */
    long CK_CERTIFICATE_CATEGORY_UNSPECIFIED    = 0L;
    long CK_CERTIFICATE_CATEGORY_TOKEN_USER     = 1L;
    long CK_CERTIFICATE_CATEGORY_AUTHORITY      = 2L;
    long CK_CERTIFICATE_CATEGORY_OTHER_ENTITY   = 3L;

    long CK_SECURITY_DOMAIN_UNSPECIFIED         = 0L;
    long CK_SECURITY_DOMAIN_MANUFACTURER        = 1L;
    long CK_SECURITY_DOMAIN_OPERATOR            = 2L;
    long CK_SECURITY_DOMAIN_THIRD_PARTY         = 3L;

    /*
     * The CKF_ARRAY_ATTRIBUTE flag identifies an attribute which consists of an array of values. new
     * for v2.20
     */
    long CKF_ARRAY_ATTRIBUTE = 0x40000000L;

    /* The following attribute types are defined: */
    long CKA_CLASS = 0x00000000L;
    long CKA_TOKEN = 0x00000001L;
    long CKA_PRIVATE = 0x00000002L;
    long CKA_LABEL = 0x00000003L;
    long CKA_UNIQUE_ID = 0x00000004;

    long CKA_APPLICATION = 0x00000010L;
    long CKA_VALUE = 0x00000011L;

    /* CKA_OBJECT_ID is new for v2.10 */
    long CKA_OBJECT_ID = 0x00000012L;

    long CKA_CERTIFICATE_TYPE = 0x00000080L;
    long CKA_ISSUER = 0x00000081L;
    long CKA_SERIAL_NUMBER = 0x00000082L;

    /*
     * CKA_AC_ISSUER, CKA_OWNER, and CKA_ATTR_TYPES are new L; for v2.10
     */
    long CKA_AC_ISSUER = 0x00000083L;
    long CKA_OWNER = 0x00000084L;
    long CKA_ATTR_TYPES = 0x00000085L;

    /* CKA_TRUSTED is new for v2.11 */
    long CKA_TRUSTED = 0x00000086L;

    /*
     * CKA_CERTIFICATE_CATEGORY ... CKA_CHECK_VALUE are new for v2.20
     */
    long CKA_CERTIFICATE_CATEGORY = 0x00000087L;
    long CKA_JAVA_MIDP_SECURITY_DOMAIN = 0x00000088L;
    long CKA_URL = 0x00000089L;
    long CKA_HASH_OF_SUBJECT_PUBLIC_KEY = 0x0000008AL;
    long CKA_HASH_OF_ISSUER_PUBLIC_KEY = 0x0000008BL;

    /* new in update to 2.40*/
    long CKA_NAME_HASH_ALGORITHM = 0x0000008CL;


    long CKA_CHECK_VALUE = 0x00000090L;

    long CKA_KEY_TYPE = 0x00000100L;
    long CKA_SUBJECT = 0x00000101L;
    long CKA_ID = 0x00000102L;
    long CKA_SENSITIVE = 0x00000103L;
    long CKA_ENCRYPT = 0x00000104L;
    long CKA_DECRYPT = 0x00000105L;
    long CKA_WRAP = 0x00000106L;
    long CKA_UNWRAP = 0x00000107L;
    long CKA_SIGN = 0x00000108L;
    long CKA_SIGN_RECOVER = 0x00000109L;
    long CKA_VERIFY = 0x0000010AL;
    long CKA_VERIFY_RECOVER = 0x0000010BL;
    long CKA_DERIVE = 0x0000010CL;
    long CKA_START_DATE = 0x00000110L;
    long CKA_END_DATE = 0x00000111L;
    long CKA_MODULUS = 0x00000120L;
    long CKA_MODULUS_BITS = 0x00000121L;
    long CKA_PUBLIC_EXPONENT = 0x00000122L;
    long CKA_PRIVATE_EXPONENT = 0x00000123L;
    long CKA_PRIME_1 = 0x00000124L;
    long CKA_PRIME_2 = 0x00000125L;
    long CKA_EXPONENT_1 = 0x00000126L;
    long CKA_EXPONENT_2 = 0x00000127L;
    long CKA_COEFFICIENT = 0x00000128L;

    /* new in update to 2.40*/
    long CKA_PUBLIC_KEY_INFO = 0x00000129L;

    long CKA_PRIME = 0x00000130L;
    long CKA_SUBPRIME = 0x00000131L;
    long CKA_BASE = 0x00000132L;

    /* CKA_PRIME_BITS and CKA_SUB_PRIME_BITS are new for v2.11 */
    long CKA_PRIME_BITS = 0x00000133L;
    long CKA_SUB_PRIME_BITS = 0x00000134L;

    long CKA_VALUE_BITS = 0x00000160L;
    long CKA_VALUE_LEN = 0x00000161L;

    /*
     * CKA_EXTRACTABLE, CKA_LOCAL, CKA_NEVER_EXTRACTABLE, CKA_ALWAYS_SENSITIVE, CKA_MODIFIABLE,
     * CKA_ECDSA_PARAMS, and CKA_EC_POINT are new for v2.0
     */
    long CKA_EXTRACTABLE = 0x00000162L;
    long CKA_LOCAL = 0x00000163L;
    long CKA_NEVER_EXTRACTABLE = 0x00000164L;
    long CKA_ALWAYS_SENSITIVE = 0x00000165L;

    /* CKA_KEY_GEN_MECHANISM is new for v2.11 */
    long CKA_KEY_GEN_MECHANISM = 0x00000166L;

    long CKA_MODIFIABLE = 0x00000170L;

    long CKA_COPYABLE = 0x00000171L;
    long CKA_DESTROYABLE = 0x00000172L;

    /*
     * CKA_ECDSA_PARAMS is deprecated in v2.11, CKA_EC_PARAMS is preferred.
     */
    long CKA_ECDSA_PARAMS = 0x00000180L;
    long CKA_EC_PARAMS = 0x00000180L;
    long CKA_EC_POINT = 0x00000181L;

    /*
     * CKA_SECONDARY_AUTH, CKA_AUTH_PIN_FLAGS, CKA_HW_FEATURE_TYPE, CKA_RESET_ON_INIT, and
     * CKA_HAS_RESET are new for v2.10
     */
    long CKA_SECONDARY_AUTH = 0x00000200L;
    long CKA_AUTH_PIN_FLAGS = 0x00000201L;

    /*
     * CKA_ALWAYS_AUTHENTICATE ... CKA_UNWRAP_TEMPLATE are new for v2.20
     */
    long CKA_ALWAYS_AUTHENTICATE = 0x00000202L;

    long CKA_WRAP_WITH_TRUSTED = 0x00000210L;
    long CKA_WRAP_TEMPLATE = (CKF_ARRAY_ATTRIBUTE | 0x00000211L);
    long CKA_UNWRAP_TEMPLATE = (CKF_ARRAY_ATTRIBUTE | 0x00000212L);
    long CKA_DERIVE_TEMPLATE = (CKF_ARRAY_ATTRIBUTE | 0x00000213L);

    /* new in update to 2.40*/
    long CKA_OTP_FORMAT = 0x00000220L;
    long CKA_OTP_LENGTH = 0x00000221L;
    long CKA_OTP_TIME_INTERVAL = 0x00000222L;
    long CKA_OTP_USER_FRIENDLY_MODE = 0x00000223L;
    long CKA_OTP_CHALLENGE_REQUIREMENT = 0x00000224L;
    long CKA_OTP_TIME_REQUIREMENT = 0x00000225L;
    long CKA_OTP_COUNTER_REQUIREMENT = 0x00000226L;
    long CKA_OTP_PIN_REQUIREMENT = 0x00000227L;
    long CKA_OTP_COUNTER = 0x0000022EL;
    long CKA_OTP_TIME = 0x0000022FL;
    long CKA_OTP_USER_IDENTIFIER = 0x0000022AL;
    long CKA_OTP_SERVICE_IDENTIFIER = 0x0000022BL;
    long CKA_OTP_SERVICE_LOGO = 0x0000022CL;
    long CKA_OTP_SERVICE_LOGO_TYPE = 0x0000022DL;

    /* new in update to 2.40*/
    long CKA_GOSTR3410_PARAMS = 0x00000250L;
    long CKA_GOSTR3411_PARAMS = 0x00000251L;
    long CKA_GOST28147_PARAMS = 0x00000252L;

    long CKA_HW_FEATURE_TYPE = 0x00000300L;
    long CKA_RESET_ON_INIT = 0x00000301L;
    long CKA_HAS_RESET = 0x00000302L;

    /* The following attributes are new for v2.20 */
    long CKA_PIXEL_X = 0x00000400L;
    long CKA_PIXEL_Y = 0x00000401L;
    long CKA_RESOLUTION = 0x00000402L;
    long CKA_CHAR_ROWS = 0x00000403L;
    long CKA_CHAR_COLUMNS = 0x00000404L;
    long CKA_COLOR = 0x00000405L;
    long CKA_BITS_PER_PIXEL = 0x00000406L;
    long CKA_CHAR_SETS = 0x00000480L;
    long CKA_ENCODING_METHODS = 0x00000481L;
    long CKA_MIME_TYPES = 0x00000482L;
    long CKA_MECHANISM_TYPE = 0x00000500L;
    long CKA_REQUIRED_CMS_ATTRIBUTES = 0x00000501L;
    long CKA_DEFAULT_CMS_ATTRIBUTES = 0x00000502L;
    long CKA_SUPPORTED_CMS_ATTRIBUTES = 0x00000503L;
    long CKA_ALLOWED_MECHANISMS = (CKF_ARRAY_ATTRIBUTE | 0x00000600L);
    long CKA_PROFILE_ID = 0x00000601L;


    /* new in update to 3.0 */
    long CKA_X2RATCHET_BAG              = 0x00000602L;
    long CKA_X2RATCHET_BAGSIZE          = 0x00000603L;
    long CKA_X2RATCHET_BOBS1STMSG       = 0x00000604L;
    long CKA_X2RATCHET_CKR              = 0x00000605L;
    long CKA_X2RATCHET_CKS              = 0x00000606L;
    long CKA_X2RATCHET_DHP              = 0x00000607L;
    long CKA_X2RATCHET_DHR              = 0x00000608L;
    long CKA_X2RATCHET_DHS              = 0x00000609L;
    long CKA_X2RATCHET_HKR              = 0x0000060aL;
    long CKA_X2RATCHET_HKS              = 0x0000060bL;
    long CKA_X2RATCHET_ISALICE          = 0x0000060cL;
    long CKA_X2RATCHET_NHKR             = 0x0000060dL;
    long CKA_X2RATCHET_NHKS             = 0x0000060eL;
    long CKA_X2RATCHET_NR               = 0x0000060fL;
    long CKA_X2RATCHET_NS               = 0x00000610L;
    long CKA_X2RATCHET_PNS              = 0x00000611L;
    long CKA_X2RATCHET_RK               = 0x00000612L;

    long CKA_VENDOR_DEFINED = 0x80000000L;

    /* the following mechanism types are defined: */
    long CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000L;
    long CKM_RSA_PKCS = 0x00000001L;
    long CKM_RSA_9796 = 0x00000002L;
    long CKM_RSA_X_509 = 0x00000003L;

    /*
     * CKM_MD2_RSA_PKCS, CKM_MD5_RSA_PKCS, and CKM_SHA1_RSA_PKCS are new for v2.0. They are mechanisms
     * which hash and sign
     */
    long CKM_MD2_RSA_PKCS = 0x00000004L;
    long CKM_MD5_RSA_PKCS = 0x00000005L;
    long CKM_SHA1_RSA_PKCS = 0x00000006L;

    /*
     * CKM_RIPEMD128_RSA_PKCS, CKM_RIPEMD160_RSA_PKCS, and CKM_RSA_PKCS_OAEP are new for v2.10
     */
    long CKM_RIPEMD128_RSA_PKCS = 0x00000007L;
    long CKM_RIPEMD160_RSA_PKCS = 0x00000008L;
    long CKM_RSA_PKCS_OAEP = 0x00000009L;

    /*
     * CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_RSA_X9_31, CKM_SHA1_RSA_X9_31, CKM_RSA_PKCS_PSS, and
     * CKM_SHA1_RSA_PKCS_PSS are new for v2.11
     */
    long CKM_RSA_X9_31_KEY_PAIR_GEN = 0x0000000AL;
    long CKM_RSA_X9_31 = 0x0000000BL;
    long CKM_SHA1_RSA_X9_31 = 0x0000000CL;
    long CKM_RSA_PKCS_PSS = 0x0000000DL;
    long CKM_SHA1_RSA_PKCS_PSS = 0x0000000EL;

    long CKM_DSA_KEY_PAIR_GEN = 0x00000010L;
    long CKM_DSA = 0x00000011L;
    long CKM_DSA_SHA1 = 0x00000012L;

    /* new in update to 2.40*/
    long CKM_DSA_SHA224 = 0x00000013L;
    long CKM_DSA_SHA256 = 0x00000014L;
    long CKM_DSA_SHA384 = 0x00000015L;
    long CKM_DSA_SHA512 = 0x00000016L;

    /* new in update 3.0*/
    long CKM_DSA_SHA3_224 = 0x00000018;
    long CKM_DSA_SHA3_256 = 0x00000019;
    long CKM_DSA_SHA3_384 = 0x0000001A;
    long CKM_DSA_SHA3_512 = 0x0000001B;

    long CKM_DH_PKCS_KEY_PAIR_GEN = 0x00000020L;
    long CKM_DH_PKCS_DERIVE = 0x00000021L;

    /*
     * CKM_X9_42_DH_KEY_PAIR_GEN, CKM_X9_42_DH_DERIVE, CKM_X9_42_DH_HYBRID_DERIVE, and
     * CKM_X9_42_MQV_DERIVE are new for v2.11
     */
    long CKM_X9_42_DH_KEY_PAIR_GEN = 0x00000030L;
    long CKM_X9_42_DH_DERIVE = 0x00000031L;
    long CKM_X9_42_DH_HYBRID_DERIVE = 0x00000032L;
    long CKM_X9_42_MQV_DERIVE = 0x00000033L;

    /* CKM_SHA256/384/512 are new for v2.20 */
    long CKM_SHA256_RSA_PKCS = 0x00000040L;
    long CKM_SHA384_RSA_PKCS = 0x00000041L;
    long CKM_SHA512_RSA_PKCS = 0x00000042L;
    long CKM_SHA256_RSA_PKCS_PSS = 0x00000043L;
    long CKM_SHA384_RSA_PKCS_PSS = 0x00000044L;
    long CKM_SHA512_RSA_PKCS_PSS = 0x00000045L;

    /* new in update to 2.40*/
    long CKM_SHA224_RSA_PKCS = 0x00000046L;
    long CKM_SHA224_RSA_PKCS_PSS = 0x00000047L;
    long CKM_SHA512_224 = 0x00000048L;
    long CKM_SHA512_224_HMAC = 0x00000049L;
    long CKM_SHA512_224_HMAC_GENERAL = 0x0000004AL;
    long CKM_SHA512_224_KEY_DERIVATION = 0x0000004BL;
    long CKM_SHA512_256 = 0x0000004CL;
    long CKM_SHA512_256_HMAC = 0x0000004DL;
    long CKM_SHA512_256_HMAC_GENERAL = 0x0000004EL;
    long CKM_SHA512_256_KEY_DERIVATION = 0x0000004FL;
    long CKM_SHA512_T = 0x00000050L;
    long CKM_SHA512_T_HMAC = 0x00000051L;
    long CKM_SHA512_T_HMAC_GENERAL = 0x00000052L;
    long CKM_SHA512_T_KEY_DERIVATION = 0x00000053L;

    /* new in update to 3.0 */
    long CKM_SHA3_256_RSA_PKCS         = 0x00000060L;
    long CKM_SHA3_384_RSA_PKCS         = 0x00000061L;
    long CKM_SHA3_512_RSA_PKCS         = 0x00000062L;
    long CKM_SHA3_256_RSA_PKCS_PSS     = 0x00000063L;
    long CKM_SHA3_384_RSA_PKCS_PSS     = 0x00000064L;
    long CKM_SHA3_512_RSA_PKCS_PSS     = 0x00000065L;
    long CKM_SHA3_224_RSA_PKCS         = 0x00000066L;
    long CKM_SHA3_224_RSA_PKCS_PSS     = 0x00000067L;

    long CKM_RC2_KEY_GEN = 0x00000100L;
    long CKM_RC2_ECB = 0x00000101L;
    long CKM_RC2_CBC = 0x00000102L;
    long CKM_RC2_MAC = 0x00000103L;

    /* CKM_RC2_MAC_GENERAL and CKM_RC2_CBC_PAD are new for v2.0 */
    long CKM_RC2_MAC_GENERAL = 0x00000104L;
    long CKM_RC2_CBC_PAD = 0x00000105L;

    long CKM_RC4_KEY_GEN = 0x00000110L;
    long CKM_RC4 = 0x00000111L;
    long CKM_DES_KEY_GEN = 0x00000120L;
    long CKM_DES_ECB = 0x00000121L;
    long CKM_DES_CBC = 0x00000122L;
    long CKM_DES_MAC = 0x00000123L;

    /* CKM_DES_MAC_GENERAL and CKM_DES_CBC_PAD are new for v2.0 */
    long CKM_DES_MAC_GENERAL = 0x00000124L;
    long CKM_DES_CBC_PAD = 0x00000125L;

    long CKM_DES2_KEY_GEN = 0x00000130L;
    long CKM_DES3_KEY_GEN = 0x00000131L;
    long CKM_DES3_ECB = 0x00000132L;
    long CKM_DES3_CBC = 0x00000133L;
    long CKM_DES3_MAC = 0x00000134L;

    /*
     * CKM_DES3_MAC_GENERAL, CKM_DES3_CBC_PAD, CKM_CDMF_KEY_GEN, CKM_CDMF_ECB, CKM_CDMF_CBC,
     * CKM_CDMF_MAC, CKM_CDMF_MAC_GENERAL, and CKM_CDMF_CBC_PAD are new for v2.0
     */
    long CKM_DES3_MAC_GENERAL = 0x00000135L;
    long CKM_DES3_CBC_PAD = 0x00000136L;

    /* new in update to 2.40*/
    long CKM_DES3_CMAC_GENERAL = 0x00000137L;
    long CKM_DES3_CMAC = 0x00000138L;

    long CKM_CDMF_KEY_GEN = 0x00000140L;
    long CKM_CDMF_ECB = 0x00000141L;
    long CKM_CDMF_CBC = 0x00000142L;
    long CKM_CDMF_MAC = 0x00000143L;
    long CKM_CDMF_MAC_GENERAL = 0x00000144L;
    long CKM_CDMF_CBC_PAD = 0x00000145L;

    /* the following four DES mechanisms are new for v2.20 */
    long CKM_DES_OFB64 = 0x00000150L;
    long CKM_DES_OFB8 = 0x00000151L;
    long CKM_DES_CFB64 = 0x00000152L;
    long CKM_DES_CFB8 = 0x00000153L;

    long CKM_MD2 = 0x00000200L;

    /* CKM_MD2_HMAC and CKM_MD2_HMAC_GENERAL are new for v2.0 */
    long CKM_MD2_HMAC = 0x00000201L;
    long CKM_MD2_HMAC_GENERAL = 0x00000202L;

    long CKM_MD5 = 0x00000210L;

    /* CKM_MD5_HMAC and CKM_MD5_HMAC_GENERAL are new for v2.0 */
    long CKM_MD5_HMAC = 0x00000211L;
    long CKM_MD5_HMAC_GENERAL = 0x00000212L;

    long CKM_SHA_1 = 0x00000220L;

    /* CKM_SHA_1_HMAC and CKM_SHA_1_HMAC_GENERAL are new for v2.0 */
    long CKM_SHA_1_HMAC = 0x00000221L;
    long CKM_SHA_1_HMAC_GENERAL = 0x00000222L;

    /*
     * CKM_RIPEMD128, CKM_RIPEMD128_HMAC, CKM_RIPEMD128_HMAC_GENERAL, CKM_RIPEMD160,
     * CKM_RIPEMD160_HMAC, and CKM_RIPEMD160_HMAC_GENERAL are new for v2.10
     */
    long CKM_RIPEMD128 = 0x00000230L;
    long CKM_RIPEMD128_HMAC = 0x00000231L;
    long CKM_RIPEMD128_HMAC_GENERAL = 0x00000232L;
    long CKM_RIPEMD160 = 0x00000240L;
    long CKM_RIPEMD160_HMAC = 0x00000241L;
    long CKM_RIPEMD160_HMAC_GENERAL = 0x00000242L;

    /* CKM_SHA256/384/512 are new for v2.20 */
    long CKM_SHA256 = 0x00000250L;
    long CKM_SHA256_HMAC = 0x00000251L;
    long CKM_SHA256_HMAC_GENERAL = 0x00000252L;

    /* new in update to 2.40*/
    long CKM_SHA224 = 0x00000255L;
    long CKM_SHA224_HMAC = 0x00000256L;
    long CKM_SHA224_HMAC_GENERAL = 0x00000257L;

    long CKM_SHA384 = 0x00000260L;
    long CKM_SHA384_HMAC = 0x00000261L;
    long CKM_SHA384_HMAC_GENERAL = 0x00000262L;
    long CKM_SHA512 = 0x00000270L;
    long CKM_SHA512_HMAC = 0x00000271L;
    long CKM_SHA512_HMAC_GENERAL = 0x00000272L;

    /* new in update to 2.40*/
    long CKM_SECURID_KEY_GEN = 0x00000280L;
    long CKM_SECURID = 0x00000282L;
    long CKM_HOTP_KEY_GEN = 0x00000290L;
    long CKM_HOTP = 0x00000291L;
    long CKM_ACTI = 0x000002A0L;
    long CKM_ACTI_KEY_GEN = 0x000002A1L;

    /* new in update to 3.0 */
    long CKM_SHA3_256 =                   0x000002B0L;
    long CKM_SHA3_256_HMAC =              0x000002B1L;
    long CKM_SHA3_256_HMAC_GENERAL =      0x000002B2L;
    long CKM_SHA3_256_KEY_GEN =           0x000002B3L;
    long CKM_SHA3_224 =                   0x000002B5L;
    long CKM_SHA3_224_HMAC =              0x000002B6L;
    long CKM_SHA3_224_HMAC_GENERAL =      0x000002B7L;
    long CKM_SHA3_224_KEY_GEN =           0x000002B8L;
    long CKM_SHA3_384 =                   0x000002C0L;
    long CKM_SHA3_384_HMAC =              0x000002C1L;
    long CKM_SHA3_384_HMAC_GENERAL =      0x000002C2L;
    long CKM_SHA3_384_KEY_GEN =           0x000002C3L;
    long CKM_SHA3_512 =                   0x000002D0L;
    long CKM_SHA3_512_HMAC =              0x000002D1L;
    long CKM_SHA3_512_HMAC_GENERAL =      0x000002D2L;
    long CKM_SHA3_512_KEY_GEN =           0x000002D3L;

    /* All of the following mechanisms are new for v2.0 */
    /* Note that CAST128 and CAST5 are the same algorithm */
    long CKM_CAST_KEY_GEN = 0x00000300L;
    long CKM_CAST_ECB = 0x00000301L;
    long CKM_CAST_CBC = 0x00000302L;
    long CKM_CAST_MAC = 0x00000303L;
    long CKM_CAST_MAC_GENERAL = 0x00000304L;
    long CKM_CAST_CBC_PAD = 0x00000305L;
    long CKM_CAST3_KEY_GEN = 0x00000310L;
    long CKM_CAST3_ECB = 0x00000311L;
    long CKM_CAST3_CBC = 0x00000312L;
    long CKM_CAST3_MAC = 0x00000313L;
    long CKM_CAST3_MAC_GENERAL = 0x00000314L;
    long CKM_CAST3_CBC_PAD = 0x00000315L;
    long CKM_CAST5_KEY_GEN = 0x00000320L;
    long CKM_CAST128_KEY_GEN = 0x00000320L;
    long CKM_CAST5_ECB = 0x00000321L;
    long CKM_CAST128_ECB = 0x00000321L;
    long CKM_CAST5_CBC = 0x00000322L;
    long CKM_CAST128_CBC = 0x00000322L;
    long CKM_CAST5_MAC = 0x00000323L;
    long CKM_CAST128_MAC = 0x00000323L;
    long CKM_CAST5_MAC_GENERAL = 0x00000324L;
    long CKM_CAST128_MAC_GENERAL = 0x00000324L;
    long CKM_CAST5_CBC_PAD = 0x00000325L;
    long CKM_CAST128_CBC_PAD = 0x00000325L;
    long CKM_RC5_KEY_GEN = 0x00000330L;
    long CKM_RC5_ECB = 0x00000331L;
    long CKM_RC5_CBC = 0x00000332L;
    long CKM_RC5_MAC = 0x00000333L;
    long CKM_RC5_MAC_GENERAL = 0x00000334L;
    long CKM_RC5_CBC_PAD = 0x00000335L;
    long CKM_IDEA_KEY_GEN = 0x00000340L;
    long CKM_IDEA_ECB = 0x00000341L;
    long CKM_IDEA_CBC = 0x00000342L;
    long CKM_IDEA_MAC = 0x00000343L;
    long CKM_IDEA_MAC_GENERAL = 0x00000344L;
    long CKM_IDEA_CBC_PAD = 0x00000345L;
    long CKM_GENERIC_SECRET_KEY_GEN = 0x00000350L;
    long CKM_CONCATENATE_BASE_AND_KEY = 0x00000360L;
    long CKM_CONCATENATE_BASE_AND_DATA = 0x00000362L;
    long CKM_CONCATENATE_DATA_AND_BASE = 0x00000363L;
    long CKM_XOR_BASE_AND_DATA = 0x00000364L;
    long CKM_EXTRACT_KEY_FROM_KEY = 0x00000365L;
    long CKM_SSL3_PRE_MASTER_KEY_GEN = 0x00000370L;
    long CKM_SSL3_MASTER_KEY_DERIVE = 0x00000371L;
    long CKM_SSL3_KEY_AND_MAC_DERIVE = 0x00000372L;

    /*
     * CKM_SSL3_MASTER_KEY_DERIVE_DH, CKM_TLS_PRE_MASTER_KEY_GEN, CKM_TLS_MASTER_KEY_DERIVE,
     * CKM_TLS_KEY_AND_MAC_DERIVE, and CKM_TLS_MASTER_KEY_DERIVE_DH are new for v2.11
     */
    long CKM_SSL3_MASTER_KEY_DERIVE_DH = 0x00000373L;
    long CKM_TLS_PRE_MASTER_KEY_GEN = 0x00000374L;
    long CKM_TLS_MASTER_KEY_DERIVE = 0x00000375L;
    long CKM_TLS_KEY_AND_MAC_DERIVE = 0x00000376L;
    long CKM_TLS_MASTER_KEY_DERIVE_DH = 0x00000377L;

    /* CKM_TLS_PRF is new for v2.20 */
    long CKM_TLS_PRF = 0x00000378L;

    long CKM_SSL3_MD5_MAC = 0x00000380L;
    long CKM_SSL3_SHA1_MAC = 0x00000381L;
    long CKM_MD5_KEY_DERIVATION = 0x00000390L;
    long CKM_MD2_KEY_DERIVATION = 0x00000391L;
    long CKM_SHA1_KEY_DERIVATION = 0x00000392L;

    /* CKM_SHA256/384/512 are new for v2.20 */
    long CKM_SHA256_KEY_DERIVATION = 0x00000393L;
    long CKM_SHA384_KEY_DERIVATION = 0x00000394L;
    long CKM_SHA512_KEY_DERIVATION = 0x00000395L;

    /* new in update to 2.40*/
    long CKM_SHA224_KEY_DERIVATION = 0x00000396L;

    /* new in update to 3.0 */
    long CKM_SHA3_256_KEY_DERIVATION   = 0x00000397L;
    long CKM_SHA3_224_KEY_DERIVATION   = 0x00000398L;
    long CKM_SHA3_384_KEY_DERIVATION   = 0x00000399L;
    long CKM_SHA3_512_KEY_DERIVATION   = 0x0000039AL;
    long CKM_SHAKE_128_KEY_DERIVATION  = 0x0000039BL;
    long CKM_SHAKE_256_KEY_DERIVATION  = 0x0000039CL;
    long CKM_SHA3_256_KEY_DERIVE  = CKM_SHA3_256_KEY_DERIVATION	;
    long CKM_SHA3_224_KEY_DERIVE  = CKM_SHA3_224_KEY_DERIVATION	;
    long CKM_SHA3_384_KEY_DERIVE  = CKM_SHA3_384_KEY_DERIVATION	;
    long CKM_SHA3_512_KEY_DERIVE  = CKM_SHA3_512_KEY_DERIVATION	;
    long CKM_SHAKE_128_KEY_DERIVE = CKM_SHAKE_128_KEY_DERIVATION;
    long CKM_SHAKE_256_KEY_DERIVE = CKM_SHAKE_256_KEY_DERIVATION;


    long CKM_PBE_MD2_DES_CBC = 0x000003A0L;
    long CKM_PBE_MD5_DES_CBC = 0x000003A1L;
    long CKM_PBE_MD5_CAST_CBC = 0x000003A2L;
    long CKM_PBE_MD5_CAST3_CBC = 0x000003A3L;
    long CKM_PBE_MD5_CAST5_CBC = 0x000003A4L;
    long CKM_PBE_MD5_CAST128_CBC = 0x000003A4L; /* Deprecated */
    long CKM_PBE_SHA1_CAST5_CBC = 0x000003A5L;
    long CKM_PBE_SHA1_CAST128_CBC = 0x000003A5L; /* Deprecated */
    long CKM_PBE_SHA1_RC4_128 = 0x000003A6L;
    long CKM_PBE_SHA1_RC4_40 = 0x000003A7L;
    long CKM_PBE_SHA1_DES3_EDE_CBC = 0x000003A8L;
    long CKM_PBE_SHA1_DES2_EDE_CBC = 0x000003A9L;
    long CKM_PBE_SHA1_RC2_128_CBC = 0x000003AAL;
    long CKM_PBE_SHA1_RC2_40_CBC = 0x000003ABL;

    /* CKM_PKCS5_PBKD2 is new for v2.10 */
    long CKM_PKCS5_PBKD2 = 0x000003B0L;

    long CKM_PBA_SHA1_WITH_SHA1_HMAC = 0x000003C0L;

    /* WTLS mechanisms are new for v2.20 */
    long CKM_WTLS_PRE_MASTER_KEY_GEN = 0x000003D0L;
    long CKM_WTLS_MASTER_KEY_DERIVE = 0x000003D1L;
    long CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC = 0x000003D2L;
    /* typo in v2.20 */
    long CKM_WTLS_MASTER_KEY_DERVIE_DH_ECC = 0x000003D2L;
    long CKM_WTLS_PRF = 0x000003D3L;
    long CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE = 0x000003D4L;
    long CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE = 0x000003D5L;


    /* new in update to 2.40*/
    long CKM_TLS10_MAC_SERVER = 0x000003D6L;
    long CKM_TLS10_MAC_CLIENT = 0x000003D7L;
    long CKM_TLS12_MAC = 0x000003D8L;
    long CKM_TLS12_KDF = 0x000003D9L;
    long CKM_TLS12_MASTER_KEY_DERIVE = 0x000003E0L;
    long CKM_TLS12_KEY_AND_MAC_DERIVE = 0x000003E1L;
    long CKM_TLS12_MASTER_KEY_DERIVE_DH = 0x000003E2L;
    long CKM_TLS12_KEY_SAFE_DERIVE = 0x000003E3L;
    long CKM_TLS_MAC = 0x000003E4L;
    long CKM_TLS_KDF = 0x000003E5L;

    long CKM_KEY_WRAP_LYNKS = 0x00000400L;
    long CKM_KEY_WRAP_SET_OAEP = 0x00000401L;

    /* CKM_CMS_SIG is new for v2.20 */
    long CKM_CMS_SIG = 0x00000500L;

    /* new in update to 2.40*/
    long CKM_KIP_DERIVE = 0x00000510L;
    long CKM_KIP_WRAP = 0x00000511L;
    long CKM_KIP_MAC = 0x00000512L;
    long CKM_CAMELLIA_KEY_GEN = 0x00000550L;
    long CKM_CAMELLIA_ECB = 0x00000551L;
    long CKM_CAMELLIA_CBC = 0x00000552L;
    long CKM_CAMELLIA_MAC = 0x00000553L;
    long CKM_CAMELLIA_MAC_GENERAL = 0x00000554L;
    long CKM_CAMELLIA_CBC_PAD = 0x00000555L;
    long CKM_CAMELLIA_ECB_ENCRYPT_DATA = 0x00000556L;
    long CKM_CAMELLIA_CBC_ENCRYPT_DATA = 0x00000557L;
    long CKM_CAMELLIA_CTR = 0x00000558L;
    long CKM_ARIA_KEY_GEN = 0x00000560L;
    long CKM_ARIA_ECB = 0x00000561L;
    long CKM_ARIA_CBC = 0x00000562L;
    long CKM_ARIA_MAC = 0x00000563L;
    long CKM_ARIA_MAC_GENERAL = 0x00000564L;
    long CKM_ARIA_CBC_PAD = 0x00000565L;
    long CKM_ARIA_ECB_ENCRYPT_DATA = 0x00000566L;
    long CKM_ARIA_CBC_ENCRYPT_DATA = 0x00000567L;
    long CKM_SEED_KEY_GEN = 0x00000650L;
    long CKM_SEED_ECB = 0x00000651L;
    long CKM_SEED_CBC = 0x00000652L;
    long CKM_SEED_MAC = 0x00000653L;
    long CKM_SEED_MAC_GENERAL = 0x00000654L;
    long CKM_SEED_CBC_PAD = 0x00000655L;
    long CKM_SEED_ECB_ENCRYPT_DATA = 0x00000656L;
    long CKM_SEED_CBC_ENCRYPT_DATA = 0x00000657L;


    /* Fortezza mechanisms */
    long CKM_SKIPJACK_KEY_GEN = 0x00001000L;
    long CKM_SKIPJACK_ECB64 = 0x00001001L;
    long CKM_SKIPJACK_CBC64 = 0x00001002L;
    long CKM_SKIPJACK_OFB64 = 0x00001003L;
    long CKM_SKIPJACK_CFB64 = 0x00001004L;
    long CKM_SKIPJACK_CFB32 = 0x00001005L;
    long CKM_SKIPJACK_CFB16 = 0x00001006L;
    long CKM_SKIPJACK_CFB8 = 0x00001007L;
    long CKM_SKIPJACK_WRAP = 0x00001008L;
    long CKM_SKIPJACK_PRIVATE_WRAP = 0x00001009L;
    long CKM_SKIPJACK_RELAYX = 0x0000100AL;
    long CKM_KEA_KEY_PAIR_GEN = 0x00001010L;
    long CKM_KEA_KEY_DERIVE = 0x00001011L;
    long CKM_FORTEZZA_TIMESTAMP = 0x00001020L;
    long CKM_BATON_KEY_GEN = 0x00001030L;
    long CKM_BATON_ECB128 = 0x00001031L;
    long CKM_BATON_ECB96 = 0x00001032L;
    long CKM_BATON_CBC128 = 0x00001033L;
    long CKM_BATON_COUNTER = 0x00001034L;
    long CKM_BATON_SHUFFLE = 0x00001035L;
    long CKM_BATON_WRAP = 0x00001036L;

    /*
     * CKM_ECDSA_KEY_PAIR_GEN is deprecated in v2.11, CKM_EC_KEY_PAIR_GEN is preferred
     */
    long CKM_ECDSA_KEY_PAIR_GEN = 0x00001040L;
    long CKM_EC_KEY_PAIR_GEN = 0x00001040L;

    long CKM_ECDSA = 0x00001041L;
    long CKM_ECDSA_SHA1 = 0x00001042L;

    /* new in update to 2.40*/
    long CKM_ECDSA_SHA224 = 0x00001043L;
    long CKM_ECDSA_SHA256 = 0x00001044L;
    long CKM_ECDSA_SHA384 = 0x00001045L;
    long CKM_ECDSA_SHA512 = 0x00001046L;
    /*
     * CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE, and CKM_ECMQV_DERIVE are new for v2.11
     */
    long CKM_ECDH1_DERIVE = 0x00001050L;
    long CKM_ECDH1_COFACTOR_DERIVE = 0x00001051L;
    long CKM_ECMQV_DERIVE = 0x00001052L;

    /* new in update to 2.40*/
    long CKM_ECDH_AES_KEY_WRAP = 0x00001053L;
    long CKM_RSA_AES_KEY_WRAP = 0x00001054L;

    long CKM_JUNIPER_KEY_GEN = 0x00001060L;
    long CKM_JUNIPER_ECB128 = 0x00001061L;
    long CKM_JUNIPER_CBC128 = 0x00001062L;
    long CKM_JUNIPER_COUNTER = 0x00001063L;
    long CKM_JUNIPER_SHUFFLE = 0x00001064L;
    long CKM_JUNIPER_WRAP = 0x00001065L;
    long CKM_FASTHASH = 0x00001070L;

    /*
     * CKM_AES_KEY_GEN, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_MAC, CKM_AES_MAC_GENERAL, CKM_AES_CBC_PAD,
     * CKM_DSA_PARAMETER_GEN, CKM_DH_PKCS_PARAMETER_GEN, and CKM_X9_42_DH_PARAMETER_GEN are new for
     * v2.11
     */
    long CKM_AES_KEY_GEN = 0x00001080L;
    long CKM_AES_ECB = 0x00001081L;
    long CKM_AES_CBC = 0x00001082L;
    long CKM_AES_MAC = 0x00001083L;
    long CKM_AES_MAC_GENERAL = 0x00001084L;
    long CKM_AES_CBC_PAD = 0x00001085L;
    long CKM_AES_CTR = 0x00001086L;

    long CKM_AES_GCM = 0x00001087L;
    long CKM_AES_CCM = 0x00001088L;

    /* new in update to 2.40*/
    long CKM_AES_CTS = 0x00001089L;
    long CKM_AES_CMAC = 0x0000108AL;
    long CKM_AES_CMAC_GENERAL = 0x0000108BL;
    long CKM_AES_XCBC_MAC = 0x0000108CL;
    long CKM_AES_XCBC_MAC_96 = 0x0000108DL;
    long CKM_AES_GMAC = 0x0000108EL;

    /* BlowFish and TwoFish are new for v2.20 */
    long CKM_BLOWFISH_KEY_GEN = 0x00001090L;
    long CKM_BLOWFISH_CBC = 0x00001091L;
    long CKM_TWOFISH_KEY_GEN = 0x00001092L;
    long CKM_TWOFISH_CBC = 0x00001093L;

    /* new in update to 2.40*/
    long CKM_BLOWFISH_CBC_PAD = 0x00001094L;
    long CKM_TWOFISH_CBC_PAD = 0x00001095L;

    /* CKM_xxx_ENCRYPT_DATA mechanisms are new for v2.20 */
    long CKM_DES_ECB_ENCRYPT_DATA = 0x00001100L;
    long CKM_DES_CBC_ENCRYPT_DATA = 0x00001101L;
    long CKM_DES3_ECB_ENCRYPT_DATA = 0x00001102L;
    long CKM_DES3_CBC_ENCRYPT_DATA = 0x00001103L;
    long CKM_AES_ECB_ENCRYPT_DATA = 0x00001104L;
    long CKM_AES_CBC_ENCRYPT_DATA = 0x00001105L;

    /* new in update to 2.40*/

    long CKM_GOSTR3410_KEY_PAIR_GEN = 0x00001200L;
    long CKM_GOSTR3410 = 0x00001201L;
    long CKM_GOSTR3410_WITH_GOSTR3411 = 0x00001202L;
    long CKM_GOSTR3410_KEY_WRAP = 0x00001203L;
    long CKM_GOSTR3410_DERIVE = 0x00001204L;
    long CKM_GOSTR3411 = 0x00001210L;
    long CKM_GOSTR3411_HMAC = 0x00001211L;
    long CKM_GOST28147_KEY_GEN = 0x00001220L;
    long CKM_GOST28147_ECB = 0x00001221L;
    long CKM_GOST28147 = 0x00001222L;
    long CKM_GOST28147_MAC = 0x00001223L;
    long CKM_GOST28147_KEY_WRAP = 0x00001224L;

    long CKM_DSA_PARAMETER_GEN = 0x00002000L;
    long CKM_DH_PKCS_PARAMETER_GEN = 0x00002001L;
    long CKM_X9_42_DH_PARAMETER_GEN = 0x00002002L;

    long CKM_DSA_PROBABLISTIC_PARAMETER_GEN = 0x00002003L;
    long CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN = 0x00002004L;

    long CKM_AES_OFB = 0x00002104L;
    long CKM_AES_CFB64 = 0x00002105L;
    long CKM_AES_CFB8 = 0x00002106L;
    long CKM_AES_CFB128 = 0x00002107L;
    long CKM_AES_CFB1 = 0x00002108L;

    long CKM_AES_KEY_WRAP = 0x00002109L     /* WAS: 0x00001090 */;
    long CKM_AES_KEY_WRAP_PAD = 0x0000210AL     /* WAS: 0x00001091 */;
    long CKM_RSA_PKCS_TPM_1_1 = 0x00004001L;
    long CKM_RSA_PKCS_OAEP_TPM_1_1 = 0x00004002L;

    /* new in update to 3.0 = */
    long CKM_SHA_1_KEY_GEN              = 0x00004003L;
    long CKM_SHA224_KEY_GEN             = 0x00004004L;
    long CKM_SHA256_KEY_GEN             = 0x00004005L;
    long CKM_SHA384_KEY_GEN             = 0x00004006L;
    long CKM_SHA512_KEY_GEN             = 0x00004007L;
    long CKM_SHA512_224_KEY_GEN         = 0x00004008L;
    long CKM_SHA512_256_KEY_GEN         = 0x00004009L;
    long CKM_SHA512_T_KEY_GEN           = 0x0000400aL;
    long CKM_NULL                       = 0x0000400bL;
    long CKM_BLAKE2B_160                = 0x0000400cL;
    long CKM_BLAKE2B_160_HMAC           = 0x0000400dL;
    long CKM_BLAKE2B_160_HMAC_GENERAL   = 0x0000400eL;
    long CKM_BLAKE2B_160_KEY_DERIVE     = 0x0000400fL;
    long CKM_BLAKE2B_160_KEY_GEN        = 0x00004010L;
    long CKM_BLAKE2B_256                = 0x00004011L;
    long CKM_BLAKE2B_256_HMAC           = 0x00004012L;
    long CKM_BLAKE2B_256_HMAC_GENERAL   = 0x00004013L;
    long CKM_BLAKE2B_256_KEY_DERIVE     = 0x00004014L;
    long CKM_BLAKE2B_256_KEY_GEN        = 0x00004015L;
    long CKM_BLAKE2B_384                = 0x00004016L;
    long CKM_BLAKE2B_384_HMAC           = 0x00004017L;
    long CKM_BLAKE2B_384_HMAC_GENERAL   = 0x00004018L;
    long CKM_BLAKE2B_384_KEY_DERIVE     = 0x00004019L;
    long CKM_BLAKE2B_384_KEY_GEN        = 0x0000401aL;
    long CKM_BLAKE2B_512                = 0x0000401bL;
    long CKM_BLAKE2B_512_HMAC           = 0x0000401cL;
    long CKM_BLAKE2B_512_HMAC_GENERAL   = 0x0000401dL;
    long CKM_BLAKE2B_512_KEY_DERIVE     = 0x0000401eL;
    long CKM_BLAKE2B_512_KEY_GEN        = 0x0000401fL;
    long CKM_SALSA20                    = 0x00004020L;
    long CKM_CHACHA20_POLY1305          = 0x00004021L;
    long CKM_SALSA20_POLY1305           = 0x00004022L;
    long CKM_X3DH_INITIALIZE            = 0x00004023L;
    long CKM_X3DH_RESPOND               = 0x00004024L;
    long CKM_X2RATCHET_INITIALIZE       = 0x00004025L;
    long CKM_X2RATCHET_RESPOND          = 0x00004026L;
    long CKM_X2RATCHET_ENCRYPT          = 0x00004027L;
    long CKM_X2RATCHET_DECRYPT          = 0x00004028L;
    long CKM_XEDDSA                     = 0x00004029L;
    long CKM_HKDF_DERIVE                = 0x0000402aL;
    long CKM_HKDF_DATA                  = 0x0000402bL;
    long CKM_HKDF_KEY_GEN               = 0x0000402cL;
    long CKM_SALSA20_KEY_GEN            = 0x0000402dL;
    long CKM_ECDSA_SHA3_224             = 0x00001047L;
    long CKM_ECDSA_SHA3_256             = 0x00001048L;
    long CKM_ECDSA_SHA3_384             = 0x00001049L;
    long CKM_ECDSA_SHA3_512             = 0x0000104aL;
    long CKM_EC_EDWARDS_KEY_PAIR_GEN    = 0x00001055L;
    long CKM_EC_MONTGOMERY_KEY_PAIR_GEN = 0x00001056L;
    long CKM_EDDSA                      = 0x00001057L;
    long CKM_SP800_108_COUNTER_KDF      = 0x000003acL;
    long CKM_SP800_108_FEEDBACK_KDF     = 0x000003adL;
    long CKM_SP800_108_DOUBLE_PIPELINE_KDF = 0x000003aeL;

    long CKM_VENDOR_DEFINED = 0x80000000L;


    /**
     * Start of vendor defiened algorithms:
     */

    long CKM_ECDSA_ECIES = CKM_VENDOR_DEFINED | 0x00001201L;
    long CKM_ECDSA_ECIES_XOR = CKM_VENDOR_DEFINED | 0x00001202L;

    /*
     * The flags are defined as follows: Bit Flag Mask Meaning
     */
    long CKF_HW = 0x00000001L; /* performed by HW */

    /*
     * The flags CKF_ENCRYPT, CKF_DECRYPT, CKF_DIGEST, CKF_SIGN, CKF_SIGN_RECOVER, CKF_VERIFY,
     * CKF_VERIFY_RECOVER, CKF_GENERATE, CKF_GENERATE_KEY_PAIR, CKF_WRAP, CKF_UNWRAP, and CKF_DERIVE
     * are new for v2.0. They specify whether or not a mechanism can be used for a particular task
     */
    long CKF_ENCRYPT = 0x00000100L;
    long CKF_DECRYPT = 0x00000200L;
    long CKF_DIGEST = 0x00000400L;
    long CKF_SIGN = 0x00000800L;
    long CKF_SIGN_RECOVER = 0x00001000L;
    long CKF_VERIFY = 0x00002000L;
    long CKF_VERIFY_RECOVER = 0x00004000L;
    long CKF_GENERATE = 0x00008000L;
    long CKF_GENERATE_KEY_PAIR = 0x00010000L;
    long CKF_WRAP = 0x00020000L;
    long CKF_UNWRAP = 0x00040000L;
    long CKF_DERIVE = 0x00080000L;

    /*
     * CKF_EC_F_P, CKF_EC_F_2M, CKF_EC_ECPARAMETERS, CKF_EC_NAMEDCURVE, CKF_EC_UNCOMPRESS, and
     * CKF_EC_COMPRESS are new for v2.11. They describe a token's EC capabilities not available in
     * mechanism information.
     */
    long CKF_EC_F_P = 0x00100000L;
    long CKF_EC_F_2M = 0x00200000L;
    long CKF_EC_ECPARAMETERS = 0x00400000L;
    long CKF_EC_NAMEDCURVE = 0x00800000L;
    long CKF_EC_UNCOMPRESS = 0x01000000L;
    long CKF_EC_COMPRESS = 0x02000000L;

    long CKF_EXTENSION = 0x80000000L; /* FALSE for 2.01 */

    /*
     * CK_RV is a value that identifies the return value of a Cryptoki function
     */
    /* CK_RV was changed from CK_USHORT to CK_ULONG for v2.0 */
    long CKR_OK = 0x00000000L;
    long CKR_CANCEL = 0x00000001L;
    long CKR_HOST_MEMORY = 0x00000002L;
    long CKR_SLOT_ID_INVALID = 0x00000003L;

    /* CKR_FLAGS_INVALID was removed for v2.0 */

    /* CKR_GENERAL_ERROR and CKR_FUNCTION_FAILED are new for v2.0 */
    long CKR_GENERAL_ERROR = 0x00000005L;
    long CKR_FUNCTION_FAILED = 0x00000006L;

    /*
     * CKR_ARGUMENTS_BAD, CKR_NO_EVENT, CKR_NEED_TO_CREATE_THREADS, and CKR_CANT_LOCK are new for
     * v2.01
     */
    long CKR_ARGUMENTS_BAD = 0x00000007L;
    long CKR_NO_EVENT = 0x00000008L;
    long CKR_NEED_TO_CREATE_THREADS = 0x00000009L;
    long CKR_CANT_LOCK = 0x0000000AL;

    long CKR_ATTRIBUTE_READ_ONLY = 0x00000010L;
    long CKR_ATTRIBUTE_SENSITIVE = 0x00000011L;
    long CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012L;
    long CKR_ATTRIBUTE_VALUE_INVALID = 0x00000013L;

    /* new in update to 2.40*/
    long CKR_ACTION_PROHIBITED = 0x0000001BL;


    long CKR_DATA_INVALID = 0x00000020L;
    long CKR_DATA_LEN_RANGE = 0x00000021L;
    long CKR_DEVICE_ERROR = 0x00000030L;
    long CKR_DEVICE_MEMORY = 0x00000031L;
    long CKR_DEVICE_REMOVED = 0x00000032L;
    long CKR_ENCRYPTED_DATA_INVALID = 0x00000040L;
    long CKR_ENCRYPTED_DATA_LEN_RANGE = 0x00000041L;
    long CKR_FUNCTION_CANCELED = 0x00000050L;
    long CKR_FUNCTION_NOT_PARALLEL = 0x00000051L;

    /* CKR_FUNCTION_NOT_SUPPORTED is new for v2.0 */
    long CKR_FUNCTION_NOT_SUPPORTED = 0x00000054L;

    long CKR_KEY_HANDLE_INVALID = 0x00000060L;

    /* CKR_KEY_SENSITIVE was removed for v2.0 */

    long CKR_KEY_SIZE_RANGE = 0x00000062L;
    long CKR_KEY_TYPE_INCONSISTENT = 0x00000063L;

    /*
     * CKR_KEY_NOT_NEEDED, CKR_KEY_CHANGED, CKR_KEY_NEEDED, CKR_KEY_INDIGESTIBLE,
     * CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_NOT_WRAPPABLE, and CKR_KEY_UNEXTRACTABLE are new for
     * v2.0
     */
    long CKR_KEY_NOT_NEEDED = 0x00000064L;
    long CKR_KEY_CHANGED = 0x00000065L;
    long CKR_KEY_NEEDED = 0x00000066L;
    long CKR_KEY_INDIGESTIBLE = 0x00000067L;
    long CKR_KEY_FUNCTION_NOT_PERMITTED = 0x00000068L;
    long CKR_KEY_NOT_WRAPPABLE = 0x00000069L;
    long CKR_KEY_UNEXTRACTABLE = 0x0000006AL;

    long CKR_MECHANISM_INVALID = 0x00000070L;
    long CKR_MECHANISM_PARAM_INVALID = 0x00000071L;

    /*
     * CKR_OBJECT_CLASS_INCONSISTENT and CKR_OBJECT_CLASS_INVALID were removed for v2.0
     */
    long CKR_OBJECT_HANDLE_INVALID = 0x00000082L;
    long CKR_OPERATION_ACTIVE = 0x00000090L;
    long CKR_OPERATION_NOT_INITIALIZED = 0x00000091L;
    long CKR_PIN_INCORRECT = 0x000000A0L;
    long CKR_PIN_INVALID = 0x000000A1L;
    long CKR_PIN_LEN_RANGE = 0x000000A2L;

    /* CKR_PIN_EXPIRED and CKR_PIN_LOCKED are new for v2.0 */
    long CKR_PIN_EXPIRED = 0x000000A3L;
    long CKR_PIN_LOCKED = 0x000000A4L;

    long CKR_SESSION_CLOSED = 0x000000B0L;
    long CKR_SESSION_COUNT = 0x000000B1L;
    long CKR_SESSION_HANDLE_INVALID = 0x000000B3L;
    long CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x000000B4L;
    long CKR_SESSION_READ_ONLY = 0x000000B5L;
    long CKR_SESSION_EXISTS = 0x000000B6L;

    /*
     * CKR_SESSION_READ_ONLY_EXISTS and CKR_SESSION_READ_WRITE_SO_EXISTS are new for v2.0
     */
    long CKR_SESSION_READ_ONLY_EXISTS = 0x000000B7L;
    long CKR_SESSION_READ_WRITE_SO_EXISTS = 0x000000B8L;

    long CKR_SIGNATURE_INVALID = 0x000000C0L;
    long CKR_SIGNATURE_LEN_RANGE = 0x000000C1L;
    long CKR_TEMPLATE_INCOMPLETE = 0x000000D0L;
    long CKR_TEMPLATE_INCONSISTENT = 0x000000D1L;
    long CKR_TOKEN_NOT_PRESENT = 0x000000E0L;
    long CKR_TOKEN_NOT_RECOGNIZED = 0x000000E1L;
    long CKR_TOKEN_WRITE_PROTECTED = 0x000000E2L;
    long CKR_UNWRAPPING_KEY_HANDLE_INVALID = 0x000000F0L;
    long CKR_UNWRAPPING_KEY_SIZE_RANGE = 0x000000F1L;
    long CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 0x000000F2L;
    long CKR_USER_ALREADY_LOGGED_IN = 0x00000100L;
    long CKR_USER_NOT_LOGGED_IN = 0x00000101L;
    long CKR_USER_PIN_NOT_INITIALIZED = 0x00000102L;
    long CKR_USER_TYPE_INVALID = 0x00000103L;

    /*
     * CKR_USER_ANOTHER_ALREADY_LOGGED_IN and CKR_USER_TOO_MANY_TYPES are new to v2.01
     */
    long CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 0x00000104L;
    long CKR_USER_TOO_MANY_TYPES = 0x00000105L;

    long CKR_WRAPPED_KEY_INVALID = 0x00000110L;
    long CKR_WRAPPED_KEY_LEN_RANGE = 0x00000112L;
    long CKR_WRAPPING_KEY_HANDLE_INVALID = 0x00000113L;
    long CKR_WRAPPING_KEY_SIZE_RANGE = 0x00000114L;
    long CKR_WRAPPING_KEY_TYPE_INCONSISTENT = 0x00000115L;
    long CKR_RANDOM_SEED_NOT_SUPPORTED = 0x00000120L;

    /* These are new to v2.0 */
    long CKR_RANDOM_NO_RNG = 0x00000121L;

    /* These are new to v2.11 */
    long CKR_DOMAIN_PARAMS_INVALID = 0x00000130L;

    /* new in update to 2.40*/
    long CKR_CURVE_NOT_SUPPORTED = 0x00000140L;


    /* These are new to v2.0 */
    long CKR_BUFFER_TOO_SMALL = 0x00000150L;
    long CKR_SAVED_STATE_INVALID = 0x00000160L;
    long CKR_INFORMATION_SENSITIVE = 0x00000170L;
    long CKR_STATE_UNSAVEABLE = 0x00000180L;

    /* These are new to v2.01 */
    long CKR_CRYPTOKI_NOT_INITIALIZED = 0x00000190L;
    long CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191L;
    long CKR_MUTEX_BAD = 0x000001A0L;
    long CKR_MUTEX_NOT_LOCKED = 0x000001A1L;

    /* new in update to 2.40*/
    long CKR_NEW_PIN_MODE = 0x000001B0L;
    long CKR_NEXT_OTP = 0x000001B1L;
    long CKR_EXCEEDED_MAX_ITERATIONS = 0x000001B5L;
    long CKR_FIPS_SELF_TEST_FAILED = 0x000001B6L;
    long CKR_LIBRARY_LOAD_FAILED = 0x000001B7L;
    long CKR_PIN_TOO_WEAK = 0x000001B8L;
    long CKR_PUBLIC_KEY_INVALID = 0x000001B9L;

    /* This is new to v2.20 */
    long CKR_FUNCTION_REJECTED = 0x00000200L;
    
    /* This is new to v3.0 */
    long CKR_TOKEN_RESOURCE_EXCEEDED           = 0x00000201L;
    long CKR_OPERATION_CANCEL_FAILED           = 0x00000202L;

    long CKR_VENDOR_DEFINED = 0x80000000L;

    /*
     * flags: bit flags that provide capabilities of the slot Bit Flag = Mask
     */
    long CKF_LIBRARY_CANT_CREATE_OS_THREADS = 0x00000001L;
    long CKF_OS_LOCKING_OK = 0x00000002L;

    /* CKF_DONT_BLOCK is for the function C_WaitForSlotEvent */
    long CKF_DONT_BLOCK = 1L;

    /* The following MGFs are defined */
    long CKG_MGF1_SHA1 = 0x00000001L;
    /* SHA256, SHA384 and SHA512 are new for v2.20 */
    long CKG_MGF1_SHA256 = 0x00000002L;
    long CKG_MGF1_SHA384 = 0x00000003L;
    long CKG_MGF1_SHA512 = 0x00000004L;
    /* new in update to 2.40*/
    long CKG_MGF1_SHA224 = 0x00000005L;
    /* new in update to 3.0 */
    long CKG_MGF1_SHA3_224 = 0x00000006L;
    long CKG_MGF1_SHA3_256 = 0x00000007L;
    long CKG_MGF1_SHA3_384 = 0x00000008L;
    long CKG_MGF1_SHA3_512 = 0x00000009L;


    /* new in update 3.0*/
    long CKG_NO_GENERATE = 0x00000000L;
    long CKG_GENERATE = 0x00000001L;
    long CKG_GENERATE_COUNTER = 0x00000002L;
    long CKG_GENERATE_RANDOM = 0x00000003L;


    /* The following encoding parameter sources are defined */
    long CKZ_DATA_SPECIFIED = 0x00000001L;

    /* the following EC Key Derivation Functions are defined */
    long CKD_NULL = 0x00000001L;
    long CKD_SHA1_KDF = 0x00000002L;

    /* the following X9.42 Diffie-Hellman Key Derivation Functions are defined */
    long CKD_SHA1_KDF_ASN1 = 0x00000003L;
    long CKD_SHA1_KDF_CONCATENATE = 0x00000004L;

    long CKD_SHA224_KDF = 0x00000005L;
    long CKD_SHA256_KDF = 0x00000006L;
    long CKD_SHA384_KDF = 0x00000007L;
    long CKD_SHA512_KDF = 0x00000008L;

    /* new in update to 2.40*/
    long CKD_CPDIVERSIFY_KDF = 0x00000009L;

    /* new in update to 3.0 */
    long CKD_SHA3_224_KDF         = 0x0000000AL;
    long CKD_SHA3_256_KDF         = 0x0000000BL;
    long CKD_SHA3_384_KDF         = 0x0000000CL;
    long CKD_SHA3_512_KDF         = 0x0000000DL;
    long CKD_SHA1_KDF_SP800       = 0x0000000EL;
    long CKD_SHA224_KDF_SP800     = 0x0000000FL;
    long CKD_SHA256_KDF_SP800     = 0x00000010L;
    long CKD_SHA384_KDF_SP800     = 0x00000011L;
    long CKD_SHA512_KDF_SP800     = 0x00000012L;
    long CKD_SHA3_224_KDF_SP800   = 0x00000013L;
    long CKD_SHA3_256_KDF_SP800   = 0x00000014L;
    long CKD_SHA3_384_KDF_SP800   = 0x00000015L;
    long CKD_SHA3_512_KDF_SP800   = 0x00000016L;
    long CKD_BLAKE2B_160_KDF      = 0x00000017L;
    long CKD_BLAKE2B_256_KDF      = 0x00000018L;
    long CKD_BLAKE2B_384_KDF      = 0x00000019L;
    long CKD_BLAKE2B_512_KDF      = 0x0000001aL;


    /* The following PRFs are defined in PKCS #5 v2.0. */
    long CKP_PKCS5_PBKD2_HMAC_SHA1 = 0x00000001L;
    /* new in update to 2.40*/
    long CKP_PKCS5_PBKD2_HMAC_GOSTR3411 = 0x00000002L;
    long CKP_PKCS5_PBKD2_HMAC_SHA224 = 0x00000003L;
    long CKP_PKCS5_PBKD2_HMAC_SHA256 = 0x00000004L;
    long CKP_PKCS5_PBKD2_HMAC_SHA384 = 0x00000005L;
    long CKP_PKCS5_PBKD2_HMAC_SHA512 = 0x00000006L;
    long CKP_PKCS5_PBKD2_HMAC_SHA512_224 = 0x00000007L;
    long CKP_PKCS5_PBKD2_HMAC_SHA512_256 = 0x00000008L;


    /* The following salt value sources are defined in PKCS #5 v2.0. */
    long CKZ_SALT_SPECIFIED = 0x00000001L;

    /* new in update to 2.40*/
    long CKF_NEXT_OTP = 0x00000001L;
    long CKF_EXCLUDE_TIME = 0x00000002L;
    long CKF_EXCLUDE_COUNTER = 0x00000004L;
    long CKF_EXCLUDE_CHALLENGE = 0x00000008L;
    long CKF_EXCLUDE_PIN = 0x00000010L;
    long CKF_USER_FRIENDLY_OTP = 0x00000020L;


    /* The string constants for the mechanism names */
    String NAME_CKM_RSA_PKCS_KEY_PAIR_GEN = "CKM_RSA_PKCS_KEY_PAIR_GEN";
    String NAME_CKM_RSA_PKCS = "CKM_RSA_PKCS";
    String NAME_CKM_RSA_9796 = "CKM_RSA_9796";
    String NAME_CKM_RSA_X_509 = "CKM_RSA_X_509";
    String NAME_CKM_MD2_RSA_PKCS = "CKM_MD2_RSA_PKCS";
    String NAME_CKM_MD5_RSA_PKCS = "CKM_MD5_RSA_PKCS";
    String NAME_CKM_SHA1_RSA_PKCS = "CKM_SHA1_RSA_PKCS";
    String NAME_CKM_RIPEMD128_RSA_PKCS = "CKM_RIPEMD128_RSA_PKCS";
    String NAME_CKM_RIPEMD160_RSA_PKCS = "CKM_RIPEMD160_RSA_PKCS";
    String NAME_CKM_RSA_PKCS_OAEP = "CKM_RSA_PKCS_OAEP";
    String NAME_CKM_RSA_X9_31_KEY_PAIR_GEN = "CKM_RSA_X9_31_KEY_PAIR_GEN";
    String NAME_CKM_RSA_X9_31 = "CKM_RSA_X9_31";
    String NAME_CKM_SHA1_RSA_X9_31 = "CKM_SHA1_RSA_X9_31";
    String NAME_CKM_RSA_PKCS_PSS = "CKM_RSA_PKCS_PSS";
    String NAME_CKM_SHA1_RSA_PKCS_PSS = "CKM_SHA1_RSA_PKCS_PSS";
    String NAME_CKM_DSA_KEY_PAIR_GEN = "CKM_DSA_KEY_PAIR_GEN";
    String NAME_CKM_DSA = "CKM_DSA";
    String NAME_CKM_DSA_SHA1 = "CKM_DSA_SHA1";
    String NAME_CKM_DSA_SHA224 = "CKM_DSA_SHA224";
    String NAME_CKM_DSA_SHA256 = "CKM_DSA_SHA256";
    String NAME_CKM_DSA_SHA384 = "CKM_DSA_SHA384";
    String NAME_CKM_DSA_SHA512 = "CKM_DSA_SHA512";
    String NAME_CKM_DH_PKCS_KEY_PAIR_GEN = "CKM_DH_PKCS_KEY_PAIR_GEN";
    String NAME_CKM_DH_PKCS_DERIVE = "CKM_DH_PKCS_DERIVE";
    String NAME_CKM_X9_42_DH_KEY_PAIR_GEN = "CKM_X9_42_DH_KEY_PAIR_GEN";
    String NAME_CKM_X9_42_DH_DERIVE = "CKM_X9_42_DH_DERIVE";
    String NAME_CKM_X9_42_DH_HYBRID_DERIVE = "CKM_X9_42_DH_HYBRID_DERIVE";
    String NAME_CKM_X9_42_MQV_DERIVE = "CKM_X9_42_MQV_DERIVE";
    String NAME_CKM_SHA256_RSA_PKCS = "CKM_SHA256_RSA_PKCS";
    String NAME_CKM_SHA384_RSA_PKCS = "CKM_SHA384_RSA_PKCS";
    String NAME_CKM_SHA512_RSA_PKCS = "CKM_SHA512_RSA_PKCS";
    String NAME_CKM_SHA256_RSA_PKCS_PSS = "CKM_SHA256_RSA_PKCS_PSS";
    String NAME_CKM_SHA384_RSA_PKCS_PSS = "CKM_SHA384_RSA_PKCS_PSS";
    String NAME_CKM_SHA512_RSA_PKCS_PSS = "CKM_SHA512_RSA_PKCS_PSS";
    String NAME_CKM_SHA224_RSA_PKCS = "CKM_SHA224_RSA_PKCS";
    String NAME_CKM_SHA224_RSA_PKCS_PSS = "CKM_SHA224_RSA_PKCS_PSS";
    String NAME_CKM_SHA512_224 = "CKM_SHA512_224";
    String NAME_CKM_SHA512_224_HMAC = "CKM_SHA512_224_HMAC";
    String NAME_CKM_SHA512_224_HMAC_GENERAL = "CKM_SHA512_224_HMAC_GENERAL";
    String NAME_CKM_SHA512_224_KEY_DERIVATION = "CKM_SHA512_224_KEY_DERIVATION";
    String NAME_CKM_SHA512_256 = "CKM_SHA512_256";
    String NAME_CKM_SHA512_256_HMAC = "CKM_SHA512_256_HMAC";
    String NAME_CKM_SHA512_256_HMAC_GENERAL = "CKM_SHA512_256_HMAC_GENERAL";
    String NAME_CKM_SHA512_256_KEY_DERIVATION = "CKM_SHA512_256_KEY_DERIVATION";
    String NAME_CKM_SHA512_T = "CKM_SHA512_T";
    String NAME_CKM_SHA512_T_HMAC = "CKM_SHA512_T_HMAC";
    String NAME_CKM_SHA512_T_HMAC_GENERAL = "CKM_SHA512_T_HMAC_GENERAL";
    String NAME_CKM_SHA512_T_KEY_DERIVATION = "CKM_SHA512_T_KEY_DERIVATION";
    String NAME_CKM_RC2_KEY_GEN = "CKM_RC2_KEY_GEN";
    String NAME_CKM_RC2_ECB = "CKM_RC2_ECB";
    String NAME_CKM_RC2_CBC = "CKM_RC2_CBC";
    String NAME_CKM_RC2_MAC = "CKM_RC2_MAC";
    String NAME_CKM_RC2_MAC_GENERAL = "CKM_RC2_MAC_GENERAL";
    String NAME_CKM_RC2_CBC_PAD = "CKM_RC2_CBC_PAD";
    String NAME_CKM_RC4_KEY_GEN = "CKM_RC4_KEY_GEN";
    String NAME_CKM_RC4 = "CKM_RC4";
    String NAME_CKM_DES_KEY_GEN = "CKM_DES_KEY_GEN";
    String NAME_CKM_DES_ECB = "CKM_DES_ECB";
    String NAME_CKM_DES_CBC = "CKM_DES_CBC";
    String NAME_CKM_DES_MAC = "CKM_DES_MAC";
    String NAME_CKM_DES_MAC_GENERAL = "CKM_DES_MAC_GENERAL";
    String NAME_CKM_DES_CBC_PAD = "CKM_DES_CBC_PAD";
    String NAME_CKM_DES2_KEY_GEN = "CKM_DES2_KEY_GEN";
    String NAME_CKM_DES3_KEY_GEN = "CKM_DES3_KEY_GEN";
    String NAME_CKM_DES3_ECB = "CKM_DES3_ECB";
    String NAME_CKM_DES3_CBC = "CKM_DES3_CBC";
    String NAME_CKM_DES3_MAC = "CKM_DES3_MAC";
    String NAME_CKM_DES3_MAC_GENERAL = "CKM_DES3_MAC_GENERAL";
    String NAME_CKM_DES3_CBC_PAD = "CKM_DES3_CBC_PAD";
    String NAME_CKM_DES3_CMAC_GENERAL = "CKM_DES3_CMAC_GENERAL";
    String NAME_CKM_DES3_CMAC = "CKM_DES3_CMAC";
    String NAME_CKM_CDMF_KEY_GEN = "CKM_CDMF_KEY_GEN";
    String NAME_CKM_CDMF_ECB = "CKM_CDMF_ECB";
    String NAME_CKM_CDMF_CBC = "CKM_CDMF_CBC";
    String NAME_CKM_CDMF_MAC = "CKM_CDMF_MAC";
    String NAME_CKM_CDMF_MAC_GENERAL = "CKM_CDMF_MAC_GENERAL";
    String NAME_CKM_CDMF_CBC_PAD = "CKM_CDMF_CBC_PAD";
    String NAME_CKM_DES_OFB64 = "CKM_DES_OFB64";
    String NAME_CKM_DES_OFB8 = "CKM_DES_OFB8";
    String NAME_CKM_DES_CFB64 = "CKM_DES_CFB64";
    String NAME_CKM_DES_CFB8 = "CKM_DES_CFB8";
    String NAME_CKM_MD2 = "CKM_MD2";
    String NAME_CKM_MD2_HMAC = "CKM_MD2_HMAC";
    String NAME_CKM_MD2_HMAC_GENERAL = "CKM_MD2_HMAC_GENERAL";
    String NAME_CKM_MD5 = "CKM_MD5";
    String NAME_CKM_MD5_HMAC = "CKM_MD5_HMAC";
    String NAME_CKM_MD5_HMAC_GENERAL = "CKM_MD5_HMAC_GENERAL";
    String NAME_CKM_SHA_1 = "CKM_SHA_1";
    String NAME_CKM_SHA_1_HMAC = "CKM_SHA_1_HMAC";
    String NAME_CKM_SHA_1_HMAC_GENERAL = "CKM_SHA_1_HMAC_GENERAL";
    String NAME_CKM_RIPEMD128 = "CKM_RIPEMD128";
    String NAME_CKM_RIPEMD128_HMAC = "CKM_RIPEMD128_HMAC";
    String NAME_CKM_RIPEMD128_HMAC_GENERAL = "CKM_RIPEMD128_HMAC_GENERAL";
    String NAME_CKM_RIPEMD160 = "CKM_RIPEMD160";
    String NAME_CKM_RIPEMD160_HMAC = "CKM_RIPEMD160_HMAC";
    String NAME_CKM_RIPEMD160_HMAC_GENERAL = "CKM_RIPEMD160_HMAC_GENERAL";
    String NAME_CKM_SHA256 = "CKM_SHA256";
    String NAME_CKM_SHA256_HMAC = "CKM_SHA256_HMAC";
    String NAME_CKM_SHA256_HMAC_GENERAL = "CKM_SHA256_HMAC_GENERAL";
    String NAME_CKM_SHA224 = "CKM_SHA224";
    String NAME_CKM_SHA224_HMAC = "CKM_SHA224_HMAC";
    String NAME_CKM_SHA224_HMAC_GENERAL = "CKM_SHA224_HMAC_GENERAL";
    String NAME_CKM_SHA384 = "CKM_SHA384";
    String NAME_CKM_SHA384_HMAC = "CKM_SHA384_HMAC";
    String NAME_CKM_SHA384_HMAC_GENERAL = "CKM_SHA384_HMAC_GENERAL";
    String NAME_CKM_SHA512 = "CKM_SHA512";
    String NAME_CKM_SHA512_HMAC = "CKM_SHA512_HMAC";
    String NAME_CKM_SHA3_224 = "CKM_SHA3_224";
    String NAME_CKM_SHA3_224_HMAC = "CKM_SHA3_224_HMAC";
    String NAME_CKM_SHA3_224_HMAC_GENERAL = "CKM_SHA3_224_HMAC_GENERAL";
    String NAME_CKM_SHA3_256 = "CKM_SHA3_256";
    String NAME_CKM_SHA3_256_HMAC = "CKM_SHA3_256_HMAC";
    String NAME_CKM_SHA3_256_HMAC_GENERAL = "CKM_SHA3_256_HMAC_GENERAL";
    String NAME_CKM_SHA3_384 = "CKM_SHA3_384";
    String NAME_CKM_SHA3_384_HMAC = "CKM_SHA3_384_HMAC";
    String NAME_CKM_SHA3_384_HMAC_GENERAL = "CKM_SHA3_384_HMAC_GENERAL";
    String NAME_CKM_SHA3_512 = "CKM_SHA3_512";
    String NAME_CKM_SHA3_512_HMAC = "CKM_SHA3_512_HMAC";
    String NAME_CKM_SHA3_512_HMAC_GENERAL = "CKM_SHA3_512_HMAC_GENERAL";    
    String NAME_CKM_SHA512_HMAC_GENERAL = "CKM_SHA512_HMAC_GENERAL";
    String NAME_CKM_SECURID_KEY_GEN = "CKM_SECURID_KEY_GEN";
    String NAME_CKM_SECURID = "CKM_SECURID";
    String NAME_CKM_HOTP_KEY_GEN = "CKM_HOTP_KEY_GEN";
    String NAME_CKM_HOTP = "CKM_HOTP";
    String NAME_CKM_ACTI = "CKM_ACTI";
    String NAME_CKM_ACTI_KEY_GEN = "CKM_ACTI_KEY_GEN";
    String NAME_CKM_CAST_KEY_GEN = "CKM_CAST_KEY_GEN";
    String NAME_CKM_CAST_ECB = "CKM_CAST_ECB";
    String NAME_CKM_CAST_CBC = "CKM_CAST_CBC";
    String NAME_CKM_CAST_MAC = "CKM_CAST_MAC";
    String NAME_CKM_CAST_MAC_GENERAL = "CKM_CAST_MAC_GENERAL";
    String NAME_CKM_CAST_CBC_PAD = "CKM_CAST_CBC_PAD";
    String NAME_CKM_CAST3_KEY_GEN = "CKM_CAST3_KEY_GEN";
    String NAME_CKM_CAST3_ECB = "CKM_CAST3_ECB";
    String NAME_CKM_CAST3_CBC = "CKM_CAST3_CBC";
    String NAME_CKM_CAST3_MAC = "CKM_CAST3_MAC";
    String NAME_CKM_CAST3_MAC_GENERAL = "CKM_CAST3_MAC_GENERAL";
    String NAME_CKM_CAST3_CBC_PAD = "CKM_CAST3_CBC_PAD";
    String NAME_CKM_CAST5_KEY_GEN = "CKM_CAST5_KEY_GEN";
    String NAME_CKM_CAST128_KEY_GEN = "CKM_CAST128_KEY_GEN";
    String NAME_CKM_CAST5_ECB = "CKM_CAST5_ECB";
    String NAME_CKM_CAST128_ECB = "CKM_CAST128_ECB";
    String NAME_CKM_CAST5_CBC = "CKM_CAST5_CBC";
    String NAME_CKM_CAST128_CBC = "CKM_CAST128_CBC";
    String NAME_CKM_CAST5_MAC = "CKM_CAST5_MAC";
    String NAME_CKM_CAST128_MAC = "CKM_CAST128_MAC";
    String NAME_CKM_CAST5_MAC_GENERAL = "CKM_CAST5_MAC_GENERAL";
    String NAME_CKM_CAST128_MAC_GENERAL = "CKM_CAST128_MAC_GENERAL";
    String NAME_CKM_CAST5_CBC_PAD = "CKM_CAST5_CBC_PAD";
    String NAME_CKM_CAST128_CBC_PAD = "CKM_CAST128_CBC_PAD";
    String NAME_CKM_RC5_KEY_GEN = "CKM_RC5_KEY_GEN";
    String NAME_CKM_RC5_ECB = "CKM_RC5_ECB";
    String NAME_CKM_RC5_CBC = "CKM_RC5_CBC";
    String NAME_CKM_RC5_MAC = "CKM_RC5_MAC";
    String NAME_CKM_RC5_MAC_GENERAL = "CKM_RC5_MAC_GENERAL";
    String NAME_CKM_RC5_CBC_PAD = "CKM_RC5_CBC_PAD";
    String NAME_CKM_IDEA_KEY_GEN = "CKM_IDEA_KEY_GEN";
    String NAME_CKM_IDEA_ECB = "CKM_IDEA_ECB";
    String NAME_CKM_IDEA_CBC = "CKM_IDEA_CBC";
    String NAME_CKM_IDEA_MAC = "CKM_IDEA_MAC";
    String NAME_CKM_IDEA_MAC_GENERAL = "CKM_IDEA_MAC_GENERAL";
    String NAME_CKM_IDEA_CBC_PAD = "CKM_IDEA_CBC_PAD";
    String NAME_CKM_GENERIC_SECRET_KEY_GEN = "CKM_GENERIC_SECRET_KEY_GEN";
    String NAME_CKM_CONCATENATE_BASE_AND_KEY = "CKM_CONCATENATE_BASE_AND_KEY";
    String NAME_CKM_CONCATENATE_BASE_AND_DATA = "CKM_CONCATENATE_BASE_AND_DATA";
    String NAME_CKM_CONCATENATE_DATA_AND_BASE = "CKM_CONCATENATE_DATA_AND_BASE";
    String NAME_CKM_XOR_BASE_AND_DATA = "CKM_XOR_BASE_AND_DATA";
    String NAME_CKM_EXTRACT_KEY_FROM_KEY = "CKM_EXTRACT_KEY_FROM_KEY";
    String NAME_CKM_SSL3_PRE_MASTER_KEY_GEN = "CKM_SSL3_PRE_MASTER_KEY_GEN";
    String NAME_CKM_SSL3_MASTER_KEY_DERIVE = "CKM_SSL3_MASTER_KEY_DERIVE";
    String NAME_CKM_SSL3_KEY_AND_MAC_DERIVE = "CKM_SSL3_KEY_AND_MAC_DERIVE";
    String NAME_CKM_SSL3_MASTER_KEY_DERIVE_DH = "CKM_SSL3_MASTER_KEY_DERIVE_DH";
    String NAME_CKM_TLS_PRE_MASTER_KEY_GEN = "CKM_TLS_PRE_MASTER_KEY_GEN";
    String NAME_CKM_TLS_MASTER_KEY_DERIVE = "CKM_TLS_MASTER_KEY_DERIVE";
    String NAME_CKM_TLS_KEY_AND_MAC_DERIVE = "CKM_TLS_KEY_AND_MAC_DERIVE";
    String NAME_CKM_TLS_MASTER_KEY_DERIVE_DH = "CKM_TLS_MASTER_KEY_DERIVE_DH";
    String NAME_CKM_TLS_PRF = "CKM_TLS_PRF";
    String NAME_CKM_SSL3_MD5_MAC = "CKM_SSL3_MD5_MAC";
    String NAME_CKM_SSL3_SHA1_MAC = "CKM_SSL3_SHA1_MAC";
    String NAME_CKM_MD5_KEY_DERIVATION = "CKM_MD5_KEY_DERIVATION";
    String NAME_CKM_MD2_KEY_DERIVATION = "CKM_MD2_KEY_DERIVATION";
    String NAME_CKM_SHA1_KEY_DERIVATION = "CKM_SHA1_KEY_DERIVATION";
    String NAME_CKM_SHA256_KEY_DERIVATION = "CKM_SHA256_KEY_DERIVATION";
    String NAME_CKM_SHA384_KEY_DERIVATION = "CKM_SHA384_KEY_DERIVATION";
    String NAME_CKM_SHA512_KEY_DERIVATION = "CKM_SHA512_KEY_DERIVATION";
    String NAME_CKM_SHA224_KEY_DERIVATION = "CKM_SHA224_KEY_DERIVATION";
    String NAME_CKM_PBE_MD2_DES_CBC = "CKM_PBE_MD2_DES_CBC";
    String NAME_CKM_PBE_MD5_DES_CBC = "CKM_PBE_MD5_DES_CBC";
    String NAME_CKM_PBE_MD5_CAST_CBC = "CKM_PBE_MD5_CAST_CBC";
    String NAME_CKM_PBE_MD5_CAST3_CBC = "CKM_PBE_MD5_CAST3_CBC";
    String NAME_CKM_PBE_MD5_CAST5_CBC = "CKM_PBE_MD5_CAST5_CBC";
    String NAME_CKM_PBE_MD5_CAST128_CBC = "CKM_PBE_MD5_CAST128_CBC";
    String NAME_CKM_PBE_SHA1_CAST5_CBC = "CKM_PBE_SHA1_CAST5_CBC";
    String NAME_CKM_PBE_SHA1_CAST128_CBC = "CKM_PBE_SHA1_CAST128_CBC";
    String NAME_CKM_PBE_SHA1_RC4_128 = "CKM_PBE_SHA1_RC4_128";
    String NAME_CKM_PBE_SHA1_RC4_40 = "CKM_PBE_SHA1_RC4_40";
    String NAME_CKM_PBE_SHA1_DES3_EDE_CBC = "CKM_PBE_SHA1_DES3_EDE_CBC";
    String NAME_CKM_PBE_SHA1_DES2_EDE_CBC = "CKM_PBE_SHA1_DES2_EDE_CBC";
    String NAME_CKM_PBE_SHA1_RC2_128_CBC = "CKM_PBE_SHA1_RC2_128_CBC";
    String NAME_CKM_PBE_SHA1_RC2_40_CBC = "CKM_PBE_SHA1_RC2_40_CBC";
    String NAME_CKM_PKCS5_PBKD2 = "CKM_PKCS5_PBKD2";
    String NAME_CKM_PBA_SHA1_WITH_SHA1_HMAC = "CKM_PBA_SHA1_WITH_SHA1_HMAC";
    String NAME_CKM_WTLS_PRE_MASTER_KEY_GEN = "CKM_WTLS_PRE_MASTER_KEY_GEN";
    String NAME_CKM_WTLS_MASTER_KEY_DERIVE = "CKM_WTLS_MASTER_KEY_DERIVE";
    String NAME_CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC = "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC";
    String NAME_CKM_WTLS_MASTER_KEY_DERVIE_DH_ECC = "CKM_WTLS_MASTER_KEY_DERVIE_DH_ECC";
    String NAME_CKM_WTLS_PRF = "CKM_WTLS_PRF";
    String NAME_CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE = "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE";
    String NAME_CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE = "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE";
    String NAME_CKM_TLS10_MAC_SERVER = "CKM_TLS10_MAC_SERVER";
    String NAME_CKM_TLS10_MAC_CLIENT = "CKM_TLS10_MAC_CLIENT";
    String NAME_CKM_TLS12_MAC = "CKM_TLS12_MAC";
    String NAME_CKM_TLS12_KDF = "CKM_TLS12_KDF";
    String NAME_CKM_TLS12_MASTER_KEY_DERIVE = "CKM_TLS12_MASTER_KEY_DERIVE";
    String NAME_CKM_TLS12_KEY_AND_MAC_DERIVE = "CKM_TLS12_KEY_AND_MAC_DERIVE";
    String NAME_CKM_TLS12_MASTER_KEY_DERIVE_DH = "CKM_TLS12_MASTER_KEY_DERIVE_DH";
    String NAME_CKM_TLS12_KEY_SAFE_DERIVE = "CKM_TLS12_KEY_SAFE_DERIVE";
    String NAME_CKM_TLS_MAC = "CKM_TLS_MAC";
    String NAME_CKM_TLS_KDF = "CKM_TLS_KDF";
    String NAME_CKM_KEY_WRAP_LYNKS = "CKM_KEY_WRAP_LYNKS";
    String NAME_CKM_KEY_WRAP_SET_OAEP = "CKM_KEY_WRAP_SET_OAEP";
    String NAME_CKM_CMS_SIG = "CKM_CMS_SIG";
    String NAME_CKM_KIP_DERIVE = "CKM_KIP_DERIVE";
    String NAME_CKM_KIP_WRAP = "CKM_KIP_WRAP";
    String NAME_CKM_KIP_MAC = "CKM_KIP_MAC";
    String NAME_CKM_CAMELLIA_KEY_GEN = "CKM_CAMELLIA_KEY_GEN";
    String NAME_CKM_CAMELLIA_ECB = "CKM_CAMELLIA_ECB";
    String NAME_CKM_CAMELLIA_CBC = "CKM_CAMELLIA_CBC";
    String NAME_CKM_CAMELLIA_MAC = "CKM_CAMELLIA_MAC";
    String NAME_CKM_CAMELLIA_MAC_GENERAL = "CKM_CAMELLIA_MAC_GENERAL";
    String NAME_CKM_CAMELLIA_CBC_PAD = "CKM_CAMELLIA_CBC_PAD";
    String NAME_CKM_CAMELLIA_ECB_ENCRYPT_DATA = "CKM_CAMELLIA_ECB_ENCRYPT_DATA";
    String NAME_CKM_CAMELLIA_CBC_ENCRYPT_DATA = "CKM_CAMELLIA_CBC_ENCRYPT_DATA";
    String NAME_CKM_CAMELLIA_CTR = "CKM_CAMELLIA_CTR";
    String NAME_CKM_ARIA_KEY_GEN = "CKM_ARIA_KEY_GEN";
    String NAME_CKM_ARIA_ECB = "CKM_ARIA_ECB";
    String NAME_CKM_ARIA_CBC = "CKM_ARIA_CBC";
    String NAME_CKM_ARIA_MAC = "CKM_ARIA_MAC";
    String NAME_CKM_ARIA_MAC_GENERAL = "CKM_ARIA_MAC_GENERAL";
    String NAME_CKM_ARIA_CBC_PAD = "CKM_ARIA_CBC_PAD";
    String NAME_CKM_ARIA_ECB_ENCRYPT_DATA = "CKM_ARIA_ECB_ENCRYPT_DATA";
    String NAME_CKM_ARIA_CBC_ENCRYPT_DATA = "CKM_ARIA_CBC_ENCRYPT_DATA";
    String NAME_CKM_SEED_KEY_GEN = "CKM_SEED_KEY_GEN";
    String NAME_CKM_SEED_ECB = "CKM_SEED_ECB";
    String NAME_CKM_SEED_CBC = "CKM_SEED_CBC";
    String NAME_CKM_SEED_MAC = "CKM_SEED_MAC";
    String NAME_CKM_SEED_MAC_GENERAL = "CKM_SEED_MAC_GENERAL";
    String NAME_CKM_SEED_CBC_PAD = "CKM_SEED_CBC_PAD";
    String NAME_CKM_SEED_ECB_ENCRYPT_DATA = "CKM_SEED_ECB_ENCRYPT_DATA";
    String NAME_CKM_SEED_CBC_ENCRYPT_DATA = "CKM_SEED_CBC_ENCRYPT_DATA";
    String NAME_CKM_SKIPJACK_KEY_GEN = "CKM_SKIPJACK_KEY_GEN";
    String NAME_CKM_SKIPJACK_ECB64 = "CKM_SKIPJACK_ECB64";
    String NAME_CKM_SKIPJACK_CBC64 = "CKM_SKIPJACK_CBC64";
    String NAME_CKM_SKIPJACK_OFB64 = "CKM_SKIPJACK_OFB64";
    String NAME_CKM_SKIPJACK_CFB64 = "CKM_SKIPJACK_CFB64";
    String NAME_CKM_SKIPJACK_CFB32 = "CKM_SKIPJACK_CFB32";
    String NAME_CKM_SKIPJACK_CFB16 = "CKM_SKIPJACK_CFB16";
    String NAME_CKM_SKIPJACK_CFB8 = "CKM_SKIPJACK_CFB8";
    String NAME_CKM_SKIPJACK_WRAP = "CKM_SKIPJACK_WRAP";
    String NAME_CKM_SKIPJACK_PRIVATE_WRAP = "CKM_SKIPJACK_PRIVATE_WRAP";
    String NAME_CKM_SKIPJACK_RELAYX = "CKM_SKIPJACK_RELAYX";
    String NAME_CKM_KEA_KEY_PAIR_GEN = "CKM_KEA_KEY_PAIR_GEN";
    String NAME_CKM_KEA_KEY_DERIVE = "CKM_KEA_KEY_DERIVE";
    String NAME_CKM_FORTEZZA_TIMESTAMP = "CKM_FORTEZZA_TIMESTAMP";
    String NAME_CKM_BATON_KEY_GEN = "CKM_BATON_KEY_GEN";
    String NAME_CKM_BATON_ECB128 = "CKM_BATON_ECB128";
    String NAME_CKM_BATON_ECB96 = "CKM_BATON_ECB96";
    String NAME_CKM_BATON_CBC128 = "CKM_BATON_CBC128";
    String NAME_CKM_BATON_COUNTER = "CKM_BATON_COUNTER";
    String NAME_CKM_BATON_SHUFFLE = "CKM_BATON_SHUFFLE";
    String NAME_CKM_BATON_WRAP = "CKM_BATON_WRAP";
    String NAME_CKM_ECDSA_KEY_PAIR_GEN = "CKM_ECDSA_KEY_PAIR_GEN";
    String NAME_CKM_EC_KEY_PAIR_GEN = "CKM_EC_KEY_PAIR_GEN";
    String NAME_CKM_ECDSA = "CKM_ECDSA";
    String NAME_CKM_ECDSA_SHA1 = "CKM_ECDSA_SHA1";
    String NAME_CKM_ECDSA_SHA224 = "CKM_ECDSA_SHA224";
    String NAME_CKM_ECDSA_SHA256 = "CKM_ECDSA_SHA256";
    String NAME_CKM_ECDSA_SHA384 = "CKM_ECDSA_SHA384";
    String NAME_CKM_ECDSA_SHA512 = "CKM_ECDSA_SHA512";
    String NAME_CKM_ECDH1_DERIVE = "CKM_ECDH1_DERIVE";
    String NAME_CKM_ECDH1_COFACTOR_DERIVE = "CKM_ECDH1_COFACTOR_DERIVE";
    String NAME_CKM_ECMQV_DERIVE = "CKM_ECMQV_DERIVE";
    String NAME_CKM_ECDH_AES_KEY_WRAP = "CKM_ECDH_AES_KEY_WRAP";
    String NAME_CKM_RSA_AES_KEY_WRAP = "CKM_RSA_AES_KEY_WRAP";
    String NAME_CKM_JUNIPER_KEY_GEN = "CKM_JUNIPER_KEY_GEN";
    String NAME_CKM_JUNIPER_ECB128 = "CKM_JUNIPER_ECB128";
    String NAME_CKM_JUNIPER_CBC128 = "CKM_JUNIPER_CBC128";
    String NAME_CKM_JUNIPER_COUNTER = "CKM_JUNIPER_COUNTER";
    String NAME_CKM_JUNIPER_SHUFFLE = "CKM_JUNIPER_SHUFFLE";
    String NAME_CKM_JUNIPER_WRAP = "CKM_JUNIPER_WRAP";
    String NAME_CKM_FASTHASH = "CKM_FASTHASH";
    String NAME_CKM_AES_KEY_GEN = "CKM_AES_KEY_GEN";
    String NAME_CKM_AES_ECB = "CKM_AES_ECB";
    String NAME_CKM_AES_CBC = "CKM_AES_CBC";
    String NAME_CKM_AES_MAC = "CKM_AES_MAC";
    String NAME_CKM_AES_MAC_GENERAL = "CKM_AES_MAC_GENERAL";
    String NAME_CKM_AES_CBC_PAD = "CKM_AES_CBC_PAD";
    String NAME_CKM_AES_CTR = "CKM_AES_CTR";
    String NAME_CKM_AES_GCM = "CKM_AES_GCM";
    String NAME_CKM_AES_CCM = "CKM_AES_CCM";
    String NAME_CKM_AES_CTS = "CKM_AES_CTS";
    String NAME_CKM_AES_CMAC = "CKM_AES_CMAC";
    String NAME_CKM_AES_CMAC_GENERAL = "CKM_AES_CMAC_GENERAL";
    String NAME_CKM_AES_XCBC_MAC = "CKM_AES_XCBC_MAC";
    String NAME_CKM_AES_XCBC_MAC_96 = "CKM_AES_XCBC_MAC_96";
    String NAME_CKM_AES_GMAC = "CKM_AES_GMAC";
    String NAME_CKM_BLOWFISH_KEY_GEN = "CKM_BLOWFISH_KEY_GEN";
    String NAME_CKM_BLOWFISH_CBC = "CKM_BLOWFISH_CBC";
    String NAME_CKM_TWOFISH_KEY_GEN = "CKM_TWOFISH_KEY_GEN";
    String NAME_CKM_TWOFISH_CBC = "CKM_TWOFISH_CBC";
    String NAME_CKM_BLOWFISH_CBC_PAD = "CKM_BLOWFISH_CBC_PAD";
    String NAME_CKM_TWOFISH_CBC_PAD = "CKM_TWOFISH_CBC_PAD";
    String NAME_CKM_DES_ECB_ENCRYPT_DATA = "CKM_DES_ECB_ENCRYPT_DATA";
    String NAME_CKM_DES_CBC_ENCRYPT_DATA = "CKM_DES_CBC_ENCRYPT_DATA";
    String NAME_CKM_DES3_ECB_ENCRYPT_DATA = "CKM_DES3_ECB_ENCRYPT_DATA";
    String NAME_CKM_DES3_CBC_ENCRYPT_DATA = "CKM_DES3_CBC_ENCRYPT_DATA";
    String NAME_CKM_AES_ECB_ENCRYPT_DATA = "CKM_AES_ECB_ENCRYPT_DATA";
    String NAME_CKM_AES_CBC_ENCRYPT_DATA = "CKM_AES_CBC_ENCRYPT_DATA";
    String NAME_CKM_GOSTR3410_KEY_PAIR_GEN = "CKM_GOSTR3410_KEY_PAIR_GEN";
    String NAME_CKM_GOSTR3410 = "CKM_GOSTR3410";
    String NAME_CKM_GOSTR3410_WITH_GOSTR3411 = "CKM_GOSTR3410_WITH_GOSTR3411";
    String NAME_CKM_GOSTR3410_KEY_WRAP = "CKM_GOSTR3410_KEY_WRAP";
    String NAME_CKM_GOSTR3410_DERIVE = "CKM_GOSTR3410_DERIVE";
    String NAME_CKM_GOSTR3411 = "CKM_GOSTR3411";
    String NAME_CKM_GOSTR3411_HMAC = "CKM_GOSTR3411_HMAC";
    String NAME_CKM_GOST28147_KEY_GEN = "CKM_GOST28147_KEY_GEN";
    String NAME_CKM_GOST28147_ECB = "CKM_GOST28147_ECB";
    String NAME_CKM_GOST28147 = "CKM_GOST28147";
    String NAME_CKM_GOST28147_MAC = "CKM_GOST28147_MAC";
    String NAME_CKM_GOST28147_KEY_WRAP = "CKM_GOST28147_KEY_WRAP";
    String NAME_CKM_DSA_PARAMETER_GEN = "CKM_DSA_PARAMETER_GEN";
    String NAME_CKM_DH_PKCS_PARAMETER_GEN = "CKM_DH_PKCS_PARAMETER_GEN";
    String NAME_CKM_X9_42_DH_PARAMETER_GEN = "CKM_X9_42_DH_PARAMETER_GEN";
    String NAME_CKM_DSA_PROBABLISTIC_PARAMETER_GEN = "CKM_DSA_PROBABLISTIC_PARAMETER_GEN";
    String NAME_CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN = "CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN";
    String NAME_CKM_AES_OFB = "CKM_AES_OFB";
    String NAME_CKM_AES_CFB64 = "CKM_AES_CFB64";
    String NAME_CKM_AES_CFB8 = "CKM_AES_CFB8";
    String NAME_CKM_AES_CFB128 = "CKM_AES_CFB128";
    String NAME_CKM_AES_CFB1 = "CKM_AES_CFB1";
    String NAME_CKM_AES_KEY_WRAP = "CKM_AES_KEY_WRAP";
    String NAME_CKM_AES_KEY_WRAP_PAD = "CKM_AES_KEY_WRAP_PAD";
    String NAME_CKM_RSA_PKCS_TPM_1_1 = "CKM_RSA_PKCS_TPM_1_1";
    String NAME_CKM_RSA_PKCS_OAEP_TPM_1_1 = "CKM_RSA_PKCS_OAEP_TPM_1_1";
    String NAME_CKM_VENDOR_DEFINED = "CKM_VENDOR_DEFINED";

    String NAME_CKM_ECDSA_ECIES = "CKM_ECDSA_ECIES | VENDOR DEFINED | UTIMACO";
    String NAME_CKM_ECDSA_ECIES_XOR = "CKM_ECDSA_XOR | VENDOR DEFINED | UTIMACO";
}
