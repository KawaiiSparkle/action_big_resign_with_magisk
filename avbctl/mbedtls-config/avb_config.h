#ifndef AVB_MBEDTLS_CONFIG_H
#define AVB_MBEDTLS_CONFIG_H

/* Minimal mbedTLS config for AVB signing tool.
 * Only enables: RSA, SHA256, PEM parsing, PK, BIGNUM, ASN1, BASE64, CIPHER, MD, OID */

#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_MD_C
#define MBEDTLS_OID_C
#define MBEDTLS_GENPRIME
#define MBEDTLS_PKCS5_C
#define MBEDTLS_PKCS12_C

/* Platform */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE

/* Remove features we don't need */
/* #define MBEDTLS_X509_CRT_PARSE_C */
/* #define MBEDTLS_X509_CRL_PARSE_C */
/* #define MBEDTLS_X509_CSR_PARSE_C */
/* #define MBEDTLS_SSL_TLS_C */

#endif /* AVB_MBEDTLS_CONFIG_H */
