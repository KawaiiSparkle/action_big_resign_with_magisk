/*
 * avbctl — a tiny, static, python-free re-implementation of the subset of
 * AOSP "avbtool" (pie-release) that action_big_resign_with_magisk needs.
 *
 * Forked from and heavily based on avb_mini_signer by Manatsu0721
 * (https://github.com/Manatsu0721/avb_mini_signer, Apache-2.0).
 * Extended to support runtime PEM keys, multiple algorithms, --prop,
 * info_image and make_vbmeta_image --chain_partition.
 *
 * The on-disk byte format intentionally replicates avbtool from the
 * Android 9 "pie-release" branch (the python2 avbtool this repo used to
 * ship into jobs):
 *   - release string           "avbtool 1.0.0"
 *   - required libavb version  1.0
 *   - property descriptor      TAG=0, 32-byte fixed part (two 64-bit
 *                              length fields), payload key\0value\0
 *   - hash descriptor          TAG=2, 132-byte fixed part
 *   - chain descriptor         TAG=4, 92-byte fixed part
 *   - add_hash_footer places the vbmeta blob right after the (4096-aligned)
 *     image, footer at the end of the partition
 *
 * Usage (drop-in for the calls made by sign_avb.sh / sign_vbmeta.sh):
 *   avbctl info_image --image IMG
 *   avbctl add_hash_footer --image IMG --partition_name NAME \
 *       --algorithm SHA256_RSA4096 --key KEY.pem --partition_size N \
 *       [--prop KEY:VALUE]...
 *   avbctl make_vbmeta_image --algorithm SHA256_RSA4096 --key KEY.pem \
 *       [--chain_partition NAME:ROLLER:pubkey.bin]... [--prop KEY:VALUE]... \
 *       --padding_size N --output OUT.img
 */

#define _GNU_SOURCE
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#define MBEDTLS_CONFIG_FILE "avb_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/bignum.h>

#define PROG "avbctl"
#define AVB_RELEASE_STRING "avbtool 1.0.0"

#define AVB_FOOTER_MAGIC "AVBf"
#define AVB_MAGIC        "AVB0"
#define FOOTER_SIZE      64
#define HEADER_SIZE      256
#define ALIGNMENT        64
#define BLOCK_SIZE       4096

/* header field offsets (see AvbVBMetaImageHeader C struct) */
#define H_LIBAVB_MAJOR     4
#define H_LIBAVB_MINOR     8
#define H_AUTH_SIZE       12
#define H_AUX_SIZE        20
#define H_ALGORITHM       28
#define H_ROLLBACK_INDEX 112
#define H_FLAGS           120
#define H_RELEASE_STRING  128

/* PKCS#1 v1.5 DigestInfo prefix (19 bytes) for SHA-256 / SHA-512 */
static const uint8_t ASN1_SHA256[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};
static const uint8_t ASN1_SHA512[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40
};

typedef struct {
    const char *name;
    uint32_t type;      /* AVB algorithm type as written into the header */
    int hash_len;       /* 32 or 64 */
    int sig_len;        /* 256/512/1024 */
    const uint8_t *asn1;
} alg_info_t;

static const alg_info_t ALGS[] = {
    { "SHA256_RSA2048", 1, 32,  256, ASN1_SHA256 },
    { "SHA256_RSA4096", 2, 32,  512, ASN1_SHA256 },
    { "SHA256_RSA8192", 3, 32, 1024, ASN1_SHA256 },
    { "SHA512_RSA2048", 4, 64,  256, ASN1_SHA512 },
    { "SHA512_RSA4096", 5, 64,  512, ASN1_SHA512 },
    { "SHA512_RSA8192", 6, 64, 1024, ASN1_SHA512 },
};

typedef struct { uint8_t *buf; size_t len, cap; } buf_t;
typedef struct { char *key; char *value; } prop_t;
typedef struct { char *name; uint32_t rollback_location; char *pk_path; } chain_t;

/* ---------- small helpers ---------- */

static uint64_t round_up(uint64_t v, uint64_t a) { return (v + a - 1) & ~(a - 1); }

static void put_u32_be(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}
static void put_u64_be(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint32_t get_u32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t get_u64_be(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static void die(const char *msg) { fprintf(stderr, PROG ": %s\n", msg); exit(1); }
static void die_errno(const char *msg) { fprintf(stderr, PROG ": %s: ", msg); perror(""); exit(1); }

static void *xmalloc(size_t n) { void *p = malloc(n ? n : 1); if (!p) die("out of memory"); return p; }
static void *xrealloc(void *p, size_t n) { p = realloc(p, n ? n : 1); if (!p) die("out of memory"); return p; }

static uint8_t *read_file(const char *path, size_t *out_size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) die_errno(path);
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz < 0) die_errno("ftell");
    rewind(fp);
    uint8_t *buf = xmalloc(sz);
    if (sz && fread(buf, 1, sz, fp) != (size_t)sz) die_errno("fread");
    fclose(fp);
    *out_size = (size_t)sz;
    return buf;
}

static void write_full(const char *path, const uint8_t *data, size_t len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) die_errno(path);
    if (len && fwrite(data, 1, len, fp) != len) die_errno("fwrite");
    if (fclose(fp) != 0) die_errno("fclose");
}

static void write_zeros(FILE *fp, uint64_t n) {
    static const uint8_t zeros[4096] = {0};
    while (n) {
        size_t chunk = n > sizeof(zeros) ? sizeof(zeros) : (size_t)n;
        if (fwrite(zeros, 1, chunk, fp) != chunk) die_errno("fwrite");
        n -= chunk;
    }
}

/* growable buffer */
static void buf_reserve(buf_t *b, size_t extra) {
    if (b->len + extra > b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 4096;
        while (cap < b->len + extra) cap *= 2;
        b->cap = cap;
        b->buf = xrealloc(b->buf, cap);
    }
}
static void buf_put(buf_t *b, const void *d, size_t n) {
    buf_reserve(b, n);
    memcpy(b->buf + b->len, d, n);
    b->len += n;
}
static void buf_put_u32(buf_t *b, uint32_t v) { uint8_t t[4]; put_u32_be(t, v); buf_put(b, t, 4); }
static void buf_put_u64(buf_t *b, uint64_t v) { uint8_t t[8]; put_u64_be(t, v); buf_put(b, t, 8); }
static void buf_pad_to(buf_t *b, size_t target) {
    if (b->len >= target) return;
    buf_reserve(b, target - b->len);
    memset(b->buf + b->len, 0, target - b->len);
    b->len = target;
}

/* RNG for mbedtls RSA blinding (blinding only; not security relevant) */
static int simple_rng(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    static unsigned int seed = 0;
    if (seed == 0) seed = (unsigned int)((uintptr_t)&seed ^ (uintptr_t)time(NULL) ^ (unsigned)getpid());
    for (size_t i = 0; i < len; i++) {
        seed = seed * 1103515245U + 12345U;
        out[i] = (unsigned char)(seed >> 16);
    }
    return 0;
}

static void random_bytes(uint8_t *out, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(out, 1, n, f) != n) {
        if (f) fclose(f);
        simple_rng(NULL, out, n); /* fallback, should never happen on CI */
        return;
    }
    fclose(f);
}

/* ---------- crypto ---------- */

static const alg_info_t *find_alg(const char *name) {
    for (size_t i = 0; i < sizeof(ALGS) / sizeof(ALGS[0]); i++)
        if (!strcmp(ALGS[i].name, name)) return &ALGS[i];
    fprintf(stderr, PROG ": unknown algorithm '%s' (supported:", name);
    for (size_t i = 0; i < sizeof(ALGS) / sizeof(ALGS[0]); i++)
        fprintf(stderr, " %s", ALGS[i].name);
    fprintf(stderr, ")\n");
    exit(1);
}

static void load_key(const char *path, mbedtls_pk_context *pk) {
    size_t len;
    uint8_t *data = read_file(path, &len);
    uint8_t *z = xmalloc(len + 1);
    memcpy(z, data, len); z[len] = 0;
    free(data);
    mbedtls_pk_init(pk);
    int ret = mbedtls_pk_parse_key(pk, z, len + 1, NULL, 0, simple_rng, NULL);
    free(z);
    if (ret != 0) { fprintf(stderr, PROG ": failed to parse key %s: -0x%04x\n", path, (unsigned)-ret); exit(1); }
    if (mbedtls_pk_get_type(pk) != MBEDTLS_PK_RSA) die("key is not RSA");
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*pk);
    if ((ret = mbedtls_rsa_complete(rsa)) != 0) { fprintf(stderr, PROG ": rsa_complete: -0x%04x\n", (unsigned)-ret); exit(1); }
}

/* raw PKCS#1 v1.5 signature, like avbtool (openssl rsautl -sign -raw over
 * the padded digest block) */
static int rsa_sign(const alg_info_t *alg, mbedtls_rsa_context *rsa,
                    const uint8_t *block, uint8_t *sig) {
    size_t k = mbedtls_rsa_get_len(rsa);
    if (k != (size_t)alg->sig_len) {
        fprintf(stderr, PROG ": key size (%zu bytes) does not match algorithm %s (%d bytes)\n",
                k, alg->name, alg->sig_len);
        return -1;
    }
    return mbedtls_rsa_private(rsa, simple_rng, NULL, block, sig) == 0 ? 0 : -1;
}

static void sha_digest(const alg_info_t *alg, const uint8_t *d1, size_t n1,
                       const uint8_t *d2, size_t n2, uint8_t *out) {
    if (alg->hash_len == 32) {
        mbedtls_sha256_context c; mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c, 0);
        mbedtls_sha256_update(&c, d1, n1);
        if (d2) mbedtls_sha256_update(&c, d2, n2);
        mbedtls_sha256_finish(&c, out); mbedtls_sha256_free(&c);
    } else {
        mbedtls_sha512_context c; mbedtls_sha512_init(&c); mbedtls_sha512_starts(&c, 0);
        mbedtls_sha512_update(&c, d1, n1);
        if (d2) mbedtls_sha512_update(&c, d2, n2);
        mbedtls_sha512_finish(&c, out); mbedtls_sha512_free(&c);
    }
}

static void build_pkcs1_block(const alg_info_t *alg, const uint8_t *digest,
                              size_t key_bytes, uint8_t *out) {
    size_t ps_len = key_bytes - 3 - 19 - alg->hash_len;
    out[0] = 0x00; out[1] = 0x01;
    memset(out + 2, 0xff, ps_len);
    out[2 + ps_len] = 0x00;
    memcpy(out + 3 + ps_len, alg->asn1, 19);
    memcpy(out + 3 + ps_len + 19, digest, alg->hash_len);
}

/* AVB public key blob: key_num_bits(4) n0inv(4) modulus rr */
static void encode_avb_pubkey(const mbedtls_rsa_context *rsa, buf_t *out) {
    const mbedtls_mpi *n = &rsa->N;
    int bits = (int)mbedtls_mpi_bitlen(n);
    int bits_rounded = 1;
    while (bits_rounded < bits) bits_rounded <<= 1;
    if (bits_rounded != (int)(rsa->len * 8)) {
        fprintf(stderr, PROG ": key bits=%d not a power of two\n", bits);
        exit(1);
    }
    int key_bytes = bits_rounded / 8;

    uint8_t *mod = xmalloc(key_bytes);
    memset(mod, 0, key_bytes);
    mbedtls_mpi_write_binary(n, mod, key_bytes);
    uint32_t n0 = ((uint32_t)mod[key_bytes-4] << 24) | ((uint32_t)mod[key_bytes-3] << 16) |
                  ((uint32_t)mod[key_bytes-2] << 8) | (uint32_t)mod[key_bytes-1];
    uint32_t inv = 1U;
    for (int i = 0; i < 5; i++) inv = inv * (2 - n0 * inv);
    uint32_t n0inv = 0U - inv;

    mbedtls_mpi r, rr, two;
    mbedtls_mpi_init(&r); mbedtls_mpi_init(&rr); mbedtls_mpi_init(&two);
    mbedtls_mpi_lset(&two, 2);
    mbedtls_mpi_set_bit(&r, bits_rounded, 1);
    mbedtls_mpi_exp_mod(&rr, &r, &two, n, NULL);
    uint8_t *rr_buf = xmalloc(key_bytes);
    memset(rr_buf, 0, key_bytes);
    mbedtls_mpi_write_binary(&rr, rr_buf, key_bytes);
    mbedtls_mpi_free(&r); mbedtls_mpi_free(&rr); mbedtls_mpi_free(&two);

    buf_put_u32(out, (uint32_t)bits_rounded);
    buf_put_u32(out, n0inv);
    buf_put(out, mod, key_bytes);
    buf_put(out, rr_buf, key_bytes);
    free(mod); free(rr_buf);
}

/* ---------- descriptors (pie formats) ---------- */

/* property: TAG=0, fixed 32 bytes: tag Q, nbf Q, key_size Q, value_size Q */
static void encode_prop_desc(buf_t *out, const char *key, const char *value) {
    size_t klen = strlen(key), vlen = strlen(value);
    size_t nbf = 32 + klen + vlen + 2 - 16;
    size_t nbf_p = round_up(nbf, 8);
    buf_put_u64(out, 0);
    buf_put_u64(out, nbf_p);
    buf_put_u64(out, klen);
    buf_put_u64(out, vlen);
    buf_put(out, key, klen);
    uint8_t z = 0; buf_put(out, &z, 1);
    buf_put(out, value, vlen);
    buf_put(out, &z, 1);
    buf_pad_to(out, out->len + (nbf_p - nbf));
}

/* hash: TAG=2, fixed 132 bytes */
static void encode_hash_desc(buf_t *out, const char *partition_name,
                             uint64_t image_size, const char *algo_name,
                             const uint8_t *salt, size_t salt_len,
                             const uint8_t *digest, size_t digest_len) {
    size_t nlen = strlen(partition_name);
    size_t nbf = 132 + nlen + salt_len + digest_len - 16;
    size_t nbf_p = round_up(nbf, 8);
    buf_put_u64(out, 2);
    buf_put_u64(out, nbf_p);
    buf_put_u64(out, image_size);
    char algo[33]; memset(algo, 0, 33);
    strncpy(algo, algo_name, 32);
    buf_put(out, algo, 32);
    buf_put_u32(out, (uint32_t)nlen);
    buf_put_u32(out, (uint32_t)salt_len);
    buf_put_u32(out, (uint32_t)digest_len);
    uint8_t reserved[64]; memset(reserved, 0, 64);
    buf_put(out, reserved, 64);          /* pie layout: reserved[64], no flags field */
    buf_put(out, partition_name, nlen);
    buf_put(out, salt, salt_len);
    buf_put(out, digest, digest_len);
    buf_pad_to(out, out->len + (nbf_p - nbf));
}

/* chain: TAG=4, fixed 92 bytes */
static void encode_chain_desc(buf_t *out, const char *partition_name,
                              uint32_t rollback_location,
                              const uint8_t *pubkey, size_t pk_len) {
    size_t nlen = strlen(partition_name);
    size_t nbf = 92 + nlen + pk_len - 16;
    size_t nbf_p = round_up(nbf, 8);
    buf_put_u64(out, 4);
    buf_put_u64(out, nbf_p);
    buf_put_u32(out, rollback_location);
    buf_put_u32(out, (uint32_t)nlen);
    buf_put_u32(out, (uint32_t)pk_len);
    uint8_t reserved[64]; memset(reserved, 0, 64);
    buf_put(out, reserved, 64);
    buf_put(out, partition_name, nlen);
    buf_put(out, pubkey, pk_len);
    buf_pad_to(out, out->len + (nbf_p - nbf));
}

/* ---------- vbmeta blob (shared) ---------- */

/* builds header+auth+aux; the auth hash/signature cover header+aux */
static void build_vbmeta_blob(const alg_info_t *alg, mbedtls_rsa_context *rsa,
                              const buf_t *descs, uint64_t rollback_index,
                              uint32_t flags, buf_t *out) {
    buf_t pubkey = {0};
    encode_avb_pubkey(rsa, &pubkey);

    size_t desc_size = descs ? descs->len : 0;
    size_t aux_padded = round_up(desc_size + pubkey.len, ALIGNMENT);
    size_t auth_padded = round_up((size_t)alg->hash_len + alg->sig_len, ALIGNMENT);

    uint8_t hdr[HEADER_SIZE]; memset(hdr, 0, sizeof(hdr));
    memcpy(hdr, AVB_MAGIC, 4);
    put_u32_be(hdr + H_LIBAVB_MAJOR, 1);
    put_u32_be(hdr + H_LIBAVB_MINOR, 0);
    put_u64_be(hdr + H_AUTH_SIZE, auth_padded);
    put_u64_be(hdr + H_AUX_SIZE, aux_padded);
    put_u32_be(hdr + H_ALGORITHM, alg->type);
    put_u64_be(hdr + 32, 0);                          /* hash_offset */
    put_u64_be(hdr + 40, alg->hash_len);              /* hash_size */
    put_u64_be(hdr + 48, alg->hash_len);              /* signature_offset */
    put_u64_be(hdr + 56, alg->sig_len);               /* signature_size */
    put_u64_be(hdr + 64, desc_size);                  /* public_key_offset */
    put_u64_be(hdr + 72, pubkey.len);                 /* public_key_size */
    put_u64_be(hdr + 80, desc_size + pubkey.len);     /* public_key_metadata_offset */
    put_u64_be(hdr + 88, 0);                          /* public_key_metadata_size */
    put_u64_be(hdr + 96, 0);                          /* descriptors_offset */
    put_u64_be(hdr + 104, desc_size);                 /* descriptors_size */
    put_u64_be(hdr + H_ROLLBACK_INDEX, rollback_index);
    put_u32_be(hdr + H_FLAGS, flags);
    memcpy(hdr + H_RELEASE_STRING, AVB_RELEASE_STRING, strlen(AVB_RELEASE_STRING));

    buf_t aux = {0};
    if (desc_size) buf_put(&aux, descs->buf, desc_size);
    buf_put(&aux, pubkey.buf, pubkey.len);
    buf_pad_to(&aux, aux_padded);

    uint8_t digest[64];
    sha_digest(alg, hdr, HEADER_SIZE, aux.buf, aux.len, digest);
    uint8_t *block = xmalloc((size_t)rsa->len);
    build_pkcs1_block(alg, digest, rsa->len, block);
    uint8_t *sig = xmalloc((size_t)alg->sig_len);
    if (rsa_sign(alg, rsa, block, sig) != 0) die("RSA signing failed");

    buf_put(out, hdr, HEADER_SIZE);
    buf_put(out, digest, alg->hash_len);
    buf_put(out, sig, alg->sig_len);
    buf_pad_to(out, HEADER_SIZE + auth_padded);
    buf_put(out, aux.buf, aux.len);

    free(block); free(sig); free(pubkey.buf); free(aux.buf);
}

/* ---------- info_image ---------- */

static void print_hex(const char *label, const uint8_t *d, size_t n) {
    printf("%s", label);
    for (size_t i = 0; i < n; i++) printf("%02x", d[i]);
    printf("\n");
}

static int info_image_cmd(const char *path) {
    size_t fsize;
    uint8_t *img = read_file(path, &fsize);

    const uint8_t *vbmeta = NULL;
    const uint8_t *footer = NULL;

    if (fsize >= FOOTER_SIZE &&
        !memcmp(img + fsize - FOOTER_SIZE, AVB_FOOTER_MAGIC, 4)) {
        footer = img + fsize - FOOTER_SIZE;
        uint64_t off = get_u64_be(footer + 20);
        if (off + HEADER_SIZE > fsize || memcmp(img + off, AVB_MAGIC, 4))
            die("footer found but no vbmeta at recorded offset");
        vbmeta = img + off;
    } else if (fsize >= HEADER_SIZE && !memcmp(img, AVB_MAGIC, 4)) {
        vbmeta = img; /* bare vbmeta image */
    } else {
        fprintf(stderr, PROG ": %s does not look like an AVB image\n", path);
        return 1;
    }

    if (footer) {
        printf("Footer version:           %u.%u\n",
               get_u32_be(footer + 4), get_u32_be(footer + 8));
        printf("Image size:               %llu bytes\n", (unsigned long long)fsize);
        printf("Original image size:      %llu bytes\n",
               (unsigned long long)get_u64_be(footer + 12));
        printf("VBMeta offset:            %llu\n", (unsigned long long)get_u64_be(footer + 20));
        printf("VBMeta size:              %llu bytes\n",
               (unsigned long long)get_u64_be(footer + 28));
        printf("--\n");
    }

    uint32_t alg_type = get_u32_be(vbmeta + H_ALGORITHM);
    const alg_info_t *alg = NULL;
    for (size_t i = 0; i < sizeof(ALGS) / sizeof(ALGS[0]); i++)
        if (ALGS[i].type == alg_type) alg = &ALGS[i];
    if (!alg) { fprintf(stderr, PROG ": unknown algorithm type %u\n", alg_type); return 1; }

    char release[49]; memcpy(release, vbmeta + H_RELEASE_STRING, 48); release[48] = 0;
    for (int i = 47; i >= 0 && release[i] == 0; i--) release[i] = 0; /* rstrip NULs (implicit) */

    printf("Minimum libavb version:   %u.%u\n",
           get_u32_be(vbmeta + H_LIBAVB_MAJOR), get_u32_be(vbmeta + H_LIBAVB_MINOR));
    printf("Header Block:             %d bytes\n", HEADER_SIZE);
    printf("Authentication Block:     %llu bytes\n", (unsigned long long)get_u64_be(vbmeta + H_AUTH_SIZE));
    printf("Auxiliary Block:          %llu bytes\n", (unsigned long long)get_u64_be(vbmeta + H_AUX_SIZE));
    printf("Algorithm:                %s\n", alg->name);
    printf("Rollback Index:           %llu\n", (unsigned long long)get_u64_be(vbmeta + H_ROLLBACK_INDEX));
    printf("Flags:                    %u\n", get_u32_be(vbmeta + H_FLAGS));
    printf("Release String:           '%s'\n", release);

    printf("Descriptors:\n");
    uint64_t auth_sz = get_u64_be(vbmeta + H_AUTH_SIZE);
    const uint8_t *d = vbmeta + HEADER_SIZE + auth_sz + get_u64_be(vbmeta + 96);
    uint64_t desc_sz = get_u64_be(vbmeta + 104);
    size_t printed = 0;
    uint64_t o = 0;
    while (o + 16 <= desc_sz) {
        uint64_t tag = get_u64_be(d + o);
        uint64_t nbf = get_u64_be(d + o + 8);
        if (o + 16 + nbf > desc_sz) { printf("    (truncated descriptor)\n"); break; }
        const uint8_t *fixed = d + o + 16;
        if (tag == 0) { /* property */
            uint64_t ks = get_u64_be(fixed);
            uint64_t vs = get_u64_be(fixed + 8);
            const uint8_t *kv = fixed + 16;
            printf("    Prop: %.*s -> '%.*s'\n", (int)ks, kv, (int)vs, kv + ks + 1);
        } else if (tag == 2) { /* hash */
            uint64_t isz = get_u64_be(fixed);
            char algo[33]; memcpy(algo, fixed + 8, 32); algo[32] = 0;
            uint32_t nlen = get_u32_be(fixed + 40);
            uint32_t slen = get_u32_be(fixed + 44);
            uint32_t dlen = get_u32_be(fixed + 48);
            const uint8_t *payload = fixed + 116;
            printf("    Hash descriptor:\n");
            printf("      Image Size:            %llu bytes\n", (unsigned long long)isz);
            printf("      Hash Algorithm:        %s\n", algo);
            printf("      Partition Name:        %.*s\n", (int)nlen, payload);
            print_hex("      Salt:                  ", payload + nlen, slen);
            print_hex("      Digest:                ", payload + nlen + slen, dlen);
        } else if (tag == 4) { /* chain partition */
            uint32_t rloc = get_u32_be(fixed);
            uint32_t nlen = get_u32_be(fixed + 4);
            uint32_t plen = get_u32_be(fixed + 8);
            const uint8_t *payload = fixed + 76;
            printf("    Chain Partition descriptor:\n");
            printf("      Partition Name:        %.*s\n", (int)nlen, payload);
            printf("      Rollback Index Location: %u\n", rloc);
            printf("      Public Key (blob size): %u bytes\n", plen);
        } else if (tag == 1) {
            printf("    Hashtree descriptor:\n");
        } else if (tag == 3) {
            printf("    Kernel CMD descriptor:\n");
        } else {
            printf("    (unknown descriptor tag %llu)\n", (unsigned long long)tag);
        }
        printed++;
        o += 16 + nbf;
    }
    if (!printed) printf("    (none)\n");
    free(img);
    return 0;
}

/* ---------- add_hash_footer ---------- */

static int add_hash_footer_cmd(const char *image_path, const char *part_name,
                               const alg_info_t *alg, const char *key_path,
                               uint64_t partition_size,
                               prop_t *props, size_t nprops) {
    mbedtls_pk_context pk;
    load_key(key_path, &pk);
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    size_t fsize;
    uint8_t *img = read_file(image_path, &fsize);

    /* idempotent: strip existing footer (avbtool behaviour) */
    if (fsize >= FOOTER_SIZE &&
        !memcmp(img + fsize - FOOTER_SIZE, AVB_FOOTER_MAGIC, 4)) {
        uint64_t orig = get_u64_be(img + fsize - FOOTER_SIZE + 12);
        printf("Footer detected, truncating to original image size (%llu)\n",
               (unsigned long long)orig);
        fsize = orig;
    }

    if (partition_size == 0 || partition_size % BLOCK_SIZE != 0)
        die("Partition size of 0 or not a multiple of image block size.");

    uint8_t salt[32];
    random_bytes(salt, 32);
    uint8_t digest[64];
    sha_digest(alg, salt, 32, img, fsize, digest);

    /* descriptors: hash desc first, then props (avbtool order) */
    buf_t descs = {0};
    encode_hash_desc(&descs, part_name, fsize,
                     alg->hash_len == 32 ? "sha256" : "sha512",
                     salt, 32, digest, alg->hash_len);
    for (size_t i = 0; i < nprops; i++)
        encode_prop_desc(&descs, props[i].key, props[i].value);

    buf_t blob = {0};
    build_vbmeta_blob(alg, rsa, &descs, 0, 0, &blob);

    /* placement, exactly like avbtool: image padded to block size, vbmeta
     * appended there, zero pad, footer at partition end */
    uint64_t image_padded = round_up(fsize, BLOCK_SIZE);
    uint64_t blob_padded = round_up(blob.len, BLOCK_SIZE);
    if (image_padded + blob_padded + FOOTER_SIZE > partition_size) {
        fprintf(stderr,
                PROG ": Image size of %llu does not fit in partition of %llu\n",
                (unsigned long long)fsize, (unsigned long long)partition_size);
        return 1;
    }
    uint64_t vbmeta_offset = image_padded;

    FILE *fp = fopen(image_path, "wb");
    if (!fp) die_errno(image_path);
    if (fsize && fwrite(img, 1, fsize, fp) != fsize) die_errno("fwrite");
    write_zeros(fp, vbmeta_offset - fsize);
    if (fwrite(blob.buf, 1, blob.len, fp) != blob.len) die_errno("fwrite");
    write_zeros(fp, (partition_size - FOOTER_SIZE) - (vbmeta_offset + blob.len));
    uint8_t ftr[FOOTER_SIZE]; memset(ftr, 0, FOOTER_SIZE);
    memcpy(ftr, AVB_FOOTER_MAGIC, 4);
    put_u32_be(ftr + 4, 1);
    put_u32_be(ftr + 8, 0);
    put_u64_be(ftr + 12, fsize);
    put_u64_be(ftr + 20, vbmeta_offset);
    put_u64_be(ftr + 28, blob.len);
    if (fwrite(ftr, 1, FOOTER_SIZE, fp) != FOOTER_SIZE) die_errno("fwrite");
    if (fclose(fp) != 0) die_errno("fclose");

    printf("Successfully added hash footer to %s (vbmeta at %llu, %zu bytes)\n",
           image_path, (unsigned long long)vbmeta_offset, blob.len);
    free(img); free(descs.buf); free(blob.buf);
    mbedtls_pk_free(&pk);
    return 0;
}

/* ---------- make_vbmeta_image ---------- */

static int make_vbmeta_cmd(const alg_info_t *alg, const char *key_path,
                           chain_t *chains, size_t nchains,
                           prop_t *props, size_t nprops,
                           uint64_t padding_size, const char *output) {
    mbedtls_pk_context pk;
    load_key(key_path, &pk);
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    buf_t descs = {0};
    /* avbtool order: chain partitions first, then props */
    for (size_t i = 0; i < nchains; i++) {
        size_t pk_len;
        uint8_t *pk_blob = read_file(chains[i].pk_path, &pk_len);
        encode_chain_desc(&descs, chains[i].name, chains[i].rollback_location,
                          pk_blob, pk_len);
        printf("Adding chain partition %s:%u:%s (%zu bytes)\n",
               chains[i].name, chains[i].rollback_location, chains[i].pk_path, pk_len);
        free(pk_blob);
    }
    for (size_t i = 0; i < nprops; i++)
        encode_prop_desc(&descs, props[i].key, props[i].value);

    buf_t blob = {0};
    build_vbmeta_blob(alg, rsa, &descs, 0, 0, &blob);

    if (padding_size) {
        if (blob.len > padding_size)
            die("padding size is smaller than the vbmeta image");
        buf_pad_to(&blob, padding_size);
    }
    write_full(output, blob.buf, blob.len);
    printf("Successfully wrote %s (%zu bytes)\n", output, blob.len);
    free(descs.buf); free(blob.buf);
    mbedtls_pk_free(&pk);
    return 0;
}

/* ---------- CLI ---------- */

static void usage(void) {
    fprintf(stderr,
        PROG " - static pie-avbtool-compatible signer (fork of avb_mini_signer)\n\n"
        "  avbctl info_image --image IMG\n"
        "  avbctl add_hash_footer --image IMG --partition_name NAME\n"
        "        --algorithm ALG --key KEY.pem --partition_size BYTES\n"
        "        [--prop KEY:VALUE]...\n"
        "  avbctl make_vbmeta_image --algorithm ALG --key KEY.pem\n"
        "        [--chain_partition NAME:ROLLER:PUBKEY.bin]...\n"
        "        [--prop KEY:VALUE]... [--padding_size BYTES] --output OUT\n\n"
        "  algorithms: SHA256_RSA2048/4096/8192 SHA512_RSA2048/4096/8192\n");
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 2) usage();
    const char *cmd = argv[1];

    const char *image = NULL, *part_name = NULL, *key = NULL, *output = NULL;
    const char *algorithm = "SHA256_RSA4096";
    uint64_t partition_size = 0, padding_size = 0;
    prop_t props[64]; size_t nprops = 0;
    chain_t chains[64]; size_t nchains = 0;

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        #define NEXTVAL() ((i + 1 < argc) ? argv[++i] : (usage(), (const char *)NULL))
        if (!strcmp(a, "--image")) image = NEXTVAL();
        else if (!strcmp(a, "--partition_name")) part_name = NEXTVAL();
        else if (!strcmp(a, "--algorithm")) algorithm = NEXTVAL();
        else if (!strcmp(a, "--key")) key = NEXTVAL();
        else if (!strcmp(a, "--partition_size")) partition_size = strtoull(NEXTVAL(), NULL, 0);
        else if (!strcmp(a, "--padding_size")) padding_size = strtoull(NEXTVAL(), NULL, 0);
        else if (!strcmp(a, "--output")) output = NEXTVAL();
        else if (!strcmp(a, "--prop")) {
            const char *kv = NEXTVAL();
            const char *colon = strchr(kv, ':');
            if (!colon) { fprintf(stderr, PROG ": malformed --prop %s\n", kv); return 1; }
            if (nprops >= 64) die("too many --prop");
            props[nprops].key = strndup(kv, colon - kv);
            props[nprops].value = strdup(colon + 1);
            nprops++;
        }
        else if (!strcmp(a, "--chain_partition")) {
            const char *s = NEXTVAL();
            char name[128]; unsigned loc; char pkpath[512];
            if (sscanf(s, "%127[^:]:%u:%511s", name, &loc, pkpath) != 3) {
                fprintf(stderr, PROG ": malformed --chain_partition %s\n", s);
                return 1;
            }
            if (nchains >= 64) die("too many --chain_partition");
            chains[nchains].name = strdup(name);
            chains[nchains].rollback_location = loc;
            chains[nchains].pk_path = strdup(pkpath);
            nchains++;
        }
        else { fprintf(stderr, PROG ": unknown argument %s\n", a); usage(); }
        #undef NEXTVAL
    }

    const alg_info_t *alg = find_alg(algorithm);

    if (!strcmp(cmd, "info_image")) {
        if (!image) die("--image is required");
        return info_image_cmd(image);
    }
    if (!strcmp(cmd, "add_hash_footer")) {
        if (!image || !part_name || !key || !partition_size) die(
            "--image, --partition_name, --key and --partition_size are required");
        return add_hash_footer_cmd(image, part_name, alg, key, partition_size,
                                   props, nprops);
    }
    if (!strcmp(cmd, "make_vbmeta_image")) {
        if (!key || !output) die("--key and --output are required");
        return make_vbmeta_cmd(alg, key, chains, nchains, props, nprops,
                               padding_size, output);
    }
    usage();
    return 1;
}
