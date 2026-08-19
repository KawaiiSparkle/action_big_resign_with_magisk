# avbctl

A tiny, dependency-free (mbedTLS, statically linked) C re-implementation of
the subset of AOSP **avbtool (pie-release)** that this repository needs —
built to replace the python2 `avbtool` in the GitHub Actions jobs, so the
signing toolchain no longer depends on python2.7 / the nested
`runner-20.04` container.

Forked from and heavily based on
[avb_mini_signer](https://github.com/Manatsu0721/avb_mini_signer) by
Manatsu0721 (Apache-2.0), with the following additions:

| capability | avb_mini_signer | avbctl |
| --- | --- | --- |
| add_hash_footer | ✅ (embedded key only) | ✅ runtime `--key` PEM (PKCS#1/PKCS#8) |
| algorithms | SHA256_RSA4096 only | SHA256/SHA512 × RSA2048/4096/8192 |
| `--prop K:V` | ❌ | ✅ pie-format property descriptors |
| `info_image` | ❌ | ✅ pie-compatible output (`sign_avb.sh` parses it) |
| `make_vbmeta_image --chain_partition` | ❌ | ✅ pie-format chain descriptors |
| key handling | compiled-in test key | key file argument (extra_key trees work) |

## Byte-format policy

The on-disk output intentionally **replicates avbtool from the Android 9
`pie-release` branch** — the exact python2 avbtool the workflows used to
download:

- release string `avbtool 1.0.0`, required libavb version 1.0
- property descriptor: TAG=0, 32-byte fixed part (two 64-bit length
  fields), payload `key\0value\0`
- hash descriptor: TAG=2, 132-byte fixed part (reserved-only tail, i.e.
  flags=0 — byte-identical to the modern layout)
- chain descriptor: TAG=4, 92-byte fixed part
- `add_hash_footer` places the vbmeta blob directly after the
  4096-aligned image (like pie), footer at the end of the partition, and
  is idempotent (an existing footer is stripped first)

## Usage

```sh
# build (fetches mbedtls-3.6 once)
make -C avbctl

# what sign_avb.sh does:
avbctl info_image --image boot-signed.img
avbctl add_hash_footer --image boot.img --partition_name boot \
    --algorithm SHA256_RSA4096 --key rsa4096_boot.pem \
    --partition_size 4194304 --prop com.android.build.boot.os_version:13

# what the generated sign_vbmeta.sh does:
avbctl make_vbmeta_image --algorithm SHA256_RSA4096 --key rsa4096_vbmeta.pem \
    --chain_partition boot:1:keys/rsa4096_boot_pub.bin \
    --padding_size 4096 --output vbmeta-sign-custom.img
```

## Verification performed (see dev log)

- `add_hash_footer` output passes `avbtool verify_image` (footer + vbmeta
  struct + per-partition hash cascade) — tested with SHA256_RSA4096 and
  SHA256_RSA2048
- `make_vbmeta_image --chain_partition` output: descriptor section and
  embedded public key are **byte-identical** to modern avbtool's output
  for the same arguments (only intended difference: release string /
  required-version fields follow pie)
- signatures independently verified with `openssl dgst -sha256 -verify`
- property descriptors byte-checked against the pie `struct` formats
  (`nbf` rounding, `key\0value\0` payload)
- `info_image` output parses correctly with the exact `grep`/`sed`/`awk`
  pipeline from `sign_avb.sh`
