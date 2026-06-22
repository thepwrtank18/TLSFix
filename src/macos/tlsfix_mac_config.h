/* TLSFix macOS — mbedTLS user config overlay (included after the default mbedtls_config.h via
 * -DMBEDTLS_USER_CONFIG_FILE). Used for the i386 slice only: the Xcode 4.6.3 / clang 4.2 toolchain
 * can't build mbedTLS's x86 AES-NI / CLMUL intrinsics for 32-bit (the assembly fast-path is
 * x86_64-only), so disable the hardware crypto paths and fall back to the portable C implementations.
 * Runtime correctness is unchanged; only AES/GCM throughput on 32-bit processes is lower. */
#undef MBEDTLS_AESNI_C
#undef MBEDTLS_PADLOCK_C
