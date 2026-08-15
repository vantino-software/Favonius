# Third-party dependencies

Every crate Favonius links, with the licence its author declares. Generated
from `Cargo.lock` by `cargo metadata`; regenerate after any dependency
change. This lists the **build graph**, so it includes dev- and
build-only crates that are not in a shipped binary.

This file is a **catalogue**, not an attribution notice. Several of
these licences require that their text accompany a binary distribution;
naming them here does not satisfy that. The release tarballs carry
`THIRD-PARTY-LICENSES.md`, generated per target by
`packaging/gen-attribution.py`, which contains the full texts for exactly
the crates linked into the shipped binaries — a narrower set than this
file, which lists the whole build graph.

**No dependency is under a copyleft licence that would affect
redistribution.** The one entry naming LGPL offers it as an alternative in
a disjunction (`MIT OR Apache-2.0 OR LGPL-2.1-or-later`), so the MIT or
Apache-2.0 arm applies.

## Summary

| count | licence |
|---|---|
| 150 | MIT OR Apache-2.0 |
| 41 | MIT |
| 23 | Apache-2.0 OR MIT |
| 18 | Unicode-3.0 |
| 14 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| 10 | MIT/Apache-2.0 |
| 4 | BSD-3-Clause |
| 3 | Apache-2.0 |
| 2 | Unlicense OR MIT |
| 2 | Apache-2.0 OR ISC OR MIT |
| 2 | MIT OR Apache-2.0 OR Zlib |
| 2 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| 2 | ISC |
| 2 | BSD-2-Clause OR Apache-2.0 OR MIT |
| 1 | BSD-2-Clause |
| 1 | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception |
| 1 | CC0-1.0 OR MIT-0 OR Apache-2.0 |
| 1 | Apache-2.0/MIT |
| 1 | (Apache-2.0 OR MIT) AND BSD-3-Clause |
| 1 | MIT OR Apache-2.0 OR BSD-1-Clause |
| 1 | Apache-2.0 / MIT |
| 1 | Zlib |
| 1 | MIT AND BSD-3-Clause |
| 1 | Apache-2.0 AND ISC |
| 1 | Apache-2.0 OR BSL-1.0 |
| 1 | Zlib OR Apache-2.0 OR MIT |
| 1 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| 1 | CDLA-Permissive-2.0 |

**289 third-party packages.**

## Full list

| crate | version | licence |
|---|---|---|
| aead | 0.5.2 | MIT OR Apache-2.0 |
| aes | 0.8.4 | MIT OR Apache-2.0 |
| aes-gcm | 0.10.3 | Apache-2.0 OR MIT |
| aho-corasick | 1.1.4 | Unlicense OR MIT |
| anstream | 1.0.0 | MIT OR Apache-2.0 |
| anstyle | 1.0.13 | MIT OR Apache-2.0 |
| anstyle-parse | 1.0.0 | MIT OR Apache-2.0 |
| anstyle-query | 1.1.5 | MIT OR Apache-2.0 |
| anstyle-wincon | 3.0.11 | MIT OR Apache-2.0 |
| anyhow | 1.0.102 | MIT OR Apache-2.0 |
| arrayref | 0.3.9 | BSD-2-Clause |
| arrayvec | 0.7.6 | MIT OR Apache-2.0 |
| async-trait | 0.1.89 | MIT OR Apache-2.0 |
| atomic-waker | 1.1.2 | Apache-2.0 OR MIT |
| autocfg | 1.5.0 | Apache-2.0 OR MIT |
| axum | 0.7.9 | MIT |
| axum-core | 0.4.5 | MIT |
| base64 | 0.22.1 | MIT OR Apache-2.0 |
| base64ct | 1.8.3 | Apache-2.0 OR MIT |
| bitflags | 2.11.0 | MIT OR Apache-2.0 |
| blake3 | 1.8.3 | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 |
| bumpalo | 3.20.2 | MIT OR Apache-2.0 |
| bytes | 1.11.1 | MIT |
| cc | 1.2.56 | MIT OR Apache-2.0 |
| cfg-if | 1.0.4 | MIT OR Apache-2.0 |
| cfg_aliases | 0.2.1 | MIT |
| cipher | 0.4.4 | MIT OR Apache-2.0 |
| clap | 4.6.0 | MIT OR Apache-2.0 |
| clap_builder | 4.6.0 | MIT OR Apache-2.0 |
| clap_derive | 4.6.0 | MIT OR Apache-2.0 |
| clap_lex | 1.1.0 | MIT OR Apache-2.0 |
| colorchoice | 1.0.4 | MIT OR Apache-2.0 |
| const-oid | 0.9.6 | Apache-2.0 OR MIT |
| constant_time_eq | 0.4.2 | CC0-1.0 OR MIT-0 OR Apache-2.0 |
| core-foundation | 0.10.1 | MIT OR Apache-2.0 |
| core-foundation | 0.9.4 | MIT OR Apache-2.0 |
| core-foundation-sys | 0.8.7 | MIT OR Apache-2.0 |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 |
| crc32c | 0.6.8 | Apache-2.0/MIT |
| crossbeam-channel | 0.5.15 | MIT OR Apache-2.0 |
| crossbeam-utils | 0.8.21 | MIT OR Apache-2.0 |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 |
| ctr | 0.9.2 | MIT OR Apache-2.0 |
| curve25519-dalek | 4.1.3 | BSD-3-Clause |
| curve25519-dalek-derive | 0.1.1 | MIT/Apache-2.0 |
| der | 0.7.10 | Apache-2.0 OR MIT |
| digest | 0.10.7 | MIT OR Apache-2.0 |
| displaydoc | 0.2.5 | MIT OR Apache-2.0 |
| ed25519 | 2.2.3 | Apache-2.0 OR MIT |
| ed25519-dalek | 2.2.0 | BSD-3-Clause |
| encoding_rs | 0.8.35 | (Apache-2.0 OR MIT) AND BSD-3-Clause |
| equivalent | 1.0.2 | Apache-2.0 OR MIT |
| errno | 0.3.14 | MIT OR Apache-2.0 |
| fastrand | 2.3.0 | Apache-2.0 OR MIT |
| fiat-crypto | 0.2.9 | MIT OR Apache-2.0 OR BSD-1-Clause |
| find-msvc-tools | 0.1.9 | MIT OR Apache-2.0 |
| fnv | 1.0.7 | Apache-2.0 / MIT |
| foldhash | 0.1.5 | Zlib |
| foreign-types | 0.3.2 | MIT/Apache-2.0 |
| foreign-types-shared | 0.1.1 | MIT/Apache-2.0 |
| form_urlencoded | 1.2.2 | MIT OR Apache-2.0 |
| futures-channel | 0.3.32 | MIT OR Apache-2.0 |
| futures-core | 0.3.32 | MIT OR Apache-2.0 |
| futures-sink | 0.3.32 | MIT OR Apache-2.0 |
| futures-task | 0.3.32 | MIT OR Apache-2.0 |
| futures-util | 0.3.32 | MIT OR Apache-2.0 |
| generic-array | 0.14.7 | MIT |
| getrandom | 0.2.17 | MIT OR Apache-2.0 |
| getrandom | 0.3.4 | MIT OR Apache-2.0 |
| getrandom | 0.4.2 | MIT OR Apache-2.0 |
| ghash | 0.5.1 | Apache-2.0 OR MIT |
| h2 | 0.4.13 | MIT |
| hashbrown | 0.15.5 | MIT OR Apache-2.0 |
| hashbrown | 0.16.1 | MIT OR Apache-2.0 |
| heck | 0.5.0 | MIT OR Apache-2.0 |
| hkdf | 0.12.4 | MIT OR Apache-2.0 |
| hmac | 0.12.1 | MIT OR Apache-2.0 |
| http | 1.4.0 | MIT OR Apache-2.0 |
| http-body | 1.0.1 | MIT |
| http-body-util | 0.1.3 | MIT |
| httparse | 1.10.1 | MIT OR Apache-2.0 |
| httpdate | 1.0.3 | MIT OR Apache-2.0 |
| hyper | 1.8.1 | MIT |
| hyper-rustls | 0.27.7 | Apache-2.0 OR ISC OR MIT |
| hyper-tls | 0.6.0 | MIT/Apache-2.0 |
| hyper-util | 0.1.20 | MIT |
| icu_collections | 2.1.1 | Unicode-3.0 |
| icu_locale_core | 2.1.1 | Unicode-3.0 |
| icu_normalizer | 2.1.1 | Unicode-3.0 |
| icu_normalizer_data | 2.1.1 | Unicode-3.0 |
| icu_properties | 2.1.2 | Unicode-3.0 |
| icu_properties_data | 2.1.2 | Unicode-3.0 |
| icu_provider | 2.1.1 | Unicode-3.0 |
| id-arena | 2.3.0 | MIT/Apache-2.0 |
| idna | 1.1.0 | MIT OR Apache-2.0 |
| idna_adapter | 1.2.1 | Apache-2.0 OR MIT |
| indexmap | 2.13.0 | Apache-2.0 OR MIT |
| inout | 0.1.4 | MIT OR Apache-2.0 |
| io-uring | 0.7.11 | MIT OR Apache-2.0 |
| ipnet | 2.12.0 | MIT OR Apache-2.0 |
| iri-string | 0.7.10 | MIT OR Apache-2.0 |
| is_terminal_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| itoa | 1.0.17 | MIT OR Apache-2.0 |
| jobserver | 0.1.34 | MIT OR Apache-2.0 |
| js-sys | 0.3.91 | MIT OR Apache-2.0 |
| lazy_static | 1.5.0 | MIT OR Apache-2.0 |
| leb128fmt | 0.1.0 | MIT OR Apache-2.0 |
| libc | 0.2.183 | MIT OR Apache-2.0 |
| linux-raw-sys | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| litemap | 0.8.1 | Unicode-3.0 |
| lock_api | 0.4.14 | MIT OR Apache-2.0 |
| log | 0.4.29 | MIT OR Apache-2.0 |
| lru-slab | 0.1.2 | MIT OR Apache-2.0 OR Zlib |
| matchers | 0.2.0 | MIT |
| matchit | 0.7.3 | MIT AND BSD-3-Clause |
| memchr | 2.8.0 | Unlicense OR MIT |
| memmap2 | 0.9.10 | MIT OR Apache-2.0 |
| memoffset | 0.9.1 | MIT |
| mime | 0.3.17 | MIT OR Apache-2.0 |
| mio | 1.1.1 | MIT |
| native-tls | 0.2.18 | MIT OR Apache-2.0 |
| nix | 0.29.0 | MIT |
| nu-ansi-term | 0.50.3 | MIT |
| once_cell | 1.21.4 | MIT OR Apache-2.0 |
| once_cell_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| opaque-debug | 0.3.1 | MIT OR Apache-2.0 |
| openssl | 0.10.76 | Apache-2.0 |
| openssl-macros | 0.1.1 | MIT/Apache-2.0 |
| openssl-probe | 0.2.1 | MIT OR Apache-2.0 |
| openssl-sys | 0.9.112 | MIT |
| parking_lot | 0.12.5 | MIT OR Apache-2.0 |
| parking_lot_core | 0.9.12 | MIT OR Apache-2.0 |
| percent-encoding | 2.3.2 | MIT OR Apache-2.0 |
| pin-project-lite | 0.2.17 | Apache-2.0 OR MIT |
| pin-utils | 0.1.0 | MIT OR Apache-2.0 |
| pkcs8 | 0.10.2 | Apache-2.0 OR MIT |
| pkg-config | 0.3.32 | MIT OR Apache-2.0 |
| polyval | 0.6.2 | Apache-2.0 OR MIT |
| potential_utf | 0.1.4 | Unicode-3.0 |
| ppv-lite86 | 0.2.21 | MIT OR Apache-2.0 |
| prettyplease | 0.2.37 | MIT OR Apache-2.0 |
| proc-macro2 | 1.0.106 | MIT OR Apache-2.0 |
| prometheus | 0.13.4 | Apache-2.0 |
| protobuf | 2.28.0 | MIT |
| quinn | 0.11.9 | MIT OR Apache-2.0 |
| quinn-proto | 0.11.14 | MIT OR Apache-2.0 |
| quinn-udp | 0.5.14 | MIT OR Apache-2.0 |
| quote | 1.0.45 | MIT OR Apache-2.0 |
| r-efi | 5.3.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| r-efi | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| rand | 0.8.5 | MIT OR Apache-2.0 |
| rand | 0.9.2 | MIT OR Apache-2.0 |
| rand_chacha | 0.3.1 | MIT OR Apache-2.0 |
| rand_chacha | 0.9.0 | MIT OR Apache-2.0 |
| rand_core | 0.6.4 | MIT OR Apache-2.0 |
| rand_core | 0.9.5 | MIT OR Apache-2.0 |
| redox_syscall | 0.5.18 | MIT |
| regex-automata | 0.4.14 | MIT OR Apache-2.0 |
| regex-syntax | 0.8.10 | MIT OR Apache-2.0 |
| reqwest | 0.12.28 | MIT OR Apache-2.0 |
| ring | 0.17.14 | Apache-2.0 AND ISC |
| rustc-hash | 2.1.1 | Apache-2.0 OR MIT |
| rustc_version | 0.4.1 | MIT OR Apache-2.0 |
| rustix | 1.1.4 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| rustls | 0.23.37 | Apache-2.0 OR ISC OR MIT |
| rustls-pki-types | 1.14.0 | MIT OR Apache-2.0 |
| rustls-webpki | 0.103.9 | ISC |
| rustversion | 1.0.22 | MIT OR Apache-2.0 |
| ryu | 1.0.23 | Apache-2.0 OR BSL-1.0 |
| schannel | 0.1.29 | MIT |
| scopeguard | 1.2.0 | MIT OR Apache-2.0 |
| security-framework | 3.7.0 | MIT OR Apache-2.0 |
| security-framework-sys | 2.17.0 | MIT OR Apache-2.0 |
| semver | 1.0.27 | MIT OR Apache-2.0 |
| serde | 1.0.228 | MIT OR Apache-2.0 |
| serde_core | 1.0.228 | MIT OR Apache-2.0 |
| serde_derive | 1.0.228 | MIT OR Apache-2.0 |
| serde_json | 1.0.149 | MIT OR Apache-2.0 |
| serde_path_to_error | 0.1.20 | MIT OR Apache-2.0 |
| serde_urlencoded | 0.7.1 | MIT/Apache-2.0 |
| sha2 | 0.10.9 | MIT OR Apache-2.0 |
| sharded-slab | 0.1.7 | MIT |
| shlex | 1.3.0 | MIT OR Apache-2.0 |
| signal-hook-registry | 1.4.8 | MIT OR Apache-2.0 |
| signature | 2.2.0 | Apache-2.0 OR MIT |
| slab | 0.4.12 | MIT |
| smallvec | 1.15.1 | MIT OR Apache-2.0 |
| socket2 | 0.5.10 | MIT OR Apache-2.0 |
| socket2 | 0.6.3 | MIT OR Apache-2.0 |
| spki | 0.7.3 | Apache-2.0 OR MIT |
| stable_deref_trait | 1.2.1 | MIT OR Apache-2.0 |
| strsim | 0.11.1 | MIT |
| subtle | 2.6.1 | BSD-3-Clause |
| syn | 2.0.117 | MIT OR Apache-2.0 |
| sync_wrapper | 1.0.2 | Apache-2.0 |
| synstructure | 0.13.2 | MIT |
| system-configuration | 0.7.0 | MIT OR Apache-2.0 |
| system-configuration-sys | 0.6.0 | MIT OR Apache-2.0 |
| tempfile | 3.27.0 | MIT OR Apache-2.0 |
| thiserror | 1.0.69 | MIT OR Apache-2.0 |
| thiserror | 2.0.18 | MIT OR Apache-2.0 |
| thiserror-impl | 1.0.69 | MIT OR Apache-2.0 |
| thiserror-impl | 2.0.18 | MIT OR Apache-2.0 |
| thread_local | 1.1.9 | MIT OR Apache-2.0 |
| tinystr | 0.8.2 | Unicode-3.0 |
| tinyvec | 1.10.0 | Zlib OR Apache-2.0 OR MIT |
| tinyvec_macros | 0.1.1 | MIT OR Apache-2.0 OR Zlib |
| tokio | 1.50.0 | MIT |
| tokio-macros | 2.6.1 | MIT |
| tokio-native-tls | 0.3.1 | MIT |
| tokio-rustls | 0.26.4 | MIT OR Apache-2.0 |
| tokio-util | 0.7.18 | MIT |
| tower | 0.5.3 | MIT |
| tower-http | 0.6.8 | MIT |
| tower-layer | 0.3.3 | MIT |
| tower-service | 0.3.3 | MIT |
| tracing | 0.1.44 | MIT |
| tracing-attributes | 0.1.31 | MIT |
| tracing-core | 0.1.36 | MIT |
| tracing-log | 0.2.0 | MIT |
| tracing-subscriber | 0.3.22 | MIT |
| try-lock | 0.2.5 | MIT |
| typenum | 1.19.0 | MIT OR Apache-2.0 |
| unicode-ident | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| unicode-xid | 0.2.6 | MIT OR Apache-2.0 |
| universal-hash | 0.5.1 | MIT OR Apache-2.0 |
| untrusted | 0.9.0 | ISC |
| url | 2.5.8 | MIT OR Apache-2.0 |
| utf8_iter | 1.0.4 | Apache-2.0 OR MIT |
| utf8parse | 0.2.2 | Apache-2.0 OR MIT |
| uuid | 1.22.0 | Apache-2.0 OR MIT |
| valuable | 0.1.1 | MIT |
| vcpkg | 0.2.15 | MIT/Apache-2.0 |
| version_check | 0.9.5 | MIT/Apache-2.0 |
| want | 0.3.1 | MIT |
| wasi | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasip2 | 1.0.2+wasi-0.2.9 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasip3 | 0.4.0+wasi-0.3.0-rc-2026-01-06 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasm-bindgen | 0.2.114 | MIT OR Apache-2.0 |
| wasm-bindgen-futures | 0.4.64 | MIT OR Apache-2.0 |
| wasm-bindgen-macro | 0.2.114 | MIT OR Apache-2.0 |
| wasm-bindgen-macro-support | 0.2.114 | MIT OR Apache-2.0 |
| wasm-bindgen-shared | 0.2.114 | MIT OR Apache-2.0 |
| wasm-encoder | 0.244.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasm-metadata | 0.244.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasmparser | 0.244.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| web-sys | 0.3.91 | MIT OR Apache-2.0 |
| web-time | 1.1.0 | MIT OR Apache-2.0 |
| webpki-roots | 1.0.6 | CDLA-Permissive-2.0 |
| windows-link | 0.2.1 | MIT OR Apache-2.0 |
| windows-registry | 0.6.1 | MIT OR Apache-2.0 |
| windows-result | 0.4.1 | MIT OR Apache-2.0 |
| windows-strings | 0.5.1 | MIT OR Apache-2.0 |
| windows-sys | 0.52.0 | MIT OR Apache-2.0 |
| windows-sys | 0.59.0 | MIT OR Apache-2.0 |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 |
| windows-targets | 0.52.6 | MIT OR Apache-2.0 |
| windows_aarch64_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_aarch64_msvc | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_gnu | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_msvc | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_gnu | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_msvc | 0.52.6 | MIT OR Apache-2.0 |
| wit-bindgen | 0.51.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wit-bindgen-core | 0.51.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wit-bindgen-rust | 0.51.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wit-bindgen-rust-macro | 0.51.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wit-component | 0.244.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wit-parser | 0.244.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| writeable | 0.6.2 | Unicode-3.0 |
| x25519-dalek | 2.0.1 | BSD-3-Clause |
| yoke | 0.8.1 | Unicode-3.0 |
| yoke-derive | 0.8.1 | Unicode-3.0 |
| zerocopy | 0.8.42 | BSD-2-Clause OR Apache-2.0 OR MIT |
| zerocopy-derive | 0.8.42 | BSD-2-Clause OR Apache-2.0 OR MIT |
| zerofrom | 0.1.6 | Unicode-3.0 |
| zerofrom-derive | 0.1.6 | Unicode-3.0 |
| zeroize | 1.8.2 | Apache-2.0 OR MIT |
| zeroize_derive | 1.4.3 | Apache-2.0 OR MIT |
| zerotrie | 0.2.3 | Unicode-3.0 |
| zerovec | 0.11.5 | Unicode-3.0 |
| zerovec-derive | 0.11.2 | Unicode-3.0 |
| zmij | 1.0.21 | MIT |
| zstd | 0.13.3 | MIT |
| zstd-safe | 7.2.4 | MIT OR Apache-2.0 |
| zstd-sys | 2.0.16+zstd.1.5.7 | MIT/Apache-2.0 |
