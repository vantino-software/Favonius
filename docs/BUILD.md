# Building Favonius

Favonius is built with `cargo`. Native Linux builds work out of the box.
Cross-compilation to Windows and macOS targets requires additional tooling.

## Native Linux build

```bash
# Debug build (fast compile, slow runtime)
cargo build

# Release build (slow compile, fast runtime — required for benchmarks)
cargo build --release

# Just the CLI and daemon binaries
cargo build --release -p ahp-cli -p ahp-daemon
```

The release binaries land in `target/release/`:

- `target/release/favonius` — sender CLI
- `target/release/favonius-daemon` — receiver daemon

## Cross-compiling to Windows from Linux

Favonius can be cross-compiled to Windows using `cargo-xwin`, which downloads
the MSVC SDK headers and libraries on demand. No Windows machine or wine
required.

### Setup (one time)

```bash
# Install cargo-xwin
cargo install cargo-xwin

# Add Windows targets
rustup target add x86_64-pc-windows-msvc
rustup target add aarch64-pc-windows-msvc
```

### Build

`ahp-cli` pulls in C build deps via `ring`, `blake3`, and `zstd-sys`, all of
which use `cc-rs`. For x86_64-pc-windows-msvc, `cc-rs` invokes `llvm-lib`
as the archiver — make sure it is on `$PATH` (Ubuntu ships it under
`/usr/lib/llvm-NN/bin/llvm-lib`):

```bash
# One-time setup: put llvm-lib on PATH for the cc crate
export PATH="/usr/lib/llvm-18/bin:$PATH"

# Cross-compile the platform-net abstraction crate
cargo xwin build -p ahp-platform-net --target x86_64-pc-windows-msvc
cargo xwin build -p ahp-platform-net --target aarch64-pc-windows-msvc

# Cross-compile the full sender CLI
cargo xwin build -p ahp-cli --target x86_64-pc-windows-msvc

# Release builds
cargo xwin build --release -p ahp-cli --target x86_64-pc-windows-msvc
```

The Windows artifacts land in `target/x86_64-pc-windows-msvc/debug/` (or
`/release/`):

- `favonius.exe` — sender CLI (~16 MB debug, smaller in release)
- `libahp_platform_net.rlib` — Rust library

> **aarch64-pc-windows-msvc:** the `ring` crate's pre-compiled ARM
> assembly currently fails to cross-build with `clang` because the
> `/imsvc` flag is interpreted as a path. Forcing `clang-cl` via
> `CC_aarch64_pc_windows_msvc=clang-cl` is the workaround. Pure-Rust
> Favonius crates (e.g. `ahp-platform-net`) do cross-compile cleanly to
> aarch64-Windows because they have no C dependencies.

## Cross-compiling to macOS from Linux

For library targets that don't link against the macOS SDK, Rust can build
directly to Apple targets without any extra tooling:

```bash
rustup target add aarch64-apple-darwin   # Apple Silicon (M1/M2/M3)
rustup target add x86_64-apple-darwin    # Intel Macs

cargo build -p ahp-platform-net --target aarch64-apple-darwin
cargo build -p ahp-platform-net --target x86_64-apple-darwin
```

For full binary builds (linking against system frameworks), you need either:

1. **A real Mac** with Xcode Command Line Tools, or
2. **`osxcross`** on Linux — see https://github.com/tpoechtrager/osxcross
   This requires extracting the macOS SDK from a legitimate Xcode install
   (Apple's licensing prohibits redistribution).

For now, library crates cross-compile cleanly without osxcross. Binary
crates that link `ahp-cli` will need a Mac or osxcross because `zstd-sys`
(via `ahp-compression`) compiles C source with `-arch arm64`/`-mmacosx-version-min`
which the host `cc` does not understand.

## Verifying cross-compile artifacts

```bash
# Linux (native)
ls target/debug/libahp_platform_net.rlib

# Windows
ls target/x86_64-pc-windows-msvc/debug/libahp_platform_net.rlib
ls target/aarch64-pc-windows-msvc/debug/libahp_platform_net.rlib

# macOS
ls target/aarch64-apple-darwin/debug/libahp_platform_net.rlib
ls target/x86_64-apple-darwin/debug/libahp_platform_net.rlib

# Inspect a Windows .rlib (it's an ar archive)
ar t target/x86_64-pc-windows-msvc/debug/libahp_platform_net.rlib | head
```

## Build matrix status

Currently:

| Target | Cross-compile from Linux | Native | Status |
|--------|--------------------------|--------|--------|
| `x86_64-unknown-linux-gnu` | n/a | yes | ✓ Production |
| `armv7-unknown-linux-gnueabihf` | via `cross` | n/a | ✓ Used for Pi daemon |
| `x86_64-pc-windows-msvc` | via `cargo-xwin` (needs `llvm-lib` on PATH) | needs Windows | ✓ `ahp-cli` builds clean |
| `aarch64-pc-windows-msvc` | via `cargo-xwin` | needs Windows ARM | ⚠ `ahp-platform-net` clean; `ahp-cli` blocked on `ring` cc-rs flag handling |
| `aarch64-apple-darwin` | library only | needs Mac | ⚠ `ahp-platform-net` clean; `ahp-cli` needs osxcross for `zstd-sys` |
| `x86_64-apple-darwin` | library only | needs Mac | ⚠ `ahp-platform-net` clean; `ahp-cli` needs osxcross for `zstd-sys` |

Pure-Rust crates cross-compile to all six targets. The four Windows/macOS
binary builds are gated by C-toolchain availability, not by Favonius Rust
code: the `net_sender.rs` Linux-only specializations (paced, zero-copy
sendmmsg, io_uring, AF_XDP) are now `#[cfg(target_os = "linux")]` and the
cross-platform `Platform` variant from `ahp_platform_net::create_best_sender`
is used everywhere else.

## Universal macOS binary (later)

To produce a single binary that runs on both Apple Silicon and Intel:

```bash
# After building both targets on a real Mac:
lipo -create -output target/release/favonius \
    target/aarch64-apple-darwin/release/favonius \
    target/x86_64-apple-darwin/release/favonius

file target/release/favonius
# → Mach-O universal binary with 2 architectures
```

## Code signing (later)

- **macOS**: requires Apple Developer ID, `codesign` + `xcrun notarytool`
- **Windows**: requires an Authenticode certificate (~$200/year)

These steps are not yet automated. Automating them is tracked
(CI setup) when the time comes for releases.
