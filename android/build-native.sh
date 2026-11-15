#!/usr/bin/env bash
# Builds libtunlens.so for the ABIs the app ships and drops them where Gradle
# expects: app/src/main/jniLibs/<abi>/libtunlens.so.
#
# Requires the Android NDK plus `cargo install cargo-ndk`. Set ANDROID_NDK_HOME
# (or ANDROID_NDK_ROOT) first, e.g.
#   export ANDROID_NDK_HOME="$HOME/Android/Sdk/ndk/27.2.12479018"
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(dirname "$here")"

if ! command -v cargo-ndk >/dev/null 2>&1; then
    echo "cargo-ndk is missing: cargo install cargo-ndk" >&2
    exit 1
fi

if [ -z "${ANDROID_NDK_HOME:-}${ANDROID_NDK_ROOT:-}" ]; then
    echo "ANDROID_NDK_HOME is not set; cargo-ndk needs it to find the toolchain" >&2
    exit 1
fi

# rust/.cargo/config.toml points the linker at Termux's clang for host builds.
# cargo-ndk passes its own linker through the environment, which wins, but any
# stale -L flags from that file would still apply. Move it aside while cross
# compiling so the NDK sysroot is the only one in play.
cfg="$repo/rust/.cargo/config.toml"
stash=""
if [ -f "$cfg" ]; then
    stash="$cfg.host-build"
    mv "$cfg" "$stash"
    trap 'mv "$stash" "$cfg"' EXIT
fi

cd "$repo/rust"
cargo ndk -t arm64-v8a -t armeabi-v7a -o "$here/app/src/main/jniLibs" build --release

echo
echo "Native libraries:"
find "$here/app/src/main/jniLibs" -name 'libtunlens.so' -exec ls -lh {} \;
