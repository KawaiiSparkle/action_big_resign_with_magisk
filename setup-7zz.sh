#!/bin/bash
# setup-7zz.sh - install a 7-Zip (7zz) binary that replaces busybox/unzip for
# every archive extraction done by this repo (original.zip / magisk.apk).
#
# Sources are tried in order, and every candidate is verified to actually run
# on the current system (catches glibc-incompatible builds) before acceptance:
#
#   1. official 7-Zip releases (github.com/ip7z/7zip): latest version, amd64
#      (linux-x64) build, asset URL resolved through the GitHub API.
#      Ships the fully static "7zzs" binary (preferred over "7zz").
#   2. mcmilk/7-Zip-zstd nightly CI artifact, served by nightly.link:
#      .../workflows/build/master/linux-clang-x64.zip (clang x64 build with
#      zstd support; dynamically linked, so only used when source 1 fails).
#
# Only curl + tar and, as a bootstrap fallback, the python3 stdlib are used
# (tar.xz / zip are unpacked without unzip).
#
# Usage: ./setup-7zz.sh [dest]    (dest defaults to /usr/local/bin/7zz)
set -u

DEST="${1:-/usr/local/bin/7zz}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log() { printf 'setup-7zz: %s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

usable() { # does the candidate binary execute on this system?
    "$1" i >/dev/null 2>&1
}

install_7zz() {
    if [ "$(id -u)" = "0" ]; then
        install -m 0755 "$1" "$DEST"
    else
        sudo install -m 0755 "$1" "$DEST"
    fi
    log "installed $("$DEST" i 2>/dev/null | head -n1 | sed 's/ : Copyright.*//') -> $DEST"
}

pick_and_install() { # $1 = dir that (recursively) holds candidate binaries
    local dir="$1" bin
    for bin in "$(find "$dir" -type f -name 7zzs -print -quit)" \
               "$(find "$dir" -type f -name 7zz  -print -quit)"; do
        [ -n "$bin" ] || continue
        chmod +x "$bin" 2>/dev/null || true
        if usable "$bin"; then
            install_7zz "$bin"
            return 0
        fi
        log "candidate $bin does not run on this system, skipping"
    done
    return 1
}

try_ip7z() { # official release: latest 7-Zip, linux-x64 (amd64), via GitHub API
    log "trying official 7-Zip (ip7z/7zip) latest linux-x64 release via GitHub API"
    local json="$WORK/ip7z.json" tarball="$WORK/7zip-linux-x64.tar.xz" url
    local hdr=()
    [ -n "${GITHUB_TOKEN:-}" ] && hdr=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
    curl -fsSL --retry 3 ${hdr[@]+"${hdr[@]}"} -o "$json" \
        "https://api.github.com/repos/ip7z/7zip/releases/latest" || return 1
    url="$(grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' "$json" \
        | grep -oE 'https://[^"]+' | grep -E -- '-linux-x64\.tar\.xz$' | head -n 1)"
    [ -n "$url" ] || { log "no linux-x64 asset found in latest ip7z/7zip release"; return 1; }
    log "asset: $url"
    curl -fsSL --retry 3 -o "$tarball" "$url" || return 1
    mkdir -p "$WORK/ip7z"
    if ! tar -xJf "$tarball" -C "$WORK/ip7z" 2>/dev/null; then
        # tar without xz support (xz-utils missing) -> python3 stdlib handles .xz
        python3 -c 'import sys,tarfile; tarfile.open(sys.argv[1]).extractall(sys.argv[2])' \
            "$tarball" "$WORK/ip7z" || return 1
    fi
    pick_and_install "$WORK/ip7z" && return 0
    return 1
}

try_mcmilk() { # nightly build artifact of mcmilk/7-Zip-zstd via nightly.link
    log "trying mcmilk/7-Zip-zstd nightly artifact (linux-clang-x64.zip via nightly.link)"
    local zip="$WORK/linux-clang-x64.zip"
    curl -fsSL --retry 3 -o "$zip" \
        "https://nightly.link/mcmilk/7-Zip-zstd/workflows/build/master/linux-clang-x64.zip" \
        || return 1
    mkdir -p "$WORK/mcmilk"
    # the artifact is a zip - bootstrap-extract it with the python3 stdlib,
    # since this repo deliberately no longer uses unzip
    python3 -c 'import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' \
        "$zip" "$WORK/mcmilk" || return 1
    pick_and_install "$WORK/mcmilk" && return 0
    return 1
}

if [ -x "$DEST" ] && usable "$DEST"; then
    log "$DEST already installed and working, nothing to do"
    exit 0
fi

try_ip7z   && exit 0
try_mcmilk && exit 0
die "failed to obtain a working 7zz binary from all sources"
