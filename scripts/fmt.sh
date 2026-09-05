#!/bin/sh
# Use the same formatter in local commands, commit hooks and CI.
script_directory=$(dirname "$0") || exit 1
repository_root=$(cd "$script_directory/.." && pwd) || exit 1
cd "$repository_root" || exit 1
if ! IFS= read -r formatter_toolchain < rustfmt-toolchain; then
    printf 'Cannot read rustfmt-toolchain\n' >&2
    exit 1
fi
if ! rustup run "$formatter_toolchain" rustfmt --version >/dev/null 2>&1; then
    printf 'Install the formatter: rustup toolchain install %s --profile minimal --component rustfmt\n' "$formatter_toolchain" >&2
    exit 1
fi
exec cargo "+$formatter_toolchain" fmt --all -- "$@"
