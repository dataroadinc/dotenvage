#!/bin/bash
# Sync all package versions with the main crate version
# Usage: sync-npm-version.sh <version>
#
# Note: Cargo.toml versions are handled by cargo version-info bump.
# This script only syncs non-Cargo package files (npm, python).

VERSION="$1"

if [ -z "$VERSION" ]; then
  echo "Error: Version required"
  exit 1
fi

# Update npm/package.json
if [ -f "npm/package.json" ]; then
  if [ "$(uname)" == "Darwin" ]; then
    sed -i '' "s/\"version\": \".*\"/\"version\": \"$VERSION\"/" npm/package.json
  else
    sed -i "s/\"version\": \".*\"/\"version\": \"$VERSION\"/" npm/package.json
  fi
  echo "✅ Updated npm/package.json to $VERSION"
fi

# Update python/pyproject.toml
if [ -f "python/pyproject.toml" ]; then
  if [ "$(uname)" == "Darwin" ]; then
    sed -i '' "s/^version = \".*\"/version = \"$VERSION\"/" python/pyproject.toml
  else
    sed -i "s/^version = \".*\"/version = \"$VERSION\"/" python/pyproject.toml
  fi
  echo "✅ Updated python/pyproject.toml to $VERSION"
fi

# Update the local dotenvage package entry in Python's uv lockfile.
if [ -f "python/uv.lock" ]; then
  python3 - "$VERSION" <<'PY'
import pathlib
import re
import sys

lock_path = pathlib.Path("python/uv.lock")
contents = lock_path.read_text()
updated, replacements = re.subn(
    r'(\[\[package\]\]\nname = "dotenvage"\nversion = ")[^"]+("\n)',
    rf'\g<1>{sys.argv[1]}\2',
    contents,
    count=1,
)
if replacements != 1:
    raise SystemExit("could not locate the dotenvage package version in python/uv.lock")
lock_path.write_text(updated)
PY
  python_rc=$?
  if [ "$python_rc" -ne 0 ]; then
    exit "$python_rc"
  fi
  echo "✅ Updated python/uv.lock to $VERSION"
fi

# Update root package.json if it exists and has a version field
if [ -f "package.json" ] && grep -q '"version":' package.json; then
  if [ "$(uname)" == "Darwin" ]; then
    sed -i '' "s/\"version\": \".*\"/\"version\": \"$VERSION\"/" package.json
  else
    sed -i "s/\"version\": \".*\"/\"version\": \"$VERSION\"/" package.json
  fi
  echo "✅ Updated package.json to $VERSION"
fi

echo "✅ Synced all package versions to $VERSION"
