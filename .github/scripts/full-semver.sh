#!/usr/bin/env bash
# Prints the full three-part SemVer of a version written X.Y, X.Y.Z or either with a -prerelease
# suffix: 3.2 -> 3.2.0, 3.2-beta1 -> 3.2.0-beta1, 3.1.1 -> 3.1.1. Anything else is refused with a
# non-zero exit and nothing on stdout.
#
# MinVer 7 rejects a two-part MinVerVersionOverride (MINVER1005), while the release tags, the release
# input and the release branches all name a version in its two-part form; every workflow that turns
# such a name into an override takes the full number from here.
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: full-semver.sh <X.Y | X.Y.Z>[-prerelease]" >&2
  exit 2
fi

version=$1
if [[ ! "$version" =~ ^([0-9]+\.[0-9]+)(\.[0-9]+)?(-[A-Za-z0-9.-]+)?$ ]]; then
  echo "'$version' is not X.Y, X.Y.Z or either with a -prerelease suffix." >&2
  exit 1
fi

echo "${BASH_REMATCH[1]}${BASH_REMATCH[2]:-.0}${BASH_REMATCH[3]}"
