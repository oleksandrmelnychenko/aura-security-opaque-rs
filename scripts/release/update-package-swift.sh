#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <version-tag-without-v-prefix> <checksum>" >&2
  exit 1
fi

VERSION="$1"
CHECKSUM="$2"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKAGE_SWIFT="$ROOT/Package.swift"

python3 - "$PACKAGE_SWIFT" "$VERSION" "$CHECKSUM" <<'PY'
from pathlib import Path
import re
import sys

package_path = Path(sys.argv[1])
version = sys.argv[2]
checksum = sys.argv[3]
text = package_path.read_text()

text = re.sub(
    r'https://github\.com/oleksandrmelnychenko/aura-security-opaque-rs/releases/download/v[^"]+/AuraOPAQUE\.xcframework\.zip',
    f'https://github.com/oleksandrmelnychenko/aura-security-opaque-rs/releases/download/v{version}/AuraOPAQUE.xcframework.zip',
    text,
)
text = re.sub(
    r'checksum: "[0-9a-f]{64}"',
    f'checksum: "{checksum}"',
    text,
)

package_path.write_text(text)
PY

echo "Updated Package.swift for v$VERSION"
