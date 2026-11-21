#!/usr/bin/env bash
# Usage: MBEDTLS_DIR=/path/to/mbedtls-3.6.x ./run_host_test.sh
# Compiler defaults to `python3 -m ziglang` (pip install ziglang).
set -euo pipefail
cd "$(dirname "$0")"
: "${MBEDTLS_DIR:?set MBEDTLS_DIR}"
CC=${CC:-"python3 -m ziglang cc"}; CXX=${CXX:-"python3 -m ziglang c++"}
OUT=$(mktemp -d)
OBJ="$MBEDTLS_DIR/.hostobj"; mkdir -p "$OBJ"
for src in "$MBEDTLS_DIR"/library/*.c; do
  o="$OBJ/$(basename "$src" .c).o"
  [ -f "$o" ] || $CC -O1 -I"$MBEDTLS_DIR/include" -I"$MBEDTLS_DIR/library" -c "$src" -o "$o" &
done; wait
$CXX -std=c++17 -Wall -Wextra -O1 -I"$MBEDTLS_DIR/include" test_protocol.cpp ../components/hayward_pump/hayward_protocol.cpp "$OBJ"/*.o -o "$OUT/test"
"$OUT/test"
