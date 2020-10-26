#!/bin/bash

# Bash "strict mode"
set -euo pipefail

NF_DIR=`pwd`
BUILD="$NF_DIR/build/parallelization"
KLEE_DIR="$VIGOR_DIR/klee"

# ==============
# Pre requisites
# ==============

cd "$NF_DIR"

if [ $(ls -dq "$NF_DIR/klee-last" 2> /dev/null | wc -l) -eq "0" ]; then
    echo "ERROR: no call paths to parse. Run \"make symbex\" first."
    exit 1
fi

# ===========
# Build setup
# ===========

mkdir -p "$BUILD"

echo "[*] Building parse-libvig-access"

make clean > /dev/null
make -f ../parallelize/Makefile > /dev/null

echo "[*] Building analyse-libvig-call-paths"

cd "$KLEE_DIR"
./build.sh > /dev/null
ln -sf "$KLEE_DIR/build/bin/analyse-libvig-call-paths" "$BUILD/analyse-libvig-call-paths"
cd "$NF_DIR"

# ================
# Parse call paths
# ================

echo "[*] Parsing call paths"
CALL_PATHS=$NF_DIR/klee-last/test*.call_path
"$BUILD/analyse-libvig-call-paths" $CALL_PATHS \
    2> "$BUILD/report-log.txt" \
    > "$BUILD/report.lva"

echo "[*] Parsing libvig report"
"$BUILD/parse-libvig-access" "$BUILD/report.lva"
