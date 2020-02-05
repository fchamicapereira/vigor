#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(cd $(dirname ${BASH_SOURCE[0]}) && pwd)

function cleanup {
  sudo killall nf 2>/dev/null || true
}
trap cleanup EXIT


function test_policer {
  sudo gdb ./build/app/nf --command=./debug.gdb
}


make clean
make ADDITIONAL_FLAGS="-DSTOP_ON_RX_0 -g"

test_policer 12500 500000

echo "Done."
