#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
make clean
make test SANITIZE=1
make demo
./build/adaptive_demo --config config/runtime.conf --steps 24
