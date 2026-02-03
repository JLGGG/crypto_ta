#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OPTEE_DIR="$HOME/optee"
EXAMPLE_NAME="crypto_ta"

echo "================== Step 1: Copy to optee_examples =================="
rm -rf "$OPTEE_DIR/optee_examples/$EXAMPLE_NAME"
cp -r "$SCRIPT_DIR" "$OPTEE_DIR/optee_examples/$EXAMPLE_NAME"
echo "Copied to $OPTEE_DIR/optee_examples/$EXAMPLE_NAME"

echo "================== Step 2: Clean build cache =================="
rm -rf "$OPTEE_DIR/out-br/build/optee_examples_ext-1.0/$EXAMPLE_NAME"

echo "================== Step 3: Build =================="
cd "$OPTEE_DIR/build"
make -j$(nproc)

if [[ "$1" == "--build-only" ]]; then
	echo "Build complete. Skipping QEMU."
	exit 0
fi

echo "================== Step 4: Run QEMU =================="
make run
