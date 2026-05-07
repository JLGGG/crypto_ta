#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OPTEE_DIR="$HOME/optee"
EXAMPLE_NAME="crypto_ta"
TA_DEV_KIT_DIR="$OPTEE_DIR/optee_os/out/arm/export-ta_arm64"
CROSS_COMPILE="aarch64-linux-gnu-"
BR_HOST_BIN="$OPTEE_DIR/out-br/host/bin"

if [[ "$1" == "--run-only" ]]; then
	echo "Start QEMU."
	cd "$OPTEE_DIR/build"
	make run-only
	exit 0
fi

echo "================== Step 1: Copy to optee_examples =================="
rm -rf "$OPTEE_DIR/optee_examples/$EXAMPLE_NAME"
cp -r "$SCRIPT_DIR" "$OPTEE_DIR/optee_examples/$EXAMPLE_NAME"

echo "================== Step 2: Build KeyMgmt TA =================="
cd "$OPTEE_DIR/optee_examples/$EXAMPLE_NAME/keymgmt_ta"
PATH="$BR_HOST_BIN:$PATH" make TA_DEV_KIT_DIR="$TA_DEV_KIT_DIR" CROSS_COMPILE="$CROSS_COMPILE" O=out

echo "================== Step 3: Clean build cache =================="
rm -rf "$OPTEE_DIR/out-br/build/optee_examples_ext-1.0/$EXAMPLE_NAME"

echo "================== Step 4: Build =================="
cd "$OPTEE_DIR/build"
make -j$(nproc)

echo "================== Step 5: Copy KeyMgmt TA =================="
cp "$OPTEE_DIR/optee_examples/$EXAMPLE_NAME/keymgmt_ta/out/"*.ta \
   "$OPTEE_DIR/out-br/target/lib/optee_armtz/"

if [[ "$1" == "--build-only" ]]; then
	echo "Build complete."
	exit 0
fi

echo "================== Step 6: Run QEMU =================="
make run
