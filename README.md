# Crypto TA for OP-TEE

Examples of Trusted Application in OP-TEE Crypto

## Features
- SHA-256   
- SHA-512   
- AES-CMAC   

## How to build
1. Set up an OP-TEE development environment (QEMU v8)   
```
mkdir ~/optee && cd ~/optee   
repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml   
repo sync   
cd build && make toolchains && make -j$(nproc)   
```   

2. Git Repo Clone   
```
gh repo clone JLGGG/crypto_ta ~/crypto_ta
```

3. Copy this project into the optee_examples   
```
cp -r ~/crypto_ta ~/optee/optee_examples/crypto_ta   
```

4. Build
```
cd ~/optee/build   
make -j$(nproc) # In the initial time, it may take above 30m.   
```

5. Build host only (When facing a build error in all code)   
```
cd ~/optee/optee_examples/crypto_ta/host   
export CROSS_COMPILE=$HOME/optee/out-br/host/bin/aarch64-linux-gnu-       
export TEEC_EXPORT=$HOME/optee/out-br/host/aarch64-buildroot-linux-gnu/sysroot/usr   
make clean   
make V=1 CC=${CROSS_COMPILE}gcc
``` 

6. Run
```
make run   
```

7. QEMU Normal World   
```
optee_example_crypto_ta   
```   

8. All-in-one build and QEMU run    
This script provides building and running the crypto_ta. To use this, you must complete step 1.
```
~/crypto_ta/run.sh # If you want to build only, you can do so by adding "--build-only" flag
```

9. Tools   
```
The command below searches for information about the supported algorithms on TEE by replacing "*".    
grep -r "*" ~/optee/optee_os/lib/libutee/include
```

## UUID   
```
12345678-1234-1234-1234-123456789abc
```
