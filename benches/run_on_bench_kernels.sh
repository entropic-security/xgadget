#! /bin/bash

set -ue
cd $(dirname "$0")
cd ..

KERNELS=()
for i in {1..10}
do
    BASE_VER_NUM=(5 0 0)
    KERNELS+=("./benches/kernels/vmlinux-${BASE_VER_NUM[0]}.${BASE_VER_NUM[1]}.$i")
done

for k in ${KERNELS[@]}; do
    if [ -f "$k" ] && file "$k" | grep -q "ELF"; then
        echo "Binary '$k' found"
    else
        echo "Binary '$k' not found. Please run bench_setup_ubuntu.sh!"
        exit 1
    fi
done

cargo run --release -- "${KERNELS[@]}"
