#! /bin/bash

# Quit on error
set -ue

# Coloring
TOGGLE_COLOR='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'

# Deps - both kernel and userspace ELF bench
echo -e "\n${YELLOW}Installing dependencies...${TOGGLE_COLOR}"
sudo apt-get install -y cmake wget gnupg2 xz-utils binutils gdb build-essential libncurses-dev bison flex libssl-dev libelf-dev gcc-8
echo -e "\n${YELLOW}Switching to GCC 8...${TOGGLE_COLOR}"
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 1
gcc --version

# Keys
echo -e "\n${YELLOW}Importing kernel signing keys...${TOGGLE_COLOR}"
gpg2 --locate-keys torvalds@kernel.org gregkh@kernel.org

# Download and build kernels
cd $(dirname "$0")
TARGET_DIR="kernels"
mkdir -p $TARGET_DIR
cd $TARGET_DIR
for i in {1..10}
do
    BASE_VER_NUM=(5 0 0)
    KERNEL="linux-${BASE_VER_NUM[0]}.${BASE_VER_NUM[1]}.$i"
    KERNEL_TAR="$KERNEL.tar.xz"
    KERNEL_SIG="$KERNEL.tar.sign"
    KERNEL_TAR_URL="https://cdn.kernel.org/pub/linux/kernel/v${BASE_VER_NUM[0]}.x/$KERNEL_TAR"
    KERNEL_SIG_URL="https://cdn.kernel.org/pub/linux/kernel/v${BASE_VER_NUM[0]}.x/$KERNEL_SIG"

    echo -e "\n${YELLOW}Downloading ${KERNEL} tar...${TOGGLE_COLOR}"
    wget -nc -q --show-progress $KERNEL_TAR_URL
    wget -nc -q --show-progress $KERNEL_SIG_URL

    echo -e "\n${YELLOW}Extracting and verifying ${KERNEL} source...${TOGGLE_COLOR}"
    xz -cd $KERNEL_TAR | gpg2 --verify $KERNEL_SIG -
    tar xf $KERNEL_TAR --checkpoint=.1000

    echo -e "\n\n${YELLOW}Configuring kernel ${KERNEL}...${TOGGLE_COLOR}"
    cd $KERNEL
    make x86_64_defconfig

    echo -e "\n\n${YELLOW}Building kernel ${KERNEL}...${TOGGLE_COLOR}"
    make -j $(nproc)

    if [ -f "vmlinux" ]; then
        TEST_KERNEL="vmlinux-${BASE_VER_NUM[0]}.${BASE_VER_NUM[1]}.$i"
        echo -e "\n${GREEN}Build OK, saving $TEST_KERNEL and cleaning up disk...${TOGGLE_COLOR}"
        mv vmlinux ../$TEST_KERNEL
        cd ..
        rm -rf $KERNEL/
        rm $KERNEL_TAR
        rm $KERNEL_SIG
    else
        echo -e "\n${RED}${KERNEL} build FAILED.${TOGGLE_COLOR}"
        exit 1
    fi

done

# Status print
echo -e "\n${GREEN}Kernels ready for benchmarking: ${TOGGLE_COLOR}"
find . -iname "vmlinux*" -exec ls -l --block-size=M {} \;