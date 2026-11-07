ifndef $(HOST_OS)
	ifeq ($(OS),Windows_NT)
		HOST_OS = Windows
	else
		HOST_OS := $(shell uname -s)
	endif
endif

HOST_ARCH ?= $(shell uname -m)
PYTHON    ?= python3

PONGO_VERSION := n56-offline
ROOT                    := ../..
SRC                     := $(ROOT)/src
INC                     := $(ROOT)/include
RA1N                    := $(ROOT)/checkra1n/kpf

# xnu.S / shellcode.S 是 arm64 指令流，主机侧只当字节数据用（源码里只做
# &start…&end 的指针差与 memcpy，从不执行这些字节）。非 arm64 主机先用
# scripts/gen_blob.py 把它们汇编成 arm64 目标文件，再按符号偏移铺成数据区，
# 字节布局与符号地址和 arm64 主机构建完全一致。
ifeq ($(HOST_ARCH),arm64)
	KPF_ASM    := $(RA1N)/shellcode.S $(SRC)/drivers/xnu/xnu.S
	IOS_TARGET := kpf-test.ios
else
	KPF_ASM    := host-blobs/shellcode.host.S host-blobs/xnu.host.S
	IOS_TARGET :=
endif

CHECKRA1N_C             := main.c $(RA1N)/main.c $(KPF_ASM) $(SRC)/drivers/xnu/xnu.c
CHECKRA1N_LDFLAGS       := -Wl,-fatal_warnings -Wl,-dead_strip
CHECKRA1N_FLAGS         := -std=gnu17 -Wall -Wunused-label -Werror -O3 -flto -I$(INC) -I$(SRC)/kernel -I$(SRC)/drivers -DCHECKRAIN_VERSION='' -Diprintf=printf -Dpanic=realpanic -DOVERRIDE_CACHEABLE_VIEW=0x800000000ULL -DDEV_BUILD=1 $(CHECKRA1N_LDFLAGS) $(KPF_CFLAGS) $(CFLAGS)

ifeq ($(HOST_OS),Darwin)
	IOS_CC              ?= xcrun -sdk iphoneos clang -arch arm64
	MACOS_CC            ?= clang -arch $(HOST_ARCH)
	IOS_FLAGS           ?= -miphoneos-version-min=7.0
	MACOS_FLAGS         ?= -mmacosx-version-min=11.0 '-Djit_set_exec(m)=void pthread_jit_write_protect_np(int); pthread_jit_write_protect_np(m)'
	SIGN                ?= codesign -s - --entitlements ent.plist
else
ifeq ($(HOST_OS),Linux)
# TODO: macOS target
	IOS_CC              ?= arm64-apple-ios12.0.0-clang -arch arm64
	SIGN                ?= ldid -Sent.plist
endif
endif


.PHONY: all clean host-blobs

all: kpf-test.macos $(IOS_TARGET)

host-blobs:
	mkdir -p $@

host-blobs/xnu.host.S: $(SRC)/drivers/xnu/xnu.S $(ROOT)/scripts/gen_blob.py | host-blobs
	$(PYTHON) $(ROOT)/scripts/gen_blob.py $< $@ host-blobs -I$(INC) -I$(SRC)/kernel -I$(SRC)/drivers

host-blobs/shellcode.host.S: $(RA1N)/shellcode.S $(ROOT)/scripts/gen_blob.py | host-blobs
	$(PYTHON) $(ROOT)/scripts/gen_blob.py $< $@ host-blobs -I$(INC) -I$(SRC)/kernel -I$(SRC)/drivers

kpf-test.ios: $(CHECKRA1N_C)
	$(IOS_CC) -o $@ $(CHECKRA1N_C) $(CHECKRA1N_FLAGS) $(IOS_FLAGS)
	$(SIGN) $@

kpf-test.macos: $(CHECKRA1N_C)
	$(MACOS_CC) -o $@ $(CHECKRA1N_C) $(CHECKRA1N_FLAGS) $(MACOS_FLAGS)

clean:
	rm -f kpf-test.ios kpf-test.macos
	rm -rf host-blobs
