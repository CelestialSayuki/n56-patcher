# Native Intel/macOS host only. CLT clang assembles ARM blobs as data; never runs ARM.
PYTHON ?= python3
HOST_ARCH ?= $(shell uname -m)
CC = clang -arch $(HOST_ARCH)
V = vendor
KPF = $(V)/checkra1n/kpf
INC = -I$(V)/include -I$(V)/src/kernel -I$(V)/src/drivers -I$(KPF) -Ihost
MODULES = developer_mode dyld launch_constraints mach_port nvram persona trustcache vfs vm_prot
SOURCES = host/main.c .build/kpf-main.c .build/xnu.c $(addprefix $(KPF)/,$(addsuffix .c,$(MODULES))) .build/shellcode.host.S .build/xnu.host.S
FLAGS = -std=gnu17 -O2 -Wall -Werror=incompatible-function-pointer-types -Wno-unused-function -Wno-unused-but-set-variable -D_GNU_SOURCE -DKPF_TEST -DDEV_BUILD -Diprintf=printf -Dpanic=realpanic -DOVERRIDE_CACHEABLE_VIEW=0x800000000ULL -DCHECKRA1N_VERSION='"e98323f8-offline"' -Wl,-dead_strip
HEADERS = $(shell find vendor host -name '*.h')

.PHONY: all clean
all: palera1n-kpf.macos

.build/prepared: scripts/prepare.py upstream-manifest.json $(shell find vendor -type f)
	$(PYTHON) scripts/prepare.py
	touch $@
.build/kpf-main.c .build/xnu.c: .build/prepared

.build/shellcode.host.S: $(KPF)/shellcode.S scripts/gen_blob.py .build/prepared
	$(PYTHON) scripts/gen_blob.py $< $@ .build $(INC)

.build/xnu.host.S: $(V)/src/drivers/xnu/xnu.S scripts/gen_blob.py .build/prepared
	$(PYTHON) scripts/gen_blob.py $< $@ .build $(INC)

palera1n-kpf.macos: Makefile $(SOURCES) $(HEADERS) .build/prepared
	$(CC) $(FLAGS) $(INC) $(SOURCES) -o $@

clean:
	rm -rf .build palera1n-kpf.macos
