BPF_CLANG ?= clang

BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
							-Iinclude -I. -I/usr/include

USER_CFLAGS := -O2 -g -Wall $(shell pkg-config --cflags libbpf) -fopenmp
USER_LDFLAGS := -Wl,-Bstatic $(shell pkg-config --libs --static libbpf) -Wl,-Bdynamic -lelf -lz -latomic -lpthread -fopenmp

BPF_OBJ := flow_xdp.bpf.o
USER_BIN := flow_user
SKEL_HDR := flow_xdp.skel.h

all: $(USER_BIN)

$(BPF_OBJ): src/bpf/flow_xdp.bpf.c include/flow_common.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL_HDR): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(USER_BIN): src/user/flow_user.c src/user/worker.c include/flow_common.h $(SKEL_HDR)
	$(CC) $(USER_CFLAGS) -Iinclude -I. src/user/flow_user.c src/user/worker.c -o $@ $(USER_LDFLAGS)

clean:
	rm -f $(BPF_OBJ) $(USER_BIN) $(SKEL_HDR)