# SPDX-License-Identifier: GPL-2.0
CFLAGS += -Wall -Wextra -Werror -O2 -no-pie -fno-pie $(KHDR_INCLUDES)
LDLIBS += -pthread
TEST_GEN_PROGS := cxlfork_test cxlfork_capsule_k0 cxlfork_spawn_bench
TEST_GEN_FILES := cxlfork_litmus

cxlfork_capsule_k0: CFLAGS += -fno-stack-protector -fcf-protection=none
cxlfork_spawn_bench: CFLAGS += -fno-stack-protector -fcf-protection=none
cxlfork_spawn_bench: LDFLAGS += -static

include ../lib.mk
