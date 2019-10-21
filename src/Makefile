ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = scionfwd

# all source are stored in SRCS-y
SRCS-y := application.c scion_bloom.c murmurhash.c key_manager.c hashdict.c hashdict_flow.c

CFLAGS += -mcmodel=medium -O3
CFLAGS += $(WERROR_FLAGS)

# this is required to find the header files!
CFLAGS += -I$(SRCDIR)

#AES
LDLIBS += -L'$(PWD)/lib/aesni'
EXTRA_LDFLAGS += -laesni

#Key manager
LDLIBS += -L'$(PWD)/lib/go'
EXTRA_LDFLAGS += -l:go_key_manager.so

#cmocka
EXTRA_LDFLAGS += -lcmocka


# this is required according to the DPDK docs
include $(RTE_SDK)/mk/rte.extapp.mk
