# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

UNAME_M = $(shell uname -m)

# binary name
APP = scionfwd

# all source are stored in SRCS-y
SRCS-y := application.c hashdict.c hashdict_flow.c key_manager.c murmurhash.c scion_bloom.c scionfwd.c

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

ifeq ($(RTE_TARGET),)
$(error "Please define RTE_TARGET environment variable")
endif

include $(RTE_SDK)/mk/rte.vars.mk

CFLAGS += -g -O3
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I$(SRCDIR)

#AES
ifeq ($(UNAME_M), x86_64)
	LDLIBS += -L'$(PWD)/lib/aesni'
	EXTRA_LDFLAGS += -laesni
else
	LDLIBS += -lcrypto
endif

#Key manager
LDLIBS += -L'$(PWD)/lib/go'
EXTRA_LDFLAGS += -l:go_key_manager.so

#cmocka
# EXTRA_LDFLAGS += -lcmocka

include $(RTE_SDK)/mk/rte.extapp.mk
