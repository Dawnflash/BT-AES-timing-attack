# Supply your implementation here
OWN_IMPLEMENTATION = aes_tbox.c

# Set this to 1 to use an OpenSSL implementation instead
USE_OPENSSL = 0
OPENSSL_PATH =
# Set this to your python binary
PYTHON = python

OUT = core
SOURCES = main.c
OPTIMIZE = fast
DEL = rm -f
RUN_PREFIX =
CFLAGS = -o $(OUT) -std=gnu11 -Wall -Wextra -pedantic -O$(OPTIMIZE)
LDFLAGS = -lm -lrt #-maes

ifeq ($(USE_OPENSSL), 1)
	CFLAGS += -DUSE_OPENSSL

ifdef OPENSSL_PATH
	CFLAGS += -I$(OPENSSL_PATH)/include
	SOURCES += $(OPENSSL_PATH)/libcrypto.so
	RUN_PREFIX += LD_LIBRARY_PATH=$(OPENSSL_PATH)
else
	LDFLAGS += -lcrypto
endif

else
	SOURCES += $(OWN_IMPLEMENTATION)
endif

.PHONY: compile run all test clean generate prepare

include Makefile.in

prepare:
