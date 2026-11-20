# SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
#
# Makefile for the CAN_ISOTP functional test suite
#
# make          build all test programs
# make doc      regenerate TESTCASES.md from the test case tables
# make clean    remove build results
#
# The CAN headers from can-tests/include are used (CAN XL / ISOTP XL API).
#

CC      ?= gcc
CFLAGS  ?= -O2 -g
CFLAGS  += -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
CPPFLAGS += -I../../include -Ilib
LDLIBS  += -lpthread

PROGRAMS := \
	tst-isotp-api \
	tst-isotp-tx \
	tst-isotp-rx \
	tst-isotp-xl \
	tst-isotp-e2e \
	tst-isotp-timing

LIBOBJS := lib/ft.o

all: $(PROGRAMS)

$(PROGRAMS): %: %.o $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c lib/ft.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

lib/ft.o: lib/ft.c lib/ft.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

doc: $(PROGRAMS)
	./gen_testcases.sh > TESTCASES.md

clean:
	rm -f $(PROGRAMS) *.o lib/*.o

.PHONY: all doc clean
