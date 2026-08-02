# CoreCoder Security Agent — Demo Vulnerable C Project
# This is intentionally vulnerable code for security audit demonstration.

CC = gcc
CFLAGS = -Wall -Wextra -g
TARGETS = parser_test auth_test network_test

.PHONY: all clean

all: $(TARGETS)

parser_test: parser.c
	$(CC) $(CFLAGS) -o $@ $<

auth_test: auth.c
	$(CC) $(CFLAGS) -o $@ $<

network_test: network.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) *.o
