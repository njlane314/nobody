.DEFAULT_GOAL := all

CARGO ?= cargo
PREFIX ?= /usr/local
DESTDIR ?=

.PHONY: all build test check run install clean distclean

all: build

build:
	$(CARGO) build

test:
	$(CARGO) test

check: test

run:
	$(CARGO) run -- run -- echo hello

install:
	$(CARGO) install --path . --root "$(DESTDIR)$(PREFIX)"

clean:
	$(CARGO) clean

distclean: clean
	rm -rf .nobody
