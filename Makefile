.DEFAULT_GOAL := all

CARGO ?= cargo
PREFIX ?= /usr/local
DESTDIR ?=

.PHONY: all build test check run install clean distclean

all: build

build:
	$(CARGO) build --workspace

test:
	$(CARGO) test --workspace

check: test

run:
	$(CARGO) run --package nobody-cli -- run -- echo hello

install:
	$(CARGO) install --path crates/cli --root "$(DESTDIR)$(PREFIX)"

clean:
	$(CARGO) clean

distclean: clean
	rm -rf .nobody
