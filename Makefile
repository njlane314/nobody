.DEFAULT_GOAL := all

CARGO ?= cargo
INSTALL ?= install
PREFIX ?= /usr/local
DESTDIR ?=
MANDIR ?= $(PREFIX)/share/man

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
	$(INSTALL) -d "$(DESTDIR)$(MANDIR)/man1"
	$(INSTALL) -d "$(DESTDIR)$(MANDIR)/man5"
	$(INSTALL) -d "$(DESTDIR)$(MANDIR)/man7"
	$(INSTALL) -m 0644 man/nobody.1 "$(DESTDIR)$(MANDIR)/man1/nobody.1"
	$(INSTALL) -m 0644 man/nobody.toml.5 "$(DESTDIR)$(MANDIR)/man5/nobody.toml.5"
	$(INSTALL) -m 0644 man/nobody-trace.5 "$(DESTDIR)$(MANDIR)/man5/nobody-trace.5"
	$(INSTALL) -m 0644 man/nobody-policy.7 "$(DESTDIR)$(MANDIR)/man7/nobody-policy.7"
	$(INSTALL) -m 0644 man/nobody-sandbox.7 "$(DESTDIR)$(MANDIR)/man7/nobody-sandbox.7"

clean:
	$(CARGO) clean

distclean: clean
	rm -rf .nobody
