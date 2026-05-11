# Minimal Makefile for Sphinx documentation.

SPHINXBUILD ?= sphinx-build
SPHINXOPTS ?=
SOURCEDIR = design
BUILDDIR = _build/design

.PHONY: design-html html clean

design-html:
	$(SPHINXBUILD) -b singlehtml "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS)
	cp "$(BUILDDIR)/index.html" design.html
	perl -pi -e 's/href="index\.html#/href="#/g; s/href="index\.html"/href="#"/g' design.html
	perl -pi -e 's/[ \t]+$$//' design.html
	rm -rf _static
	cp -R "$(BUILDDIR)/_static" _static
	find _static -type f \( -name '*.css' -o -name '*.js' \) -exec perl -pi -e 's/[ \t]+$$//' {} +
	find _static -type f \( -name '*.css' -o -name '*.js' \) -exec perl -0pi -e 's/\n{2,}\z/\n/' {} +

html:
	$(SPHINXBUILD) -b html "$(SOURCEDIR)" "$(BUILDDIR)/html" $(SPHINXOPTS)

clean:
	rm -rf _build _static
