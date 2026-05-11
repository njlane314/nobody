# Configuration file for the Sphinx documentation builder.

project = "nobody"
author = "nobody contributors"
copyright = "2026, nobody contributors"

version = "0.1"
release = f"{version} draft"

extensions = [
    "sphinx.ext.autosectionlabel",
]

autosectionlabel_prefix_document = True
numfig = True
numfig_format = {
    "code-block": "Listing %s",
    "figure": "Fig. %s",
    "section": "Section %s",
    "table": "Table %s",
}

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "bizstyle"
html_title = "nobody Design Outline"
html_last_updated_fmt = "%b %d, %Y"
html_copy_source = False
html_show_sourcelink = False
html_static_path = []
rst_epilog = ".. _here: here"

latex_documents = [
    ("index", "nobody-design.tex", "nobody Design Outline", author, "manual"),
]
