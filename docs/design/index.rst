nobody Design Outline
=====================

.. raw:: latex

   \section*{Preface}

``nobody`` is a least-privilege execution runtime for autonomous software.
It runs agents, tools, MCP servers, and shell commands with declared
capabilities instead of ambient authority inherited from the launching shell.

This document gives a brief introduction to what ``nobody`` aims to achieve and
the design elements in support of those aims.

.. only:: html and pdf_already_exists

   .. admonition:: PDF available

      A PDF rendering of this documentation is available `here`_.

.. toctree::
   :maxdepth: 2
   :numbered:

   introduction
   preliminaries
   conceptual_design
   supporting_design

.. raw:: latex

   \appendix

.. toctree::
   :caption: Appendices:
   :numbered:
   :maxdepth: 2

   appendices/glossary
   appendices/policy_schema
   appendices/threat_model
   appendices/deployment
   appendices/roadmap
