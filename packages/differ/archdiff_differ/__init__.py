"""archdiff_differ: Permission Graph v1 differ.

Two stages, kept separate on purpose:

* ``archdiff_differ.structural`` -- Stage 1: hash-set comparison of node/edge digests
  with the Merkle module-tree prune (SCHEMA.md section 5).
* ``archdiff_differ.semantic``   -- Stage 2: effective capabilities, privilege paths,
  confidence (SCHEMA.md sections 4, 7).

``archdiff_differ.differ.diff_graphs`` orchestrates both and emits the section-7 diff
document; ``archdiff_differ.render`` turns that document into a PR comment.
"""
from .differ import diff_graphs, dumps  # noqa: F401
from .graph import Graph, load_graph  # noqa: F401

__version__ = "0.1.0"
