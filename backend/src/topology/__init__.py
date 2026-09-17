"""Infrastructure topology: reconstruct the physical picture from what was observed.

This package answers one question — *what does this network actually look like?* —
from whatever set of sources happened to be onboarded, and it is careful to
answer it with observations rather than with plausible shapes.

It is kept strictly apart from `src.graph`, which is the POLICY graph. Nothing in
here may be imported by `src.graph`, and `verify_engine` asserts that
`cross_tool_paths` is byte-identical with and without every model in here
populated. A cable is not a grant.
"""

from .reconstruct import reconstruct

__all__ = ["reconstruct"]
