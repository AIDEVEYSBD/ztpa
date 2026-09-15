"""Vendor console projections: the estate rendered in each tool's own payload shape.

A connector answers one question only — "what would this console have returned?"
— and answers it from `src.estate` alone. It never invents a field the estate
does not contain, and it never emits a device the tool's `seen_by` does not
list, because partial coverage is the behaviour being demonstrated rather than a
gap to be papered over.
"""
