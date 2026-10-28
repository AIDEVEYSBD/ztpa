"""Firewall Rule Review: intake, rule inventory and the review checks.

The analysis engine (`src.analyzers`) works on canonical grants -- one
`PolicyRecord` per (source, destination, service). A rule review needs facts the
grant model deliberately does not carry: whether the rule is enabled, when it
expires, how often it has been hit, which gateways it is installed on, how it is
NATed. Those live here, in `RuleMeta` / `NatRule`, keyed back to the grants each
rule produced (`RuleMeta.record_ids`).
"""
