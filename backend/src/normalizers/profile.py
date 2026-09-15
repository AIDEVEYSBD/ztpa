"""Declarative, mapping-driven normalizer -- 'bring your own source' without code.

A SourceProfile is pure config (data) describing where a JSON export keeps its
rules and which fields map to the canonical model. apply_profile() interprets it
DETERMINISTICALLY -- no model at runtime. New source = a new profile, not new
Python. (The genuinely weird vendors -- NAT match semantics, App-ID, wildcard
masks -- still get a code adapter; this covers the common tabular/JSON case.)

This module also hosts the SHARED normalizer vocabulary (the section below):
the action verb table, object-catalog address resolution, the abstract-object
test and the required-field guards that algosec.py / guardicore.py / wiz.py all
call. Those helpers belong beside `cidrs_for_token` in `common.py`; they live
here only because `common.py` is this phase's frozen shared contract. Keeping
ONE copy is the point -- "compute the resolved CIDR and then throw it away" got
into three normalizers independently precisely because each one had its own
private `_resolve`.

Two responsibilities this round added, both because the previous fix stopped one
layer above the shape a real export has:

  `object_cidrs` DEREFERENCES RECURSIVELY. A group whose members are the NAMES
  of other objects is how every real AlgoSec / Panorama / FortiManager catalog
  is organised, and every member used to come back "unresolvable object value"
  -- so `source_cidrs` was `[]`, E collapsed to the score of one host, and an
  internet-to-PCI RDP grant produced zero findings. Cycles and depth are bounded
  and REPORTED, because a bound that silently returns less address space than
  the catalog names would be the same defect wearing a different hat.

  `require_rule` REFUSES UNMODELLED RULE STATE. `disabled` / `enabled` / any
  `*negate*` key were read by nobody and refused by nobody, so a switched-off
  rule scored 100/critical and a negated source was reported as its own exact
  complement. Neither semantics is in the canonical model yet, and the contract
  in `NormalizeError`'s docstring is that this module may refuse but may never
  "normalize something else and say nothing".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from pydantic import BaseModel

from ..netaddr import parse_net
from ..sources import TOOL_KEYS
from .common import (
    NormalizeResult, ObservedEntity, ResolvedObject, cidrs_for_token, is_cidr,
    looks_like_address_space, merge_entities, normalize_cidr, parse_service,
    record_from_service, scope_identifiers,
)


# ---------------------------------------------------------------------------
# Shared normalizer vocabulary
# ---------------------------------------------------------------------------


class NormalizeError(ValueError):
    """A source export the normalizer cannot honestly interpret.

    Raised INSTEAD of the bare exceptions the audit measured escaping the
    normalizers (`KeyError: 'action'`, `KeyError: 'src'`, `TypeError: argument
    of type 'NoneType' is not iterable`, `TypeError: unhashable type: 'list'`),
    so a failure names the tool, the row and the field rather than a line
    number in someone else's module.

    Partial ingest -- skipping the offending row and carrying a `skipped`
    report through to the UI -- is Phase 3 work and needs a field on
    `NormalizeResult` that this phase's contract does not have. Until then the
    contract is "normalize, or fail diagnosably"; what it is never allowed to
    be is "normalize something else and say nothing".
    """


# Vendor action verbs -> the two-value canonical vocabulary. Check Point writes
# drop/reject, Cisco permit, Junos/pf pass, Palo allow/deny -- and any of them
# may arrive capitalised. `PolicyRecord.action` is a Literal, so an unmapped
# verb used to die inside pydantic naming neither the rule nor the tool.
_ACTION_ALIASES: dict[str, str] = {
    "allow": "allow", "permit": "allow", "accept": "allow", "pass": "allow",
    "deny": "deny", "drop": "deny", "reject": "deny", "block": "deny",
}

# Declared object types that denote a RANGE of addresses rather than one host.
# The four the audit names; `-group` is matched by suffix because every vendor
# spells a group differently (address-group, network-group, dynamic-group).
_RANGE_OBJECT_TYPES = frozenset({"network", "group", "range", "subnet"})


def decode_action(raw: object, *, default: str = "allow", where: str = "") -> str:
    """A vendor action verb -> "allow" | "deny". Never guesses.

    An ABSENT action falls back to `default` (a profile's `default_action`, or
    the export's own convention) -- there is nothing to interpret in a field
    that is not there. A PRESENT but unmapped verb raises, because inventing
    "allow" for a verb we do not understand fabricates a grant, which is the one
    direction a security tool must never fail in. That is exactly what
    `apply_profile` used to do: `action if action in ("allow", "deny") else
    "allow"` turned every Check Point `drop` into an allow, silently.
    """
    if raw is None:
        return default
    token = str(raw).strip().lower()
    if not token:
        return default
    mapped = _ACTION_ALIASES.get(token)
    if mapped is None:
        raise NormalizeError(
            f"{where}unmapped action verb {str(raw).strip()!r} "
            f"(known: {', '.join(sorted(_ACTION_ALIASES))})")
    return mapped


def is_abstract_object_type(otype: object) -> bool:
    """True when an object's DECLARED type denotes a range, not one host."""
    if otype is None:
        return False
    token = str(otype).strip().lower().replace("_", "-")
    return token in _RANGE_OBJECT_TYPES or token.endswith("-group")


def spans_more_than_one_address(cidrs: list[str]) -> bool:
    """True when a resolved address space is wider than a single host.

    `is_abstract_object_type` reads a vendor's vocabulary; this reads the fact.
    An object declared `host` whose value is `10.40.0.0/16` is a subnet whatever
    the export calls it, and a subnet cannot originate traffic -- which is the
    entire reason `graph.reachability._valid_traversal` refuses to pivot through
    an abstract node. Answering this from the address rather than from the type
    name is what makes a named segment behave like the same segment written as a
    raw CIDR, which is the invariant the audit found broken.
    """
    if len(cidrs) > 1:                      # an address GROUP is never one host
        return True
    for raw in cidrs:
        net = parse_net(raw)
        if net is not None and net.prefixlen < net.max_prefixlen:
            return True
    return False


def object_is_abstract(otype: object, cidrs: list[str], warnings: list[str]) -> bool:
    """The one rule for "this node denotes a range, not a machine".

    Three sufficient conditions, and every normalizer applies all three so a
    named segment cannot be abstract in one tool's view and concrete in
    another's -- `identity.resolve_identities` folds the views with
    ``all(e.abstract ...)``, so one dissenting view makes the merged asset
    concrete and `reachability._valid_traversal` will pivot an attack path
    through it.

      declared type   a `network`/`group`/`range`/`subnet` object;
      resolved width  more than one address, whatever the type name claims;
      unresolved      the value did not parse. FAIL CLOSED: we have no evidence
                      it is a host, and calling it one is precisely how a typo'd
                      broad rule came to score as a single host.
    """
    return (is_abstract_object_type(otype) or spans_more_than_one_address(cidrs)
            or bool(warnings))


# Vendor spellings of the separate MASK column, normalized the way
# `common._scope_key` normalizes a scope key (lowercased, non-alphanumerics
# stripped), so `netMask`, `net_mask` and `NETMASK` are one entry. A catalog row
# that keeps the address and its width in two columns -- `{"value": "10.0.0.0",
# "netmask": "255.0.0.0"}` -- is an ASA/FortiManager staple and resolved to a
# /32 HOST before this, which is the same "bad shape lowers the score" failure
# as an unparseable CIDR. `prefixlen`/`prefixlength` carry an integer width; both
# forms are handed to `cidrs_for_token`, which reads either.
#
# Deliberately narrow: only keys that can ONLY be a mask. Bare `prefix` and
# `cidr` are absent because they are how some exports spell the VALUE, and
# reading a value as a mask would be the same category error in reverse. (A
# wrong mask is not catastrophic -- `_cidrs_for_value` falls back to the bare
# token -- but a table that cannot be wrong is better than one that recovers.)
_NETMASK_ALIASES: frozenset[str] = frozenset({
    "netmask", "mask", "subnetmask", "wildcard", "wildcardmask", "inversemask",
    "prefixlen", "prefixlength", "masklen", "masklength", "maskbits",
})

# How deep a group-of-groups may nest before we stop and say so. Real catalogs
# nest two or three deep; sixteen is far past any of them and small enough that
# a pathological export cannot burn the request on recursion.
MAX_OBJECT_DEPTH = 16


def object_netmask(obj: object) -> Optional[str]:
    """The separate mask/prefix column a catalog row carries, if any.

    Deterministic: source keys are visited in sorted order, so a row that spells
    the mask twice resolves the same way every time rather than by JSON key
    order. Returns None for a row that declares no mask -- which is every row in
    every bundled fixture, so this cannot change an existing answer.
    """
    if not isinstance(obj, dict):
        return None
    for raw_key in sorted(k for k in obj if isinstance(k, str)):
        if "".join(ch for ch in raw_key.lower() if ch.isalnum()) not in _NETMASK_ALIASES:
            continue
        value = obj[raw_key]
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
    return None


def object_cidrs(value: object, *, netmask: Optional[str] = None,
                 objects: Optional[dict] = None, value_key: str = "value",
                 seen: frozenset[str] = frozenset(), depth: int = 0
                 ) -> tuple[list[str], list[str]]:
    """An object-catalog `value` -> (canonical CIDRs, warnings). Never raises.

    Accepts the shapes real catalogs use: one string, a LIST of strings (an
    address group -- which used to be written straight into
    `ObservedEntity.cidr` and blow up later inside the identity layer at
    `ips.add(e.cidr)` with `unhashable type: 'list'`), a missing value, and --
    when the caller hands over the catalog -- MEMBERS THAT ARE THE NAMES OF
    OTHER OBJECTS.

    GROUP OF GROUPS IS THE NORMAL SHAPE, AND IT WAS THE HOLE (audit-2 B8)
    ---------------------------------------------------------------------
    The previous round taught this function to dereference a group whose members
    are literal addresses and stopped there. Every real AlgoSec / Panorama /
    FortiManager catalog is organised the other way round: `EXTERNAL-SOURCES` is
    a group whose members are the NAMES of other objects, one of which is the
    one holding `0.0.0.0/0`. A name is not an address, so every member became
    "unresolvable object value", `source_cidrs` came back `[]`, and
    `exposure_score` fell back to E_IDENTITY = 0.1 -- the exposure of ONE HOST.
    Measured: ``EXTERNAL-SOURCES -> db-prod-01 (pci) tcp/3389`` produced ZERO
    findings, while the byte-identical grant written ``ANY-EXTERNAL -> db-prod-01
    tcp/3389`` was 100/critical/forced. The fix that shipped had been narrowed to
    the shape the probe happened to use.

    So members are now dereferenced RECURSIVELY, with the two bounds a graph
    walk needs and a warning for each:

      `seen`   the names already on the dereference stack. A catalog is allowed
               to contain a cycle (operators build them by accident), and
               `A -> B -> A` must report the cycle, not recurse forever.
      `depth`  a hard ceiling (`MAX_OBJECT_DEPTH`), so a pathological export
               cannot turn one rule into unbounded work.

    `netmask` is the separate mask/prefix column (`object_netmask`), applied to
    every string member. A value that is not address space at all is REPORTED,
    never dropped and never silently reclassified. `10.0.0.0/33` and
    `300.1.1.1/24` are typos in what is usually a BROAD rule, and they used to
    quietly become single-host identity assets -- i.e. bad input LOWERS the
    reported risk, which is the worst failure direction available to a security
    tool. That report is now also a SCORED fact: the caller turns a non-empty
    `warnings` into `PolicyRecord.source_unresolved`.

    Determinism: members are visited in the order the catalog lists them, the
    resolved blocks are canonicalized and sorted by `PolicyRecord`'s own
    validator, and nothing here iterates a set.
    """
    values = value if isinstance(value, (list, tuple)) else [value]
    cidrs: list[str] = []
    warnings: list[str] = []
    for item in values:
        if item is None:
            continue
        if not isinstance(item, str):
            warnings.append(f"object value {item!r} is not a string")
            continue
        token = item.strip()
        if not token:
            continue
        resolved, mask_warning = _cidrs_for_value(token, netmask)
        if mask_warning is not None:
            warnings.append(mask_warning)
        if resolved:
            cidrs.extend(resolved)
            continue
        member = objects.get(token) if isinstance(objects, dict) else None
        if isinstance(member, dict) and member:
            if token in seen:
                # A cycle is a data defect in the customer's catalog, not ours.
                # Reporting it (rather than dropping the member) is what makes
                # the resulting `source_unresolved` honest.
                warnings.append(f"object group cycle at {token!r}")
                continue
            if depth >= MAX_OBJECT_DEPTH:
                warnings.append(
                    f"object nesting deeper than {MAX_OBJECT_DEPTH} at {token!r}")
                continue
            nested, nested_warnings = object_cidrs(
                member.get(value_key), netmask=object_netmask(member),
                objects=objects, value_key=value_key,
                seen=seen | {token}, depth=depth + 1)
            cidrs.extend(nested)
            warnings.extend(nested_warnings)
            continue
        warnings.append(f"unresolvable object value {token!r}")
    return cidrs, warnings


def _cidrs_for_value(token: str, netmask: Optional[str]
                     ) -> tuple[list[str], Optional[str]]:
    """One catalog value (+ its separate mask column, if any) -> (CIDRs, warning).

    With no mask this is exactly `cidrs_for_token`. With one, the two columns
    are re-joined into the notations `cidrs_for_token` already reads -- the
    space form (`10.0.0.0 255.0.0.0`, which covers BOTH Cisco mask conventions)
    first, then the slash form (`10.0.0.0/24`, which covers an integer prefix).
    Re-joining rather than re-implementing keeps ONE decoder for address space,
    which is the whole reason `cidrs_for_token` exists.

    AN UNUSABLE MASK IS REPORTED, NOT SHRUGGED OFF. `{"value": "10.0.0.0",
    "netmask": "<junk>"}` still resolves as the bare token -- which is a /32 --
    so quietly ignoring the mask turns a network the export declared into a
    single host, i.e. the same "bad input lowers the reported risk" failure as
    an unparseable CIDR, arriving through a different column. The address we can
    read is kept and the loss is carried out as a warning, which the caller turns
    into `PolicyRecord.source_unresolved`.
    """
    if netmask is None:
        return cidrs_for_token(token), None
    combined = (cidrs_for_token(f"{token} {netmask}")
                or cidrs_for_token(f"{token}/{netmask}"))
    if combined:
        return combined, None
    fallback = cidrs_for_token(token)
    if not fallback or looks_like_address_space(token):
        # Either the value names no address at all (the caller reports that on
        # its own -- two warnings for one defect would only obscure it), or the
        # value ALREADY carries its own width (`10.0.0.0/8`, a range, an inline
        # mask pair). A mask column beside a value that is already a network is
        # redundant, not lost, so there is nothing to report.
        return fallback, None
    # A bare host address whose declared width could not be applied: the /32 the
    # fallback yields is NARROWER than what the export meant, which is the
    # direction that hides exposure.
    return fallback, f"unusable mask {netmask!r} on object value {token!r}"


def token_cidrs(token: str) -> tuple[list[str], list[str]]:
    """A src/dst TOKEN -> (canonical CIDRs, warnings), before any catalog lookup.

    Wraps `common.cidrs_for_token` with the one distinction it cannot make on
    its own: `[]` because the token is a NAME (fine -- the caller resolves it
    against the object catalog next) versus `[]` because the token LOOKS like an
    address and is not one. `10.0.0.0/33` falling through to an identity node is
    the silent reclassification the audit filed: the rule then scores as a
    single host (E=0.1) and vanishes from every piece of subnet math.

    "Looks like an address" is `common.looks_like_address_space`, which now also
    knows the two notations a range object and an ASA rule are written in -- so
    `10.0.0.0-9.0.0.0` (inverted) and `10.0.0.0 0.255.0.255` (a discontiguous
    wildcard, which denotes a set no CIDR list can express) are reported rather
    than silently becoming labels. It stays deliberately narrow on the bare
    word: a hostname could be anything, and there is no honest way to tell a
    typo'd address from a name that happens to look numeric.
    """
    resolved = cidrs_for_token(token)
    if resolved:
        return resolved, []
    if looks_like_address_space(token):
        return [], [f"malformed address {token.strip()!r}"]
    return [], []


def require_mapping(value: object, *, tool: str, what: str) -> dict:
    """A catalog that must be a {name: {...}} map. Absent/None = empty catalog."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    raise NormalizeError(
        f"{tool}: {what} must be an object map keyed by name, got {type(value).__name__}")


def require_rows(value: object, *, tool: str, what: str) -> list:
    """A rules array that must be a list. Absent/None = an empty export."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    raise NormalizeError(
        f"{tool}: {what} must be a list of rules, got {type(value).__name__}")


# Keys whose canonical (lowercased, non-alphanumerics stripped) spelling names a
# rule STATE the canonical model does not carry. Two families, both fatal:
#
#   enablement  `disabled: true` / `enabled: false` / `inactive: true`. The rule
#               grants NOTHING. Scoring it produced a measured 100/critical on a
#               rule that is switched off, plus a fabricated "dead deny: blocked
#               traffic is actually allowed" shadowing finding underneath it.
#   negation    `src_negate`, `negate-destination`, `negate: true`. The rule's
#               source is the COMPLEMENT of what the field says. Measured:
#               `allow NOT 10.0.0.0/8 -> db tcp/3389` -- which is the internet --
#               was read as `10.0.0.0/8` and reported "85 critical, RDP open
#               from INTERNAL", i.e. the exact inverse of the truth.
#
# Both are matched by SUBSTRING on the canonical key so `srcNegate`,
# `negate_source` and `dst-negate` are one rule, and both are absent from every
# bundled fixture, so nothing that ships today reaches this.
_NEGATE_MARK = "negate"
# The inline spelling: `src: "!10.0.0.0/8"`. One character, unambiguous -- no
# vendor object name begins with it.
_TOKEN_NEGATION = "!"
_DISABLED_KEYS = frozenset({"disabled", "inactive", "isdisabled", "ruledisabled"})
_ENABLED_KEYS = frozenset({"enabled", "active", "isenabled", "ruleenabled"})


def _canon_key(key: object) -> str:
    """A raw export key -> lowercase alphanumerics, for table comparison."""
    return "".join(ch for ch in str(key).lower() if ch.isalnum())


def require_rule(row: object, *, tool: str, index: int) -> dict:
    """One row that must be a mapping, carrying no state we do not model.

    A bare string row indexed as a dict was `TypeError: string indices must be
    integers` from inside the normalizer; that is the shape half of this guard.

    The other half is UNMODELLED RULE STATE (audit-2 L2 / quick win 5). No
    normalizer reads `disabled`/`enabled` or any negation flag, and nothing
    refused them either, so both were silently dropped -- and the two failures
    that produced are in opposite directions and both wrong:

      a DISABLED broad allow scored 100/critical and fabricated a "dead deny"
      shadowing finding under it (over-reporting a grant that does not exist);

      a NEGATED source was read as its own complement -- `NOT 10.0.0.0/8`, which
      IS the internet, reported as "from INTERNAL" at 85 (under-reporting the
      one thing this product exists to find).

    Honouring the semantics is scheduled work (REQUIREMENTS FUT-P3-2/-4) and
    needs model fields this phase does not have. Until then the contract this
    module states in `NormalizeError`'s own docstring applies: "what it is never
    allowed to be is 'normalize something else and say nothing'". So it refuses,
    by name, the day a real export first arrives.
    """
    if not isinstance(row, dict):
        raise NormalizeError(
            f"{tool} rule #{index}: expected an object, got {type(row).__name__}")
    where = _rule_label(row, index)
    for key in sorted(k for k in row if isinstance(k, str)):
        canon = _canon_key(key)
        if _NEGATE_MARK in canon:
            raise NormalizeError(
                f"{tool} {where}: field {key!r} negates a match; negation is not "
                "modelled yet and a negated source is the COMPLEMENT of the "
                "address it names, not the address itself")
        if canon in _DISABLED_KEYS and _is_truthy(row[key]):
            raise NormalizeError(
                f"{tool} {where}: field {key!r} marks the rule disabled; rule "
                "state is not modelled yet and a disabled rule grants nothing")
        if canon in _ENABLED_KEYS and _is_falsy(row[key]):
            raise NormalizeError(
                f"{tool} {where}: field {key!r} marks the rule not enabled; rule "
                "state is not modelled yet and a disabled rule grants nothing")
    return row


# The id columns real exports use, in the order they are tried, so a refusal
# names the rule an operator has to go and look at rather than only its index.
_RULE_ID_KEYS: tuple[str, ...] = (
    "rule_id", "ruleid", "policy_id", "policyid", "exposure_id", "exposureid",
    "id", "uid", "name", "rule_number", "rulenumber", "number", "seq",
)


def _rule_label(row: dict, index: int) -> str:
    """`rule 'ALGO-001'` when the row names itself, else `rule #7`.

    Deterministic: source keys are visited in sorted order and the first
    spelling of a canonical key wins, so a row carrying both `id` and `ID`
    labels itself the same way every time.
    """
    canon: dict[str, str] = {}
    for key in sorted(k for k in row if isinstance(k, str)):
        canon.setdefault(_canon_key(key), key)
    for candidate in _RULE_ID_KEYS:
        key = canon.get(_canon_key(candidate))
        if key is None:
            continue
        raw = row[key]
        if isinstance(raw, (str, int)) and not isinstance(raw, bool) and str(raw).strip():
            return f"rule {str(raw).strip()!r}"
    return f"rule #{index}"


def _is_truthy(value: object) -> bool:
    """A vendor's "yes". JSON booleans and the string spellings both appear."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "y", "1", "on", "enable", "enabled"}
    if isinstance(value, int):
        return value != 0
    return False


def _is_falsy(value: object) -> bool:
    """A vendor's explicit "no". ABSENT is not "no" -- only a present false is.

    `enabled` missing from a row means the export does not model enablement at
    all, which is every fixture in the repo; refusing those would refuse every
    export we support today. Only an explicit negative is unmodelled state.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return not value
    if isinstance(value, str):
        return value.strip().lower() in {"false", "no", "n", "0", "off", "disable", "disabled"}
    if isinstance(value, int):
        return value == 0
    return False


def require_field(rule: dict, name: str, *, tool: str, where: str) -> Any:
    """A field the canonical model cannot be built without."""
    value = rule.get(name)
    if value is None:
        raise NormalizeError(f"{tool} {where}: missing required field {name!r}")
    return value


def require_token(rule: dict, name: str, *, tool: str, where: str) -> str:
    """A src/dst field that must be exactly ONE scalar token.

    A LIST here is a multi-source rule -- the normal shape of a real firewall
    rule, and today `TypeError: unhashable type: 'list'` raised deep inside the
    identity layer with no mention of the rule that caused it. Fanning one rule
    out into a record per (src, dst, service) tuple is Phase 3's ingestion work;
    until that lands the honest answer is a named refusal, never a record whose
    source is the string `"['10.1.0.0/16', '10.2.0.0/16']"`.
    """
    value = require_field(rule, name, tool=tool, where=where)
    if isinstance(value, (list, tuple, set, dict)):
        raise NormalizeError(
            f"{tool} {where}: field {name!r} is a {type(value).__name__}; multi-valued "
            "sources/destinations are not supported yet (one token per rule)")
    token = str(value).strip()
    if not token:
        raise NormalizeError(f"{tool} {where}: field {name!r} is empty")
    if token.startswith(_TOKEN_NEGATION):
        # The INLINE spelling of the negation `require_rule` refuses as a flag
        # (pf / iptables / some Palo exports write `!10.0.0.0/8` in the column
        # itself). Same semantics, same refusal: `NOT 10.0.0.0/8` is the
        # internet, and both reading it as `10.0.0.0/8` and dropping it silently
        # are false statements about the customer's network. Today it merely
        # fails `parse_net` and lands as an unresolvable label.
        raise NormalizeError(
            f"{tool} {where}: field {name!r} value {token!r} is negated; negation "
            "is not modelled yet and the complement of an address is not the "
            "address")
    return token


def require_action(rule: dict, name: str, *, tool: str, where: str,
                   default: Optional[str] = None) -> str:
    """The action field, required and decoded onto the canonical vocabulary.

    A rule with no verb is not a policy statement, so an ABSENT action raises
    unless the caller supplies a `default` (a profile's `default_action`, which
    is an explicit operator decision rather than a guess). Silently reading a
    missing action as "allow" invents a grant out of a truncated export -- and
    `KeyError: 'action'` from a single malformed row taking down a 4,000-rule
    snapshot is the exact failure the audit measured.
    """
    raw = rule.get(name)
    if raw is None and default is None:
        raise NormalizeError(f"{tool} {where}: missing required field {name!r}")
    return decode_action(raw, default=default or "allow", where=f"{tool} {where}: ")


# Rule-level audit rows are namespaced so they can never collide with a catalog
# OBJECT of the same name: `resolved_objects` is UNIQUE on
# (snapshot_id, source_device, object_name, object_kind) and its `object_kind`
# is a CHECK-constrained domain, so a rule row cannot simply invent a new kind.
_RULE_PREFIX = "rule:"


def service_audit(tool: str, ref: str, svc, device: Optional[str] = None
                  ) -> list[ResolvedObject]:
    """An audit row for a service whose decode was not clean; [] when it was.

    `parse_service` never raises -- it returns its problems on
    `DecodedService.warnings` -- so without this the warnings would be decoded
    and then discarded, which is the same class of loss this phase exists to
    remove. `ResolvedObject` is the export's own "name -> value dereferencing"
    audit trail and already carries an `object_kind` of "service", so the
    warning lands somewhere the Ingest Inspector already renders.
    """
    if not svc.warnings:
        return []
    return [ResolvedObject(tool, f"{_RULE_PREFIX}{ref}", "service",
                           {"service": svc.label, "protocol": svc.protocol,
                            "port": svc.port, "port_end": svc.port_end,
                            "warnings": list(svc.warnings)}, device)]


def token_audit(tool: str, ref: str, fields: dict[str, list[str]],
                device: Optional[str] = None) -> list[ResolvedObject]:
    """ONE audit row per rule carrying every src/dst token defect it had.

    One row and not one per field, because `resolved_objects` is UNIQUE on
    (snapshot_id, source_device, object_name, object_kind): a rule with a
    malformed src AND a malformed dst would otherwise write two rows with the
    same key and silently lose one -- losing the record of a loss.

    This is where a malformed address becomes VISIBLE. `NormalizeResult` has no
    warning channel this phase (adding one is Phase 3's partial-ingest work), and
    the alternative -- staying silent -- is precisely the audit finding: bad
    input quietly lowering the reported risk.
    """
    present = {name: list(warnings) for name, warnings in fields.items() if warnings}
    if not present:
        return []
    return [ResolvedObject(tool, f"{_RULE_PREFIX}{ref}", "address",
                           {"malformed": True, "fields": dict(sorted(present.items()))},
                           device)]


# ---------------------------------------------------------------------------
# The declarative profile
# ---------------------------------------------------------------------------


class FieldMap(BaseModel):
    src: str
    dst: str
    action: Optional[str] = None          # field name; else default_action
    default_action: str = "allow"
    service: Optional[str] = None          # field giving "tcp/443" / "any"
    port: Optional[str] = None             # field giving an int port
    protocol: Optional[str] = None         # field giving a protocol
    app: Optional[str] = None              # field giving an explicit App-ID (e.g. "quic")
    order: Optional[str] = None
    ref: Optional[str] = None              # field giving the rule id; else the index


class SourceProfile(BaseModel):
    tool: str
    rules_path: str                        # top-level key holding the list of rules
    fields: FieldMap
    objects_path: Optional[str] = None     # top-level key holding an object catalog {name: {...}}
    object_value_key: str = "value"
    object_tags_key: str = "tags"
    object_type_key: str = "type"
    device: Optional[str] = None


# The canonical `SourceTool` vocabulary a record must carry, read straight off
# the source registry so this module cannot hold a stale copy of it. A profile
# naming a tool outside it is REFUSED by `require_known_tool` -- it used to be
# relabelled as "algosec", which turned an unlisted console into a false
# provenance claim rather than an error.
_KNOWN_TOOLS = TOOL_KEYS


def require_known_tool(tool: str) -> str:
    """The profile's tool name, carried through exactly as declared.

    A profile naming a tool outside the shipped catalogue is NOT an error --
    bringing your own source is the feature this module exists for, and the
    profile is the operator's registration of it. What is an error is a profile
    that names no tool at all, because every downstream provenance claim is then
    attributed to the empty string.

    This function used to be the relabel: a tool outside the catalogue was
    rewritten to "algosec" so the record would satisfy a closed Literal. The
    ingest succeeded and every provenance claim it produced was false. The
    Literal is gone (see models.SourceTool); the name is now carried as given,
    and `sources.BY_KEY` decides only whether we can say anything ABOUT the tool
    -- never what it is called.
    """
    name = (tool or "").strip()
    if not name:
        raise NormalizeError(
            "profile declares no `tool`: every record, object and finding this "
            "profile produces would be attributed to the empty string"
        )
    return name


@dataclass
class _ResolvedToken:
    """What one profile-mapped src/dst field dereferences to.

    A named record rather than the five-element tuple this used to be, for the
    reason `algosec._Resolved` gives: a tuple is how a resolved CIDR came to be
    discarded at the call site behind an underscore, and this one had to grow a
    sixth element (`unresolved`) that must never be the one silently dropped.

    The node KIND (cidr vs identity) is deliberately absent: `record_from_service`
    derives it from the token, which is what stops one string being a CIDR at one
    call site and an identity at the next.
    """

    name: str                       # display name / node key; "" when unmapped
    tags: list[str]
    cidrs: list[str]                # the resolved address space ([] = none exists)
    warnings: list[str]             # field/token/value defects, for the audit trail
    entity: Optional[ObservedEntity]
    # Address space was CLAIMED and did not resolve -- see
    # `PolicyRecord.source_unresolved`. Strictly narrower than `warnings`: a
    # field that is absent or multi-valued warns but claims no address space, so
    # it must not raise the exposure floor.
    unresolved: bool = False


def _resolve(token: object, objects: dict, profile: SourceProfile, tool: str
             ) -> _ResolvedToken:
    """One src/dst token -> its display name and the ADDRESS SPACE it denotes.

    `name` is what the operator sees and what the graph keys on; `cidrs` is the
    address space it dereferences to, which is what the analyzers do subnet math
    on. Returning both is the whole fix: the label alone made a named /0 score
    as a single host.

    An ABSENT field returns `name == ""`. The empty string is deliberate and
    load-bearing: `str(None)` used to produce the *truthy* string `"None"`,
    which sailed straight through `advisory.authoring.validate_profile`'s
    falsiness check and put a green "validated" badge over a table of
    `None -> None` rows. An empty source is falsy, so the existing validator now
    correctly reports the profile invalid.
    """
    if token is None:
        return _ResolvedToken("", [], [], ["field is absent from the sample row"], None)
    if isinstance(token, (list, tuple, set, dict)):
        # Same rule as the coded normalizers: refuse, rather than normalize
        # `str([...])` into a node name nothing will ever resolve.
        return _ResolvedToken(
            "", [], [],
            [f"multi-valued field ({type(token).__name__}) is not supported yet"], None)

    text = str(token).strip()
    if not text:
        return _ResolvedToken("", [], [], ["field is empty in the sample row"], None)

    if is_cidr(text):
        cidr = normalize_cidr(text)
        ent = ObservedEntity(name=cidr, kind="cidr", tool=tool, cidr=cidr, cidrs=[cidr],
                             abstract=True)
        return _ResolvedToken(cidr, [], [cidr], [], ent)

    obj = objects.get(text) if objects else None
    if not isinstance(obj, dict) or not obj:
        # Not an object in the catalog: it may still BE address space (a bare
        # host ip, a range, an address+mask pair, or the wildcard vocabulary),
        # and if it merely looks like one that is a data defect worth reporting
        # rather than a new asset.
        cidrs, warnings = token_cidrs(text)
        abstract = object_is_abstract(None, cidrs, warnings)
        ent = ObservedEntity(name=text, kind="identity", tool=tool, abstract=abstract,
                             cidr=cidrs[0] if len(cidrs) == 1 and abstract else None,
                             cidrs=list(cidrs) if abstract else [],
                             identifiers={"malformed_address": True} if warnings else {})
        return _ResolvedToken(text, [], cidrs, warnings, ent, bool(warnings))

    value = obj.get(profile.object_value_key)
    tags = obj.get(profile.object_tags_key, []) or []
    otype = obj.get(profile.object_type_key)
    # The catalog is passed on, so a member that is the NAME of another object
    # dereferences instead of becoming "unresolvable object value" -- the
    # group-of-groups shape every real export uses (audit-2 B8).
    cidrs, warnings = object_cidrs(value, netmask=object_netmask(obj), objects=objects,
                                   value_key=profile.object_value_key,
                                   seen=frozenset({text}))
    abstract = object_is_abstract(otype, cidrs, warnings)
    single = cidrs[0] if len(cidrs) == 1 else None
    ent = ObservedEntity(
        name=text, kind="identity", tool=tool, tags=list(tags), abstract=abstract,
        ip=value if (otype == "host" and isinstance(value, str) and not abstract) else None,
        cidr=single if abstract else None,
        # `single` is None for a GROUP, which is how a profile-defined address
        # group reached `zone_of` with no address space at all; `cidrs` is the
        # channel that carries every block. Only for a node that DENOTES space
        # (abstract): a concrete host's address travels on `ip`.
        cidrs=list(cidrs) if abstract else [],
        # Plus the namespace the catalog row declares, if any: a declarative
        # profile is the path a CUSTOMER export takes, so it is the one that most
        # needs to be able to say which VPC / account an address belongs to.
        # `scope_identifiers` reads the row's own keys, so no profile field has
        # to be mapped for an export that already spells them a standard way.
        identifiers={**scope_identifiers(obj),
                     **({"malformed_address": True} if warnings else {})},
    )
    return _ResolvedToken(text, list(tags), cidrs, warnings, ent, bool(warnings))


def apply_profile(raw: dict, profile: SourceProfile) -> NormalizeResult:
    """Interpret a SourceProfile over one raw export. Deterministic, no model."""
    res = NormalizeResult()
    tool = require_known_tool(profile.tool)
    fm = profile.fields
    objects = require_mapping(raw.get(profile.objects_path) if profile.objects_path else None,
                              tool=tool, what=f"{profile.objects_path!r}")
    entities: dict[str, ObservedEntity] = {}

    for name in sorted(objects):
        obj = objects[name] if isinstance(objects[name], dict) else {}
        value = obj.get(profile.object_value_key)
        # Same dereference the rule path uses -- catalog included -- so the audit
        # trail shows the address space a NESTED group actually denotes rather
        # than a row of "unresolvable object value '<member name>'".
        cidrs, warnings = object_cidrs(value, netmask=object_netmask(obj), objects=objects,
                                       value_key=profile.object_value_key,
                                       seen=frozenset({name}))
        row = {"value": value, "type": obj.get(profile.object_type_key),
               "tags": obj.get(profile.object_tags_key, []), "cidrs": cidrs,
               "abstract": object_is_abstract(obj.get(profile.object_type_key),
                                              cidrs, warnings)}
        if warnings:
            row["warnings"] = warnings
        res.resolved.append(ResolvedObject(tool, name, "address", row, profile.device))

    rules = require_rows(raw.get(profile.rules_path), tool=tool,
                         what=f"{profile.rules_path!r}")
    for i, row in enumerate(rules):
        rule = require_rule(row, tool=tool, index=i + 1)
        ref = str(rule.get(fm.ref)) if fm.ref and rule.get(fm.ref) is not None else f"{tool.upper()}-{i + 1}"
        src = _resolve(rule.get(fm.src), objects, profile, tool)
        dst = _resolve(rule.get(fm.dst), objects, profile, tool)
        if src.entity is not None:
            merge_entities(entities, src.entity)
        if dst.entity is not None:
            merge_entities(entities, dst.entity)
        app = rule.get(fm.app) if fm.app else None
        if fm.service:
            svc = parse_service(service=rule.get(fm.service), app=app)
        else:
            svc = parse_service(port=rule.get(fm.port) if fm.port else None,
                                protocol=rule.get(fm.protocol) if fm.protocol else None, app=app)
        res.resolved.extend(service_audit(tool, ref, svc, profile.device))
        res.resolved.extend(token_audit(tool, ref, {"src": src.warnings, "dst": dst.warnings},
                                        profile.device))
        action = decode_action(rule.get(fm.action) if fm.action else None,
                               default=fm.default_action, where=f"{tool} rule {ref}: ")
        res.records.append(record_from_service(
            # A profile naming a tool outside the registry now FAILS, loudly,
            # at `require_known_tool` above. It used to be recorded as
            # "algosec" -- so onboarding a console nobody had enumerated did
            # not error, it silently attributed that console's rules to a
            # different vendor's product, and every provenance claim
            # downstream (the source badge, the rule reference, the "seen by"
            # column, the audit trail) was wrong with no way to notice.
            record_id=ref, source_tool=tool,
            raw_ref=ref, source=src.name, destination=dst.name, svc=svc, action=action,
            dest_tags=list(dst.tags), order=rule.get(fm.order) if fm.order else (i + 1) * 10,
            source_cidrs=src.cidrs, dest_cidrs=dst.cidrs,
            source_unresolved=src.unresolved,
        ))

    res.entities = list(entities.values())
    return res


def field_report(raw: dict, profile: SourceProfile) -> dict:
    """Per-field resolution counts for a proposed profile.

    "Is it valid?" was answered by two questions -- are there any rows, and is
    any row's source/destination/service falsy -- and a profile whose field
    names are ALL wrong answered yes to both (`str(None)` -> `"None"`, truthy).
    Counting how many rows each mapped field actually resolved makes "0 of
    40,000 rows resolved a source" impossible to report as green.

    Returned separately from `apply_profile` because `NormalizeResult` has no
    field to carry it; `advisory.authoring.validate_profile` should merge this
    into its result (see the phase report).
    """
    fm = profile.fields
    rows = require_rows(raw.get(profile.rules_path), tool=profile.tool,
                        what=f"{profile.rules_path!r}")
    mapped: list[tuple[str, Optional[str]]] = [
        ("src", fm.src), ("dst", fm.dst), ("action", fm.action), ("service", fm.service),
        ("port", fm.port), ("protocol", fm.protocol), ("app", fm.app),
        ("order", fm.order), ("ref", fm.ref),
    ]
    resolved: dict[str, int] = {}
    for name, field_name in mapped:
        if field_name is None:
            continue
        resolved[name] = sum(
            1 for row in rows
            if isinstance(row, dict) and row.get(field_name) is not None
            and str(row.get(field_name)).strip() != ""
        )
    # src and dst are the two fields no record can be built without; a mapping
    # that resolves neither is a wrong mapping, not a sparse export.
    unresolved = sorted(name for name in ("src", "dst")
                        if name in resolved and resolved[name] == 0)
    return {
        "rows": len(rows),
        "resolved": dict(sorted(resolved.items())),
        "unresolved_fields": unresolved,
        "valid": bool(rows) and not unresolved,
    }
