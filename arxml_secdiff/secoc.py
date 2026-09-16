"""Decide whether a bus-visible connector is actually authenticated.

Two sources, because real programmes rarely give you both:

* **From ARXML** — a ``SECURED-I-PDU`` wraps an authentic I-PDU via ``PAYLOAD-REF``
  and carries the freshness and MAC-length parameters. Where present this is hard
  evidence and is preferred.
* **From an overlay** — a small YAML side input keyed by PDU path, for programmes
  where SecOC lives in vendor-confidential ECU configuration that never ships with
  the architecture files.

The three-valued result is the point of this module. ``authenticated`` is:

* ``None`` — SecOC is *not applicable*: the connector never reaches a PDU, so it is
  RTE-internal and there is nothing on a wire to protect.
* ``False`` — SecOC is *applicable and absent*: the data crosses a bus unprotected.
* ``True`` — protected.

Collapsing None into False is the classic way to drown a report in false positives,
since most connectors in any real ECU extract are internal.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import networkx as nx

from . import signals
from .model import Model

# Where a profile came from, for reporting and for the limitations section.
FROM_ARXML = "secured-i-pdu"
FROM_OVERLAY = "overlay"
ABSENT = "absent"


@dataclass(frozen=True)
class SecOcProfile:
    """Authentication settings for one authentic (payload) PDU."""

    pdu: str
    authenticated: bool
    freshness_bits: int | None = None
    auth_info_bits: int | None = None
    source: str = ABSENT


def from_arxml(model: Model) -> dict[str, SecOcProfile]:
    """Read SECURED-I-PDU wrappers, keyed by the PDU each one protects."""
    profiles: dict[str, SecOcProfile] = {}
    for pdu in model.pdus.values():
        if pdu.kind != "SECURED-I-PDU":
            continue
        payload = _resolve_payload(model, pdu.payload_ref)
        if not payload:
            continue
        el = model.index.get(pdu.path)
        profiles[payload] = SecOcProfile(
            pdu=payload,
            authenticated=True,
            freshness_bits=_int_child(el, "FRESHNESS-VALUE-LENGTH"),
            auth_info_bits=_int_child(el, "AUTH-INFO-TX-LENGTH"),
            source=FROM_ARXML,
        )
    return profiles


def _resolve_payload(model: Model, ref: str | None) -> str | None:
    """Follow PAYLOAD-REF to the protected PDU.

    Depending on schema revision and tool, this points either straight at the
    I-PDU or at its PDU-TRIGGERING, so both are handled.
    """
    if not ref:
        return None
    if ref in model.pdus:
        return ref
    triggering = model.index.get(ref)
    if triggering is not None and triggering.tag == "PDU-TRIGGERING":
        from . import xmlutil

        target = xmlutil.ref(triggering, "I-PDU-REF")
        if target in model.pdus:
            return target
    return None


def _int_child(el, tag: str) -> int | None:
    if el is None:
        return None
    child = el.find(tag)
    if child is None or child.text is None:
        return None
    try:
        return int(child.text.strip())
    except ValueError:
        return None


def load_overlay(path: str | Path) -> dict[str, SecOcProfile]:
    """Load synthetic SecOC config from YAML.

    Expected shape::

        secoc:
          /B/Comm/CmdIPdu:
            authenticated: true
            freshness_bits: 8
            auth_info_bits: 32

    Imported lazily so the ARXML-evidence path stays usable without PyYAML.
    """
    import yaml

    data = yaml.safe_load(Path(path).read_text()) or {}
    entries = data.get("secoc", {}) or {}
    return {
        pdu: SecOcProfile(
            pdu=pdu,
            authenticated=bool(cfg.get("authenticated", False)),
            freshness_bits=cfg.get("freshness_bits"),
            auth_info_bits=cfg.get("auth_info_bits"),
            source=FROM_OVERLAY,
        )
        for pdu, cfg in entries.items()
    }


def profiles(
    model: Model, overlay: str | Path | dict[str, SecOcProfile] | None = None
) -> dict[str, SecOcProfile]:
    """Merge ARXML-derived and overlay profiles.

    ARXML wins on conflict: a SECURED-I-PDU in the file is evidence, while the
    overlay is an assumption.
    """
    merged: dict[str, SecOcProfile] = {}
    if overlay is not None:
        merged.update(
            overlay if isinstance(overlay, dict) else load_overlay(overlay)
        )
    merged.update(from_arxml(model))
    return merged


def annotate(
    graph: nx.MultiDiGraph,
    model: Model,
    profiles_by_pdu: dict[str, SecOcProfile] | None = None,
) -> nx.MultiDiGraph:
    """Attach bus visibility and authentication state to every edge, in place."""
    profiles_by_pdu = profiles_by_pdu if profiles_by_pdu is not None else profiles(model)

    for _, _, attrs in graph.edges(data=True):
        carriers = signals.pdus_for_port(model, attrs.get("provider_port")) | (
            signals.pdus_for_port(model, attrs.get("requester_port"))
        )
        attrs["pdus"] = tuple(sorted(carriers))
        attrs["bus_visible"] = bool(carriers)

        if not carriers:
            # Nothing on a wire: SecOC is not applicable, which is not a failure.
            attrs["authenticated"] = None
            attrs["secoc_source"] = None
            attrs["unprotected_pdus"] = ()
            continue

        unprotected = tuple(
            sorted(
                pdu
                for pdu in carriers
                if not (
                    pdu in profiles_by_pdu and profiles_by_pdu[pdu].authenticated
                )
            )
        )
        attrs["unprotected_pdus"] = unprotected
        attrs["authenticated"] = not unprotected
        sources = {
            profiles_by_pdu[pdu].source for pdu in carriers if pdu in profiles_by_pdu
        }
        attrs["secoc_source"] = sorted(sources)[0] if sources else ABSENT

    return graph


def unprotected_edges(graph: nx.MultiDiGraph) -> list[tuple[str, str, str]]:
    """Edges that cross a bus with at least one unprotected PDU.

    Excludes edges where SecOC is not applicable, so the list is actionable.
    """
    return [
        (u, v, k)
        for u, v, k, d in graph.edges(keys=True, data=True)
        if d.get("authenticated") is False
    ]
