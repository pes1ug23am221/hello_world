"""Resolve which physical ECU each component prototype is deployed to.

This is what turns the abstract software graph into something that can answer
cross-HPC questions ("can infotainment reach ADAS?"), because an edge between two
prototypes on the *same* ECU is RTE-internal while an edge between prototypes on
*different* ECUs must traverse a bus — and only the latter can carry SecOC.

The mapping lives in ``SYSTEM/MAPPINGS/SYSTEM-MAPPING/SW-MAPPINGS/SWC-TO-ECU-MAPPING``.
An ECU extract has none: it is already scoped to one ECU, so it never names one.
Use `assume_single_host` for that case rather than leaving every host None.
"""

from __future__ import annotations

from lxml import etree

from . import xmlutil
from .model import EcuInstance, Model


def extract(index: dict[str, etree._Element], model: Model) -> None:
    """Populate `model.ecus` and `model.swc_to_ecu` in place."""
    for path, el in index.items():
        if el.tag == "ECU-INSTANCE":
            model.ecus[path] = EcuInstance(
                path=path,
                short_name=xmlutil.short_name(el) or "",
                comm_connectors=tuple(
                    sorted(
                        f"{path}/{name}"
                        for name in (
                            xmlutil.short_name(c) for c in el.findall("CONNECTORS/*")
                        )
                        if name
                    )
                ),
            )

    for el in index.values():
        if el.tag == "SWC-TO-ECU-MAPPING":
            _apply_mapping(el, model)


def _apply_mapping(el: etree._Element, model: Model) -> None:
    """Join one SWC-TO-ECU-MAPPING's component IREFs to its ECU instance.

    Keyed on TARGET-COMPONENT-REF, which is the same absolute prototype path the
    graph uses for node identity. The CONTEXT-COMPONENT-REF chain only matters for
    prototypes nested more than one composition deep; that is recorded as a
    limitation rather than handled, since it needs an instance-path node key.
    """
    ecu = xmlutil.ref(el, "ECU-INSTANCE-REF")
    if not ecu:
        return
    for iref in el.findall("COMPONENT-IREFS/COMPONENT-IREF"):
        target = xmlutil.ref(iref, "TARGET-COMPONENT-REF")
        if target:
            model.swc_to_ecu[target] = ecu
    # Some tools emit a single un-pluralised COMPONENT-IREF child instead.
    for iref in el.findall("COMPONENT-IREF"):
        target = xmlutil.ref(iref, "TARGET-COMPONENT-REF")
        if target:
            model.swc_to_ecu[target] = ecu


def assume_single_host(model: Model, host: str) -> None:
    """Treat an unmapped snapshot (e.g. an ECU extract) as one host.

    Only fills prototypes that have no mapping, so a partial System Description
    is never overwritten.
    """
    for path in model.prototypes:
        model.swc_to_ecu.setdefault(path, host)


def host_of(model: Model, prototype: str) -> str | None:
    """Short name of the ECU a prototype runs on, or None if unmapped."""
    ecu_path = model.swc_to_ecu.get(prototype)
    if ecu_path is None:
        return None
    ecu = model.ecus.get(ecu_path)
    return ecu.short_name if ecu is not None else ecu_path.rsplit("/", 1)[-1]


def is_cross_ecu(model: Model, source: str, target: str) -> bool | None:
    """Whether an edge between two prototypes must cross a bus.

    Returns None when either endpoint is unmapped, so callers can distinguish
    "same ECU" from "unknown" instead of silently treating unknown as local.
    """
    a, b = model.swc_to_ecu.get(source), model.swc_to_ecu.get(target)
    if a is None or b is None:
        return None
    return a != b
