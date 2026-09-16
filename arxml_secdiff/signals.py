"""Walk the communication chain from a port down to the PDU on the wire.

    port + data element  ->  SYSTEM-SIGNAL  ->  I-SIGNAL  ->  I-SIGNAL-I-PDU

This chain is the join key for SecOC. SecOC is configured against PDUs, while
connectors are declared at the software level, so nothing links a connector to its
authentication config directly — you have to walk this.

The chain is also a *discriminator*, not merely plumbing: a connector whose data
element has no ``SENDER-RECEIVER-TO-SIGNAL-MAPPING`` never leaves the ECU, gets no
PDU, and therefore cannot carry SecOC at all. Absence of authentication on such a
connector is correct, not a finding.

Note that ``SENDER-RECEIVER-TO-SIGNAL-MAPPING`` carries no SHORT-NAME, so it is
not an identifiable element and never appears in the path index. It is reached
through its ``SYSTEM-MAPPING`` parent, which is identifiable.
"""

from __future__ import annotations

from lxml import etree

from . import xmlutil
from .model import (
    SENDER_RECEIVER,
    DataMapping,
    ISignal,
    Model,
    Pdu,
    SignalRoute,
    SystemSignal,
)

# PDU tags we treat as signal carriers. SECURED-I-PDU is the R4.2+ element that
# wraps an authentic I-PDU and is itself direct evidence of SecOC.
PDU_TAGS = {
    "I-SIGNAL-I-PDU",
    "SECURED-I-PDU",
    "NM-PDU",
    "DCM-I-PDU",
    "N-PDU",
    "XCP-PDU",
    "GENERAL-PURPOSE-I-PDU",
    "GENERAL-PURPOSE-PDU",
    "MULTIPLEXED-I-PDU",
    "USER-DEFINED-I-PDU",
}


def extract(index: dict[str, etree._Element], model: Model) -> None:
    """Populate signals, PDUs, data mappings and resolved routes, in place."""
    for path, el in index.items():
        tag = el.tag
        if tag == "SYSTEM-SIGNAL":
            model.system_signals[path] = SystemSignal(
                path=path, short_name=xmlutil.short_name(el) or ""
            )
        elif tag == "I-SIGNAL":
            model.isignals[path] = ISignal(
                path=path,
                short_name=xmlutil.short_name(el) or "",
                system_signal=xmlutil.ref(el, "SYSTEM-SIGNAL-REF"),
            )
        elif tag in PDU_TAGS:
            model.pdus[path] = _pdu(path, el)
        elif tag == "SYSTEM-MAPPING":
            model.data_mappings.extend(_data_mappings(el))

    _resolve_routes(model)


def _pdu(path: str, el: etree._Element) -> Pdu:
    isignals = tuple(
        sorted(
            ref
            for ref in (
                xmlutil.ref(m, "I-SIGNAL-REF")
                for m in el.findall("I-SIGNAL-TO-PDU-MAPPINGS/I-SIGNAL-TO-I-PDU-MAPPING")
            )
            if ref
        )
    )
    return Pdu(
        path=path,
        short_name=xmlutil.short_name(el) or "",
        kind=el.tag,
        isignals=isignals,
        payload_ref=xmlutil.ref(el, "PAYLOAD-REF"),
    )


def _data_mappings(system_mapping: etree._Element) -> list[DataMapping]:
    """Read every DATA-MAPPINGS entry under one SYSTEM-MAPPING."""
    mappings: list[DataMapping] = []

    for el in system_mapping.findall("DATA-MAPPINGS/SENDER-RECEIVER-TO-SIGNAL-MAPPING"):
        signal = xmlutil.ref(el, "SYSTEM-SIGNAL-REF")
        if not signal:
            continue
        iref = el.find("DATA-ELEMENT-IREF")
        mappings.append(
            DataMapping(
                system_signal=signal,
                port=xmlutil.ref(iref, "CONTEXT-PORT-REF") if iref is not None else None,
                data_prototype=(
                    xmlutil.ref(iref, "TARGET-DATA-PROTOTYPE-REF")
                    if iref is not None
                    else None
                ),
                kind=SENDER_RECEIVER,
            )
        )

    # Client-server over a bus splits into a call signal and a return signal, so
    # one mapping yields up to two routes with opposite directions.
    for el in system_mapping.findall("DATA-MAPPINGS/CLIENT-SERVER-TO-SIGNAL-MAPPING"):
        iref = el.find("CLIENT-SERVER-OPERATION-IREF")
        port = operation = None
        if iref is not None:
            port = xmlutil.ref(iref, "CONTEXT-P-PORT-REF") or xmlutil.ref(
                iref, "CONTEXT-R-PORT-REF"
            )
            operation = xmlutil.ref(iref, "TARGET-OPERATION-REF")
        for tag, kind in (
            ("CALL-SIGNAL-REF", "CLIENT-SERVER-CALL"),
            ("RETURN-SIGNAL-REF", "CLIENT-SERVER-RETURN"),
        ):
            signal = xmlutil.ref(el, tag)
            if signal:
                mappings.append(
                    DataMapping(
                        system_signal=signal,
                        port=port,
                        operation=operation,
                        kind=kind,
                    )
                )

    return mappings


def _resolve_routes(model: Model) -> None:
    """Join mappings to signals to PDUs, keeping partial chains.

    A route whose `isignal` or `pdu` is None means the chain stops early — the
    signal is declared but never placed on a PDU. That is a real condition worth
    surfacing, so it is recorded rather than dropped.
    """
    isignals_by_signal: dict[str, list[str]] = {}
    for isig in model.isignals.values():
        if isig.system_signal:
            isignals_by_signal.setdefault(isig.system_signal, []).append(isig.path)

    pdus_by_isignal: dict[str, list[str]] = {}
    for pdu in model.pdus.values():
        for isig_ref in pdu.isignals:
            pdus_by_isignal.setdefault(isig_ref, []).append(pdu.path)

    for mapping in model.data_mappings:
        for isig in sorted(isignals_by_signal.get(mapping.system_signal, [])) or [None]:
            carriers = sorted(pdus_by_isignal.get(isig, [])) if isig else []
            for pdu in carriers or [None]:
                model.routes.append(
                    SignalRoute(
                        port=mapping.port,
                        data_prototype=mapping.data_prototype,
                        system_signal=mapping.system_signal,
                        isignal=isig,
                        pdu=pdu,
                        kind=mapping.kind,
                    )
                )


def pdus_for_port(model: Model, port: str | None) -> set[str]:
    """Every PDU that carries data from `port`."""
    if port is None:
        return set()
    return {r.pdu for r in model.routes if r.port == port and r.pdu}


def is_bus_visible(model: Model, port: str | None) -> bool:
    """Whether any of this port's data actually reaches a PDU.

    False means RTE-internal, which is precisely the case where missing SecOC is
    expected rather than a finding.
    """
    return bool(pdus_for_port(model, port))

