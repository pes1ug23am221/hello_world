"""Generate before/after ARXML fixture pairs for real-world-inspired scenarios.

Each scenario is a minimal 3-5 node chain (entry -> [mid] -> critical) modeled on a
documented, sourced real-world incident. The "before" and "after" snapshots differ
in exactly the way that incident's root cause or fix did: an edge is added/removed,
a hop stops/starts crossing a bus, or SecOC protection is added/removed.

This is deliberately NOT a reproduction of any real vehicle's actual architecture
(that data isn't public) -- it's a small, schema-valid AUTOSAR graph shaped to
exercise the same *pattern* the real incident exhibits, so arxml-secdiff's
reachability/SecOC logic can be exercised against it and produce a real verdict.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

NS = "http://autosar.org/schema/r4.0"


@dataclass
class Node:
    short: str          # prototype short name, e.g. "tel"
    type_short: str      # component type short name, e.g. "Telematics"
    ecu: str              # ECU instance short name
    kind: str = "APPLICATION-SW-COMPONENT-TYPE"


@dataclass
class Edge:
    src: str          # node.short
    dst: str          # node.short
    name: str          # connector short name
    iface: str          # interface short name
    secured: bool | None = None  # True = SECURED-I-PDU present, False = bus, no wrapper, None = RTE-local (no mapping at all)


@dataclass
class Scenario:
    id: str
    title: str
    source: str
    summary: str
    expected_before: str  # PASS / n-a
    expected_after: str   # PASS / FLAG / BLOCK
    before_nodes: list[Node]
    before_edges: list[Edge]
    after_nodes: list[Node]
    after_edges: list[Edge]
    entry: list[str]      # node.short of entry points (same both snapshots)
    critical: list[str]   # node.short of critical points (same both snapshots), ASIL D


def _pkg_name(scenario_id: str) -> str:
    # AUTOSAR SHORT-NAME must be a valid identifier-ish token; keep it short.
    return "S" + scenario_id.split("_")[0].upper()[:3] + scenario_id.split("_")[-1][:4].upper()


def build_arxml(scn: Scenario, nodes: list[Node], edges: list[Edge]) -> str:
    pkg = _pkg_name(scn.id)
    ecus = sorted({n.ecu for n in nodes})
    node_by_short = {n.short: n for n in nodes}

    # -- interfaces (one SENDER-RECEIVER-INTERFACE per edge) --------------------
    if_xml = []
    for e in edges:
        if_xml.append(f"""            <SENDER-RECEIVER-INTERFACE>
              <SHORT-NAME>{e.iface}</SHORT-NAME>
              <DATA-ELEMENTS>
                <VARIABLE-DATA-PROTOTYPE>
                  <SHORT-NAME>val</SHORT-NAME>
                </VARIABLE-DATA-PROTOTYPE>
              </DATA-ELEMENTS>
            </SENDER-RECEIVER-INTERFACE>""")

    # -- component types: one P-PORT per outgoing edge, one R-PORT per incoming --
    out_edges: dict[str, list[Edge]] = {}
    in_edges: dict[str, list[Edge]] = {}
    for e in edges:
        out_edges.setdefault(e.src, []).append(e)
        in_edges.setdefault(e.dst, []).append(e)

    comp_xml = []
    for n in nodes:
        ports = []
        for e in out_edges.get(n.short, []):
            ports.append(f"""                <P-PORT-PROTOTYPE>
                  <SHORT-NAME>{e.name}Out</SHORT-NAME>
                  <PROVIDED-INTERFACE-TREF DEST="SENDER-RECEIVER-INTERFACE">/{pkg}/If/{e.iface}</PROVIDED-INTERFACE-TREF>
                </P-PORT-PROTOTYPE>""")
        for e in in_edges.get(n.short, []):
            ports.append(f"""                <R-PORT-PROTOTYPE>
                  <SHORT-NAME>{e.name}In</SHORT-NAME>
                  <REQUIRED-INTERFACE-TREF DEST="SENDER-RECEIVER-INTERFACE">/{pkg}/If/{e.iface}</REQUIRED-INTERFACE-TREF>
                </R-PORT-PROTOTYPE>""")
        comp_xml.append(f"""            <{n.kind}>
              <SHORT-NAME>{n.type_short}</SHORT-NAME>
              <PORTS>
{chr(10).join(ports) if ports else "              "}
              </PORTS>
            </{n.kind}>""")

    # -- composition: prototypes + assembly connectors --------------------------
    proto_xml = [
        f"""                <SW-COMPONENT-PROTOTYPE>
                  <SHORT-NAME>{n.short}</SHORT-NAME>
                  <TYPE-TREF DEST="{n.kind}">/{pkg}/Swc/{n.type_short}</TYPE-TREF>
                </SW-COMPONENT-PROTOTYPE>"""
        for n in nodes
    ]
    conn_xml = []
    for e in edges:
        conn_xml.append(f"""                <ASSEMBLY-SW-CONNECTOR>
                  <SHORT-NAME>{e.name}</SHORT-NAME>
                  <PROVIDER-IREF>
                    <CONTEXT-COMPONENT-REF DEST="SW-COMPONENT-PROTOTYPE">/{pkg}/Swc/Root/{e.src}</CONTEXT-COMPONENT-REF>
                    <TARGET-P-PORT-REF DEST="P-PORT-PROTOTYPE">/{pkg}/Swc/{node_by_short[e.src].type_short}/{e.name}Out</TARGET-P-PORT-REF>
                  </PROVIDER-IREF>
                  <REQUESTER-IREF>
                    <CONTEXT-COMPONENT-REF DEST="SW-COMPONENT-PROTOTYPE">/{pkg}/Swc/Root/{e.dst}</CONTEXT-COMPONENT-REF>
                    <TARGET-R-PORT-REF DEST="R-PORT-PROTOTYPE">/{pkg}/Swc/{node_by_short[e.dst].type_short}/{e.name}In</TARGET-R-PORT-REF>
                  </REQUESTER-IREF>
                </ASSEMBLY-SW-CONNECTOR>""")

    # -- comm layer: SYSTEM-SIGNAL / I-SIGNAL / I-SIGNAL-I-PDU / SECURED-I-PDU --
    comm_xml = []
    for e in edges:
        if e.secured is None:
            continue  # RTE-local: no signal chain at all
        comm_xml.append(f"""            <SYSTEM-SIGNAL>
              <SHORT-NAME>{e.name}SSig</SHORT-NAME>
            </SYSTEM-SIGNAL>
            <I-SIGNAL>
              <SHORT-NAME>{e.name}ISig</SHORT-NAME>
              <SYSTEM-SIGNAL-REF DEST="SYSTEM-SIGNAL">/{pkg}/Comm/{e.name}SSig</SYSTEM-SIGNAL-REF>
            </I-SIGNAL>
            <I-SIGNAL-I-PDU>
              <SHORT-NAME>{e.name}IPdu</SHORT-NAME>
              <I-SIGNAL-TO-PDU-MAPPINGS>
                <I-SIGNAL-TO-I-PDU-MAPPING>
                  <SHORT-NAME>{e.name}Map</SHORT-NAME>
                  <I-SIGNAL-REF DEST="I-SIGNAL">/{pkg}/Comm/{e.name}ISig</I-SIGNAL-REF>
                </I-SIGNAL-TO-I-PDU-MAPPING>
              </I-SIGNAL-TO-PDU-MAPPINGS>
            </I-SIGNAL-I-PDU>""")
        if e.secured is True:
            comm_xml.append(f"""            <SECURED-I-PDU>
              <SHORT-NAME>{e.name}SecuredIPdu</SHORT-NAME>
              <AUTH-INFO-TX-LENGTH>32</AUTH-INFO-TX-LENGTH>
              <FRESHNESS-VALUE-ID>1</FRESHNESS-VALUE-ID>
              <FRESHNESS-VALUE-LENGTH>8</FRESHNESS-VALUE-LENGTH>
              <PAYLOAD-REF DEST="I-SIGNAL-I-PDU">/{pkg}/Comm/{e.name}IPdu</PAYLOAD-REF>
            </SECURED-I-PDU>""")

    # -- topology: ECU instances + SWC-TO-ECU mapping + data mappings -----------
    ecu_xml = [f"""            <ECU-INSTANCE>
              <SHORT-NAME>{ecu}</SHORT-NAME>
            </ECU-INSTANCE>""" for ecu in ecus]

    swc_map_xml = []
    for ecu in ecus:
        members = [n.short for n in nodes if n.ecu == ecu]
        refs = "\n".join(
            f"""                        <COMPONENT-IREF>
                          <TARGET-COMPONENT-REF DEST="SW-COMPONENT-PROTOTYPE">/{pkg}/Swc/Root/{m}</TARGET-COMPONENT-REF>
                        </COMPONENT-IREF>"""
            for m in members
        )
        swc_map_xml.append(f"""                    <SWC-TO-ECU-MAPPING>
                      <SHORT-NAME>To{ecu}</SHORT-NAME>
                      <COMPONENT-IREFS>
{refs}
                      </COMPONENT-IREFS>
                      <ECU-INSTANCE-REF DEST="ECU-INSTANCE">/{pkg}/Topology/{ecu}</ECU-INSTANCE-REF>
                    </SWC-TO-ECU-MAPPING>""")

    data_map_xml = []
    for e in edges:
        if e.secured is None:
            continue
        data_map_xml.append(f"""                    <SENDER-RECEIVER-TO-SIGNAL-MAPPING>
                      <DATA-ELEMENT-IREF>
                        <CONTEXT-COMPOSITION-REF DEST="ROOT-SW-COMPOSITION-PROTOTYPE">/{pkg}/Topology/Veh/Root</CONTEXT-COMPOSITION-REF>
                        <CONTEXT-PORT-REF DEST="P-PORT-PROTOTYPE">/{pkg}/Swc/{node_by_short[e.src].type_short}/{e.name}Out</CONTEXT-PORT-REF>
                        <TARGET-DATA-PROTOTYPE-REF DEST="VARIABLE-DATA-PROTOTYPE">/{pkg}/If/{e.iface}/val</TARGET-DATA-PROTOTYPE-REF>
                      </DATA-ELEMENT-IREF>
                      <SYSTEM-SIGNAL-REF DEST="SYSTEM-SIGNAL">/{pkg}/Comm/{e.name}SSig</SYSTEM-SIGNAL-REF>
                    </SENDER-RECEIVER-TO-SIGNAL-MAPPING>""")

    comment_text = f"{scn.title}\n     Source: {scn.source}\n     {scn.summary}".replace("--", "\u2013\u2013")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!-- {comment_text}
-->
<AUTOSAR xmlns="{NS}">
  <AR-PACKAGES>
    <AR-PACKAGE>
      <SHORT-NAME>{pkg}</SHORT-NAME>
      <AR-PACKAGES>
        <AR-PACKAGE>
          <SHORT-NAME>If</SHORT-NAME>
          <ELEMENTS>
{chr(10).join(if_xml)}
          </ELEMENTS>
        </AR-PACKAGE>
        <AR-PACKAGE>
          <SHORT-NAME>Swc</SHORT-NAME>
          <ELEMENTS>
{chr(10).join(comp_xml)}
            <COMPOSITION-SW-COMPONENT-TYPE>
              <SHORT-NAME>Root</SHORT-NAME>
              <COMPONENTS>
{chr(10).join(proto_xml)}
              </COMPONENTS>
              <CONNECTORS>
{chr(10).join(conn_xml)}
              </CONNECTORS>
            </COMPOSITION-SW-COMPONENT-TYPE>
          </ELEMENTS>
        </AR-PACKAGE>
        <AR-PACKAGE>
          <SHORT-NAME>Comm</SHORT-NAME>
          <ELEMENTS>
{chr(10).join(comm_xml) if comm_xml else ""}
          </ELEMENTS>
        </AR-PACKAGE>
        <AR-PACKAGE>
          <SHORT-NAME>Topology</SHORT-NAME>
          <ELEMENTS>
{chr(10).join(ecu_xml)}
            <SYSTEM>
              <SHORT-NAME>Veh</SHORT-NAME>
              <ROOT-SOFTWARE-COMPOSITIONS>
                <ROOT-SW-COMPOSITION-PROTOTYPE>
                  <SHORT-NAME>Root</SHORT-NAME>
                  <SOFTWARE-COMPOSITION-TREF DEST="COMPOSITION-SW-COMPONENT-TYPE">/{pkg}/Swc/Root</SOFTWARE-COMPOSITION-TREF>
                </ROOT-SW-COMPOSITION-PROTOTYPE>
              </ROOT-SOFTWARE-COMPOSITIONS>
              <MAPPINGS>
                <SYSTEM-MAPPING>
                  <SHORT-NAME>Map</SHORT-NAME>
                  <DATA-MAPPINGS>
{chr(10).join(data_map_xml) if data_map_xml else ""}
                  </DATA-MAPPINGS>
                  <SW-MAPPINGS>
{chr(10).join(swc_map_xml)}
                  </SW-MAPPINGS>
                </SYSTEM-MAPPING>
              </MAPPINGS>
            </SYSTEM>
          </ELEMENTS>
        </AR-PACKAGE>
      </AR-PACKAGES>
    </AR-PACKAGE>
  </AR-PACKAGES>
</AUTOSAR>
"""


def _yaml_str(s: str) -> str:
    """Double-quote and escape a string for safe use as a YAML scalar value."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_roles(scn: Scenario, nodes: list[Node]) -> str:
    pkg = _pkg_name(scn.id)
    lines = ["entry_points:"]
    for short in scn.entry:
        lines.append(f"  - node: /{pkg}/Swc/Root/{short}")
        lines.append(f"    reason: {_yaml_str(scn.title + ' entry point')}")
    lines.append("")
    lines.append("critical:")
    for short in scn.critical:
        lines.append(f"  - node: /{pkg}/Swc/Root/{short}")
        lines.append("    asil: D")
        lines.append(f"    reason: {_yaml_str(scn.title + ' safety-critical target')}")
    return "\n".join(lines) + "\n"
