"""The 9 real-world-inspired scenarios: node/edge graphs for before and after."""

from generate_scenarios import Edge, Node, Scenario

SCENARIOS: list[Scenario] = []


# 1 -- Jeep Cherokee / Uconnect (Miller & Valasek, 2015) ----------------------
# Cellular -> head unit (unauth D-Bus, port 6667) -> V850 chip bridge -> CAN bus
# -> steering/brakes. FCA recalled 1.4M vehicles. Source: Miller & Valasek,
# "Remote Exploitation of an Unaltered Passenger Vehicle" (Black Hat 2015);
# Dark Reading, "Jeep Hack 0Day: An Exposed Port" (2015-08-06).
_n = [
    Node("tel", "Telematics", "TelematicsEcu"),
    Node("ivi", "HeadUnit", "TelematicsEcu"),
    Node("bridge", "V850Bridge", "GatewayEcu"),
    Node("steer", "SteeringCtrl", "ChassisEcu"),
]
_before_edges = [
    Edge("tel", "ivi", "cellToHu", "CellLink", secured=None),   # RTE-local, same ECU
    # no ivi -> bridge link before the flaw: head unit cannot reach the bridge
]
_after_edges = [
    Edge("tel", "ivi", "cellToHu", "CellLink", secured=None),
    Edge("ivi", "bridge", "huToBridge", "DbusCmd", secured=False),   # unauth D-Bus, port 6667
    Edge("bridge", "steer", "bridgeToSteer", "CanFrame", secured=False),  # firmware-rewrite path
]
SCENARIOS.append(Scenario(
    id="01_jeep_uconnect",
    title="Jeep Cherokee / Uconnect remote exploit (2015)",
    source="Miller & Valasek, Black Hat USA 2015; recall of 1.4M FCA vehicles",
    summary="Update path opens an unauthenticated head-unit-to-CAN-bridge hop that "
             "reaches steering. Expected: BLOCK.",
    expected_before="PASS", expected_after="BLOCK",
    before_nodes=_n, before_edges=_before_edges,
    after_nodes=_n, after_edges=_after_edges,
    entry=["tel", "ivi"], critical=["steer"],
))


# 2 -- BMW ConnectedDrive (Tencent Keen Security Lab, 2018) -------------------
# TCU (NGTP/HTTP RCE) -> Central Gateway -> UDS diagnostic messages -> chassis
# CAN buses. Source: Keen Security Lab, "Experimental Security Assessment of
# BMW Cars" (2018); Security Affairs, 2018-05-23.
_n = [
    Node("tcu", "TelematicsUnit", "TcuEcu"),
    Node("cgw", "CentralGateway", "GatewayEcu"),
    Node("chassis", "ChassisCtrl", "ChassisEcu"),
]
_before_edges = [
    Edge("tcu", "cgw", "tcuToGw", "RemoteSvc", secured=True),   # authenticated remote service only
]
_after_edges = [
    Edge("tcu", "cgw", "tcuToGw", "RemoteSvc", secured=True),
    Edge("cgw", "chassis", "gwToChassis", "UdsDiag", secured=False),  # new diagnostic passthrough, unauth
]
SCENARIOS.append(Scenario(
    id="02_bmw_connecteddrive",
    title="BMW ConnectedDrive TCU-to-gateway diagnostic passthrough (2018)",
    source="Tencent Keen Security Lab, 'Experimental Security Assessment of BMW Cars' (2018)",
    summary="Update adds an unauthenticated UDS diagnostic passthrough from the gateway "
             "to chassis ECUs. Expected: BLOCK.",
    expected_before="PASS", expected_after="BLOCK",
    before_nodes=_n, before_edges=_before_edges,
    after_nodes=_n, after_edges=_after_edges,
    entry=["tcu"], critical=["chassis"],
))


# 3 -- Tesla 2016 OTA fix: code-signing / SecOC added (CONTROL, benign) -------
# Source: Nie et al. (Keen Security Lab), "Free-Fall: Hacking Tesla From
# Wireless To CAN Bus" (Black Hat 2017): "Tesla responded with an update ...
# and introduced the code signing protection."
_n = [
    Node("ic", "InfotainmentClient", "IcEcu"),
    Node("gw", "Gateway", "GatewayEcu"),
    Node("ape", "AutopilotEcu", "ApeEcu"),
]
_before_edges = [
    Edge("ic", "gw", "icToGw", "CanBridge", secured=False),   # pre-fix: unauthenticated
    Edge("gw", "ape", "gwToApe", "CanFrame", secured=False),
]
_after_edges = [
    Edge("ic", "gw", "icToGw", "CanBridge", secured=True),    # OTA fix: code signing / SecOC added
    Edge("gw", "ape", "gwToApe", "CanFrame", secured=True),
]
SCENARIOS.append(Scenario(
    id="03_tesla_2016_fix",
    title="Tesla 2016 remote-attack OTA fix: code signing added (control case)",
    source="Nie et al., Tencent Keen Security Lab, Black Hat USA 2017",
    summary="A real hardening update: no new reachability, only added authentication. "
             "Expected: PASS (true-negative control; tool must not cry wolf on a fix).",
    expected_before="BLOCK", expected_after="PASS",
    before_nodes=_n, before_edges=_before_edges,
    after_nodes=_n, after_edges=_after_edges,
    entry=["ic"], critical=["ape"],
))


# 4 -- Mitsubishi Outlander PHEV Wi-Fi PSK weakness -> GSM module swap --------
# Source: cited in "Developments in Connected Vehicles and the Requirement for
# Increased Cybersecurity" (arXiv:2111.11612): Mitsubishi later swapped the
# Wi-Fi module for a GSM module (2019 model).
_n_before = [
    Node("wifi", "WifiModule", "TelematicsEcu"),
    Node("alarm", "AlarmCtrl", "BodyEcu"),
]
_n_after = [
    Node("gsm", "GsmModule", "TelematicsEcu"),   # component swapped/rehosted
    Node("alarm", "AlarmCtrl", "BodyEcu"),
]
_before_edges = [
    Edge("wifi", "alarm", "wifiToAlarm", "AppCmd", secured=False),  # crackable PSK, unauth in practice
]
_after_edges = [
    Edge("gsm", "alarm", "gsmToAlarm", "AppCmd", secured=True),   # stronger auth on the new module
]
SCENARIOS.append(Scenario(
    id="04_mitsubishi_outlander",
    title="Mitsubishi Outlander PHEV Wi-Fi module weak PSK -> GSM module fix",
    source="Pen Test Partners disclosure (2016); component-swap noted in arXiv:2111.11612",
    summary="Update replaces the whole telecom component and strengthens auth. Naively "
             "expected PASS, but the tool correctly returns FLAG: 'gsm' is a brand-new "
             "node with no prior reachability history, so the newly-reachable pair is "
             "reported even though the hop is fully SecOC-protected -- a genuinely "
             "unreviewed route is not the same claim as a safe one. Worth keeping as-is: "
             "this is a case where the tool's actual behavior is more defensible than "
             "the intuitive expectation.",
    expected_before="BLOCK", expected_after="FLAG",
    before_nodes=_n_before, before_edges=_before_edges,
    after_nodes=_n_after, after_edges=_after_edges,
    # "wifi" only exists in the before graph, "gsm" only in the after: each
    # snapshot's reach.analyse() filters entry_points to nodes actually present,
    # so this correctly models "the entry point itself was rehosted/renamed".
    entry=["wifi", "gsm"], critical=["alarm"],
))


# 5 -- FCA network-level fix layered on top of the 2015 recall (CONTROL) ------
# Source: Stellantis/FCA press statement, 2015-07-24: "network-level security
# measures ... block remote access to certain vehicle systems."
_n = [
    Node("tel", "Telematics", "TelematicsEcu"),
    Node("gw", "Gateway", "GatewayEcu"),
    Node("steer", "SteeringCtrl", "ChassisEcu"),
]
_before_edges = [
    Edge("tel", "gw", "telToGw", "RemoteCmd", secured=False),
    Edge("gw", "steer", "gwToSteer", "CanFrame", secured=False),
]
_after_edges = [
    Edge("tel", "gw", "telToGw", "RemoteCmd", secured=True),  # network-level block modeled as auth added
    # gw -> steer connector removed entirely: access blocked, not just authenticated
]
SCENARIOS.append(Scenario(
    id="05_fca_network_fix",
    title="FCA post-recall network-level access restriction (2015)",
    source="Stellantis/FCA media statement, 2015-07-24",
    summary="Fix removes a connector entirely and authenticates what remains. "
             "Expected: PASS (removed-pair, no regression).",
    expected_before="BLOCK", expected_after="PASS",
    before_nodes=_n, before_edges=_before_edges,
    after_nodes=_n, after_edges=_after_edges,
    entry=["tel"], critical=["steer"],
))


# 6 -- Sam Curry / Nissan cloud API authorization regression (2023) ----------
# Source: Sam Curry et al. disclosure, Jan 2023; Nissan confirmed the fix was
# "bugs in the configuration of the APIs" (Allgeier/secion coverage).
# Modeled with the cloud API as an entry-point node reachable from outside.
_n = [
    Node("api", "CloudApi", "TelematicsEcu"),
    Node("cmdsvc", "VehicleCmdService", "GatewayEcu"),
    Node("ignition", "IgnitionCtrl", "PowertrainEcu"),
]
_before_edges = [
    Edge("api", "cmdsvc", "apiToCmd", "VinCmd", secured=True),   # object-level auth check present
    Edge("cmdsvc", "ignition", "cmdToIgn", "IgnCmd", secured=True),
]
_after_edges = [
    Edge("api", "cmdsvc", "apiToCmd", "VinCmd", secured=False),  # BOPLA: auth check dropped
    Edge("cmdsvc", "ignition", "cmdToIgn", "IgnCmd", secured=True),
]
SCENARIOS.append(Scenario(
    id="06_curry_nissan_api",
    title="Cloud API authorization-object regression (Sam Curry disclosure, 2023)",
    source="Sam Curry et al., 'Web Hackers vs. The Auto Industry' (Jan 2023); "
           "Nissan statement re: API configuration fix",
    summary="Backend API loses its per-VIN authorization check, reaching ignition "
             "control by VIN alone. Expected: BLOCK (secoc-removed).",
    expected_before="PASS", expected_after="BLOCK",
    before_nodes=_n, before_edges=_before_edges,
    after_nodes=_n, after_edges=_after_edges,
    entry=["api"], critical=["ignition"],
))


# 7 -- Spireon fleet admin-panel misconfiguration (2023) ----------------------
# Source: disclosed alongside the Curry research, Jan 2023 (Security Ledger,
# The Hacker News): "full administrative access ... to an estimated 15.5
# million vehicles ... disable starters."
_n = [
    Node("panel", "AdminPanel", "TelematicsEcu"),
    Node("fleet", "FleetGateway", "GatewayEcu"),
    Node("starter", "StarterCtrl", "PowertrainEcu"),
]
_before_edges = [
    Edge("panel", "fleet", "panelToFleet", "AdminCmd", secured=True),
    Edge("fleet", "starter", "fleetToStarter", "StarterCmd", secured=True),
]
_after_edges = [
    Edge("panel", "fleet", "panelToFleet", "AdminCmd", secured=False),  # admin auth misconfigured away
    Edge("fleet", "starter", "fleetToStarter", "StarterCmd", secured=True),
]
SCENARIOS.append(Scenario(
    id="07_spireon_fleet_admin",
    title="Spireon fleet admin-panel authentication misconfiguration (2023)",
    source="Security Ledger / The Hacker News coverage of Sam Curry et al. disclosures, Jan 2023",
    summary="Admin panel loses authentication to the fleet gateway, enabling mass "
             "remote starter disable. Expected: BLOCK.",
    expected_before="PASS", expected_after="BLOCK",
    before_nodes=_n, before_edges=_before_edges,
    after_nodes=_n, after_edges=_after_edges,
    entry=["panel"], critical=["starter"],
))


# 8 -- SOME/IP de-association: discovery auth removed -------------------------
# Source: Zelle et al., "Analyzing and Securing SOME/IP Automotive Services
# with Formal and Practical Methods" (ARES 2021); also VERA paper Scenario B.
_n = [
    Node("consumer", "ServiceConsumer", "GatewayEcu"),
    Node("provider", "AdasService", "AdasEcu"),
]
_before_edges = [
    Edge("consumer", "provider", "discover", "SomeIpDiscover", secured=True),
]
_after_edges = [
    Edge("consumer", "provider", "discover", "SomeIpDiscover", secured=False),  # StopOffer spoofable
]
SCENARIOS.append(Scenario(
    id="08_someip_deassociation",
    title="SOME/IP service-discovery de-association (Zelle et al., 2021)",
    source="Zelle, Lauser, Kern, Krauss, ARES 2021; also VERA paper Scenario A/B",
    summary="Update removes authentication from SOME/IP service discovery, enabling a "
             "spoofed StopOffer to disconnect the ADAS service. Expected: BLOCK.",
    expected_before="PASS", expected_after="BLOCK",
    before_nodes=_n, before_edges=_before_edges,
    after_nodes=_n, after_edges=_after_edges,
    entry=["consumer"], critical=["provider"],
))


# 9 -- NHTSA supply-chain component-injection pattern -------------------------
# Source: NHTSA, "Cybersecurity Best Practices for the Modern Vehicle" (2020
# report on OTA malware vectors): malware injected via supplier/third-party
# components bundled into a feature update.
_n_before = [
    Node("ivi", "HeadUnit", "TelematicsEcu"),
    Node("gw", "Gateway", "GatewayEcu"),
    Node("body", "BodyCtrl", "BodyEcu"),
]
_n_after = [
    Node("ivi", "HeadUnit", "TelematicsEcu"),
    Node("sdk", "ThirdPartyAdSdk", "TelematicsEcu"),   # new supplier component, added by the update
    Node("gw", "Gateway", "GatewayEcu"),
    Node("body", "BodyCtrl", "BodyEcu"),
]
_before_edges = [
    Edge("ivi", "gw", "ivitogw", "InfoLink", secured=True),
    Edge("gw", "body", "gwtobody", "BodyCmd", secured=True),
]
_after_edges = [
    Edge("ivi", "gw", "ivitogw", "InfoLink", secured=True),
    Edge("gw", "body", "gwtobody", "BodyCmd", secured=True),
    Edge("sdk", "gw", "sdktogw", "TelemetryLink", secured=False),  # new SDK wired straight to the gateway
]
SCENARIOS.append(Scenario(
    id="09_supply_chain_sdk",
    title="Third-party supplier SDK bundled into an infotainment feature update",
    source="NHTSA, 'Cybersecurity Best Practices for the Safety of Modern Vehicles' (2020)",
    summary="A feature update bundles a third-party telemetry SDK that gets an "
             "unauthenticated connector straight to the gateway it doesn't need. "
             "Expected: BLOCK (component-added + unprotected-new-hop).",
    expected_before="PASS", expected_after="BLOCK",
    before_nodes=_n_before, before_edges=_before_edges,
    after_nodes=_n_after, after_edges=_after_edges,
    entry=["ivi", "sdk"], critical=["body"],
))
